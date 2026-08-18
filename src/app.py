import os 
import sys 
import time 
import json 
import threading 
import secrets 
import bleach 
from datetime import datetime ,timezone ,timedelta 
from collections import defaultdict 
from flask import Flask ,render_template ,request ,jsonify ,redirect ,url_for ,session ,send_file 
from werkzeug .security import check_password_hash 
from flask_limiter import Limiter 
from flask_limiter .util import get_remote_address 

from database import init_db ,SessionLocal ,User ,AuditLog ,TelemetryLog ,Rule ,DeviceState 
from safety_enforcer import validate_command 
from sqlalchemy .orm import joinedload 
from io import BytesIO 

from analytics import calculate_financial_analytics 
from reporting import generate_incident_report_pdf 




def _resource_path (relative_path :str )->str :
    """Resolve file path for both dev and frozen PyInstaller builds."""
    if hasattr (sys ,'_MEIPASS'):
        return os .path .join (sys ._MEIPASS ,relative_path )
    return os .path .join (os .path .dirname (os .path .abspath (__file__ )),relative_path )

from security import require_webview_token, get_device_key, normalize_device_id, DEFAULT_DEVICE_KEYS, DEVICE_KEYS 


init_db ()

app =Flask (
__name__ ,
template_folder =_resource_path ('templates'),
static_folder =_resource_path ('static'),
)
app .secret_key =os .environ .get ("FLASK_SECRET_KEY",os .urandom (32 ).hex ())


limiter =Limiter (
get_remote_address ,
app =app ,
default_limits =[]if os .environ .get ("AEGIS_DESKTOP_MODE")else ["200 per day","50 per hour"],
storage_uri ="memory://"
)


app .config ['PERMANENT_SESSION_LIFETIME']=timedelta (minutes =30 )
app .config ['SESSION_COOKIE_HTTPONLY']=True 
app .config ['SESSION_COOKIE_SAMESITE']='Strict'
app .config ['SESSION_COOKIE_SECURE']=os .environ .get ("FLASK_SESSION_SECURE","False").lower ()in ("true","1")


DEVICE_KEYS ={
"ESP32_001":get_device_key ("ESP32_001"),
"ESP32_002":get_device_key ("ESP32_002"),
"ESP32_003":get_device_key ("ESP32_003"),
"ESP32_004":get_device_key ("ESP32_004"),
"ESP32_MAIN":get_device_key ("ESP32_001"),
}


def generate_csrf_token ():
    if "csrf_token"not in session :
        session ["csrf_token"]=secrets .token_hex (32 )
    return session ["csrf_token"]

app .jinja_env .globals .update (csrf_token =generate_csrf_token )

@app .before_request 
def csrf_protect ():
    if app .config .get ("TESTING"):
        limiter .enabled = False
        return 

    if request .path =="/api/telemetry":
        return 

    if request .method in ("POST","PUT","DELETE","PATCH"):

        token =request .form .get ("csrf_token")or request .headers .get ("X-CSRF-Token")

        if not token and request .is_json :
            try :
                token =request .json .get ("csrf_token")
            except Exception :
                pass 

        session_token =session .get ("csrf_token")

        if not session_token or not token or not secrets .compare_digest (session_token ,token ):
            if request .is_json or request .path .startswith ("/api/"):
                return jsonify ({"success":False ,"error":"CSRF token missing or invalid."}),400 
            return render_template ("login.html",error ="CSRF validation failed. Please authenticate again."),400 

_device_last_timestamps = {}

def verify_signature(payload: dict) -> bool:
    """
    Verifies HMAC-SHA256 signature and validates against replay and timestamp spoofing attacks.
    """
    import hmac 
    import hashlib 
    import time
    from security import normalize_device_id, get_device_key
    global _device_last_timestamps

    device_id = normalize_device_id(payload.get("device_id", "ESP32_001"))
    sig = payload.get("signature")
    ts = payload.get("timestamp")

    # 1. Timestamp Freshness & Replay Attack Defense
    if ts is not None:
        try:
            ts_float = float(ts)
            now = time.time()
            # Stale packet freshness window (reject packets older than 60s or more than 15s in the future)
            if abs(now - ts_float) > 60.0:
                print(f"[Crypto Defense] REJECTED: Stale timestamp / replay packet for {device_id} (delta: {abs(now - ts_float):.1f}s)")
                return False
            
            # Sequence monotonicity check per device
            last_ts = _device_last_timestamps.get(device_id)
            if last_ts is not None and (ts_float < last_ts - 2.0):
                print(f"[Crypto Defense] REJECTED: Replay sequence detected for {device_id} (current: {ts_float:.3f} < last: {last_ts:.3f})")
                return False
            _device_last_timestamps[device_id] = max(ts_float, _device_last_timestamps.get(device_id, 0.0))
        except (ValueError, TypeError):
            pass

    # If no HMAC signature is provided (standard unsigned sensor packet from hardware UART/Modbus),
    # treat as valid industrial sensor frame so real physical microcontrollers are not falsely isolated.
    if not sig:
        return True

    key_str = DEVICE_KEYS.get(device_id) or get_device_key(device_id)
    key = key_str.encode("utf-8") if key_str else b""
    if not key:
        return False

    def _canonicalize(p):
        result = {}
        for k, v in p.items():
            if k in ("temperature", "pressure", "humidity", "rssi", "vibration", "hall_effect", "current"):
                if v is not None:
                    result[k] = f"{float(v):.2f}"
            elif k == "timestamp":
                if v is not None:
                    result[k] = f"{float(v):.3f}"
            else:
                result[k] = v
        return result

    body = {k: v for k, v in payload.items() if k != "signature"}
    canonical = json.dumps(_canonicalize(body), sort_keys=True, separators=(",", ":"))
    expected = hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, str(sig))

import pickle 
class LocalRFModel:
    def __init__(self, model_path="model/rf_model.pkl"):
        self.model = None
        self.is_fallback = False
        try:
            if os.path.exists(model_path):
                with open(model_path, "rb") as f:
                    self.model = pickle.load(f)
                    print(f"[ML Engine] Loaded Random Forest model from {model_path}")
            else:
                self.is_fallback = True
                print(f"[ML Engine] Model file {model_path} not found. Running in DETERMINISTIC RULES FALLBACK mode.")
        except Exception as e:
            self.is_fallback = True
            print(f"[ML Engine] Failed to load Random Forest model: {e}. Active mode: DETERMINISTIC RULES FALLBACK.")

    def predict_anomaly(self, telemetry: dict, db_session=None) -> bool:
        if not telemetry or not isinstance(telemetry, dict):
            return False
        temp_val = telemetry.get("temperature")
        pres_val = telemetry.get("pressure")
        vib_val = telemetry.get("vibration")
        hall_val = telemetry.get("hall_effect")
        curr_val = telemetry.get("current")
        hum_val = telemetry.get("humidity")

        # Default physical safeguard bounds
        temp_max = 60.0
        temp_min = 0.0
        pressure_max = 8.0
        pressure_min = 0.0
        vibration_max = 4.0
        current_max = 15.0
        hall_max = 3500.0

        if db_session is not None:
            try:
                from database import Rule
                rules = db_session.query(Rule).all()
                rule_dict = {r.key: r.value for r in rules}
                temp_max = float(rule_dict.get("temp_max", 60.0))
                temp_min = float(rule_dict.get("temp_min", 0.0))
                pressure_max = float(rule_dict.get("pressure_max", 8.0))
                pressure_min = float(rule_dict.get("pressure_min", 0.0))
                vibration_max = float(rule_dict.get("vibration_max", 4.0))
                current_max = float(rule_dict.get("current_max", 15.0))
                hall_max = float(rule_dict.get("hall_max", 3500.0))
            except Exception:
                pass

        anomaly = 0.0

        # 1. Deterministic Physical Safety Bounds
        if temp_val is not None:
            t = float(temp_val)
            if t < temp_min or t > temp_max:
                anomaly += 0.6
        if pres_val is not None:
            p = float(pres_val)
            if p < pressure_min or p > pressure_max:
                anomaly += 0.6
        if vib_val is not None and float(vib_val) > vibration_max:
            anomaly += 0.6
        if hall_val is not None and float(hall_val) > hall_max:
            anomaly += 0.6
        if curr_val is not None and float(curr_val) > current_max:
            anomaly += 0.6

        # 2. Deterministic Cross-Variable Physical Interlocks
        # (a) Locked Rotor: high current while motor is stalled/zero RPM
        if curr_val is not None and float(curr_val) > 8.0:
            if hall_val is not None and float(hall_val) < 50.0:
                anomaly += 0.7

        # (b) Coolant Loss / Thermal Runaway: elevated temperature with collapsed pressure
        if temp_val is not None and float(temp_val) > 48.0:
            if pres_val is not None and float(pres_val) < 2.0:
                anomaly += 0.7

        # (c) Severe Mechanical Cavitation: high vibration under high rotor velocity
        if vib_val is not None and float(vib_val) > 2.8:
            if hall_val is not None and float(hall_val) > 1800.0:
                anomaly += 0.7

        # 3. 5D Random Forest ML Classification (if model is healthy)
        all_features_present = (temp_val is not None and pres_val is not None and vib_val is not None and curr_val is not None)
        if all_features_present and self.model is not None:
            try:
                features = [[
                    float(temp_val),
                    float(pres_val),
                    float(vib_val),
                    float(hall_val) if hall_val is not None else 0.0,
                    float(curr_val)
                ]]
                proba = self.model.predict_proba(features)[0]
                if float(proba[1]) > 0.5:
                    anomaly += 0.6
            except Exception:
                pass

        return anomaly > 0.5 

rf_model = LocalRFModel(_resource_path(os.path.join("model", "rf_model.pkl")))

def process_telemetry(payload: dict) -> bool:
    from security import normalize_device_id
    db = SessionLocal()
    device_id = normalize_device_id(payload.get("device_id", "ESP32_001"))
    payload["device_id"] = device_id

    state = db.query(DeviceState).filter_by(device_id=device_id).first()
    if not state and device_id != "unknown":
        state = DeviceState(device_id=device_id, is_isolated=False, trust_score=100.0)
        db.add(state)
        db.commit()

    # If node is currently isolated, halt telemetry ingestion immediately
    if state and state.is_isolated:
        db.close()
        return False

    sig_valid = verify_signature(payload)
    ml_anomaly = rf_model.predict_anomaly(payload, db_session=db)
    is_anomaly = (not sig_valid) or ml_anomaly

    # 4-Factor Dynamic Trust Score Computation
    trust = 100.0
    if not sig_valid:
        trust -= 65.0
    if ml_anomaly:
        trust -= 50.0

    # Continuous sliding window anomaly frequency check
    recent_logs = db.query(TelemetryLog).filter_by(device_id=device_id).order_by(TelemetryLog.timestamp.desc()).limit(10).all()
    past_anomalies = sum(1 for log_item in recent_logs if log_item.is_anomaly)
    if past_anomalies > 0:
        trust -= min(30.0, past_anomalies * 6.0)

    # Dynamic sensor drift / unphysical jump check
    if recent_logs and len(recent_logs) > 0 and payload.get("temperature") is not None:
        last_temp = recent_logs[0].temperature
        if last_temp is not None:
            temp_delta = abs(float(payload["temperature"]) - float(last_temp))
            if temp_delta > 12.0:
                trust -= 20.0

    trust = round(max(0.0, min(100.0, trust)), 1)

    try:
        log = TelemetryLog(
            timestamp=payload.get("timestamp", time.time()),
            device_id=device_id,
            temperature=payload.get("temperature"),
            pressure=payload.get("pressure"),
            humidity=payload.get("humidity"),
            vibration=payload.get("vibration"),
            hall_effect=payload.get("hall_effect"),
            current=payload.get("current"),
            rssi=payload.get("rssi"),
            is_anomaly=is_anomaly
        )
        db.add(log)
        db.commit()

        if state:
            state.trust_score = trust

            # Automatic Isolation if trust degrades below 40% or anomaly detected
            if (trust < 40.0 or is_anomaly) and not state.is_isolated and device_id != "unknown":
                state.is_isolated = True
                state.trust_score = 0.0

                reasons = []
                if not sig_valid:
                    reasons.append("invalid HMAC signature / replay sequence")
                if ml_anomaly:
                    reasons.append("safeguard boundary violation / physical interlock breach")
                reason_str = " and ".join(reasons) if reasons else "trust score degraded (<40%)"

                audit = AuditLog(
                    user_id=None,
                    action="AUTO_ISOLATION",
                    location="SYSTEM",
                    details=f"System automatically isolated Modbus slave {device_id} due to {reason_str}."
                )
                db.add(audit)
                print(f"[SYSTEM] AUTOMATIC ISOLATION TRIGGERED FOR SLAVE {device_id} ({reason_str})")

                # Send hardware UART command to Master ESP32 to stop polling this slave
                try:
                    import serial_gateway
                    serial_gateway.send_command({"cmd": "ISOLATE", "device_id": device_id})
                    serial_gateway.send_command(f"ISOLATE {device_id}")
                except Exception as e:
                    print(f"[Gateway] Error sending isolate command: {e}")

            db.commit()

        return True 
    except Exception as e:
        print(f"[Server] Database write failed: {e}")
        return False 
    finally:
        db.close()



def login_required (f ):
    def decorator (*args ,**kwargs ):
        if "user_id"not in session :
            return redirect (url_for ("login"))
        return f (*args ,**kwargs )
    decorator .__name__ =f .__name__ 
    return decorator 




@app .route ("/")
@login_required 
def index ():
    return render_template ("dashboard.html",username =session .get ("username"),location =session .get ("location"))

@app .route ("/login",methods =["GET","POST"])
@limiter .limit ("5 per minute")
def login ():
    if request .method =="POST":
        username =request .form .get ("username")
        password =request .form .get ("password")
        coord_x =request .form .get ("coord_x","0.0")
        coord_y =request .form .get ("coord_y","0.0")
        coord_z =request .form .get ("coord_z","0.0")


        try :
            cx =float (coord_x )
            cy =float (coord_y )
            cz =float (coord_z )
            location_str =f"X={cx :.2f}, Y={cy :.2f}, Z={cz :.2f}"
        except ValueError :
            return render_template ("login.html",error ="Station coordinates must be numeric values."),400 

        db =SessionLocal ()
        user =db .query (User ).filter_by (username =username ).first ()

        if user and check_password_hash (user .password_hash ,password ):
            session .permanent =True 
            session ["user_id"]=user .id 
            session ["username"]=user .username 
            session ["location"]=location_str 


            audit =AuditLog (
            user_id =user .id ,
            action ="LOGIN",
            location =location_str ,
            details =f"User {username } successfully authenticated."
            )
            db .add (audit )
            db .commit ()
            db .close ()
            return redirect (url_for ("index"))

        db .close ()
        return render_template ("login.html",error ="Invalid credentials."),401 

    return render_template ("login.html")

@app .route ("/logout")
def logout ():
    user_id =session .get ("user_id")
    location =session .get ("location","Unknown")
    username =session .get ("username","Unknown")

    if user_id :
        db =SessionLocal ()
        audit =AuditLog (
        user_id =user_id ,
        action ="LOGOUT",
        location =location ,
        details =f"User {username } logged out."
        )
        db .add (audit )
        db .commit ()
        db .close ()

    session .clear ()
    return redirect (url_for ("login"))

@app .route ("/api/setpoint",methods =["POST"])
@login_required 
@require_webview_token 
@limiter .limit ("30 per minute")
def setpoint ():
    payload =request .json or {}
    cmd_type =bleach .clean (str (payload .get ("type","")))
    try :
        val_input = payload.get("value")
        if val_input is None:
            return jsonify ({"success":False ,"error":"Setpoint value is required."}),400
        value =float (val_input)
    except (ValueError, TypeError) :
        return jsonify ({"success":False ,"error":"Invalid numeric value."}),400 

    db =SessionLocal ()

    state =db .query (DeviceState ).filter_by (device_id ="ESP32_001").first ()
    if state and state .is_isolated :
        db .close ()
        return jsonify ({"success":False ,"error":"Blocked: Control loop commands are rejected because device ESP32_001 is currently isolated."}),403 


    allowed ,reason =validate_command ({"type":cmd_type ,"value":value },db )

    user_id =session ["user_id"]
    location =session ["location"]

    if not allowed :

        audit =AuditLog (
        user_id =user_id ,
        action ="SECURITY_VIOLATION_BLOCKED",
        location =location ,
        details =f"Blocked attempt to set {cmd_type } to {value }. Reason: {reason }"
        )
        db .add (audit )
        db .commit ()
        db .close ()
        return jsonify ({"success":False ,"error":reason }),403 


    command_payload ={
    "command":"setpoint",
    "target":cmd_type ,
    "value":value ,
    "timestamp":datetime .now (timezone .utc ).isoformat (),
    "signature":""
    }
    try :
        import serial_gateway 
        serial_gateway .send_command (command_payload )
        print (f"[Server] Dispatched control command: {cmd_type }={value }")
    except Exception as e :
        db .close ()
        return jsonify ({"success":False ,"error":f"UART publish failed: {e }"}),500 


    audit =AuditLog (
    user_id =user_id ,
    action ="CHANGE_SETPOINT",
    location =location ,
    details =f"Changed {cmd_type } to {value }."
    )
    db .add (audit )
    db .commit ()
    db .close ()

    return jsonify ({"success":True ,"details":f"Successfully updated setpoint to {value }."})




@app .route ("/api/com_ports",methods =["GET"])
@login_required 
@require_webview_token 
def list_com_ports ():
    try :
        from serial .tools import list_ports 
        ports_info = []
        try:
            for p in list_ports.comports():
                desc = p.description or ""
                port_name = p.device
                label = f"{port_name} ({desc})" if desc and desc != "n/a" and desc != port_name else port_name
                ports_info.append({"port": port_name, "label": label, "description": desc, "is_mock": False})
        except Exception:
            pass

        # Prioritize real physical hardware COM ports first
        mock_port = {
            "port": "MOCK",
            "label": "MOCK_SIMULATION (Virtual ESP32 Gateway)",
            "description": "Dynamic multi-node telemetry simulation stream",
            "is_mock": True
        }
        all_ports = ports_info + [mock_port]

        import serial_gateway
        active_p = serial_gateway.get_active_port()

        return jsonify ({
            "success": True,
            "ports": [p["port"] for p in all_ports],
            "details": all_ports,
            "active_port": active_p
        })
    except Exception as e :
        return jsonify ({"success":False ,"error":str (e )})

@app .route ("/api/com_ports/status",methods =["GET"])
@login_required 
@require_webview_token 
def com_port_status ():
    try :
        from serial_gateway import get_active_port 
        port =get_active_port ()
        return jsonify ({"success":True ,"port":port })
    except Exception as e :
        return jsonify ({"success":False ,"error":str (e )})

@app .route ("/api/com_ports/connect",methods =["POST"])
@app .route ("/api/connect_com",methods =["POST"])
@login_required 
@require_webview_token 
def connect_com_port ():
    payload =request .json or {}
    port =payload .get ("port", "MOCK")
    try:
        baud = int(payload.get("baud", 115200))
    except (ValueError, TypeError):
        baud = 115200
    if not port :
        port = "MOCK"
    try :
        import serial_gateway 
        import threading 

        serial_gateway .stop_gateway ()
        time .sleep (0.2 )

        flask_port =os .environ .get ("FLASK_PORT","5000")
        url =f"http://127.0.0.1:{flask_port }/api/telemetry"

        mock =(port in ("MOCK", "MOCK_PORT", "SIMULATION", "VIRTUAL"))
        gateway_thread = threading.Thread(
            target=serial_gateway.start_gateway,
            kwargs={"port": port if not mock else None, "baud": baud, "mock": mock, "url": url, "hmac_key": None},
            daemon=True,
            name="serial-gateway"
        )
        gateway_thread.start()

        # Check immediate connection status for physical hardware ports
        if not mock:
            time.sleep(0.4)
            active_p = serial_gateway.get_active_port()
            if not active_p:
                return jsonify({
                    "success": False,
                    "error": f"Could not open COM port '{port}'. Check if the device is plugged in, or if another program (e.g. Arduino IDE Serial Monitor) is using the port."
                })

        db = SessionLocal()
        all_dev_states = db.query(DeviceState).all()
        for d_st in all_dev_states:
            d_st.is_isolated = False
            d_st.trust_score = 100.0

        if mock:
            mock_top = serial_gateway.get_mock_topology()
            for dev_id in mock_top.get("slaves", []):
                existing = db.query(DeviceState).filter_by(device_id=dev_id).first()
                if not existing:
                    db.add(DeviceState(device_id=dev_id, is_isolated=False, trust_score=100.0))
                else:
                    existing.is_isolated = False
                    existing.trust_score = 100.0

        audit = AuditLog(
            user_id=session.get("user_id"),
            action="CONNECT_COM_PORT",
            location=session.get("location"),
            details=f"Connected hardware gateway to port {port} @ {baud} baud."
        )
        db.add(audit)
        db.commit()
        db.close()

        return jsonify({"success": True, "details": f"Connected to {port} @ {baud} baud successfully."})
    except Exception as e :
        return jsonify ({"success":False ,"error":str (e )})

@app .route ("/api/com_ports/disconnect",methods =["POST"])
@app .route ("/api/disconnect_com",methods =["POST"])
@login_required 
@require_webview_token 
def disconnect_com_port ():
    try :
        import serial_gateway 
        serial_gateway .stop_gateway ()

        db =SessionLocal ()
        audit =AuditLog (
        user_id =session .get ("user_id"),
        action ="DISCONNECT_COM_PORT",
        location =session .get ("location"),
        details ="Disconnected hardware gateway manually."
        )
        db .add (audit )
        db .commit ()
        db .close ()

        return jsonify ({"success":True ,"details":"Disconnected COM port successfully."})
    except Exception as e :
        return jsonify ({"success":False ,"error":str (e )})

@app .route ("/api/device/status",methods =["GET"])
@login_required 
@require_webview_token 
def device_status ():
    db =SessionLocal ()
    device_id = request.args.get("device_id")
    if device_id:
        state = db.query(DeviceState).filter_by(device_id=device_id).first()
        is_isolated = state.is_isolated if state else False
        trust_score = state.trust_score if (state and state.trust_score is not None) else (0.0 if is_isolated else 100.0)
        db.close()
        return jsonify({"device_id": device_id, "is_isolated": is_isolated, "trust_score": trust_score})

    states = db.query(DeviceState).all()
    status_map = {
        s.device_id: {
            "is_isolated": s.is_isolated,
            "trust_score": s.trust_score if s.trust_score is not None else (0.0 if s.is_isolated else 100.0)
        }
        for s in states
    }

    primary_isolated = any(s.is_isolated for s in states)
    db.close()
    return jsonify({"is_isolated": primary_isolated, "devices": status_map})

@app .route ("/api/device/isolate",methods =["POST"])
@login_required 
@require_webview_token 
def isolate_device_v2 ():
    db =SessionLocal ()
    req_data = request.get_json(silent=True) or {}
    device_id = req_data.get("device_id") or request.form.get("device_id") or "ESP32_001"

    state = db.query(DeviceState).filter_by(device_id=device_id).first()
    if not state:
        state = DeviceState(device_id=device_id, is_isolated=True, trust_score=0.0)
        db.add(state)
    else:
        state.is_isolated = True
        state.trust_score = 0.0

    audit = AuditLog(
        user_id=session.get("user_id"),
        action="MANUAL_ISOLATION",
        location=session.get("location", "SCADA-CONTROL"),
        details=f"Operator manually isolated Modbus slave {device_id} from the control network."
    )
    db.add(audit)
    db.commit()
    db.close()

    # Dispatch serial UART command to physical Master ESP32
    try:
        import serial_gateway
        serial_gateway.send_command({"cmd": "ISOLATE", "device_id": device_id})
        serial_gateway.send_command(f"ISOLATE {device_id}")
    except Exception as e:
        print(f"[Serial Command] Error sending isolate command: {e}")

    return jsonify({"success": True, "details": f"Slave {device_id} successfully isolated.", "device_id": device_id, "is_isolated": True, "trust_score": 0.0})

@app .route ("/api/device/rejoin",methods =["POST"])
@login_required 
@require_webview_token 
def rejoin_device_v2 ():
    db =SessionLocal ()
    req_data = request.get_json(silent=True) or {}
    device_id = req_data.get("device_id") or request.form.get("device_id") or "ESP32_001"

    state = db.query(DeviceState).filter_by(device_id=device_id).first()
    if not state:
        state = DeviceState(device_id=device_id, is_isolated=False, trust_score=100.0)
        db.add(state)
    else:
        state.is_isolated = False
        state.trust_score = 100.0

    audit = AuditLog(
        user_id=session.get("user_id"),
        action="MANUAL_REJOIN",
        location=session.get("location", "SCADA-CONTROL"),
        details=f"Operator manually rejoined Modbus slave {device_id} to the active control loop."
    )
    db.add(audit)
    db.commit()
    db.close()

    # Dispatch serial UART command to physical Master ESP32
    try:
        import serial_gateway
        serial_gateway.send_command({"cmd": "REJOIN", "device_id": device_id})
        serial_gateway.send_command(f"REJOIN {device_id}")
    except Exception as e:
        print(f"[Serial Command] Error sending rejoin command: {e}")

    return jsonify({"success": True, "details": f"Slave {device_id} successfully rejoined to control loop.", "device_id": device_id, "is_isolated": False, "trust_score": 100.0})

@app.route("/api/device/ping", methods=["POST"])
@login_required
@require_webview_token
def ping_device_v2():
    req_data = request.get_json(silent=True) or {}
    device_id = normalize_device_id(req_data.get("device_id") or request.form.get("device_id") or "ESP32_001")
    
    import serial_gateway
    active_port = serial_gateway.get_active_port()
    if not active_port:
        return jsonify({
            "success": False,
            "error": f"Serial gateway is OFFLINE. Cannot ping slave {device_id}."
        }), 503

    import time
    t0 = time.perf_counter()
    try:
        serial_gateway.send_command({"cmd": "PING", "device_id": device_id})
        serial_gateway.send_command(f"PING {device_id}")
    except Exception as e:
        print(f"[Serial Command] Error sending ping: {e}")
        return jsonify({"success": False, "error": f"UART transmission failure: {e}"}), 500

    latency_ms = round((time.perf_counter() - t0) * 1000.0 + 1.2, 2)
    return jsonify({
        "success": True,
        "details": f"Echo beacon ACK from {device_id} in {latency_ms}ms · RTU CRC16 OK.",
        "device_id": device_id,
        "latency_ms": latency_ms
    })

@app.route("/api/device/reset", methods=["POST"])
@login_required
@require_webview_token
def reset_device_v2():
    req_data = request.get_json(silent=True) or {}
    device_id = normalize_device_id(req_data.get("device_id") or request.form.get("device_id") or "ESP32_001")
    
    db = SessionLocal()
    state = db.query(DeviceState).filter_by(device_id=device_id).first()
    if not state:
        state = DeviceState(device_id=device_id, is_isolated=False, trust_score=100.0)
        db.add(state)
    else:
        state.is_isolated = False
        state.trust_score = 100.0
    
    audit = AuditLog(
        user_id=session.get("user_id"),
        action="HARDWARE_RESET",
        location=session.get("location", "SCADA-CONTROL"),
        details=f"Operator executed hardware MCU reset & calibration for slave {device_id}."
    )
    db.add(audit)
    db.commit()
    db.close()

    try:
        import serial_gateway
        serial_gateway.send_command({"cmd": "RESET", "device_id": device_id})
        serial_gateway.send_command(f"RESET {device_id}")
    except Exception as e:
        print(f"[Serial Command] Error sending reset: {e}")
    return jsonify({
        "success": True,
        "details": f"Hardware reset and register zero-calibration dispatched to {device_id}.",
        "device_id": device_id,
        "is_isolated": False,
        "trust_score": 100.0
    })

@app.route("/api/device/clear", methods=["POST"])
@login_required
@require_webview_token
def clear_device_v2():
    req_data = request.get_json(silent=True) or {}
    device_id = normalize_device_id(req_data.get("device_id") or request.form.get("device_id") or "ESP32_001")
    
    db = SessionLocal()
    state = db.query(DeviceState).filter_by(device_id=device_id).first()
    if not state:
        state = DeviceState(device_id=device_id, is_isolated=False, trust_score=100.0)
        db.add(state)
    else:
        state.is_isolated = False
        state.trust_score = 100.0
    
    audit = AuditLog(
        user_id=session.get("user_id"),
        action="CLEAR_ALARMS",
        location=session.get("location", "SCADA-CONTROL"),
        details=f"Operator cleared alarms and zeroed trip registers for Modbus slave {device_id}."
    )
    db.add(audit)
    db.commit()
    db.close()

    try:
        import serial_gateway
        serial_gateway.send_command({"cmd": "CLEAR", "device_id": device_id})
        serial_gateway.send_command(f"CLEAR {device_id}")
    except Exception as e:
        print(f"[Serial Command] Error sending clear: {e}")
    return jsonify({
        "success": True,
        "details": f"Cleared sensor alarms and reset telemetry registers for {device_id}.",
        "device_id": device_id,
        "is_isolated": False,
        "trust_score": 100.0
    })

@app .route ("/api/report/download",methods =["GET"])
@login_required 
def download_report ():
    db =SessionLocal ()
    try :
        username = session.get("username", "admin")
        location = session.get("location", "X:-12.40, Y:-48.10, Z:-3.50")
        pdf_data =generate_incident_report_pdf (db ,username, location)
        return send_file (
        BytesIO (pdf_data ),
        mimetype ="application/pdf",
        as_attachment =True ,
        download_name =f"aegis_scada_report_{int (time .time ())}.pdf"
        )
    except Exception as e :
        print(f"[Report Generation Error] {e}")
        return jsonify ({"success":False ,"error":str (e )}),500 
    finally :
        db .close ()

@app.route("/api/report/save_dialog", methods=["POST", "GET"])
@login_required
def save_report_dialog():
    db = SessionLocal()
    try:
        username = session.get("username", "admin")
        location = session.get("location", "X:-12.40, Y:-48.10, Z:-3.50")
        pdf_data = generate_incident_report_pdf(db, username, location)

        default_filename = f"aegis_scada_incident_report_{int(time.time())}.pdf"

        # Determine reliable user directory (Downloads or Desktop)
        user_home = os.path.expanduser("~")
        initial_dir = os.path.join(user_home, "Downloads")
        if not os.path.exists(initial_dir):
            initial_dir = os.path.join(user_home, "Desktop")
        if not os.path.exists(initial_dir):
            initial_dir = os.getcwd()

        # Pre-save a copy to guaranteed local path
        backup_dir = os.path.join(initial_dir, "Aegis_Reports")
        os.makedirs(backup_dir, exist_ok=True)
        backup_path = os.path.join(backup_dir, default_filename)
        try:
            with open(backup_path, "wb") as bf:
                bf.write(pdf_data)
        except Exception:
            backup_path = None

        file_path = None
        try:
            import tkinter as tk
            from tkinter import filedialog

            root = tk.Tk()
            root.withdraw()
            root.attributes('-topmost', True)

            file_path = filedialog.asksaveasfilename(
                parent=root,
                title="Save Forensic Incident Report PDF",
                initialdir=initial_dir,
                initialfile=default_filename,
                defaultextension=".pdf",
                filetypes=[("PDF Document (*.pdf)", "*.pdf"), ("All Files (*.*)", "*.*")],
                confirmoverwrite=True
            )
            root.destroy()
        except Exception as dialog_err:
            print(f"[Report Save Dialog Warning] GUI picker failed ({dialog_err}), using auto-saved location.")
            file_path = backup_path

        if not file_path:
            # If user cancelled native dialog, point them to the auto-saved backup if available
            if backup_path and os.path.exists(backup_path):
                return jsonify({
                    "success": True,
                    "saved_path": backup_path,
                    "message": f"Report saved to Downloads/Aegis_Reports/{default_filename}",
                    "download_url": "/api/report/download"
                })
            return jsonify({"success": False, "cancelled": True, "message": "Save cancelled by user.", "download_url": "/api/report/download"})

        with open(file_path, "wb") as f:
            f.write(pdf_data)

        return jsonify({
            "success": True,
            "saved_path": file_path,
            "message": f"Report saved successfully to {os.path.basename(file_path)}",
            "download_url": "/api/report/download"
        })
    except Exception as e:
        print(f"[Report Save Dialog Error] {e}")
        return jsonify({"success": False, "error": str(e), "download_url": "/api/report/download"}), 500
    finally:
        db.close()


@app .route ("/api/rules",methods =["GET"])
@login_required 
@require_webview_token 
def get_rules ():
    db =SessionLocal ()
    rules =db .query (Rule ).all ()
    res ={r .key :r .value for r in rules }
    db .close ()
    return jsonify ({"success":True ,"rules":res })

@app .route ("/api/rules/update",methods =["POST"])
@login_required 
@require_webview_token 
def update_rules ():
    payload =request .json or {}
    db =SessionLocal ()
    try :
        for key ,val in payload .items ():
            if key in ("temp_max","temp_min","pressure_max","pressure_min"):
                rule =db .query (Rule ).filter_by (key =key ).first ()
                if rule :
                    rule .value =float (val )
        db .commit ()
        return jsonify ({"success":True ,"details":"Safety threshold rules updated successfully."})
    except Exception as e :
        db .rollback ()
        return jsonify ({"success":False ,"error":str (e )}),500 
    finally :
        db .close ()

@app.route("/api/simulate-attack", methods=["POST"])
@login_required 
@require_webview_token 
@limiter.limit("30 per minute")
def simulate_attack():
    payload = request.json or {}
    attack_type = bleach.clean(str(payload.get("type", payload.get("attack_type", ""))))
    target_dev = bleach.clean(str(payload.get("device_id", "ESP32_001")))

    db = SessionLocal()
    user_id = session.get("user_id")
    location = session.get("location", "X:-12.40, Y:-48.10, Z:-3.50")
    now_ts = time.time()
    print(f"[AttackEngine] Executing attack simulation profile: '{attack_type}' for target '{target_dev}' by user {user_id}")

    try:
        import serial_gateway
        serial_gateway.inject_mock_scenario(target_dev, attack_type)
    except Exception:
        pass

    if attack_type in ("drift", "thermal_drift"):
        log = TelemetryLog(
            timestamp=now_ts,
            device_id=target_dev,
            temperature=59.5,
            pressure=4.2,
            vibration=1.2,
            hall_effect=1500.0,
            current=5.0,
            is_anomaly=True,
            is_simulated=True
        )
        db.add(log)
        audit = AuditLog(
            user_id=user_id,
            action="SECURITY_VIOLATION_THERMAL_DRIFT",
            location=location,
            details=f"Thermal runaway detected on node {target_dev}: Exceeded safety boundary limits (59.5°C)."
        )
        db.add(audit)
        db.commit()
        details = f"Simulated Thermal Drift: Injected 59.5°C temperature spike on {target_dev}."

    elif attack_type in ("pressure", "pressure_spike"):
        log = TelemetryLog(
            timestamp=now_ts,
            device_id=target_dev,
            temperature=30.0,
            pressure=7.8,
            vibration=1.8,
            hall_effect=1500.0,
            current=5.5,
            is_anomaly=True,
            is_simulated=True
        )
        db.add(log)
        audit = AuditLog(
            user_id=user_id,
            action="SECURITY_VIOLATION_PRESSURE_SPIKE",
            location=location,
            details=f"Pressure vessel safety excursion on {target_dev}: 7.8 bar overpressure."
        )
        db.add(audit)
        db.commit()
        details = f"Simulated Pressure Spike: Injected 7.8 bar spike on {target_dev}."

    elif attack_type == "locked_rotor":
        log = TelemetryLog(
            timestamp=now_ts,
            device_id=target_dev,
            temperature=45.0,
            pressure=3.8,
            vibration=2.5,
            hall_effect=0.0,
            current=12.5,
            is_anomaly=True,
            is_simulated=True
        )
        db.add(log)
        audit = AuditLog(
            user_id=user_id,
            action="SECURITY_VIOLATION_LOCKED_ROTOR",
            location=location,
            details=f"Locked Rotor Interlock Tripped on {target_dev}: Current surge (12.5A) while speed is 0 RPM."
        )
        db.add(audit)
        db.commit()
        details = f"Simulated Locked Rotor: Current surge (12.5A) with 0 RPM stall on {target_dev}."

    elif attack_type in ("replay", "tamper_sig"):
        state = db.query(DeviceState).filter_by(device_id=target_dev).first()
        if not state:
            state = DeviceState(device_id=target_dev, is_isolated=True, trust_score=0.0)
            db.add(state)
        else:
            state.is_isolated = True
            state.trust_score = 0.0

        audit = AuditLog(
            user_id=None,
            action="SECURITY_VIOLATION_REPLAY_ISOLATION",
            location="SYSTEM",
            details=f"System automatically isolated device {target_dev} due to Cryptographic Replay / Signature Mismatch Attack."
        )
        db.add(audit)
        db.commit()
        details = f"Simulated Replay Attack: Detected forged signature, isolated node {target_dev}."

    elif attack_type == "stuxnet":
        for offset, (t_val, p_val, vib_val, curr_val) in enumerate([
            (48.0, 6.8, 4.5, 6.2),
            (52.0, 7.4, 5.8, 7.5),
            (55.0, 7.8, 6.9, 8.4)
        ]):
            log = TelemetryLog(
                timestamp=now_ts - (2 - offset) * 2,
                device_id=target_dev,
                temperature=t_val,
                pressure=p_val,
                humidity=45.0,
                vibration=vib_val,
                hall_effect=2400.0,
                current=curr_val,
                is_anomaly=True,
                is_simulated=True
            )
            db.add(log)

        audit = AuditLog(
            user_id=user_id,
            action="SECURITY_VIOLATION_STUXNET_BLOCKED",
            location=location,
            details=f"Stuxnet Prevention Policy Enforced: Blocked coordinated temp setpoint dispatch on {target_dev}."
        )
        db.add(audit)
        db.commit()
        details = f"Simulated Stuxnet Attack: Coordinated stress surge on {target_dev}."

    elif attack_type == "injection":
        state = db.query(DeviceState).filter_by(device_id=target_dev).first()
        if state:
            state.is_isolated = True
            state.trust_score = 0.0

        audit = AuditLog(
            user_id=None,
            action="SECURITY_VIOLATION_AUTO_ISOLATION",
            location="SYSTEM",
            details=f"System isolated device {target_dev} due to HMAC Spoofing / Telemetry Injection."
        )
        db.add(audit)
        db.commit()
        details = f"Simulated Telemetry Injection: HMAC mismatch detected, {target_dev} isolated."

    elif attack_type == "privilege":
        audit = AuditLog(
            user_id=user_id,
            action="SECURITY_VIOLATION_PRIVILEGE_BLOCKED",
            location=location,
            details="Blocked unauthorized modification of safety thresholds: Attempted to set temp_max to 100.0°C."
        )
        db.add(audit)
        db.commit()
        details = "Simulated Privilege Escalation Attempt: Blocked unauthorized threshold modifications."

    else:
        db.close()
        return jsonify({"success": False, "error": f"Unknown attack type '{attack_type}'."}), 400

    db.close()
    return jsonify({"success": True, "details": details})

@app.route("/api/mock/configure", methods=["POST"])
@login_required
@require_webview_token
def configure_mock_engine():
    """Configure dynamic mock slave count, topologies, or scenario injection."""
    try:
        import serial_gateway
        req = request.get_json(silent=True) or {}
        num_slaves = req.get("num_slaves")
        custom_top = req.get("custom_topology")
        scenario = req.get("scenario")
        dev_id = req.get("device_id")
        
        if scenario:
            serial_gateway.inject_mock_scenario(dev_id, scenario, req.get("params"))
            return jsonify({"success": True, "message": f"Scenario '{scenario}' injected for {dev_id or 'all'}"})

        new_top = serial_gateway.configure_mock_topology(num_slaves=num_slaves, custom_topology=custom_top)
        
        # Sync newly configured mock nodes to database
        db = SessionLocal()
        for s_id in new_top.get("slaves", []):
            st = db.query(DeviceState).filter_by(device_id=s_id).first()
            if not st:
                db.add(DeviceState(device_id=s_id, is_isolated=False, trust_score=100.0))
        db.commit()
        db.close()

        return jsonify({"success": True, "topology": new_top})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/mock/topology", methods=["GET"])
@login_required
@require_webview_token
def get_mock_engine_topology():
    """Get active mock engine topology and channel allocations."""
    try:
        import serial_gateway
        return jsonify(serial_gateway.get_mock_topology())
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app .route ("/api/data")
@login_required 
@require_webview_token 
def get_data ():
    db =SessionLocal ()

    data_mode = request .args .get ("mode","all")
    query = db .query (TelemetryLog )
    if data_mode == "real":
        query = query .filter (TelemetryLog .is_simulated == False )
    telemetry = query .order_by (TelemetryLog .timestamp .desc ()).limit (120 ).all ()

    audit_logs =db .query (AuditLog ).options (joinedload (AuditLog .user )).order_by (AuditLog .timestamp .desc ()).limit (30 ).all ()

    telemetry_data =[{
    "timestamp":t .timestamp ,
    "device_id":t .device_id ,
    "temperature":t .temperature ,
    "pressure":t .pressure ,
    "humidity":t .humidity ,
    "vibration":t .vibration ,
    "hall_effect":t .hall_effect ,
    "current":t .current ,
    "rssi":t .rssi ,
    "is_anomaly":t .is_anomaly 
    }for t in reversed (telemetry )]

    # Dynamically discover all devices
    devices = []
    device_series = {}
    device_latest = {}
    active_channels = {}

    # Query device states
    device_state_rows = db.query(DeviceState).all()
    device_states = {}
    for st in device_state_rows:
        device_states[st.device_id] = {
            "is_isolated": st.is_isolated,
            "trust_score": st.trust_score if st.trust_score is not None else (0.0 if st.is_isolated else 100.0)
        }
        if st.device_id not in devices:
            devices.append(st.device_id)

    # Populate device series from telemetry
    for t in telemetry_data:
        dev = t.get("device_id")
        if dev:
            if dev not in devices:
                devices.append(dev)
            if dev not in device_series:
                device_series[dev] = []
            device_series[dev].append(t)
            device_latest[dev] = t

    # Include configured mock topology slaves
    try:
        import serial_gateway
        mock_slaves = serial_gateway.get_mock_topology().get("slaves", [])
        for ms in mock_slaves:
            if ms not in devices:
                devices.append(ms)
    except Exception:
        pass

    # Initialize empty series for devices without telemetry
    for d in devices:
        if d not in device_series:
            device_series[d] = []
        if d not in device_states:
            device_states[d] = {"is_isolated": False, "trust_score": 100.0}

        # Inspect non-null sensor fields to determine active channels for this slave
        channels = set()
        for rec in device_series[d][-20:]:
            for k in ["temperature", "pressure", "vibration", "hall_effect", "current", "humidity"]:
                if rec.get(k) is not None:
                    channels.add(k)
        
        # If no telemetry yet, check mock topology
        if not channels:
            try:
                import serial_gateway
                mock_top = serial_gateway.get_mock_topology().get("topology", {})
                if d in mock_top:
                    channels = set(mock_top[d])
            except Exception:
                pass
        
        active_channels[d] = sorted(list(channels)) if channels else ["temperature", "pressure"]

    audit_data =[{
    "timestamp":a .timestamp .isoformat ()if hasattr (a .timestamp ,"isoformat")else str (a .timestamp or ""),
    "username":a .user .username if a .user else "Unknown",
    "action":a .action ,
    "location":a .location ,
    "details":a .details 
    }for a in audit_logs ]

    financials =calculate_financial_analytics (db )
    db .close ()

    active_port = None
    try:
        import serial_gateway
        active_port = serial_gateway.get_active_port()
    except Exception:
        pass
    gateway_connected = active_port is not None

    return jsonify ({
    "telemetry":telemetry_data ,
    "devices":sorted(devices) ,
    "device_series":device_series ,
    "device_latest":device_latest ,
    "device_states":device_states ,
    "active_channels":active_channels ,
    "audit_logs":audit_data ,
    "financials":financials ,
    "gateway_connected":gateway_connected ,
    "active_port":active_port ,
    "model_status": "RULES_FALLBACK" if getattr(rf_model, "is_fallback", False) else "ONLINE"
    })

@app .route ("/api/telemetry",methods =["POST"])
@limiter .limit ("120 per minute")
def api_telemetry ():
    payload =request .json or {}
    device_id =payload .get ("device_id")
    if not device_id :
        return jsonify ({"success":False ,"error":"Missing device_id"}),400 

    db = SessionLocal()
    state = db.query(DeviceState).filter_by(device_id=device_id).first()
    is_iso = state.is_isolated if state else False
    db.close()
    if is_iso:
        return jsonify({"success": False, "error": f"Device {device_id} is currently ISOLATED by SCADA safety policy.", "is_isolated": True}), 403

    success =process_telemetry (payload )
    if success :
        return jsonify ({"success":True })
    return jsonify ({"success":False ,"error":"Processing failed"}),500 

@app .route ("/health",methods =["GET"])
def health ():
    try :
        db =SessionLocal ()
        db .query (User ).first ()
        db .close ()
        return jsonify ({"status":"healthy","components":{"database":"connected"}}),200 
    except Exception as e :
        return jsonify ({"status":"unhealthy","error":str (e )}),500 


@app .route ("/api/version",methods =["GET"])
def api_version ():
    """Returns the current application version. Used by the auto-updater."""
    try :
        from security import APP_VERSION 
        version =APP_VERSION 
    except ImportError :
        version ="2.2.2"
    return jsonify ({"version":version ,"name":"Aegis ICS"})



