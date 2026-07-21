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

from security import require_webview_token 


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
default_limits =["200 per day","50 per hour"],
storage_uri ="memory://"
)


app .config ['PERMANENT_SESSION_LIFETIME']=timedelta (minutes =30 )
app .config ['SESSION_COOKIE_HTTPONLY']=True 
app .config ['SESSION_COOKIE_SAMESITE']='Strict'
app .config ['SESSION_COOKIE_SECURE']=os .environ .get ("FLASK_SESSION_SECURE","False").lower ()in ("true","1")


DEVICE_KEYS ={
"ESP32_001":os .environ .get ("DEVICE_KEY_ESP32_001",secrets .token_hex (16 )),
"ESP32_002":os .environ .get ("DEVICE_KEY_ESP32_002",secrets .token_hex (16 )),
}


def generate_csrf_token ():
    if "csrf_token"not in session :
        session ["csrf_token"]=secrets .token_hex (32 )
    return session ["csrf_token"]

app .jinja_env .globals .update (csrf_token =generate_csrf_token )

@app .before_request 
def csrf_protect ():

    if app .config .get ("TESTING")or request .path =="/api/telemetry":
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

def verify_signature (payload :dict )->bool :
    import hmac 
    import hashlib 

    device_id =str (payload .get ("device_id"))
    key =DEVICE_KEYS .get (device_id ,"").encode ("utf-8")
    if not key :return False 

    def _canonicalize (p ):
        result ={}
        for k ,v in p .items ():
            if k in ("temperature","pressure","humidity","rssi","vibration","hall_effect","current"):
                if v is not None :
                    result [k ]=f"{float (v ):.2f}"
            elif k =="timestamp":
                if v is not None :
                    result [k ]=f"{float (v ):.3f}"
            else :
                result [k ]=v 
        return result 

    sig =payload .get ("signature")
    body ={k :v for k ,v in payload .items ()if k !="signature"}
    canonical =json .dumps (_canonicalize (body ),sort_keys =True ,separators =(",",":"))
    expected =hmac .new (key ,canonical .encode ("utf-8"),hashlib .sha256 ).hexdigest ()
    return hmac .compare_digest (expected ,str (sig ))if sig else False 

import pickle 
class LocalRFModel :
    def __init__ (self ,model_path ="model/rf_model.pkl"):
        self .model =None 
        try :
            if os .path .exists (model_path ):
                with open (model_path ,"rb")as f :
                    self .model =pickle .load (f )
        except Exception as e :
            print (f"[Server] Failed to load Random Forest model: {e }")

    def predict_anomaly (self ,telemetry :dict )->bool :
        temp_val = telemetry.get("temperature")
        pres_val = telemetry.get("pressure")
        vib_val = telemetry.get("vibration")
        hall_val = telemetry.get("hall_effect")
        curr_val = telemetry.get("current")
        hum_val = telemetry.get("humidity")

        temp = float(temp_val) if temp_val is not None else 0.0
        pres = float(pres_val) if pres_val is not None else 0.0
        vib = float(vib_val) if vib_val is not None else 0.0
        hall = float(hall_val) if hall_val is not None else 0.0
        curr = float(curr_val) if curr_val is not None else 0.0
        hum = float(hum_val) if hum_val is not None else 0.0

        features =[[
        temp,
        pres,
        vib or pres if str (telemetry .get ("device_id"))=="ESP32_002"else 0.0,
        hall or hum if str (telemetry .get ("device_id"))=="ESP32_002"else 0.0,
        curr or hum if str (telemetry .get ("device_id"))=="ESP32_001"else 0.0
        ]]
        if self .model is None :

            temp =features [0 ][0 ]
            pressure =features [0 ][1 ]
            vib =features [0 ][2 ]
            hall =features [0 ][3 ]
            curr =features [0 ][4 ]
            anomaly =0.0 
            if temp_val is not None and (temp <0.0 or temp >50.0 ):anomaly +=0.3 
            if pres_val is not None and (pressure <0.0 or pressure >8.0 ):anomaly +=0.3 
            if vib_val is not None and vib >6.0 :anomaly +=0.4 
            if hall_val is not None and hall >1800.0 :anomaly +=0.4 
            if curr_val is not None and curr >8.0 :anomaly +=0.4 
            return min (1.0 ,anomaly )>0.5 

        try :
            proba =self .model .predict_proba (features )[0 ]
            return float (proba [1 ])>0.5 
        except Exception :
            return False 

rf_model =LocalRFModel (_resource_path (os .path .join ("model","rf_model.pkl")))

def process_telemetry (payload :dict )->bool :
    db =SessionLocal ()
    device_id =payload .get ("device_id","unknown")


    state =db .query (DeviceState ).filter_by (device_id =device_id ).first ()
    if state and state .is_isolated :
        db .close ()
        print (f"[Server] Telemetry REJECTED from isolated device: {device_id }")
        return False 

    sig_valid =verify_signature (payload )
    ml_anomaly =rf_model .predict_anomaly (payload )
    is_anomaly =(not sig_valid )or ml_anomaly 

    try :
        log =TelemetryLog (
        timestamp =payload .get ("timestamp",time .time ()),
        device_id =device_id ,
        temperature =payload .get ("temperature"),
        pressure =payload .get ("pressure"),
        humidity =payload .get ("humidity"),
        vibration =payload .get ("vibration"),
        hall_effect =payload .get ("hall_effect"),
        current =payload .get ("current"),
        rssi =payload .get ("rssi"),
        is_anomaly =is_anomaly 
        )
        db .add (log )
        db .commit ()


        if is_anomaly and device_id !="unknown":
            state =db .query (DeviceState ).filter_by (device_id =device_id ).first ()
            if state and not state .is_isolated :
                state .is_isolated =True 


                reason ="invalid HMAC signature"if not sig_valid else "AI Random Forest anomaly detection"
                audit =AuditLog (
                user_id =None ,
                action ="AUTO_ISOLATION",
                location ="SYSTEM",
                details =f"System automatically isolated device {device_id } due to {reason }."
                )
                db .add (audit )
                db .commit ()
                print (f"[SYSTEM] AUTOMATIC ISOLATION TRIGGERED FOR DEVICE {device_id } ({reason })")
        return True 
    except Exception as e :
        print (f"[Server] Database write failed: {e }")
        return False 
    finally :
        db .close ()


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
        value =float (payload .get ("value",0 ))
    except ValueError :
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
        ports =[p .device for p in list_ports .comports ()]
        return jsonify ({"success":True ,"ports":ports })
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
@login_required 
@require_webview_token 
def connect_com_port ():
    payload =request .json or {}
    port =payload .get ("port")
    if not port :
        return jsonify ({"success":False ,"error":"No port specified."})
    try :
        import serial_gateway 
        import threading 


        serial_gateway .stop_gateway ()
        time .sleep (0.2 )

        flask_port =os .environ .get ("FLASK_PORT","5000")
        url =f"http://127.0.0.1:{flask_port }/api/telemetry"

        mock =(port =="MOCK")
        hmac_key =DEVICE_KEYS .get ("ESP32_001")
        gateway_thread =threading .Thread (
        target =serial_gateway .start_gateway ,
        kwargs ={"port":port if not mock else None ,"mock":mock ,"url":url ,"hmac_key":hmac_key },
        daemon =True ,
        name ="serial-gateway"
        )
        gateway_thread .start ()


        db =SessionLocal ()
        audit =AuditLog (
        user_id =session .get ("user_id"),
        action ="CONNECT_COM_PORT",
        location =session .get ("location"),
        details =f"Connected hardware gateway to port {port }."
        )
        db .add (audit )
        db .commit ()
        db .close ()

        return jsonify ({"success":True ,"details":f"Gateway connecting to {port }."})
    except Exception as e :
        return jsonify ({"success":False ,"error":str (e )})

@app .route ("/api/com_ports/disconnect",methods =["POST"])
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
    state =db .query (DeviceState ).filter_by (device_id ="ESP32_001").first ()
    is_isolated =state .is_isolated if state else False 
    db .close ()
    return jsonify ({"is_isolated":is_isolated })

@app .route ("/api/device/isolate",methods =["POST"])
@login_required 
@require_webview_token 
def isolate_device_v2 ():
    db =SessionLocal ()
    state =db .query (DeviceState ).filter_by (device_id ="ESP32_001").first ()
    if state :
        state .is_isolated =True 


        audit =AuditLog (
        user_id =session ["user_id"],
        action ="MANUAL_ISOLATION",
        location =session ["location"],
        details ="Operator manually isolated the device from the control loop."
        )
        db .add (audit )
        db .commit ()
    db .close ()
    return jsonify ({"success":True ,"details":"Device ESP32_001 successfully isolated."})

@app .route ("/api/device/rejoin",methods =["POST"])
@login_required 
@require_webview_token 
def rejoin_device_v2 ():
    db =SessionLocal ()
    state =db .query (DeviceState ).filter_by (device_id ="ESP32_001").first ()
    if state :
        state .is_isolated =False 


        audit =AuditLog (
        user_id =session ["user_id"],
        action ="MANUAL_REJOIN",
        location =session ["location"],
        details ="Operator manually rejoined the device to the control loop."
        )
        db .add (audit )
        db .commit ()
    db .close ()
    return jsonify ({"success":True ,"details":"Device ESP32_001 successfully rejoined to control loop."})

@app .route ("/api/report/download",methods =["GET"])
@login_required 
@require_webview_token 
def download_report ():
    db =SessionLocal ()
    try :
        pdf_data =generate_incident_report_pdf (db ,session ["username"],session ["location"])
        return send_file (
        BytesIO (pdf_data ),
        mimetype ="application/pdf",
        as_attachment =True ,
        download_name =f"aegis_scada_report_{int (time .time ())}.pdf"
        )
    except Exception as e :
        return jsonify ({"success":False ,"error":str (e )}),500 
    finally :
        db .close ()

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

@app .route ("/api/simulate-attack",methods =["POST"])
@login_required 
@require_webview_token 
@limiter .limit ("5 per minute")
def simulate_attack ():
    payload =request .json or {}
    attack_type =bleach .clean (str (payload .get ("type","")))

    db =SessionLocal ()
    user_id =session ["user_id"]
    location =session ["location"]
    print(f"[AttackEngine] Executing attack simulation profile: '{attack_type}' for user {user_id}")

    if attack_type =="stuxnet":

        log =TelemetryLog (
        timestamp =time .time (),
        device_id ="ESP32_001",
        temperature =30.0 ,
        pressure =7.5 ,
        humidity =50.0 ,
        is_anomaly =False ,
        is_simulated =True 
        )
        db .add (log )
        db .commit ()


        audit =AuditLog (
        user_id =user_id ,
        action ="SECURITY_VIOLATION_BLOCKED",
        location =location ,
        details ="Blocked attempt to set set_temp to 55.0. Reason: Stuxnet Prevention Policy - Temperature setpoint (55.0) rejected while system pressure is high (7.5 bar)."
        )
        db .add (audit )
        db .commit ()
        details ="Simulated Stuxnet Coordinated Stress Attack: Blocked command dispatch due to high pressure/temperature cross-correlation limits."

    elif attack_type =="injection":

        log =TelemetryLog (
        timestamp =time .time (),
        device_id ="ESP32_001",
        temperature =58.0 ,
        pressure =4.0 ,
        humidity =50.0 ,
        is_anomaly =True ,
        is_simulated =True 
        )
        db .add (log )


        state =db .query (DeviceState ).filter_by (device_id ="ESP32_001").first ()
        if state :
            state .is_isolated =True 

        audit =AuditLog (
        user_id =None ,
        action ="AUTO_ISOLATION",
        location ="SYSTEM",
        details ="System automatically isolated device ESP32_001 due to invalid HMAC signature (Telemetry Spoofing / Injection Attack detected)."
        )
        db .add (audit )
        db .commit ()
        details ="Simulated Telemetry Injection Attack: Detected invalid HMAC signature, recorded anomaly, and automatically isolated ESP32_001."

    elif attack_type =="privilege":

        audit =AuditLog (
        user_id =user_id ,
        action ="SECURITY_VIOLATION_BLOCKED",
        location =location ,
        details ="Blocked unauthorized modification of safety thresholds: Attempted to set temp_max to 100.0 without Master Engineering credentials."
        )
        db .add (audit )
        db .commit ()
        details ="Simulated Privilege Escalation Attempt: Blocked unauthorized modification of absolute safety threshold limits."

    else :
        db .close ()
        return jsonify ({"success":False ,"error":"Unknown attack type."}),400 

    db .close ()
    return jsonify ({"success":True ,"details":details })

@app .route ("/api/data")
@login_required 
@require_webview_token 
def get_data ():
    db =SessionLocal ()

    data_mode = request .args .get ("mode","all")
    query = db .query (TelemetryLog )
    if data_mode == "real":
        query = query .filter (TelemetryLog .is_simulated == False )
    telemetry = query .order_by (TelemetryLog .timestamp .desc ()).limit (50 ).all ()

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

    audit_data =[{
    "timestamp":a .timestamp .isoformat (),
    "username":a .user .username if a .user else "Unknown",
    "action":a .action ,
    "location":a .location ,
    "details":a .details 
    }for a in audit_logs ]

    financials =calculate_financial_analytics (db )
    db .close ()
    return jsonify ({
    "telemetry":telemetry_data ,
    "audit_logs":audit_data ,
    "financials":financials 
    })

@app .route ("/api/telemetry",methods =["POST"])
@limiter .limit ("120 per minute")
def api_telemetry ():
    payload =request .json or {}
    device_id =payload .get ("device_id")
    if not device_id :
        return jsonify ({"success":False ,"error":"Missing device_id"}),400 

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



