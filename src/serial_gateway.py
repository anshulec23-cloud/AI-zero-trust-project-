
"""
Aegis ICS V2 — Production Serial COM Port Telemetry Gateway Driver

Listens to the designated serial COM port (USB connection from the ESP32),
parses the sensor readings (supporting both CSV and JSON formats), signs
the payload using HMAC-SHA256, and forwards it to the Aegis REST API.
"""

import sys 
import os 
import time 
import json 
import hmac 
import hashlib 
import argparse 
import requests 

try :
    import serial 
    serial_available =True 
except ImportError :
    serial_available =False 

import secrets 
import queue 

from security import get_device_key 

DEFAULT_GATEWAY_URL ="http://127.0.0.1:5000/api/telemetry"

DEFAULT_DEVICE_KEY = get_device_key ("ESP32_001")

import threading 
_gateway_stop_event =threading .Event ()
_active_port =None 
_command_queue =queue .Queue ()
_isolated_nodes = set()

def stop_gateway ():
    _gateway_stop_event .set ()

def get_active_port ():
    return _active_port if not _gateway_stop_event .is_set ()else None 

def send_command (payload ):
    """Enqueues a command to be written to the serial port and updates local isolation state."""
    global _isolated_nodes
    if isinstance(payload, dict):
        cmd_name = str(payload.get("cmd", "")).upper()
        dev = payload.get("device_id") or payload.get("device")
        if dev:
            dev = str(dev).strip()
            if cmd_name in ("ISOLATE", "SHUTDOWN"):
                _isolated_nodes.add(dev)
                print(f"[Gateway Driver] Node {dev} marked ISOLATED — Telemetry polling halted.")
            elif cmd_name in ("REJOIN", "RESET", "CLEAR"):
                _isolated_nodes.discard(dev)
                print(f"[Gateway Driver] Node {dev} marked REJOINED — Telemetry polling resumed.")
    elif isinstance(payload, str):
        parts = payload.strip().split()
        if len(parts) >= 2:
            cmd_name = parts[0].upper()
            dev = parts[1].strip()
            if cmd_name in ("ISOLATE", "SHUTDOWN"):
                _isolated_nodes.add(dev)
                print(f"[Gateway Driver] Node {dev} marked ISOLATED — Telemetry polling halted.")
            elif cmd_name in ("REJOIN", "RESET", "CLEAR"):
                _isolated_nodes.discard(dev)
                print(f"[Gateway Driver] Node {dev} marked REJOINED — Telemetry polling resumed.")
    _command_queue.put(payload)

def canonicalize_payload (payload :dict )->dict :
    canonical ={}
    for k ,v in payload .items ():
        if k in ("temperature","pressure","humidity","rssi","vibration","hall_effect","current"):
            canonical [k ]=f"{float (v ):.2f}"
        elif k =="timestamp":
            canonical [k ]=f"{float (v ):.3f}"
        else :
            canonical [k ]=v 
    return canonical 

def sign_message (payload :dict ,key :str )->str :
    canonical_payload =canonicalize_payload (payload )
    canonical =json .dumps (canonical_payload ,sort_keys =True ,separators =(",",":"))
    return hmac .new (key .encode ("utf-8"),canonical .encode ("utf-8"),hashlib .sha256 ).hexdigest ()

from security import normalize_device_id, get_device_key

def parse_serial_line(line: str, mode: str = "plc"):
    """
    Ultra-resilient parser for real hardware serial/UART streams.
    Accepts JSON, CSV, key-value strings, space/tab/colon-delimited tokens,
    and freeform engineer debugging text.
    """
    if not line:
        return None
    line = line.strip()
    if not line:
        return None

    import re

    # 1. JSON Parsing (handles standard JSON and single-quoted JSON)
    json_match = re.search(r'(\{.*\})', line)
    if json_match:
        raw_json_str = json_match.group(1)
        # Convert single quotes to double quotes for standard json parsing
        try:
            data = json.loads(raw_json_str)
        except Exception:
            try:
                data = json.loads(raw_json_str.replace("'", '"'))
            except Exception:
                data = None

        if isinstance(data, dict):
            res = {}
            raw_dev = data.get("device_id") or data.get("device") or data.get("slave_id") or data.get("slave") or data.get("node") or data.get("id") or data.get("esp")
            res["device_id"] = normalize_device_id(raw_dev) if raw_dev else "ESP32_001"

            # Parse metrics
            for k, v in data.items():
                k_lower = str(k).lower().strip()
                try:
                    val = float(v)
                    if k_lower in ("temp", "temperature", "t", "temp_c", "temperature_c"):
                        res["temperature"] = val
                    elif k_lower in ("pres", "pressure", "p", "pressure_bar", "bar"):
                        res["pressure"] = val
                    elif k_lower in ("vib", "vibration", "v", "vib_g", "vibration_g"):
                        res["vibration"] = val
                    elif k_lower in ("hall", "hall_effect", "rpm", "speed", "hall_rpm"):
                        res["hall_effect"] = val
                    elif k_lower in ("curr", "current", "c", "amps", "current_a"):
                        res["current"] = val
                    elif k_lower in ("hum", "humidity", "h", "humidity_pct"):
                        res["humidity"] = val
                    elif k_lower in ("rssi", "signal"):
                        res["rssi"] = val
                except (ValueError, TypeError):
                    pass

            if len(res) > 1 or "temperature" in res:
                return res

    # 2. Key-Value String Parsing (e.g., "SLAVE: 1, TEMP: 24.5, PRES: 4.1, VIB: 0.05, HALL: 1200, CURR: 5.1, HUM: 45")
    # Handles '=', ':', commas, semicolons
    kv_pattern = re.findall(r'([A-Za-z0-9_]+)\s*[:=]\s*([^\s,;]+)', line)
    if kv_pattern and len(kv_pattern) >= 1:
        kv_res = {}
        for k, v in kv_pattern:
            k_lower = k.lower().strip()
            v_clean = v.strip()
            if k_lower in ('dev', 'device', 'device_id', 'slave', 'slave_id', 'node', 'esp', 'id'):
                kv_res['device_id'] = normalize_device_id(v_clean)
            else:
                try:
                    val = float(v_clean)
                    if k_lower in ('t', 'temp', 'temperature'):
                        kv_res['temperature'] = val
                    elif k_lower in ('p', 'pres', 'pressure'):
                        kv_res['pressure'] = val
                    elif k_lower in ('v', 'vib', 'vibration'):
                        kv_res['vibration'] = val
                    elif k_lower in ('h', 'hall', 'hall_effect', 'rpm', 'speed'):
                        kv_res['hall_effect'] = val
                    elif k_lower in ('c', 'curr', 'current', 'amps'):
                        kv_res['current'] = val
                    elif k_lower in ('hum', 'humidity'):
                        kv_res['humidity'] = val
                    elif k_lower in ('rssi',):
                        kv_res['rssi'] = val
                except ValueError:
                    pass
        if 'temperature' in kv_res or len(kv_res) >= 2:
            if 'device_id' not in kv_res:
                kv_res['device_id'] = "ESP32_001"
            return kv_res

    # 3. Delimited CSV / Semicolon / Colon / Tab / Space parsing
    clean_line = line.replace(';', ',').replace('\t', ',')
    parts = [p.strip() for p in clean_line.split(',') if p.strip()]
    if not parts:
        parts = [p.strip() for p in line.split() if p.strip()]

    dev_prefix = None
    if parts:
        try:
            float(parts[0])
        except ValueError:
            dev_prefix = normalize_device_id(parts[0])
            parts = parts[1:]

    # Collect all numeric values
    num_vals = []
    for p in parts:
        try:
            num_vals.append(float(p))
        except ValueError:
            pass

    if num_vals:
        parsed = {}
        if dev_prefix:
            parsed["device_id"] = dev_prefix
        else:
            parsed["device_id"] = "ESP32_001"

        if len(num_vals) >= 6:
            parsed["temperature"] = num_vals[0]
            parsed["pressure"] = num_vals[1]
            parsed["vibration"] = num_vals[2]
            parsed["hall_effect"] = num_vals[3]
            parsed["current"] = num_vals[4]
            parsed["humidity"] = num_vals[5]
        elif len(num_vals) == 5:
            parsed["temperature"] = num_vals[0]
            parsed["pressure"] = num_vals[1]
            parsed["vibration"] = num_vals[2]
            parsed["hall_effect"] = num_vals[3]
            parsed["current"] = num_vals[4]
        elif len(num_vals) == 4:
            parsed["temperature"] = num_vals[0]
            parsed["pressure"] = num_vals[1]
            parsed["vibration"] = num_vals[2]
            parsed["current"] = num_vals[3]
        elif len(num_vals) == 3:
            parsed["temperature"] = num_vals[0]
            parsed["pressure"] = num_vals[1]
            parsed["vibration"] = num_vals[2]
        elif len(num_vals) == 2:
            parsed["temperature"] = num_vals[0]
            parsed["pressure"] = num_vals[1]
        elif len(num_vals) == 1:
            parsed["temperature"] = num_vals[0]

        return parsed

    # 4. Fallback: extract any floating point numbers in order
    all_floats = [float(f) for f in re.findall(r'[-+]?(?:\d*\.\d+|\d+)', line)]
    if all_floats:
        parsed = {"device_id": "ESP32_001", "temperature": all_floats[0]}
        if len(all_floats) > 1:
            parsed["pressure"] = all_floats[1]
        if len(all_floats) > 2:
            parsed["vibration"] = all_floats[2]
        if len(all_floats) > 3:
            parsed["hall_effect"] = all_floats[3]
        if len(all_floats) > 4:
            parsed["current"] = all_floats[4]
        return parsed

    print(f"[Gateway] Unrecognized serial frame: '{line}'")
    return None

# Dynamic Mock Data Engine State
_mock_cycle_idx = 0
_mock_topology = {
    "ESP32_001": ["temperature", "pressure"],
    "ESP32_002": ["current", "hall_effect", "vibration"],
    "ESP32_003": ["temperature", "pressure", "current"],
    "ESP32_004": ["temperature", "vibration", "humidity"]
}
_mock_injected_scenarios = {}
_mock_lock = threading.RLock()

def get_mock_topology():
    """Return the currently configured mock topology dictionary."""
    with _mock_lock:
        return {
            "slaves": list(_mock_topology.keys()),
            "topology": {k: list(v) for k, v in _mock_topology.items()},
            "active_scenarios": dict(_mock_injected_scenarios)
        }

def configure_mock_topology(num_slaves=None, custom_topology=None):
    """
    Dynamically configure the mock topology.
    If num_slaves is specified (1 to 6+), generates that many slaves with randomized channel subsets.
    If custom_topology is provided, sets the topology directly.
    """
    global _mock_topology
    import random
    with _mock_lock:
        if custom_topology and isinstance(custom_topology, dict):
            _mock_topology = {k: list(v) for k, v in custom_topology.items()}
            return get_mock_topology()

        n = max(1, min(8, int(num_slaves or 4)))
        all_channels = ["temperature", "pressure", "vibration", "hall_effect", "current", "humidity"]
        new_top = {}
        for i in range(1, n + 1):
            dev_id = f"ESP32_{i:03d}"
            # Select 1 to 4 random channels for each slave
            k_count = random.randint(2, 4)
            chosen = random.sample(all_channels, k=k_count)
            new_top[dev_id] = chosen
        _mock_topology = new_top
        return get_mock_topology()

def inject_mock_scenario(device_id, scenario_type, params=None):
    """Inject an on-demand cyber/physical test scenario into a mock slave."""
    global _mock_injected_scenarios
    with _mock_lock:
        if not device_id:
            device_id = list(_mock_topology.keys())[0] if _mock_topology else "ESP32_001"
        _mock_injected_scenarios[device_id] = {
            "type": scenario_type,
            "params": params or {},
            "injected_at": time.time()
        }
        print(f"[MockEngine] Injected scenario '{scenario_type}' on {device_id}")

def clear_mock_scenarios(device_id=None):
    """Clear active test scenarios."""
    global _mock_injected_scenarios
    with _mock_lock:
        if device_id:
            _mock_injected_scenarios.pop(device_id, None)
        else:
            _mock_injected_scenarios.clear()

def mock_serial_stream(mode):
    """
    Dynamic Mock Stream Generator:
    Cycles through active mock slaves, generating realistic telemetry ONLY for the
    channels that slave reports, applying any active scenario injections.
    """
    global _mock_cycle_idx, _isolated_nodes
    import random 
    time.sleep(0.30)
    _mock_cycle_idx += 1
    
    with _mock_lock:
        nodes = list(_mock_topology.keys())
        if not nodes:
            nodes = ["ESP32_001"]
            _mock_topology["ESP32_001"] = ["temperature", "pressure"]

        # Filter out isolated nodes if possible
        active_nodes = [n for n in nodes if n not in _isolated_nodes]
        if not active_nodes:
            return None

        current_node = active_nodes[_mock_cycle_idx % len(active_nodes)]
        active_channels = _mock_topology.get(current_node, ["temperature", "pressure"])
        scenario = _mock_injected_scenarios.get(current_node)

    # Base realistic physical baseline readings
    base_values = {
        "temperature": round(24.0 + random.uniform(-0.5, 0.5), 1),
        "pressure": round(4.2 + random.uniform(-0.15, 0.15), 2),
        "vibration": round(1.2 + random.uniform(-0.08, 0.08), 2),
        "current": round(5.0 + random.uniform(-0.2, 0.2), 2),
        "hall_effect": float(random.choice([1450, 1500, 1550])),
        "humidity": round(45.0 + random.uniform(-1.0, 1.0), 1)
    }

    # Apply scenario manipulations if active
    corrupt_signature = False
    if scenario:
        s_type = scenario.get("type", "")
        if s_type == "drift" or s_type == "thermal_drift":
            base_values["temperature"] = round(58.5 + random.uniform(0.5, 3.0), 1)
        elif s_type == "pressure" or s_type == "pressure_spike":
            base_values["pressure"] = round(7.8 + random.uniform(0.2, 1.2), 2)
        elif s_type == "locked_rotor":
            base_values["current"] = round(11.5 + random.uniform(0.5, 2.0), 2)
            base_values["hall_effect"] = 0.0
        elif s_type == "cavitation":
            base_values["vibration"] = round(3.6 + random.uniform(0.2, 0.8), 2)
            base_values["hall_effect"] = 2200.0
        elif s_type == "tamper_sig" or s_type == "replay":
            corrupt_signature = True

    # Assemble payload containing ONLY the active channels configured for this slave
    frame_dict = {"device_id": current_node}
    if "temperature" in active_channels:
        frame_dict["temp"] = base_values["temperature"]
    if "pressure" in active_channels:
        frame_dict["pres"] = base_values["pressure"]
    if "vibration" in active_channels:
        frame_dict["vib"] = base_values["vibration"]
    if "current" in active_channels:
        frame_dict["curr"] = base_values["current"]
    if "hall_effect" in active_channels:
        frame_dict["hall"] = base_values["hall_effect"]
    if "humidity" in active_channels:
        frame_dict["hum"] = base_values["humidity"]

    if corrupt_signature:
        frame_dict["signature"] = "BAD_TAMPERED_SIGNATURE_0xDEADBEEF"

    return json.dumps(frame_dict) + "\n"

def start_gateway (port ="COM3",baud =115200 ,mode ="plc",device_id =None ,hmac_key =None ,url =DEFAULT_GATEWAY_URL ,mock =False ):
    global _active_port, _isolated_nodes
    import time 
    _gateway_stop_event .clear ()
    _isolated_nodes.clear()
    _active_port =port if not mock else "MOCK_PORT"

    default_dev_id = device_id or ("ESP32_001" if mode =="plc" else "ESP32_002")

    print ("="*60 )
    print (f" Aegis Edge Serial Gateway: {default_dev_id }")
    print (f" Port         : {port } (@ {baud } baud)")
    print (f" Mode Profile : {mode .upper ()}")
    print (f" Ingestion URL: {url }")
    print ("="*60 )

    ser =None 
    if not mock :
        if not serial_available :
            print ("[CRITICAL] PySerial not installed. Install it or run with mock=True.")
            sys .exit (1 )
        try :
            ser = serial.Serial(
                port,
                baudrate=baud,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=0.1,
                write_timeout=0.5,
                rtscts=False,
                dsrdtr=False
            )
            # Avoid holding ESP32 in reset/bootloader mode upon initial connection
            try:
                ser.dtr = False
                ser.rts = False
                time.sleep(0.05)
                ser.reset_input_buffer()
            except Exception:
                pass
            print(f"[Gateway] Connected to COM port: {port} @ {baud} baud (8N1)")
        except Exception as e :
            print(f"[Gateway] FAILED to connect to COM port {port}: {e}")
            print("[Gateway] Connection failed. Gateway will NOT fall back to emulation.")
            _active_port = None
            return

    line_accumulator = ""

    while not _gateway_stop_event .is_set ():
        try :

            while not _command_queue .empty ():
                cmd =_command_queue .get_nowait ()
                if not mock and ser and ser .is_open :
                    try:
                        if isinstance(cmd, dict):
                            ser.write((json.dumps(cmd) + "\n").encode("utf-8"))
                            c_name = cmd.get("cmd")
                            c_dev = cmd.get("device_id") or cmd.get("device")
                            if c_name and c_dev:
                                ser.write(f"{c_name} {c_dev}\n".encode("utf-8"))
                        else:
                            ser.write((str(cmd) + "\n").encode("utf-8"))
                        ser .flush ()
                        print (f"[Gateway] Wrote command to UART: {cmd }")
                    except Exception as cmd_err:
                        print(f"[Gateway] UART command write error: {cmd_err}")
                elif mock :
                    print (f"[Gateway MOCK] Wrote command: {cmd }")

            lines_to_process = []
            if mock :
                mock_line = mock_serial_stream (mode )
                if _gateway_stop_event .is_set ():
                    break 
                if mock_line:
                    lines_to_process.append(mock_line)
            else :
                try:
                    raw_bytes = ser.read(ser.in_waiting or 1)
                    if raw_bytes:
                        line_accumulator += raw_bytes.decode("utf-8", errors="ignore")
                        if "\n" in line_accumulator:
                            split_lines = line_accumulator.split("\n")
                            # The last part is either empty or a partial line
                            line_accumulator = split_lines[-1]
                            lines_to_process = [l.strip() for l in split_lines[:-1] if l.strip()]
                    else:
                        time.sleep(0.01)
                        continue
                except (OSError, Exception) as ser_err:
                    print(f"[Gateway] HARDWARE DISCONNECT / READ ERROR on {port}: {ser_err}")
                    _active_port = None
                    _gateway_stop_event.set()
                    break

            for line in lines_to_process:
                raw_data =parse_serial_line (line ,mode )
                if not raw_data :
                    continue 

                target_device_id = raw_data.get("device_id") or default_dev_id
                target_hmac_key = hmac_key or get_device_key(target_device_id)

                payload ={
                    "timestamp":time .time (),
                    "device_id":target_device_id ,
                }
                if "temperature" in raw_data:
                    payload["temperature"] = raw_data["temperature"]
                if "pressure" in raw_data:
                    payload["pressure"] = raw_data["pressure"]
                if "vibration" in raw_data:
                    payload["vibration"] = raw_data["vibration"]
                if "hall_effect" in raw_data:
                    payload["hall_effect"] = raw_data["hall_effect"]
                if "current" in raw_data:
                    payload["current"] = raw_data["current"]
                if "humidity" in raw_data:
                    payload["humidity"] = raw_data["humidity"]
                if "rssi" in raw_data:
                    payload["rssi"] = raw_data["rssi"]

                # Debug: log raw fields received this timestep
                reported_fields = [k for k in raw_data.keys()]
                print(f"[Gateway DEBUG] Node: {target_device_id} | Raw fields: {reported_fields} -> {raw_data}")

                payload ["signature"]=sign_message (payload ,target_hmac_key )

                headers ={"Content-Type":"application/json"}
                try:
                    resp =requests .post (url ,json =payload ,headers =headers ,timeout =3 )
                    if resp .status_code ==200 :
                        print (f"[Gateway] Success -> {raw_data }")
                    elif resp .status_code ==403 :
                        print (f"[Gateway] ACCESS DENIED: Device is isolated by Gateway.")
                    else :
                        print (f"[Gateway] Error status {resp .status_code }: {resp .text }")
                except Exception as req_err:
                    print(f"[Gateway] HTTP Ingestion Error: {req_err}")

        except Exception as e :
            print (f"[Gateway] Telemetry acquisition exception: {e }")
            if _gateway_stop_event.is_set():
                break
            if not mock and (ser is None or not ser.is_open):
                print ("[Gateway] Critical connection failure. Stopping gateway.")
                _active_port = None
                _gateway_stop_event.set()
                break
            time .sleep (0.1 )

    if ser and ser .is_open :
        try :
            ser .close ()
            print (f"[Gateway] COM port {port } closed safely.")
        except Exception as e :
            print (f"[Gateway] Error closing COM port: {e }")
    _active_port =None 
    print ("[Gateway] Shutdown complete.")

if __name__ =="__main__":
    parser =argparse .ArgumentParser (description ="Aegis ICS V2 — Edge Serial Gateway Driver")
    parser .add_argument ("--port",type =str ,default ="COM3",help ="Serial COM port name (e.g. COM3 or /dev/ttyUSB0)")
    parser .add_argument ("--baud",type =int ,default =9600 ,help ="Baud rate (9600, 115200, etc.)")
    parser .add_argument ("--mode",type =str ,choices =["plc","non-plc"],default ="plc",help ="Machine Profile Profile")
    parser .add_argument ("--device-id",type =str ,default =None ,help ="Device ID override")
    parser .add_argument ("--key",type =str ,default =None ,help ="HMAC Pre-Shared Key")
    parser .add_argument ("--url",type =str ,default =DEFAULT_GATEWAY_URL ,help ="Aegis REST Telemetry Ingest URL")
    parser .add_argument ("--mock",action ="store_true",help ="Emulate serial input (no COM port required)")

    args =parser .parse_args ()
    start_gateway (
    port =args .port ,
    baud =args .baud ,
    mode =args .mode ,
    device_id =args .device_id ,
    hmac_key =args .key ,
    url =args .url ,
    mock =args .mock 
    )
