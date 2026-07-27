
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

def stop_gateway ():
    _gateway_stop_event .set ()

def get_active_port ():
    return _active_port if not _gateway_stop_event .is_set ()else None 

def send_command (payload_dict ):
    """Enqueues a command to be written to the serial port."""
    _command_queue .put (payload_dict )

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

def parse_serial_line (line :str ,mode :str ):
    line =line .strip ()
    if not line :
        return None 


    import re 
    json_match =re .search (r'(\{.*\})',line )
    if json_match :
        try :
            data =json .loads (json_match .group (1 ))
            res = {}
            if "temp" in data or "temperature" in data:
                res["temperature"] = float(data.get("temp", data.get("temperature")))
            if "pres" in data or "pressure" in data:
                res["pressure"] = float(data.get("pres", data.get("pressure")))
            if "vib" in data or "vibration" in data:
                res["vibration"] = float(data.get("vib", data.get("vibration")))
            if "hall" in data or "hall_effect" in data:
                res["hall_effect"] = float(data.get("hall", data.get("hall_effect")))
            if "curr" in data or "current" in data:
                res["current"] = float(data.get("curr", data.get("current")))
            return res
        except Exception :
            pass 


    try :
        parts =[p .strip ()for p in line .split (",")]

        if len (parts )>=5 :
            return {
            "temperature":float (parts [0 ]),
            "pressure":float (parts [1 ]),
            "vibration":float (parts [2 ]),
            "hall_effect":float (parts [3 ]),
            "current":float (parts [4 ])
            }

        elif len (parts )==1 :
            return {
            "temperature":float (parts [0 ])
            }

        elif len (parts )==2 :
            return {
            "temperature":float (parts [0 ]),
            "pressure":float (parts [1 ])
            }
    except Exception as e :
        pass

    # Key-Value fallback parsing (e.g., "TEMP:42.5", "T:42.5", "temp=42.5", "P:4.2")
    kv_res = {}
    for item in line.replace('=', ':').split(','):
        if ':' in item:
            k, v = item.split(':', 1)
            k = k.strip().lower()
            try:
                val = float(v.strip())
                if k in ('t', 'temp', 'temperature'):
                    kv_res['temperature'] = val
                elif k in ('p', 'pres', 'pressure'):
                    kv_res['pressure'] = val
                elif k in ('v', 'vib', 'vibration'):
                    kv_res['vibration'] = val
                elif k in ('h', 'hall', 'hall_effect'):
                    kv_res['hall_effect'] = val
                elif k in ('c', 'curr', 'current'):
                    kv_res['current'] = val
            except ValueError:
                pass
    if kv_res:
        return kv_res

    print(f"[Gateway] Could not parse serial line: '{line}'")
    return None 

def mock_serial_stream (mode ):
    import random 
    time .sleep (2 )
    if mode =="plc":

        temp =round (25.0 +random .uniform (-1 ,1 ),1 )
        pres =round (4.5 +random .uniform (-0.2 ,0.2 ),2 )
        vib =round (1.2 +random .uniform (-0.1 ,0.1 ),2 )
        current =round (4.5 +random .uniform (-0.2 ,0.2 ),2 )
        return json .dumps ({
        "temp":temp ,
        "pres":pres ,
        "vib":vib ,
        "hall":0.0 ,
        "curr":current 
        })+"\n"
    else :

        vib =round (0.8 +random .uniform (-0.05 ,0.05 ),2 )
        rpm =float (random .choice ([1000 ,1200 ,1500 ,1800 ]))
        return json .dumps ({
        "temp":0.0 ,
        "pres":vib ,
        "vib":vib ,
        "hall":rpm ,
        "curr":0.0 
        })+"\n"

def start_gateway (port ="COM3",baud =115200 ,mode ="plc",device_id =None ,hmac_key =None ,url =DEFAULT_GATEWAY_URL ,mock =False ):
    global _active_port 
    import time 
    _gateway_stop_event .clear ()
    _active_port =port if not mock else "MOCK_PORT"

    device_id =device_id or ("ESP32_001"if mode =="plc"else "ESP32_002")
    hmac_key =hmac_key or os .environ .get (f"DEVICE_KEY_{device_id }",DEFAULT_DEVICE_KEY )

    print ("="*60 )
    print (f" Aegis Edge Serial Gateway: {device_id }")
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
            ser =serial .Serial (port ,baudrate =baud ,timeout =1 )
            ser .setDTR (False )
            ser .setRTS (False )
            print (f"[Gateway] Connected to COM port: {port } @ {baud} baud")
        except Exception as e :
            print (f"[Gateway] FAILED to connect to COM port {port }: {e }")
            print ("[Gateway] Connection failed. Gateway will NOT fall back to emulation.")
            _active_port = None
            return

    while not _gateway_stop_event .is_set ():
        try :

            while not _command_queue .empty ():
                cmd =_command_queue .get_nowait ()
                if not mock and ser and ser .is_open :
                    ser .write ((json .dumps (cmd )+"\n").encode ("utf-8"))
                    ser .flush ()
                    print (f"[Gateway] Wrote command to UART: {cmd }")
                elif mock :
                    print (f"[Gateway MOCK] Wrote command: {cmd }")


            if mock :
                line =mock_serial_stream (mode )
                if _gateway_stop_event .is_set ():
                    break 
            else :
                line =ser .readline ().decode ("utf-8",errors ="ignore")
                if not line :
                    continue 


            raw_data =parse_serial_line (line ,mode )
            if not raw_data :
                continue 


            payload ={
            "timestamp":time .time (),
            "device_id":device_id ,
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
            print(f"[Gateway DEBUG] Raw fields this tick: {reported_fields} -> {raw_data}")


            payload ["signature"]=sign_message (payload ,hmac_key )


            headers ={"Content-Type":"application/json"}
            resp =requests .post (url ,json =payload ,headers =headers ,timeout =3 )

            if resp .status_code ==200 :
                print (f"[Gateway] Success -> {raw_data }")
            elif resp .status_code ==403 :
                print (f"[Gateway] ACCESS DENIED: Device is isolated by Gateway.")
            else :
                print (f"[Gateway] Error status {resp .status_code }: {resp .text }")

        except Exception as e :
            print (f"[Gateway] Telemetry acquisition exception: {e }")
            if _gateway_stop_event.is_set():
                break
            if not mock and (ser is None or not ser.is_open):
                print ("[Gateway] Critical connection failure. Stopping gateway.")
                break
            time .sleep (1 )


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
