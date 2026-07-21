import os 
from datetime import datetime ,timezone 
from sqlalchemy import create_engine ,Column ,Integer ,String ,Float ,Boolean ,ForeignKey ,DateTime ,event 
from sqlalchemy .ext .declarative import declarative_base 
from sqlalchemy .orm import sessionmaker ,relationship 
from werkzeug .security import generate_password_hash 

DATABASE_URL =os .environ .get ("DATABASE_URL","sqlite:///aegis_v2.db")

engine =create_engine (DATABASE_URL ,connect_args ={"check_same_thread":False ,"timeout":15 })

@event .listens_for (engine ,"connect")
def set_sqlite_pragma (dbapi_connection ,connection_record ):
    cursor =dbapi_connection .cursor ()
    cursor .execute ("PRAGMA journal_mode=WAL")
    cursor .execute ("PRAGMA synchronous=NORMAL")
    cursor .execute ("PRAGMA busy_timeout=5000")
    cursor .close ()

Base =declarative_base ()

class User (Base ):
    __tablename__ ="users"
    id =Column (Integer ,primary_key =True )
    username =Column (String (50 ),unique =True ,nullable =False )
    password_hash =Column (String (255 ),nullable =False )

    logs =relationship ("AuditLog",back_populates ="user")

class AuditLog (Base ):
    __tablename__ ="audit_logs"
    id =Column (Integer ,primary_key =True )
    timestamp =Column (DateTime ,default =lambda :datetime .now (timezone .utc ))
    user_id =Column (Integer ,ForeignKey ("users.id"),nullable =True )
    action =Column (String (100 ),nullable =False )
    location =Column (String (100 ),nullable =False )
    details =Column (String (255 ),nullable =True )

    user =relationship ("User",back_populates ="logs")

class TelemetryLog (Base ):
    __tablename__ ="telemetry_logs"
    id =Column (Integer ,primary_key =True )
    timestamp =Column (Float ,nullable =False )
    device_id =Column (String (50 ),nullable =False )
    temperature =Column (Float ,nullable =True )
    pressure =Column (Float ,nullable =True )
    humidity =Column (Float ,nullable =True )
    vibration =Column (Float ,nullable =True )
    hall_effect =Column (Float ,nullable =True )
    current =Column (Float ,nullable =True )
    rssi =Column (Float ,nullable =True )
    is_anomaly =Column (Boolean ,default =False )
    is_simulated =Column (Boolean ,default =False )

class DeviceState (Base ):
    __tablename__ ="device_states"
    id =Column (Integer ,primary_key =True )
    device_id =Column (String (50 ),unique =True ,nullable =False )
    is_isolated =Column (Boolean ,default =False )
    updated_at =Column (DateTime ,default =lambda :datetime .now (timezone .utc ))

class Rule (Base ):
    __tablename__ ="rules"
    id =Column (Integer ,primary_key =True )
    key =Column (String (50 ),unique =True ,nullable =False )
    value =Column (Float ,nullable =False )
    description =Column (String (255 ),nullable =True )

engine =create_engine (DATABASE_URL ,connect_args ={"check_same_thread":False })
SessionLocal =sessionmaker (autocommit =False ,autoflush =False ,bind =engine )

def init_db ():
    Base .metadata .create_all (bind =engine )
    db =SessionLocal ()
    try :

        if not db .query (User ).filter_by (username ="admin").first ():
            admin =User (
            username ="admin",
            password_hash =generate_password_hash (os .environ .get ("ADMIN_PASSWORD","admin"))
            )
            db .add (admin )


        rules ={
        "temp_max":(60.0 ,"Absolute maximum allowed temperature setpoint (C)"),
        "temp_min":(0.0 ,"Absolute minimum allowed temperature setpoint (C)"),
        "pressure_max":(8.0 ,"Absolute maximum allowed pressure setpoint (bar)"),
        "pressure_min":(0.0 ,"Absolute minimum allowed pressure setpoint (bar)")
        }
        for key ,(val ,desc )in rules .items ():
            if not db .query (Rule ).filter_by (key =key ).first ():
                db .add (Rule (key =key ,value =val ,description =desc ))


        if not db .query (DeviceState ).filter_by (device_id ="ESP32_001").first ():
            db .add (DeviceState (device_id ="ESP32_001",is_isolated =False ))

        db .commit ()
    finally :
        db .close ()
