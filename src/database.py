import os 
import sys
from datetime import datetime ,timezone 
from sqlalchemy import create_engine ,Column ,Integer ,String ,Float ,Boolean ,ForeignKey ,DateTime ,event 
from sqlalchemy .ext .declarative import declarative_base 
from sqlalchemy .orm import sessionmaker ,relationship 
from werkzeug .security import generate_password_hash 

def get_database_url():
    if "DATABASE_URL" in os.environ:
        return os.environ["DATABASE_URL"]
    if getattr(sys, "frozen", False):
        base_dir = os.path.dirname(sys.executable)
    else:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    db_file = os.path.join(base_dir, "aegis_v2.db")
    return f"sqlite:///{db_file}"

DATABASE_URL = get_database_url()

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
    trust_score =Column (Float ,default =100.0 )
    updated_at =Column (DateTime ,default =lambda :datetime .now (timezone .utc ))

class Rule (Base ):
    __tablename__ ="rules"
    id =Column (Integer ,primary_key =True )
    key =Column (String (50 ),unique =True ,nullable =False )
    value =Column (Float ,nullable =False )
    description =Column (String (255 ),nullable =True )

engine =create_engine (DATABASE_URL ,connect_args ={"check_same_thread":False })
SessionLocal =sessionmaker (autocommit =False ,autoflush =False ,bind =engine )

def migrate_sqlite_schema ():
    import sqlite3 
    db_path =DATABASE_URL .replace ("sqlite:///","")
    if os .path .exists (db_path ):
        try :
            conn =sqlite3 .connect (db_path )
            cursor =conn .cursor ()
            cols =cursor .execute ("PRAGMA table_info('telemetry_logs')").fetchall ()
            needs_migration =any (row [1 ]in ("temperature","pressure","humidity")and row [3 ]==1 for row in cols )
            if needs_migration :
                print ("[Database] Migrating telemetry_logs table to support nullable sensor fields...")
                cursor .execute ("""
                CREATE TABLE IF NOT EXISTS telemetry_logs_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp FLOAT NOT NULL,
                    device_id VARCHAR(50) NOT NULL,
                    temperature FLOAT,
                    pressure FLOAT,
                    humidity FLOAT,
                    vibration FLOAT,
                    hall_effect FLOAT,
                    current FLOAT,
                    rssi FLOAT,
                    is_anomaly BOOLEAN DEFAULT 0,
                    is_simulated BOOLEAN DEFAULT 0
                );
                """)
                cursor .execute ("""
                INSERT INTO telemetry_logs_new (id, timestamp, device_id, temperature, pressure, humidity, vibration, hall_effect, current, rssi, is_anomaly, is_simulated)
                SELECT id, timestamp, device_id, temperature, pressure, humidity, vibration, hall_effect, current, rssi, is_anomaly, is_simulated FROM telemetry_logs;
                """)
                cursor .execute ("DROP TABLE telemetry_logs;")
                cursor .execute ("ALTER TABLE telemetry_logs_new RENAME TO telemetry_logs;")
                conn .commit ()
                print ("[Database] Schema migration complete.")

            # Ensure device_states has trust_score column
            dev_cols = cursor.execute("PRAGMA table_info('device_states')").fetchall()
            if dev_cols and not any(row[1] == "trust_score" for row in dev_cols):
                cursor.execute("ALTER TABLE device_states ADD COLUMN trust_score FLOAT DEFAULT 100.0;")
                conn.commit()

            conn .close ()
        except Exception as e :
            print (f"[Database] Auto-migration note: {e }")

def init_db ():
    migrate_sqlite_schema ()
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
        "pressure_min":(0.0 ,"Absolute minimum allowed pressure setpoint (bar)"),
        "vibration_max":(4.0 ,"Absolute maximum allowed mechanical vibration ceiling (g)"),
        "current_max":(15.0 ,"Absolute maximum electrical motor current ceiling (A)"),
        "hall_max":(3500.0 ,"Absolute maximum rotor speed ceiling (RPM)")
        }
        for key ,(val ,desc )in rules .items ():
            if not db .query (Rule ).filter_by (key =key ).first ():
                db .add (Rule (key =key ,value =val ,description =desc ))

        db .commit ()
    finally :
        db .close ()
