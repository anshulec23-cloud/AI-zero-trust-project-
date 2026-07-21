from sqlalchemy .orm import Session 
from database import Rule ,TelemetryLog 

def validate_command (command :dict ,db :Session )->tuple [bool ,str ]:
    """
    Validates a SCADA command against safety rules and Stuxnet correlation hazards.
    """
    cmd_type =command .get ("type")
    value =command .get ("value")

    if cmd_type not in ("set_temp","set_pressure"):
        return False ,f"Denied: Unknown command type '{cmd_type }'. Only 'set_temp' and 'set_pressure' are permitted."

    if not isinstance (value ,(int ,float )):
        return False ,"Command setpoint value must be numeric."


    if cmd_type =="set_temp":
        temp_max_rule =db .query (Rule ).filter_by (key ="temp_max").first ()
        temp_min_rule =db .query (Rule ).filter_by (key ="temp_min").first ()

        t_max =temp_max_rule .value if temp_max_rule else 60.0 
        t_min =temp_min_rule .value if temp_min_rule else 0.0 

        if not (t_min <=value <=t_max ):
            return False ,f"Rule violation: Temperature setpoint {value }C exceeds boundaries ({t_min }-{t_max }C)."

    elif cmd_type =="set_pressure":
        pres_max_rule =db .query (Rule ).filter_by (key ="pressure_max").first ()
        pres_min_rule =db .query (Rule ).filter_by (key ="pressure_min").first ()

        p_max =pres_max_rule .value if pres_max_rule else 8.0 
        p_min =pres_min_rule .value if pres_min_rule else 0.0 

        if not (p_min <=value <=p_max ):
            return False ,f"Rule violation: Pressure setpoint {value } bar exceeds boundaries ({p_min }-{p_max } bar)."





    if cmd_type =="set_temp"and value >=45.0 :

        latest_telemetry =db .query (TelemetryLog ).order_by (TelemetryLog .timestamp .desc ()).first ()
        if latest_telemetry and latest_telemetry .pressure >=6.0 :
            return False ,(
            f"AI SECURITY EXPOSURE BLOCK (Stuxnet Prevention): "
            f"Blocked raising Temperature to {value }C because live Pressure is {latest_telemetry .pressure } bar. "
            "Coordinated high-temperature/high-pressure damage profile detected."
            )

    if cmd_type =="set_pressure"and value >=6.0 :
        latest_telemetry =db .query (TelemetryLog ).order_by (TelemetryLog .timestamp .desc ()).first ()
        if latest_telemetry and latest_telemetry .temperature >=45.0 :
            return False ,(
            f"AI SECURITY EXPOSURE BLOCK (Stuxnet Prevention): "
            f"Blocked raising Pressure to {value } bar because live Temperature is {latest_telemetry .temperature }C. "
            "Coordinated high-temperature/high-pressure damage profile detected."
            )

    return True ,"Approved"
