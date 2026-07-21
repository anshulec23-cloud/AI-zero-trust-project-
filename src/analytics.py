from database import TelemetryLog ,AuditLog 

def calculate_financial_analytics (db ):
    """
    Financial & Risk Analytics Engine
    """

    telemetry =db .query (TelemetryLog ).order_by (TelemetryLog .timestamp .desc ()).limit (50 ).all ()

    violations =db .query (AuditLog ).filter (AuditLog .action .like ("%VIOLATION%")).all ()
    violation_count =len (violations )



    incurred_cost =violation_count *5000.0 



    prevented_cost =violation_count *400000.0 


    threat_index =0.0 
    drift_risk =0.0 
    corr_risk =0.0 
    boundary_risk =0.0 

    n =len (telemetry )
    if n >=15 :

        chrono_telemetry =list (reversed (telemetry ))
        # Filter to rows where both temperature and pressure are available
        valid_telemetry = [t for t in chrono_telemetry if t.temperature is not None and t.pressure is not None]
        n_valid = len(valid_telemetry)
        if n_valid < 2:
            return {
                "violation_count": violation_count,
                "incurred_cost": incurred_cost,
                "prevented_cost": prevented_cost,
                "threat_index": 0.0,
                "drift_risk": 0.0,
                "corr_risk": 0.0,
                "boundary_risk": 0.0,
                "expected_loss": 0.0,
            }
        temps =[t .temperature for t in valid_telemetry ]
        pressures =[t .pressure for t in valid_telemetry ]
        times =[t .timestamp for t in valid_telemetry ]
        n = n_valid


        latest_temp =temps [-1 ]
        older_temp =temps [-15 ]
        time_diff =(times [-1 ]-times [-15 ])/60.0 
        drift =abs ((latest_temp -older_temp )/(time_diff or 1.0 ))
        drift_risk =min (30.0 ,drift *5.0 )


        t_mean =sum (temps )/n 
        p_mean =sum (pressures )/n 
        num =sum ((temps [i ]-t_mean )*(pressures [i ]-p_mean )for i in range (n ))
        den_t =sum ((temps [i ]-t_mean )**2 for i in range (n ))
        den_p =sum ((pressures [i ]-p_mean )**2 for i in range (n ))
        r =num /((den_t *den_p )**0.5 or 1.0 )


        if n >20 :
            abs_r =abs (r )
            if abs_r <0.2 :
                corr_risk =40.0 
            elif abs_r <0.5 :
                corr_risk =20.0 


        if temps [-1 ]>=45.0 :boundary_risk +=15.0 
        if pressures [-1 ]>=6.0 :boundary_risk +=15.0 

        threat_index =min (100.0 ,drift_risk +corr_risk +boundary_risk )

    expected_loss =(threat_index /100.0 )*400000.0 

    return {
    "violation_count":violation_count ,
    "incurred_cost":incurred_cost ,
    "prevented_cost":prevented_cost ,
    "threat_index":round (threat_index ,1 ),
    "drift_risk":round (drift_risk ,1 ),
    "corr_risk":round (corr_risk ,1 ),
    "boundary_risk":round (boundary_risk ,1 ),
    "expected_loss":round (expected_loss ,2 )
    }
