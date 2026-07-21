import time 
from datetime import datetime ,timezone 
from io import BytesIO 
from sqlalchemy .orm import joinedload 
from reportlab .lib .pagesizes import letter 
from reportlab .lib import colors 
from reportlab .platypus import SimpleDocTemplate ,Paragraph ,Spacer ,Table ,TableStyle 
from reportlab .lib .styles import getSampleStyleSheet ,ParagraphStyle 
from reportlab .graphics .shapes import Drawing ,Rect ,String ,Line 

from database import TelemetryLog ,AuditLog 
from analytics import calculate_financial_analytics 

def generate_incident_report_pdf (db_session ,username ,location ):
    buffer =BytesIO ()
    doc =SimpleDocTemplate (buffer ,pagesize =letter ,rightMargin =40 ,leftMargin =40 ,topMargin =40 ,bottomMargin =40 )
    story =[]


    styles =getSampleStyleSheet ()
    title_style =ParagraphStyle (
    'TitleStyle',
    parent =styles ['Heading1'],
    fontSize =20 ,
    leading =24 ,
    textColor =colors .HexColor ('#000000'),
    spaceAfter =5 
    )
    meta_style =ParagraphStyle (
    'MetaStyle',
    parent =styles ['Normal'],
    fontSize =9 ,
    leading =13 ,
    textColor =colors .HexColor ('#86868b'),
    spaceAfter =15 
    )
    h2_style =ParagraphStyle (
    'H2Style',
    parent =styles ['Heading2'],
    fontSize =12 ,
    leading =16 ,
    textColor =colors .HexColor ('#1d1d1f'),
    spaceBefore =12 ,
    spaceAfter =6 
    )
    body_style =ParagraphStyle (
    'BodyStyle',
    parent =styles ['Normal'],
    fontSize =8.5 ,
    leading =12 ,
    textColor =colors .HexColor ('#1d1d1f'),
    spaceAfter =8 
    )
    table_text =ParagraphStyle (
    'TableText',
    parent =styles ['Normal'],
    fontSize =8 ,
    leading =11 ,
    textColor =colors .HexColor ('#1d1d1f')
    )
    table_header =ParagraphStyle (
    'TableHeader',
    parent =styles ['Normal'],
    fontSize =8 ,
    leading =11 ,
    textColor =colors .HexColor ('#1d1d1f'),
    fontName ='Helvetica-Bold'
    )


    story .append (Paragraph ("Aegis SCADA Security & Loss Analysis Report",title_style ))
    story .append (Paragraph (f"Generated: {datetime .now (timezone .utc ).isoformat ()} | Station Coordinates: {location } | Operator: {username }",meta_style ))
    story .append (Spacer (1 ,10 ))


    story .append (Paragraph ("1. Incident Financial Audit & Loss Projections",h2_style ))


    financials =calculate_financial_analytics (db_session )


    fin_data =[
    [Paragraph ("Audit Category",table_header ),Paragraph ("Financial Impact",table_header ),Paragraph ("Security / Cost Breakdown",table_header )],
    [Paragraph ("Incurred Incident Cost",table_text ),Paragraph (f"${financials ['incurred_cost']:,.2f}",table_text ),Paragraph ("Triage and investigation cost ($5,000 per violation attempt)",table_text )],
    [Paragraph ("Projected Downtime Cost",table_text ),Paragraph (f"${financials ['expected_loss']:,.2f}",table_text ),Paragraph ("Liability projection based on dynamic Threat Index",table_text )],
    [Paragraph ("Total Prevented Losses (Savings)",table_text ),Paragraph (f"${financials ['prevented_cost']:,.2f}",table_text ),Paragraph ("Savings from blocked centrifugal casing ruptures ($400,000 each)",table_text )]
    ]
    t_fin =Table (fin_data ,colWidths =[150 ,100 ,280 ])
    t_fin .setStyle (TableStyle ([
    ('BACKGROUND',(0 ,0 ),(-1 ,0 ),colors .HexColor ('#f5f5f7')),
    ('ALIGN',(0 ,0 ),(-1 ,-1 ),'LEFT'),
    ('BOTTOMPADDING',(0 ,0 ),(-1 ,-1 ),5 ),
    ('TOPPADDING',(0 ,0 ),(-1 ,-1 ),5 ),
    ('GRID',(0 ,0 ),(-1 ,-1 ),0.5 ,colors .HexColor ('#d2d2d7')),
    ]))
    story .append (t_fin )
    story .append (Spacer (1 ,15 ))


    story .append (Paragraph ("2. Telemetry Plot (Historical Temperature vs. Pressure)",h2_style ))

    telemetry =db_session .query (TelemetryLog ).filter (
        TelemetryLog .is_simulated ==False
    ).order_by (TelemetryLog .timestamp .desc ()).limit (30 ).all ()
    if telemetry :
        chrono_telemetry =list (reversed (telemetry ))
        # Filter to rows with both temperature and pressure available
        valid_telemetry = [t for t in chrono_telemetry if t.temperature is not None and t.pressure is not None]
        if not valid_telemetry:
            story.append(Paragraph("No telemetry readings with temperature and pressure available for charting.", body_style))
        else:
            drawing =Drawing (530 ,160 )


            drawing .add (Rect (0 ,0 ,530 ,160 ,fillColor =colors .HexColor ('#fafafa'),strokeColor =colors .HexColor ('#e5e5ea'),strokeWidth =1 ))


            temp_pts =[]
            pres_pts =[]
            for idx ,t in enumerate (valid_telemetry ):


                x =50 +(idx /max (1 ,len (valid_telemetry )-1 ))*430 

                y_temp =30 +(min (80.0 ,max (0.0 ,t .temperature ))/80.0 )*110 

                y_pres =30 +(min (10.0 ,max (0.0 ,t .pressure ))/10.0 )*110 

                temp_pts .append ((x ,y_temp ))
                pres_pts .append ((x ,y_pres ))




            for y_val in [30 ,57.5 ,85 ,112.5 ,140 ]:
                drawing .add (Line (50 ,y_val ,480 ,y_val ,strokeColor =colors .HexColor ('#e5e5ea'),strokeWidth =0.5 ))


            for i in range (len (temp_pts )-1 ):
                p1 =temp_pts [i ]
                p2 =temp_pts [i +1 ]
                drawing .add (Line (p1 [0 ],p1 [1 ],p2 [0 ],p2 [1 ],strokeColor =colors .HexColor ('#000000'),strokeWidth =1.5 ))


            for i in range (len (pres_pts )-1 ):
                p1 =pres_pts [i ]
                p2 =pres_pts [i +1 ]
                drawing .add (Line (p1 [0 ],p1 [1 ],p2 [0 ],p2 [1 ],strokeColor =colors .HexColor ('#86868b'),strokeWidth =1 ,strokeDashArray =[3 ,3 ]))


            drawing .add (String (10 ,135 ,"Temp (C)",fontName ="Helvetica-Bold",fontSize =8 ,fillColor =colors .HexColor ('#000000')))
            drawing .add (String (490 ,135 ,"Pres (bar)",fontName ="Helvetica-Bold",fontSize =8 ,fillColor =colors .HexColor ('#86868b')))
            drawing .add (String (10 ,82 ,"40C / 5bar",fontName ="Helvetica",fontSize =7 ,fillColor =colors .HexColor ('#86868b')))
            drawing .add (String (10 ,30 ,"0C / 0bar",fontName ="Helvetica",fontSize =7 ,fillColor =colors .HexColor ('#86868b')))

            story .append (drawing )
    else :
        story .append (Paragraph ("No telemetry readings available for charting.",body_style ))
    story .append (Spacer (1 ,15 ))


    story .append (Paragraph ("3. Chronological Incident Narrative",h2_style ))
    story .append (Paragraph ("Below is the complete sequence of logged user access, parameter updates, enforcer interventions, and isolation actions.",body_style ))


    audit_logs =db_session .query (AuditLog ).options (joinedload (AuditLog .user )).order_by (AuditLog .timestamp .desc ()).limit (100 ).all ()

    audit_headers =[
    Paragraph ("Timestamp",table_header ),
    Paragraph ("User",table_header ),
    Paragraph ("Action",table_header ),
    Paragraph ("Location Coords",table_header ),
    Paragraph ("Event Details",table_header )
    ]
    audit_rows =[audit_headers ]

    for a in reversed (audit_logs ):
        u_name =a .user .username if a .user else "SYSTEM"
        action_text =a .action 


        color_hex ="#1d1d1f"
        if "VIOLATION"in action_text or "ISOLATION"in action_text :
            color_hex ="#c93b3b"
        elif "LOGIN"in action_text or "REJOIN"in action_text :
            color_hex ="#1f824c"

        act_style =ParagraphStyle ('ActStyle',parent =table_text ,textColor =colors .HexColor (color_hex ),fontName ="Helvetica-Bold")

        audit_rows .append ([
        Paragraph (a .timestamp .strftime ('%Y-%m-%d %H:%M:%S'),table_text ),
        Paragraph (u_name ,table_text ),
        Paragraph (action_text ,act_style ),
        Paragraph (a .location ,table_text ),
        Paragraph (a .details or "",table_text )
        ])

    t_audit =Table (audit_rows ,colWidths =[90 ,60 ,110 ,90 ,180 ])
    t_audit .setStyle (TableStyle ([
    ('BACKGROUND',(0 ,0 ),(-1 ,0 ),colors .HexColor ('#f5f5f7')),
    ('ALIGN',(0 ,0 ),(-1 ,-1 ),'LEFT'),
    ('BOTTOMPADDING',(0 ,0 ),(-1 ,-1 ),4 ),
    ('TOPPADDING',(0 ,0 ),(-1 ,-1 ),4 ),
    ('GRID',(0 ,0 ),(-1 ,-1 ),0.5 ,colors .HexColor ('#e5e5ea')),
    ]))

    story .append (t_audit )
    story .append (Spacer (1 ,15 ))


    story .append (Paragraph ("4. Recommended Mitigation Steps",h2_style ))
    story .append (Paragraph ("• <b>HMAC Credential Rotation</b>: Rotate secret device validation keys (DEVICE_KEY) on all ESP32 PLCs to prevent replay and injection vectors.<br/>"
    "• <b>Session Audit</b>: Inspect operator station coordinates to isolate coordinates outside permitted operational zones.<br/>"
    "• <b>Device Loop Check</b>: If a device status is MANUAL_ISOLATION, run hardware testing loop checks before rejoining the device to the operational loop.<br/>"
    "• <b>Stuxnet Mitigation</b>: Keep Aegis enforcer correlation rules active. The enforcer prevents centrifugal over-pressurization even under administrator credentials.",body_style ))


    doc .build (story )
    buffer .seek (0 )
    return buffer .getvalue ()
