import time
from datetime import datetime, timezone
from io import BytesIO
import socket
from sqlalchemy.orm import joinedload
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Circle

from database import TelemetryLog, AuditLog
from analytics import calculate_financial_analytics

def generate_incident_report_pdf(db_session, username, location):
    """
    Generates a formal, professional incident report PDF adhering to Harvard/Chicago
    publication formatting standards. Contains executive summary, system/station login details,
    detailed attack breakdown, financial loss projections, telemetry plots, audit trail, and
    actionable technical mitigations.
    """
    buffer = BytesIO()
    # Letter size: 612 x 792 points. Margins: 36pt (0.5 inch). Printable width: 540pt.
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )
    story = []

    styles = getSampleStyleSheet()

    # Color Palette: Chicago/Harvard Formal Academic/Security Standard
    PRIMARY_NAVY = colors.HexColor('#1A2530')
    SECONDARY_SLATE = colors.HexColor('#2C3E50')
    CRIMSON_ACCENT = colors.HexColor('#8B0000')
    DARK_RED = colors.HexColor('#A91D22')
    FOREST_GREEN = colors.HexColor('#1E7E34')
    AMBER_GOLD = colors.HexColor('#D97706')
    BG_LIGHT_GREY = colors.HexColor('#F8F9FA')
    BORDER_GREY = colors.HexColor('#BDC3C7')
    TEXT_DARK = colors.HexColor('#111827')
    TEXT_MUTED = colors.HexColor('#4B5563')

    # Typography Styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=PRIMARY_NAVY,
        spaceAfter=2
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9.5,
        leading=13,
        textColor=CRIMSON_ACCENT,
        spaceAfter=6
    )
    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=14,
        textColor=PRIMARY_NAVY,
        spaceBefore=10,
        spaceAfter=4
    )
    body_style = ParagraphStyle(
        'StandardBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=TEXT_DARK,
        spaceAfter=5
    )
    body_bold = ParagraphStyle(
        'StandardBodyBold',
        parent=body_style,
        fontName='Helvetica-Bold'
    )
    meta_label = ParagraphStyle(
        'MetaLabel',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=11,
        textColor=PRIMARY_NAVY
    )
    meta_val = ParagraphStyle(
        'MetaVal',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=TEXT_DARK
    )
    table_text = ParagraphStyle(
        'TableText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.5,
        leading=10,
        textColor=TEXT_DARK
    )
    table_header = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=10,
        textColor=colors.white
    )

    # --- Header / Document Title Block ---
    story.append(Paragraph("AEGIS ICS SECURITY & INCIDENT ANALYSIS REPORT", title_style))
    story.append(Paragraph("CHICAGO MANUAL OF STYLE STANDARDS · INDUSTRIAL CONTROL SYSTEM SECURITY AUDIT", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=PRIMARY_NAVY, spaceAfter=8))

    # --- Document Metadata & Computer / Station Login Control Block ---
    hostname = socket.gethostname()
    generated_time = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

    meta_table_data = [
        [
            Paragraph("Document Identifier:", meta_label),
            Paragraph("AEGIS-AUDIT-2026-v2.2.2", meta_val),
            Paragraph("Authenticated Operator:", meta_label),
            Paragraph(str(username), meta_val)
        ],
        [
            Paragraph("Timestamp (UTC):", meta_label),
            Paragraph(generated_time, meta_val),
            Paragraph("Station Coordinates:", meta_label),
            Paragraph(str(location), meta_val)
        ],
        [
            Paragraph("Host Computer Name:", meta_label),
            Paragraph(hostname, meta_val),
            Paragraph("Security Classification:", meta_label),
            Paragraph("RESTRICTED / FOR OFFICIAL USE ONLY", meta_val)
        ]
    ]
    meta_table = Table(meta_table_data, colWidths=[105, 165, 105, 165])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), BG_LIGHT_GREY),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('BOX', (0, 0), (-1, -1), 0.5, BORDER_GREY),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E5E7EB')),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 8))

    # --- 1. Executive Summary & Financial Loss Projections ---
    story.append(Paragraph("1. Executive Summary & Financial Loss Projections", h2_style))
    story.append(Paragraph(
        "This section summarizes the financial damage assessments, risk liabilities, and cost savings realized by the "
        "Aegis Real-Time Safety Enforcer. Incident triage cost is fixed at $5,000.00 per violation or isolation event, "
        "while savings of $400,000.00 are credited for each blocked centrifugal casing rupture.",
        body_style
    ))

    financials = calculate_financial_analytics(db_session)

    fin_data = [
        [Paragraph("Audit Category", table_header), Paragraph("Financial Impact", table_header), Paragraph("Security / Cost Basis & Calculation Logic", table_header)],
        [Paragraph("Incurred Incident Cost", table_text), Paragraph(f"${financials['incurred_cost']:,.2f}", table_text), Paragraph("Direct investigation and triage overhead ($5,000 per violation/isolation)", table_text)],
        [Paragraph("Projected Downtime Liability", table_text), Paragraph(f"${financials['expected_loss']:,.2f}", table_text), Paragraph("Estimated loss calculated dynamically from system Threat Index", table_text)],
        [Paragraph("Net Loss (Incurred + Projected)", table_text), Paragraph(f"${(financials['incurred_cost'] + financials['expected_loss']):,.2f}", table_text), Paragraph("Total combined active financial liability exposure", table_text)],
        [Paragraph("Total Prevented Losses (Savings)", table_text), Paragraph(f"${financials['prevented_cost']:,.2f}", table_text), Paragraph("Capital savings achieved by blocking physical centrifugal casing ruptures ($400,000 each)", table_text)]
    ]
    t_fin = Table(fin_data, colWidths=[140, 110, 290])
    t_fin.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_NAVY),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT_GREY]),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_GREY),
    ]))
    story.append(t_fin)
    story.append(Spacer(1, 8))

    # --- 2. Cyber Threat Vector & Security Incident Breakdown ---
    story.append(Paragraph("2. Cyber Threat Vector & Incident Breakdown", h2_style))
    story.append(Paragraph(
        "Categorized record of all cyber security attack vectors identified, blocked, or isolated during system operation:",
        body_style
    ))

    attack_headers = [
        Paragraph("Attack Vector / Type", table_header),
        Paragraph("Timestamp (UTC)", table_header),
        Paragraph("Severity", table_header),
        Paragraph("Enforcer Action", table_header),
        Paragraph("Target Subsystem & Security Impact", table_header)
    ]
    attack_rows = [attack_headers]

    audit_violations = db_session.query(AuditLog).filter(
        (AuditLog.action.like("%VIOLATION%")) | (AuditLog.action.like("%ISOLATION%"))
    ).order_by(AuditLog.timestamp.desc()).limit(20).all()

    if not audit_violations:
        attack_rows.append([
            Paragraph("No Cyber Attacks Detected", table_text),
            Paragraph(datetime.now(timezone.utc).strftime('%H:%M:%S'), table_text),
            Paragraph("LOW", table_text),
            Paragraph("NORMAL", table_text),
            Paragraph("No security violations or isolation events recorded in audit history.", table_text)
        ])
    else:
        for a in reversed(audit_violations):
            if hasattr(a.timestamp, "strftime"):
                ts_str = a.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            elif isinstance(a.timestamp, (int, float)):
                ts_str = datetime.fromtimestamp(a.timestamp, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
            else:
                ts_str = str(a.timestamp or '')

            vec_name = "Security Violation"
            sev_text = "HIGH"
            sev_color = DARK_RED
            if "STUXNET" in a.action or "Stuxnet" in (a.details or ""):
                vec_name = "Stuxnet Coordinated Hazard"
                sev_text = "CRITICAL"
            elif "ISOLATION" in a.action or "HMAC" in (a.details or ""):
                vec_name = "Telemetry Injection / Spoofing"
                sev_text = "HIGH"
            elif "PRIVILEGE" in a.action or "thresholds" in (a.details or ""):
                vec_name = "Privilege Escalation Attempt"
                sev_text = "MEDIUM"
                sev_color = AMBER_GOLD

            sev_style = ParagraphStyle('SevStyle', parent=table_text, textColor=sev_color, fontName="Helvetica-Bold")
            act_style = ParagraphStyle('ActStyle', parent=table_text, textColor=FOREST_GREEN, fontName="Helvetica-Bold")

            attack_rows.append([
                Paragraph(vec_name, table_text),
                Paragraph(ts_str, table_text),
                Paragraph(sev_text, sev_style),
                Paragraph("BLOCKED / ISOLATED", act_style),
                Paragraph(a.details or "", table_text)
            ])

    t_attack = Table(attack_rows, colWidths=[120, 85, 55, 95, 185])
    t_attack.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), SECONDARY_SLATE),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT_GREY]),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_GREY),
    ]))
    story.append(t_attack)
    story.append(Spacer(1, 8))

    # --- 3. Telemetry Dynamics & Sensor Plot ---
    story.append(Paragraph("3. Sensor Telemetry & Physical Dynamics Plot", h2_style))
    telemetry = db_session.query(TelemetryLog).order_by(TelemetryLog.timestamp.desc()).limit(35).all()

    if telemetry:
        chrono_telemetry = list(reversed(telemetry))
        valid_telemetry = [t for t in chrono_telemetry if t.temperature is not None and t.pressure is not None]
        if valid_telemetry:
            drawing = Drawing(540, 130)
            drawing.add(Rect(0, 0, 540, 130, fillColor=BG_LIGHT_GREY, strokeColor=BORDER_GREY, strokeWidth=0.5))

            temp_pts = []
            pres_pts = []
            for idx, t in enumerate(valid_telemetry):
                x = 50 + (idx / max(1, len(valid_telemetry) - 1)) * 440
                y_temp = 20 + (min(80.0, max(0.0, float(t.temperature))) / 80.0) * 90
                y_pres = 20 + (min(10.0, max(0.0, float(t.pressure))) / 10.0) * 90
                temp_pts.append((x, y_temp))
                pres_pts.append((x, y_pres))

            for y_val in [20, 42.5, 65, 87.5, 110]:
                drawing.add(Line(50, y_val, 490, y_val, strokeColor=colors.HexColor('#E5E7EB'), strokeWidth=0.5))

            for i in range(len(temp_pts) - 1):
                p1 = temp_pts[i]
                p2 = temp_pts[i + 1]
                drawing.add(Line(p1[0], p1[1], p2[0], p2[1], strokeColor=PRIMARY_NAVY, strokeWidth=1.5))

            for i in range(len(pres_pts) - 1):
                p1 = pres_pts[i]
                p2 = pres_pts[i + 1]
                drawing.add(Line(p1[0], p1[1], p2[0], p2[1], strokeColor=CRIMSON_ACCENT, strokeWidth=1, strokeDashArray=[3, 3]))

            drawing.add(String(10, 110, "Temp (°C)", fontName="Helvetica-Bold", fontSize=7, fillColor=PRIMARY_NAVY))
            drawing.add(String(498, 110, "Pres (bar)", fontName="Helvetica-Bold", fontSize=7, fillColor=CRIMSON_ACCENT))
            drawing.add(String(10, 65, "40°C / 5bar", fontName="Helvetica", fontSize=6, fillColor=TEXT_MUTED))
            drawing.add(String(10, 20, "0°C / 0bar", fontName="Helvetica", fontSize=6, fillColor=TEXT_MUTED))

            story.append(drawing)
    else:
        story.append(Paragraph("No telemetry readings available for charting.", body_style))
    story.append(Spacer(1, 8))

    # --- 4. Chronological System & Audit Log Narrative ---
    story.append(Paragraph("4. Chronological Audit Trail & System Event Log", h2_style))

    audit_logs = db_session.query(AuditLog).options(joinedload(AuditLog.user)).order_by(AuditLog.timestamp.desc()).limit(40).all()

    audit_headers = [
        Paragraph("Timestamp (UTC)", table_header),
        Paragraph("User", table_header),
        Paragraph("Action", table_header),
        Paragraph("Location Coords", table_header),
        Paragraph("Event Description & Details", table_header)
    ]
    audit_rows = [audit_headers]

    for a in reversed(audit_logs):
        u_name = a.user.username if a.user else "SYSTEM"
        action_text = a.action

        color_hex = "#111827"
        if "VIOLATION" in action_text or "ISOLATION" in action_text:
            color_hex = "#A91D22"
        elif "LOGIN" in action_text or "REJOIN" in action_text:
            color_hex = "#1E7E34"

        act_style = ParagraphStyle('ActStyle', parent=table_text, textColor=colors.HexColor(color_hex), fontName="Helvetica-Bold")

        if hasattr(a.timestamp, "strftime"):
            ts_str = a.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        elif isinstance(a.timestamp, (int, float)):
            ts_str = datetime.fromtimestamp(a.timestamp, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        else:
            ts_str = str(a.timestamp or '')

        audit_rows.append([
            Paragraph(ts_str, table_text),
            Paragraph(u_name, table_text),
            Paragraph(action_text, act_style),
            Paragraph(a.location, table_text),
            Paragraph(a.details or "", table_text)
        ])

    t_audit = Table(audit_rows, colWidths=[85, 55, 110, 85, 205])
    t_audit.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), PRIMARY_NAVY),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, BG_LIGHT_GREY]),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER_GREY),
    ]))
    story.append(t_audit)
    story.append(Spacer(1, 8))

    # --- 5. Harvard / Chicago Style Systematic Mitigation Protocols ---
    story.append(Paragraph("5. Systematic Technical Mitigation Protocols", h2_style))
    story.append(Paragraph(
        "Adhering to Chicago/Harvard security publication standards, the following technical countermeasures "
        "and mitigation protocols are mandated for deployment across all Aegis SCADA operational nodes:",
        body_style
    ))

    mitigations = [
        "<b>1. Stuxnet Coordinated Stress Mitigation (Cross-Correlation Policy)</b>: Maintain active cross-variable "
        "enforcer rules. The enforcer automatically rejects temperature setpoint dispatches exceeding 45.0°C whenever system "
        "pressure is equal to or greater than 6.0 bar, preventing physical centrifugal over-pressurization.",

        "<b>2. Telemetry Ingest & Replay Defense (HMAC-SHA256 Signatures)</b>: All field sensors (e.g. ESP32 PLCs) must "
        "sign telemetry payloads using HMAC-SHA256 with floating-point canonicalization. Telemetry failing signature verification "
        "must immediately trigger auto-isolation of the offending hardware device.",

        "<b>3. Access Control & Privilege Escalation Defenses</b>: Boundary rule modifications require Master Engineering "
        "clearance. Restrict administrative routes using sliding-window rate limiting (30 requests/min), HttpOnly session cookies, "
        "SameSite=Strict headers, and dynamic CSRF tokens.",

        "<b>4. Device Loop Isolation & Recovery Protocol</b>: Devices placed in MANUAL_ISOLATION or AUTO_ISOLATION state "
        "must pass hardware diagnostic loop tests before operators issue MANUAL_REJOIN commands to rejoin the operational loop."
    ]

    for m in mitigations:
        story.append(Paragraph(f"• {m}", body_style))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
