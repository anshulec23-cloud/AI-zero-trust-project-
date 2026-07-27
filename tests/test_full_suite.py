import sys
import os
import time
import json
import threading
import pytest
from concurrent.futures import ThreadPoolExecutor

# Add src to python path
src_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src")
sys.path.insert(0, src_dir)

from database import init_db, SessionLocal, User, AuditLog, TelemetryLog, Rule, DeviceState
from security import get_device_key
from safety_enforcer import validate_command
from analytics import calculate_financial_analytics
from reporting import generate_incident_report_pdf
from serial_gateway import parse_serial_line, sign_message, canonicalize_payload
from werkzeug.security import generate_password_hash

# Initialize DB for tests
init_db()

def get_test_db():
    return SessionLocal()

# --- 1. Database & User Unit Tests ---
def test_database_init_and_users():
    db = get_test_db()
    try:
        # Create test user if not exists
        existing = db.query(User).filter_by(username="test_operator").first()
        if existing:
            db.delete(existing)
            db.commit()

        user = User(username="test_operator", password_hash=generate_password_hash("securepass123"))
        db.add(user)
        db.commit()

        queried = db.query(User).filter_by(username="test_operator").first()
        assert queried is not None
        assert queried.id > 0
    finally:
        db.close()

# --- 2. Security & HMAC Signatures ---
def test_security_hmac_and_tokens():
    key = get_device_key("ESP32_001")
    assert key is not None and len(key) > 0

    payload = {
        "device_id": "ESP32_001",
        "timestamp": 1700000000.123,
        "temperature": 25.5,
        "pressure": 4.2
    }
    sig1 = sign_message(payload, key)
    sig2 = sign_message(payload, key)
    assert sig1 == sig2
    assert len(sig1) == 64  # SHA-256 hex digest length

    # Canonicalization check
    can = canonicalize_payload(payload)
    assert can["temperature"] == "25.50"
    assert can["pressure"] == "4.20"
    assert can["timestamp"] == "1700000000.123"

# --- 3. Safety Enforcer & Stuxnet Prevention Rules ---
def test_safety_enforcer_rules():
    db = get_test_db()
    try:
        # Reset rules for clean safety test
        db.query(Rule).delete()
        db.commit()

        # 1. Unknown command type
        ok, msg = validate_command({"type": "invalid_cmd", "value": 10}, db)
        assert not ok
        assert "Unknown command type" in msg

        # 2. Non-numeric value
        ok, msg = validate_command({"type": "set_temp", "value": "fifty"}, db)
        assert not ok
        assert "numeric" in msg

        # 3. Temperature boundary exceed (default max 60.0, min 0.0)
        ok, msg = validate_command({"type": "set_temp", "value": 65.0}, db)
        assert not ok
        assert "exceeds boundaries" in msg

        ok, msg = validate_command({"type": "set_temp", "value": -5.0}, db)
        assert not ok

        # 4. Valid set_temp within limits (when pressure is normal)
        # Seed a normal telemetry log
        db.query(TelemetryLog).delete()
        db.commit()

        normal_log = TelemetryLog(
            timestamp=time.time(),
            device_id="ESP32_001",
            temperature=25.0,
            pressure=3.0,
            humidity=50.0
        )
        db.add(normal_log)
        db.commit()

        ok, msg = validate_command({"type": "set_temp", "value": 40.0}, db)
        assert ok
        assert msg == "Approved"

        # 5. Stuxnet Coordinated Hazard: High Pressure + High Temp Setpoint
        high_pres_log = TelemetryLog(
            timestamp=time.time() + 1,
            device_id="ESP32_001",
            temperature=30.0,
            pressure=7.2,
            humidity=50.0
        )
        db.add(high_pres_log)
        db.commit()

        ok, msg = validate_command({"type": "set_temp", "value": 50.0}, db)
        assert not ok
        assert "Stuxnet Prevention" in msg

        # 6. Stuxnet Coordinated Hazard: High Temp + High Pressure Setpoint
        high_temp_log = TelemetryLog(
            timestamp=time.time() + 2,
            device_id="ESP32_001",
            temperature=52.0,
            pressure=2.0,
            humidity=50.0
        )
        db.add(high_temp_log)
        db.commit()

        ok, msg = validate_command({"type": "set_pressure", "value": 6.5}, db)
        assert not ok
        assert "Stuxnet Prevention" in msg
    finally:
        db.close()

# --- 4. Financial & Threat Index Analytics ---
def test_financial_analytics():
    db = get_test_db()
    try:
        # Test 1: Empty database
        db.query(TelemetryLog).delete()
        db.query(AuditLog).delete()
        db.commit()

        fin = calculate_financial_analytics(db)
        assert fin["violation_count"] == 0
        assert fin["incurred_cost"] == 0.0
        assert fin["prevented_cost"] == 0.0
        assert fin["threat_index"] == 0.0

        # Test 2: Insert 5 telemetry logs (< 15 logs)
        for i in range(5):
            t = TelemetryLog(
                timestamp=100.0 + i * 10,
                device_id="ESP32_001",
                temperature=20.0 + i,
                pressure=3.0 + i * 0.1
            )
            db.add(t)
        db.commit()

        fin_5 = calculate_financial_analytics(db)
        assert fin_5["threat_index"] >= 0.0
        assert "expected_loss" in fin_5

        # Test 3: Insert 20 logs to trigger correlation and drift calculations
        for i in range(5, 25):
            t = TelemetryLog(
                timestamp=100.0 + i * 10,
                device_id="ESP32_001",
                temperature=20.0 + i * 1.5,
                pressure=3.0 + i * 0.2
            )
            db.add(t)
        db.commit()

        fin_20 = calculate_financial_analytics(db)
        assert fin_20["threat_index"] > 0.0
        assert fin_20["drift_risk"] >= 0.0
    finally:
        db.close()

# --- 5. PDF Incident Report Generation ---
def test_pdf_report_generation():
    db = get_test_db()
    try:
        pdf_bytes = generate_incident_report_pdf(db, "test_operator", "X:10.0, Y:20.0, Z:30.0")
        assert pdf_bytes is not None
        assert len(pdf_bytes) > 500
        assert pdf_bytes.startswith(b"%PDF")
    finally:
        db.close()

# --- 6. Serial Gateway Parser Tests ---
def test_serial_gateway_parsing():
    # 1. JSON format
    json_line = '{"temp": 42.5, "pres": 5.1, "vib": 1.2, "hall": 1200, "curr": 3.4}\n'
    res = parse_serial_line(json_line, "plc")
    assert res is not None
    assert res["temperature"] == 42.5
    assert res["pressure"] == 5.1

    # 2. CSV format (5 parts)
    csv_line = "35.2, 4.1, 0.9, 1500, 2.8\n"
    res_csv = parse_serial_line(csv_line, "plc")
    assert res_csv is not None
    assert res_csv["temperature"] == 35.2
    assert res_csv["pressure"] == 4.1

    # 3. Key-Value format
    kv_line = "TEMP:48.2, P:6.5, VIB:1.1\n"
    res_kv = parse_serial_line(kv_line, "plc")
    assert res_kv is not None
    assert res_kv["temperature"] == 48.2
    assert res_kv["pressure"] == 6.5

    # 4. Invalid / empty string
    assert parse_serial_line("", "plc") is None
    assert parse_serial_line("  \n", "plc") is None

# --- 7. Flask REST API Integration & Attack Simulation Tests ---
def test_flask_api_routes():
    from app import app
    app.config["TESTING"] = True
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "admin"
        sess["location"] = "X:-12.40, Y:-48.10, Z:-3.50"
        sess["csrf_token"] = "valid_csrf_token"

    headers = {"X-CSRF-Token": "valid_csrf_token"}

    # 1. Get Data
    res = client.get("/api/data", headers=headers)
    assert res.status_code == 200
    data = res.get_json()
    assert "telemetry" in data
    assert "audit_logs" in data
    assert "financials" in data

    # 2. Rule updates
    res = client.post(
        "/api/rules/update",
        json={"temp_max": 65.0, "temp_min": 5.0, "pressure_max": 9.0, "pressure_min": 0.5, "csrf_token": "valid_csrf_token"},
        headers=headers
    )
    assert res.status_code == 200
    assert res.get_json()["success"] is True

    # 3. Attack Simulation: Stuxnet
    res = client.post("/api/simulate-attack", json={"type": "stuxnet", "csrf_token": "valid_csrf_token"}, headers=headers)
    assert res.status_code == 200
    assert res.get_json()["success"] is True

    # Verify data after Stuxnet simulation
    res_data = client.get("/api/data", headers=headers)
    assert res_data.get_json()["financials"]["violation_count"] > 0
    assert res_data.get_json()["financials"]["prevented_cost"] > 0.0

    # 4. Attack Simulation: Injection
    res = client.post("/api/simulate-attack", json={"type": "injection", "csrf_token": "valid_csrf_token"}, headers=headers)
    assert res.status_code == 200
    assert res.get_json()["success"] is True

    # 5. Attack Simulation: Privilege
    res = client.post("/api/simulate-attack", json={"type": "privilege", "csrf_token": "valid_csrf_token"}, headers=headers)
    assert res.status_code == 200
    assert res.get_json()["success"] is True

    # 6. Device Isolation & Rejoin
    res = client.post("/api/device/isolate", json={"csrf_token": "valid_csrf_token"}, headers=headers)
    assert res.status_code == 200
    assert res.get_json()["success"] is True

    res = client.post("/api/device/rejoin", json={"csrf_token": "valid_csrf_token"}, headers=headers)
    assert res.status_code == 200
    assert res.get_json()["success"] is True

    # 7. Report PDF Download
    res = client.get("/api/report/download", headers=headers)
    assert res.status_code == 200
    assert res.content_type == "application/pdf"
    assert len(res.data) > 1000

# --- 8. STRESS TEST & Concurrency ---
def test_stress_concurrent_telemetry_and_api():
    from app import app
    app.config["TESTING"] = True

    key = get_device_key("ESP32_001")
    client = app.test_client()

    success_count = [0]
    error_count = [0]
    lock = threading.Lock()

    def worker(worker_id):
        client = app.test_client()
        with client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = f"user_{worker_id}"
            sess["location"] = "X:0.0, Y:0.0, Z:0.0"
            sess["csrf_token"] = "stress_csrf"

        for i in range(25):
            # Ingest telemetry payload with HMAC signature
            payload = {
                "timestamp": time.time(),
                "device_id": "ESP32_001",
                "temperature": 25.0 + (i % 10),
                "pressure": 4.0 + (i % 3) * 0.5,
                "humidity": 50.0,
                "vibration": 1.0,
                "current": 4.5
            }
            payload["signature"] = sign_message(payload, key)

            try:
                res = client.post("/api/telemetry", json=payload)
                if res.status_code == 200:
                    with lock:
                        success_count[0] += 1
                else:
                    with lock:
                        error_count[0] += 1

                # Concurrent data query
                res_data = client.get("/api/data", headers={"X-CSRF-Token": "stress_csrf"})
                assert res_data.status_code in (200, 429)

            except Exception as exc:
                with lock:
                    error_count[0] += 1

    num_threads = 10
    threads = []
    for tid in range(num_threads):
        t = threading.Thread(target=worker, args=(tid,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print(f"\n[Stress Test Results] Total Ingest Requests: {success_count[0]}, Errors: {error_count[0]}")
    assert error_count[0] == 0, f"Stress test encountered {error_count[0]} errors!"
    assert success_count[0] == num_threads * 25

# --- 8b. STRESS TEST: 3 Simulation Attacks & PDF Report Downloads ---
def test_stress_all_3_simulation_attacks_and_pdf_download():
    from app import app
    app.config["TESTING"] = True

    sim_success = [0]
    sim_errors = [0]
    report_success = [0]
    report_errors = [0]
    lock = threading.Lock()

    attack_types = ["stuxnet", "injection", "privilege"]

    def sim_worker(worker_id):
        client = app.test_client()
        with client.session_transaction() as sess:
            sess["user_id"] = worker_id + 1
            sess["username"] = f"operator_stress_{worker_id}"
            sess["location"] = f"X:{worker_id}.0, Y:10.0, Z:5.0"
            sess["csrf_token"] = f"stress_token_{worker_id}"

        headers = {"X-CSRF-Token": f"stress_token_{worker_id}"}

        for cycle in range(5):
            for atype in attack_types:
                try:
                    res = client.post(
                        "/api/simulate-attack",
                        json={"type": atype, "csrf_token": f"stress_token_{worker_id}"},
                        headers=headers
                    )
                    if res.status_code == 200 and res.get_json().get("success") is True:
                        with lock:
                            sim_success[0] += 1
                    else:
                        with lock:
                            sim_errors[0] += 1
                except Exception:
                    with lock:
                        sim_errors[0] += 1

            # Download PDF Report after simulations
            try:
                rep_res = client.get("/api/report/download", headers=headers)
                if rep_res.status_code == 200 and rep_res.content_type == "application/pdf" and len(rep_res.data) > 1000:
                    with lock:
                        report_success[0] += 1
                else:
                    with lock:
                        report_errors[0] += 1
            except Exception:
                with lock:
                    report_errors[0] += 1

    num_sim_threads = 5
    threads = []
    for tid in range(num_sim_threads):
        t = threading.Thread(target=sim_worker, args=(tid,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print(f"\n[Attack & Report Stress Results] Successful Simulations: {sim_success[0]}, Errors: {sim_errors[0]}")
    print(f"[Attack & Report Stress Results] Successful Report Downloads: {report_success[0]}, Report Errors: {report_errors[0]}")

    assert sim_errors[0] == 0, f"Simulation attack stress test failed with {sim_errors[0]} errors!"
    assert report_errors[0] == 0, f"PDF Report download stress test failed with {report_errors[0]} errors!"
    assert sim_success[0] == num_sim_threads * 5 * 3
    assert report_success[0] == num_sim_threads * 5

# --- 9. Payload Fuzzing & Boundary Tests ---
def test_fuzzing_and_boundary_conditions():
    from app import app
    app.config["TESTING"] = True
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "fuzzer"
        sess["location"] = "X:0, Y:0, Z:0"
        sess["csrf_token"] = "fuzz_csrf"

    headers = {"X-CSRF-Token": "fuzz_csrf"}

    fuzz_payloads = [
        {},  # Empty payload
        {"type": ""},  # Empty string type
        {"type": "<script>alert(1)</script>", "value": "1' OR '1'='1"},  # XSS / SQLi attempt
        {"type": "set_temp", "value": 999999999999.99},  # Huge number
        {"type": "set_temp", "value": -999999999999.99},  # Large negative number
        {"type": "set_temp", "value": None},  # None value
        {"type": "set_temp", "value": [1, 2, 3]},  # List value
        {"type": "set_temp", "value": {"a": 1}},  # Dict value
    ]

    for p in fuzz_payloads:
        # Ensure no endpoint crashes with 500 error
        res_sp = client.post("/api/setpoint", json=p, headers=headers)
        assert res_sp.status_code in (200, 400, 403, 429), f"Fuzzing /api/setpoint with {p} returned {res_sp.status_code}"

        res_sim = client.post("/api/simulate-attack", json=p, headers=headers)
        assert res_sim.status_code in (200, 400, 403, 429), f"Fuzzing /api/simulate-attack with {p} returned {res_sim.status_code}"
