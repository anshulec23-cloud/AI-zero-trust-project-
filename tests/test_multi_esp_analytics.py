import os
import sys
import json
import time
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from database import init_db, SessionLocal, TelemetryLog, AuditLog, User, DeviceState
from security import get_device_key
from werkzeug.security import generate_password_hash
from serial_gateway import parse_serial_line, mock_serial_stream, sign_message
from analytics import calculate_financial_analytics
from reporting import generate_incident_report_pdf
from app import app, verify_signature

@pytest.fixture(scope="module")
def test_db():
    init_db()
    db = SessionLocal()
    # Ensure test operator exists
    if not db.query(User).filter_by(username="operator").first():
        user = User(
            username="operator",
            password_hash=generate_password_hash("Operator@123")
        )
        db.add(user)
        db.commit()
    yield db
    db.close()

def test_multi_esp_serial_parsing():
    # 1. JSON parsing with node / slave_id
    j1 = '{"device_id": "ESP32_SLAVE_01", "temp": 34.2, "pres": 4.1, "vib": 1.5, "curr": 5.2}'
    res1 = parse_serial_line(j1, "plc")
    assert res1["device_id"] == "ESP32_001"
    assert res1["temperature"] == 34.2
    assert res1["current"] == 5.2

    j2 = '{"slave_id": 2, "temp": 38.0, "pres": 5.2, "vib": 0.9, "hall": 1000}'
    res2 = parse_serial_line(j2, "plc")
    assert res2["device_id"] == "ESP32_002"
    assert res2["temperature"] == 38.0
    assert res2["hall_effect"] == 1000.0

    # 2. CSV parsing with device prefix
    csv1 = "ESP32_SLAVE_01, 31.5, 3.8, 1.8, 1500, 6.2"
    res3 = parse_serial_line(csv1, "plc")
    assert res3["device_id"] == "ESP32_001"
    assert res3["temperature"] == 31.5
    assert res3["hall_effect"] == 1500.0

    # 3. Key-Value parsing
    kv1 = "DEVICE:SLAVE_3, TEMP:40.2, PRES:5.6, VIB:1.1, CURR:4.8"
    res4 = parse_serial_line(kv1, "plc")
    assert res4["device_id"] == "ESP32_003"
    assert res4["temperature"] == 40.2
    assert res4["pressure"] == 5.6

    # 4. Raw float stream
    raw1 = "28.5, 4.2, 0.05, 1200, 5.1"
    res5 = parse_serial_line(raw1, "plc")
    assert res5["device_id"] == "ESP32_001"
    assert res5["temperature"] == 28.5
    assert res5["pressure"] == 4.2
    assert res5["vibration"] == 0.05

def test_mock_stream_multi_node_cycling():
    from serial_gateway import _isolated_nodes
    _isolated_nodes.clear()
    nodes_seen = set()
    for _ in range(8):
        line = mock_serial_stream("plc")
        data = json.loads(line)
        nodes_seen.add(data["device_id"])
    assert "ESP32_001" in nodes_seen
    assert "ESP32_002" in nodes_seen
    assert "ESP32_003" in nodes_seen
    assert "ESP32_004" in nodes_seen

def test_hmac_signing_multi_devices():
    devices = ["ESP32_001", "ESP32_SLAVE_01", "ESP32_SLAVE_02", "ESP32_SLAVE_99"]
    for dev in devices:
        key = get_device_key(dev)
        assert key is not None and len(key) > 10
        payload = {
            "device_id": dev,
            "timestamp": time.time(),
            "temperature": 29.5,
            "pressure": 4.5,
            "vibration": 1.2
        }
        sig = sign_message(payload, key)
        payload["signature"] = sig
        assert verify_signature(payload) is True

def test_financial_analytics_edge_cases(test_db):
    # Test financial calculation with arbitrary telemetry
    fin = calculate_financial_analytics(test_db)
    assert "violation_count" in fin
    assert "incurred_cost" in fin
    assert "prevented_cost" in fin
    assert "threat_index" in fin
    assert "expected_loss" in fin
    assert fin["incurred_cost"] == fin["violation_count"] * 5000.0
    assert fin["prevented_cost"] == fin["violation_count"] * 400000.0
    assert 0.0 <= fin["threat_index"] <= 100.0
    assert fin["expected_loss"] >= 0.0

def test_multi_esp_api_data_partitioning(test_db):
    # Ingest telemetry for multiple devices
    t_now = time.time()
    for dev, temp, pres in [("ESP32_001", 25.0, 4.5), ("ESP32_SLAVE_01", 32.0, 3.8), ("ESP32_SLAVE_02", 39.0, 5.2)]:
        entry = TelemetryLog(
            device_id=dev,
            timestamp=t_now,
            temperature=temp,
            pressure=pres,
            vibration=1.0,
            hall_effect=1200.0,
            current=4.5,
            is_anomaly=False,
            is_simulated=False
        )
        test_db.add(entry)
    test_db.commit()

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "operator"
            sess["role"] = "operator"
            sess["location"] = "GRID-01"
            sess["token"] = "valid"
            sess["csrf_token"] = "valid_csrf"

        resp = client.get("/api/data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "devices" in data
        assert "device_series" in data
        assert "device_latest" in data
        assert "ESP32_001" in data["devices"]
        assert "ESP32_SLAVE_01" in data["devices"]
        assert "ESP32_SLAVE_02" in data["devices"]
        assert "device_states" in data
        assert "financials" in data
        assert data["financials"]["total_asset_var"] == 1200000.0

def test_multi_esp_pdf_report_generation(test_db):
    pdf_bytes = generate_incident_report_pdf(test_db, "operator", "GRID-01")
    assert pdf_bytes is not None
    assert len(pdf_bytes) > 5000
    assert pdf_bytes.startswith(b'%PDF')

def test_slave_auto_isolation_and_manual_rejoin(test_db):
    from app import process_telemetry

    # Retrieve or reset existing device state
    st = test_db.query(DeviceState).filter_by(device_id="ESP32_003").first()
    if not st:
        st = DeviceState(device_id="ESP32_003", is_isolated=False, trust_score=100.0)
        test_db.add(st)
    else:
        st.is_isolated = False
        st.trust_score = 100.0
    test_db.commit()

    # Send tampered payload (invalid signature) to trigger trust drop and auto-isolation
    tampered_payload = {
        "device_id": "ESP32_003",
        "timestamp": time.time(),
        "temperature": 85.0,
        "pressure": 9.5,
        "signature": "BAD_SIGNATURE_TAMPERED_12345"
    }
    process_telemetry(tampered_payload)

    # Check that ESP32_003 is now automatically isolated with 0% trust
    st_updated = test_db.query(DeviceState).filter_by(device_id="ESP32_003").first()
    assert st_updated.is_isolated is True
    assert st_updated.trust_score == 0.0

    # Test manual rejoin via API
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "admin"
            sess["role"] = "admin"
            sess["location"] = "CONTROL-CENTER"
            sess["token"] = "valid"
            sess["csrf_token"] = "valid_csrf"

        resp = client.post("/api/device/rejoin", json={"device_id": "ESP32_003"})
        assert resp.status_code == 200
        rejoin_data = resp.get_json()
        assert rejoin_data["success"] is True
        assert rejoin_data["is_isolated"] is False

    test_db.expire_all()
    st_rejoined = test_db.query(DeviceState).filter_by(device_id="ESP32_003").first()
    assert st_rejoined.is_isolated is False
    assert st_rejoined.trust_score == 100.0

def test_replay_attack_detection(test_db):
    from app import verify_signature

    # 1. Fresh packet
    fresh_ts = time.time()
    packet_1 = {
        "device_id": "ESP32_001",
        "timestamp": fresh_ts,
        "temperature": 25.0
    }
    assert verify_signature(packet_1) is True

    # 2. Stale timestamp (replay of 100s old packet)
    stale_packet = {
        "device_id": "ESP32_001",
        "timestamp": fresh_ts - 100.0,
        "temperature": 25.0
    }
    assert verify_signature(stale_packet) is False

def test_hardware_reset_endpoint(test_db):
    st = test_db.query(DeviceState).filter_by(device_id="ESP32_004").first()
    if not st:
        st = DeviceState(device_id="ESP32_004", is_isolated=True, trust_score=0.0)
        test_db.add(st)
    else:
        st.is_isolated = True
        st.trust_score = 0.0
    test_db.commit()

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "admin"
            sess["role"] = "admin"
            sess["location"] = "CONTROL-CENTER"
            sess["token"] = "valid"
            sess["csrf_token"] = "valid_csrf"

        resp = client.post("/api/device/reset", json={"device_id": "ESP32_004"})
        assert resp.status_code == 200
        res_data = resp.get_json()
        assert res_data["success"] is True
        assert res_data["is_isolated"] is False
        assert res_data["trust_score"] == 100.0

    test_db.expire_all()
    st_reset = test_db.query(DeviceState).filter_by(device_id="ESP32_004").first()
    assert st_reset.is_isolated is False
    assert st_reset.trust_score == 100.0

def test_ml_rules_fallback_safeguard(test_db):
    from app import LocalRFModel
    # Test model with non-existent path
    fallback_model = LocalRFModel(model_path="non_existent_path.pkl")
    assert fallback_model.is_fallback is True

    # Test physical boundary violation on fallback model
    anomaly_payload = {
        "temperature": 75.0, # Exceeds 60C
        "pressure": 3.5,
        "vibration": 1.0,
        "current": 5.0
    }
    assert fallback_model.predict_anomaly(anomaly_payload, db_session=test_db) is True

    # Test locked rotor cross-variable interlock
    locked_rotor_payload = {
        "temperature": 30.0,
        "pressure": 4.0,
        "vibration": 1.0,
        "hall_effect": 0.0,  # 0 RPM
        "current": 12.0      # High current
    }
    assert fallback_model.predict_anomaly(locked_rotor_payload, db_session=test_db) is True

def test_dynamic_topology_1_to_6_slaves(test_db):
    import serial_gateway
    from app import app

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "admin"
            sess["role"] = "admin"
            sess["location"] = "CONTROL-CENTER"
            sess["token"] = "valid"
            sess["csrf_token"] = "valid_csrf"

        # Test 1 Slave Configuration
        top1 = serial_gateway.configure_mock_topology(num_slaves=1)
        assert len(top1["slaves"]) == 1
        resp = client.get("/api/data")
        assert resp.status_code == 200
        d1 = resp.get_json()
        assert len(d1["devices"]) >= 1
        assert "active_channels" in d1

        # Test 6 Slaves Configuration
        top6 = serial_gateway.configure_mock_topology(num_slaves=6)
        assert len(top6["slaves"]) == 6
        resp6 = client.get("/api/data")
        assert resp6.status_code == 200
        d6 = resp6.get_json()
        assert len(d6["devices"]) >= 6

def test_partial_sensor_vectors_and_rule_evaluation(test_db):
    from app import LocalRFModel
    model = LocalRFModel()

    # Partial metric: Temperature only (normal)
    tel_temp_normal = {"temperature": 25.0}
    assert model.predict_anomaly(tel_temp_normal, db_session=test_db) is False

    # Partial metric: Temperature only (out of bounds > 60C)
    tel_temp_bad = {"temperature": 75.0}
    assert model.predict_anomaly(tel_temp_bad, db_session=test_db) is True

    # Partial metric: Current + Vibration only (normal)
    tel_partial_norm = {"current": 4.5, "vibration": 1.1}
    assert model.predict_anomaly(tel_partial_norm, db_session=test_db) is False

    # Partial metric: Current + Vibration only (vibration exceeding limit)
    tel_partial_bad = {"current": 4.5, "vibration": 5.5}
    assert model.predict_anomaly(tel_partial_bad, db_session=test_db) is True

def test_mock_scenario_injection_and_topology_api(test_db):
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "admin"
            sess["role"] = "admin"
            sess["location"] = "CONTROL-CENTER"
            sess["token"] = "valid"
            sess["csrf_token"] = "valid_csrf"

        # 1. Get mock topology
        resp = client.get("/api/mock/topology")
        assert resp.status_code == 200
        top = resp.get_json()
        assert "slaves" in top
        assert "topology" in top

        # 2. Configure 3 mock slaves via API
        resp2 = client.post("/api/mock/configure", json={"num_slaves": 3})
        assert resp2.status_code == 200
        res2_data = resp2.get_json()
        assert res2_data["success"] is True
        assert len(res2_data["topology"]["slaves"]) == 3

        # 3. Inject scenario via API
        resp3 = client.post("/api/mock/configure", json={"scenario": "drift", "device_id": "ESP32_001"})
        assert resp3.status_code == 200
        assert resp3.get_json()["success"] is True

def test_radar_posture_and_contour_analytics(test_db):
    from analytics import calculate_financial_analytics
    fin = calculate_financial_analytics(test_db)

    assert "radar_posture" in fin
    radar = fin["radar_posture"]
    assert len(radar["labels"]) == 5
    assert len(radar["values"]) == 5
    assert all(0.0 <= v <= 100.0 for v in radar["values"])

    assert "contour_grid" in fin
    contour = fin["contour_grid"]
    assert "density_matrix" in contour
    assert len(contour["density_matrix"]) == 6


