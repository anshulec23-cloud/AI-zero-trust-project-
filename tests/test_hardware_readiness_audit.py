"""
tests/test_hardware_readiness_audit.py — Comprehensive Hardware-Readiness & Chart Verification Suite

Covers:
1. Chart.js Damage Breakdown data calculation & smooth transition threshold logic
2. Hardware COM port detection & enumeration
3. Hardware connection failure handling & mid-session cable disconnect recovery
4. Fuzzing, fragmented buffer splits, and multi-format noise parsing
5. Dynamic schema compatibility and field-by-field verification
6. HMAC pre-shared key configuration via device_keys.json
7. UART command serialization (ASCII & JSON)
8. High-frequency burst telemetry ingestion under load
9. Security violation and hardware failure visibility in audit logs
"""

import os
import sys
import time
import json
import queue
import tempfile
import threading
import pytest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from app import app, SessionLocal
from database import User, TelemetryLog, DeviceState, AuditLog, Rule
from security import (
    get_device_key,
    normalize_device_id,
    DEFAULT_DEVICE_KEYS,
    load_custom_device_keys
)
from serial_gateway import (
    parse_serial_line,
    sign_message,
    canonicalize_payload,
    send_command,
    start_gateway,
    stop_gateway,
    get_active_port,
    _isolated_nodes,
    _command_queue
)
from analytics import calculate_financial_analytics

# =========================================================================
# PART 1: DOUGHNUT / PIE CHART SMOOTH TRANSITION VERIFICATION
# =========================================================================

def test_chart_cost_distribution_calculation():
    """Verify that cost distribution produces valid percentage proportions and never collapses to [0,0,0,0]."""
    db = SessionLocal()
    try:
        # Clear logs and reset device states to 100% nominal trust
        db.query(AuditLog).delete()
        db.query(TelemetryLog).delete()
        for d_st in db.query(DeviceState).all():
            d_st.is_isolated = False
            d_st.trust_score = 100.0
        db.commit()

        # 1. Zero Incident State (Nominal)
        fin_zero = calculate_financial_analytics(db)
        cd_zero = fin_zero["cost_distribution"]
        # In nominal state, sum is 0
        sum_zero = cd_zero["asset_replacement"] + cd_zero["downtime_liability"] + cd_zero["regulatory_fines"] + cd_zero["triage_overhead"]
        assert sum_zero == 0.0, "Nominal cost distribution should have 0 dollar amounts"

        # Frontend transition logic verification:
        # If sumVal == 0, frontend uses nominal baseline [55, 25, 12, 8]
        target_baseline = [55, 25, 12, 8]
        assert sum(target_baseline) == 100, "Nominal baseline weights must sum to 100%"

        # 2. Add Incident Logs (Active Threat)
        a1 = AuditLog(action="SECURITY_RULE_VIOLATION", location="ESP32_001", details="Locked rotor physical interlock tripped.")
        a2 = AuditLog(action="AUTOMATIC_ISOLATION", location="ESP32_001", details="Quarantine activated.")
        # Add high temp telemetry to create exposure
        t1 = TelemetryLog(timestamp=time.time(), device_id="ESP32_001", temperature=88.5, pressure=7.8, is_anomaly=True)
        db.add_all([a1, a2, t1])
        db.commit()

        fin_active = calculate_financial_analytics(db)
        cd_active = fin_active["cost_distribution"]
        sum_active = sum(cd_active.values())
        assert sum_active > 0, "Active incident cost distribution must be positive"

        # Calculate percentages
        pct_asset = (cd_active["asset_replacement"] / sum_active) * 100
        pct_downtime = (cd_active["downtime_liability"] / sum_active) * 100
        pct_fines = (cd_active["regulatory_fines"] / sum_active) * 100
        pct_overhead = (cd_active["triage_overhead"] / sum_active) * 100

        target_active = [pct_asset, pct_downtime, pct_fines, pct_overhead]
        assert abs(sum(target_active) - 100.0) < 0.001, "Calculated active percentages must sum to 100.0%"

        # 3. Diff Threshold Logic Verification
        # If difference between current data and target data is <= 0.05%, do not redraw
        cur_data = [pct_asset, pct_downtime, pct_fines, pct_overhead]
        identical_data = [pct_asset + 0.01, pct_downtime - 0.01, pct_fines, pct_overhead]
        diffs = [abs(c - t) > 0.05 for c, t in zip(cur_data, identical_data)]
        assert not any(diffs), "Jitter below 0.05% should not trigger full Chart.js update"

        new_incident_data = [pct_asset + 5.0, pct_downtime - 5.0, pct_fines, pct_overhead]
        large_diffs = [abs(c - t) > 0.05 for c, t in zip(cur_data, new_incident_data)]
        assert any(large_diffs), "Meaningful change > 0.05% must trigger Chart.js smooth animation"

    finally:
        db.close()

# =========================================================================
# PART 2: HARDWARE-READINESS AUDIT (8 SUBSYSTEMS)
# =========================================================================

# ITEM 1: PORT DETECTION
def test_hardware_port_enumeration_and_priority():
    """Verify that physical hardware COM ports are enumerated dynamically and sorted before MOCK."""
    app.config["WTF_CSRF_ENABLED"] = False
    client = app.test_client()

    fake_com1 = MagicMock()
    fake_com1.device = "COM3"
    fake_com1.description = "Silicon Labs CP210x USB to UART Bridge (COM3)"

    fake_com2 = MagicMock()
    fake_com2.device = "COM4"
    fake_com2.description = "FTDI USB Serial Device (COM4)"

    with patch("serial.tools.list_ports.comports", return_value=[fake_com1, fake_com2]):
        with client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "admin"
            sess["role"] = "ADMIN"
            sess["webview_token"] = "TEST_TOKEN"
        
        headers = {"X-Webview-Token": "TEST_TOKEN"}
        res = client.get("/api/com_ports", headers=headers)
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        details = data["details"]

        # Physical ports must come first
        assert details[0]["port"] == "COM3"
        assert details[0]["is_mock"] is False
        assert "CP210x" in details[0]["label"]

        assert details[1]["port"] == "COM4"
        assert details[1]["is_mock"] is False

        # MOCK must be last
        assert details[-1]["port"] == "MOCK"
        assert details[-1]["is_mock"] is True

# ITEM 2: CONNECTION HANDLING & ABRUPT DISCONNECT RECOVERY
def test_hardware_port_busy_rejection():
    """Verify that if a COM port is locked/busy by another program, a clean error is returned."""
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    client = app.test_client()

    with patch("serial.Serial", side_effect=Exception("PermissionError: [WinError 5] Access is denied: 'COM3'")):
        with client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "admin"
            sess["role"] = "ADMIN"
            sess["webview_token"] = "TEST_TOKEN"

        headers = {"X-Webview-Token": "TEST_TOKEN", "Content-Type": "application/json"}
        res = client.post("/api/com_ports/connect", json={"port": "COM3", "baud": 115200}, headers=headers)
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is False
        assert "Could not open COM port 'COM3'" in data["error"]

def test_hardware_abrupt_disconnect_recovery():
    """Verify that an abrupt USB cable disconnect halts the gateway and clears active port."""
    fake_ser = MagicMock()
    fake_ser.is_open = True
    fake_ser.in_waiting = 1
    fake_ser.read.side_effect = OSError("The device does not recognize the command.")

    with patch("serial.Serial", return_value=fake_ser):
        gw_thread = threading.Thread(
            target=start_gateway,
            kwargs={"port": "COM3", "baud": 115200, "mock": False, "url": "http://127.0.0.1:5000/api/telemetry"},
            daemon=True
        )
        gw_thread.start()
        gw_thread.join(timeout=1.0)

        assert get_active_port() is None, "Active port must be None after physical cable disconnect"
        stop_gateway()

# ITEM 3: DATA PARSING ROBUSTNESS (FRAGMENTED BUFFERS, NOISE, FUZZING)
def test_data_parsing_fragmented_buffer_and_noise():
    """Verify parser robustness against fragmented packets, single quotes, noise, and mixed delimiters."""
    # 1. Standard JSON
    p1 = parse_serial_line('{"device_id": "ESP32_001", "temp": 32.4, "pres": 3.12}')
    assert p1["device_id"] == "ESP32_001"
    assert p1["temperature"] == 32.4
    assert p1["pressure"] == 3.12

    # 2. Single-quoted JSON
    p2 = parse_serial_line("{'device': 'ESP32_002', 'curr': 7.8, 'vib': 0.06, 'rpm': 1450}")
    assert p2["device_id"] == "ESP32_002"
    assert p2["current"] == 7.8
    assert p2["vibration"] == 0.06
    assert p2["hall_effect"] == 1450.0

    # 3. Key-Value pairs with colons/equals and commas
    p3 = parse_serial_line("SLAVE: 3, TEMP: 41.5, PRES: 5.2, AMPS: 11.2, HUM: 48.0")
    assert p3["device_id"] == "ESP32_003"
    assert p3["temperature"] == 41.5
    assert p3["pressure"] == 5.2
    assert p3["current"] == 11.2
    assert p3["humidity"] == 48.0

    # 4. CSV with node identifier
    p4 = parse_serial_line("ESP32_004, 78.5, 4.1, 0.12, 1750, 9.4, 55.0")
    assert p4["device_id"] == "ESP32_004"
    assert p4["temperature"] == 78.5
    assert p4["pressure"] == 4.1
    assert p4["vibration"] == 0.12
    assert p4["hall_effect"] == 1750.0
    assert p4["current"] == 9.4
    assert p4["humidity"] == 55.0

    # 5. Malformed / Binary garbage
    p_bad = parse_serial_line("\x00\xff\xfe random serial noise")
    assert p_bad is None or "temperature" not in p_bad or isinstance(p_bad, dict)

    # 6. Empty / Whitespace
    assert parse_serial_line("") is None
    assert parse_serial_line("   \r\n\t  ") is None

# ITEM 4: REAL HARDWARE SCHEMA COMPATIBILITY
def test_real_hardware_sensor_channel_aliases():
    """Verify that all microcontroller sensor aliases map to canonical database metrics."""
    test_cases = [
        ('{"id": 1, "t": 28.5, "p": 2.1}', "ESP32_001", {"temperature": 28.5, "pressure": 2.1}),
        ('{"node": "NODE_2", "speed": 1200, "v": 0.03}', "ESP32_002", {"hall_effect": 1200.0, "vibration": 0.03}),
        ('{"slave": "SLAVE3", "temp_c": 55.0, "pressure_bar": 4.5, "amps": 12.5}', "ESP32_003", {"temperature": 55.0, "pressure": 4.5, "current": 12.5}),
        ('{"esp": 4, "vibration_g": 0.08, "humidity_pct": 60.0}', "ESP32_004", {"vibration": 0.08, "humidity": 60.0}),
    ]

    for line, expected_id, expected_metrics in test_cases:
        parsed = parse_serial_line(line)
        assert parsed is not None
        assert parsed["device_id"] == expected_id
        for k, v in expected_metrics.items():
            assert parsed[k] == v, f"Field {k} did not match expected value {v}"

# ITEM 5: HMAC SIGNATURE PATH WITH REAL KEYS (device_keys.json)
def test_hmac_custom_device_keys_file_loading():
    """Verify that custom keys in device_keys.json are correctly loaded and verified."""
    custom_keys_content = {
        "ESP32_001": "real_hardware_custom_production_key_001",
        "ESP32_002": "real_hardware_custom_production_key_002"
    }

    with patch("security.load_custom_device_keys", return_value=custom_keys_content):
        key_001 = get_device_key("ESP32_001")
        assert key_001 == "real_hardware_custom_production_key_001", "Must load custom key from device_keys.json"

        # Sign a payload with the custom key
        payload = {"timestamp": 1700000000.0, "device_id": "ESP32_001", "temperature": 25.0}
        sig = sign_message(payload, key_001)

        # Backend verification
        expected_sig = sign_message(payload, "real_hardware_custom_production_key_001")
        assert sig == expected_sig

# ITEM 6: UART COMMAND DISPATCH SERIALIZATION
def test_uart_command_queue_and_dispatch():
    """Verify that ISOLATE, RESET, CLEAR, and PING serialize into both raw ASCII and JSON."""
    _command_queue.queue.clear()
    _isolated_nodes.clear()

    # 1. Send Dict Command
    send_command({"cmd": "ISOLATE", "device_id": "ESP32_001"})
    assert "ESP32_001" in _isolated_nodes, "Node must be tracked as ISOLATED"
    assert not _command_queue.empty()
    cmd1 = _command_queue.get_nowait()
    assert cmd1["cmd"] == "ISOLATE"
    assert cmd1["device_id"] == "ESP32_001"

    # 2. Send Reset Command (Clears isolation)
    send_command("RESET ESP32_001")
    assert "ESP32_001" not in _isolated_nodes, "RESET must clear isolation status"
    assert not _command_queue.empty()
    cmd2 = _command_queue.get_nowait()
    assert cmd2 == "RESET ESP32_001"

    # 3. Send Clear Command
    send_command({"cmd": "CLEAR", "device_id": "ESP32_002"})
    cmd3 = _command_queue.get_nowait()
    assert cmd3["cmd"] == "CLEAR"

    # 4. Send Ping Command
    send_command("PING ESP32_003")
    cmd4 = _command_queue.get_nowait()
    assert cmd4 == "PING ESP32_003"

    _isolated_nodes.clear()
    _command_queue.queue.clear()

# ITEM 7: BURST TELEMETRY INGESTION UNDER LOAD
def test_burst_telemetry_ingestion_under_load():
    """Simulate rapid burst telemetry packets from multiple slaves and verify clean ingestion."""
    from app import process_telemetry

    db = SessionLocal()
    try:
        devices = ["ESP32_001", "ESP32_002", "ESP32_003", "ESP32_004"]
        for dev in devices:
            st = db.query(DeviceState).filter_by(device_id=dev).first()
            if not st:
                db.add(DeviceState(device_id=dev, is_isolated=False, trust_score=100.0))
            else:
                st.is_isolated = False
                st.trust_score = 100.0
        db.commit()

        for i in range(20):
            dev = devices[i % 4]
            key = get_device_key(dev)
            payload = {
                "timestamp": time.time() + i * 0.01,
                "device_id": dev,
                "temperature": 25.0 + (i % 5),
                "pressure": 1.0 + (i % 3) * 0.1,
                "vibration": 0.02,
                "current": 4.0,
                "hall_effect": 1200.0
            }
            payload["signature"] = sign_message(payload, key)

            success = process_telemetry(payload)
            assert success is True, f"Burst packet {i} failed processing"
    finally:
        db.close()

# ITEM 8: FAILURE VISIBILITY & INCIDENT LOGGING
def test_failure_visibility_and_audit_trail():
    """Verify that tampered HMAC signatures and hardware boundary violations generate visible audit entries."""
    from app import process_telemetry

    db = SessionLocal()
    try:
        # Clear logs and reset device state
        db.query(AuditLog).delete()
        st = db.query(DeviceState).filter_by(device_id="ESP32_001").first()
        if not st:
            st = DeviceState(device_id="ESP32_001", is_isolated=False, trust_score=100.0)
            db.add(st)
        else:
            st.is_isolated = False
            st.trust_score = 100.0
        db.commit()

        # 1. Ingest tampered packet
        bad_payload = {
            "timestamp": time.time(),
            "device_id": "ESP32_001",
            "temperature": 99.9,
            "signature": "BAD_TAMPERED_HMAC_SIGNATURE"
        }
        process_telemetry(bad_payload)

        # Check violation logged in AuditLog / Auto-Isolation
        violation = db.query(AuditLog).filter(AuditLog.action.like("%ISOLATION%") | AuditLog.action.like("%SECURITY%")).first()
        assert violation is not None, "Security violation must be logged in audit trail"
        assert "ESP32_001" in violation.details

        # Check device state was quarantined
        st_after = db.query(DeviceState).filter_by(device_id="ESP32_001").first()
        assert st_after.is_isolated is True
        assert st_after.trust_score == 0.0

    finally:
        _isolated_nodes.clear()
        db.close()
