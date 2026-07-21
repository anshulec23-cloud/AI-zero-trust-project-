# Quickstart

## 1. Set up env
1. Copy `.env.example` to `.env`.
2. Fill in `FLASK_SECRET_KEY`.
3. Set `DEVICE_KEY_ESP32_001` and `DEVICE_KEY_ESP32_002`.
4. If you want to protect admin routes, set `API_ADMIN_TOKEN`.

## 2. Generate certs
Run this from the repo root:

```bash
python certs/generate_certs.py --out-dir certs --device-id ESP32_001 --device-id ESP32_002
```

## 3. Start MQTT broker
Use the Mosquitto config in `server/mqtt_broker/`.

```bash
mosquitto -c server/mqtt_broker/mosquitto.conf
```

## 4. Start the API
From the repo root:

```bash
python -m server.api.app
```

## 5. Start the simulator
Run one device at a time:

```bash
python esp32_sim/simulator.py --config esp32_sim/device_config.json
```

## 6. Run tests

```bash
python -m unittest discover -s tests
```

## What To Expect
- MQTT telemetry from the simulator
- Trust scores in the API
- Device isolation when the score drops too low
