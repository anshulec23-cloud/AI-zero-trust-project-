# Aegis ICS

## Abstract
This project presents a zero-trust architecture for industrial control systems that combines device-side policy enforcement, MQTT isolation controls, and AI-driven trust scoring.

## Contributions
1. Micro-segmentation with isolation instead of shutdown.
2. Device-side command rejection before execution.

## Architecture
- Field layer: ESP32 telemetry simulator
- Communication layer: MQTT over TLS with ACL isolation
- Enforcement layer: policy checks and micro-segmentation
- Intelligence layer: trust scoring and anomaly detection
- Presentation layer: live dashboard and operator assistant
