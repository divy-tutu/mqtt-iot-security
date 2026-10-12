FROM python:3.12-slim
# paho-mqtt: MQTT client (undefended + hardened devices).
# jsonschema: payload schema validation for the hardened devices (Phase 2).
RUN pip install --no-cache-dir "paho-mqtt<2.0" "jsonschema>=4,<5"
WORKDIR /app
COPY . /app
