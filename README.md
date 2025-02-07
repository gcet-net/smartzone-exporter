# SmartZone Exporter

Ruckus SmartZone exporter for [prometheus](https://prometheus.io), written in Python.

## Background
This exporter was designed to provide a faster and more reliable alternative to SNMP for retrieving metrics from a Ruckus SmartZone controller.

## Features
Controller Metrics
* General Information: Model, serial number, hostname, software version, AP firmware version.
* Uptime: Total uptime of the controller in seconds.

Zone Metrics
* AP Counts: Total APs, discovered APs, connected APs, disconnected APs, and rebooting APs per zone.
* Client Statistics: Total number of connected clients per zone.

Access Point (AP) Metrics
* Status: AP status (Online, Offline, Flagged) and the number of active alerts per AP.
* Alerts: Number of active alerts per AP
* Latency: AP latency for 2.4GHz and 5GHz bands (in milliseconds).
* Client Distribution: Number of clients connected to 2.4GHz and 5GHz bands per AP.


## Usage
```shell
usage: smartzone_exporter.py [-h] -u USER -p PASSWORD -t TARGET [--insecure] [--port PORT]

Ruckus SmartZone exporter for Prometheus

options:
  -h, --help            show this help message and exit
  --insecure            Allow insecure SSL connections to SmartZone
  --port PORT           Port on which to expose metrics and web interface (default: 9345)

required named arguments:
  -u USER, --user USER  SmartZone API user
  -p PASSWORD, --password PASSWORD
                        SmartZone API password
  -t TARGET, --target TARGET
                        Target URL and port to access SmartZone (e.g. https://smartzone.example.com:8443)
```

### Example
```shell
python smartzone_exporter.py -u jimmy -p jangles -t https://ruckus.jjangles.com:8443
```

## Requirements
This exporter works with following SmartZone versions:

| Model | Release | API Versions  |
|-------|---------| ------------- |
| vSZ-H | `3.5`   | `v5_0`        |


## Installation
Although not required, it is recommended to run this exporter in a Python virtual environment for better dependency management.

```shell
git clone https://github.com/gcet-net/smartzone-exporter.git
cd smartzone-exporter

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate

# Install the exporter
pip install .
```

## Additional Resources
* [vSCG 3.5 Carrier Public API Reference](https://docs.ruckuswireless.com/vscg-carrier/vsz-h-public-api-reference-guide-3-5.html)