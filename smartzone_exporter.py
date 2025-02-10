import argparse
import logging
import time

import requests
from prometheus_client import Summary, start_http_server
from prometheus_client.core import REGISTRY, CounterMetricFamily, GaugeMetricFamily
from requests.packages.urllib3.exceptions import InsecureRequestWarning

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SmartZoneCollector:

    def __init__(self, target, user, password, insecure):
        self.vsz_api_url = target.rstrip("/") + "/"  # ensure trailing slash for URL construction
        self.vsz_api_user = user
        self.vsz_api_password = password
        self.vsz_api_ver = "v5_0"                    # API version maybe this should be passed as an arg?
        self.vsz_api_session = requests.Session()
        self.vsz_api_session_timeout = 4             # API session timeout in seconds

        # If SSL verification is disabled, set verify to False and disable warnings.
        if not insecure:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            self.vsz_api_session.verify = False
            logger.warning(f"Connection to {self.vsz_api_url} may not be secure.")

        else:
            self.vsz_api_session.verify = True

        # Initialize the session.
        self.ensure_authenticated()

    def ensure_authenticated(self):
        """
        Checks if the session is still authenticated. If not, re-logins.
        """
        try:
            # Check if session cookie is still valid
            resp = self.vsz_api_session.get(
                f'{self.vsz_api_url}wsg/api/public/{self.vsz_api_ver}/session',
                timeout=self.vsz_api_session_timeout
            )

            if not resp.ok:
                # If not valid, log in
                credentials = {
                    'username': self.vsz_api_user,
                    'password': self.vsz_api_password
                }
                login_resp = self.vsz_api_session.post(
                    f'{self.vsz_api_url}wsg/api/public/{self.vsz_api_ver}/session',
                    json=credentials,
                    timeout=self.vsz_api_session_timeout
                )
                login_resp.raise_for_status()
                # Update session headers (this header will be sent on all subsequent requests)
                self.vsz_api_session.headers.update({
                    'Content-Type': 'application/json;charset=UTF-8'
                })
        except requests.exceptions.RequestException as err:
            logger.error(f"Failed to initialize SmartZone session: {err}")

    def get_controller(self):
        """
        Retrieve controller data from the SmartZone API.

        Returns:
            list: A list of system records, or an empty list if none are found.
        """
        self.ensure_authenticated()
        try:
            api_url = f"{self.vsz_api_url}wsg/api/public/{self.vsz_api_ver}/controller"
            r = self.vsz_api_session.get(api_url, timeout=self.vsz_api_session_timeout)
            r.raise_for_status()
            data = r.json()
            # If the response is a dict and contains a 'list' key, return that.
            if isinstance(data, dict):
                return data.get('list', [])
            # If the response is already a list, return it.
            elif isinstance(data, list):
                return data
            else:
                return []
        except requests.exceptions.RequestException as err:
            logger.error(f"Retrieving controller data: {err}")
            return []

    def get_zones(self):
        """
        Retrieve AP Zone data via SmartZone API.

        Returns:
            list: A list of zone records, or an empty list if none are found.
        """
        try:
            api_url = f"{self.vsz_api_url}wsg/api/public/{self.vsz_api_ver}/system/inventory"
            r = self.vsz_api_session.get(api_url, timeout=self.vsz_api_session_timeout)
            r.raise_for_status()
            data = r.json()
            # If the response is a dict and contains a 'list' key, return that.
            if isinstance(data, dict):
                return data.get('list', [])
            # If the response is already a list, return it.
            elif isinstance(data, list):
                return data
            else:
                return []
        except requests.exceptions.RequestException as err:
            logger.error(f"Retrieving AP zone data: {err}")
            return []

    def get_aps(self):
        """
        Retrieve AP data via SmartZone API.

        Returns:
            list: A list of AP records, or an empty list if none are found or an error occurs.
        """
        try:
            # For APs, use POST and API query to reduce the number of requests and improve performance
            # To-do: set dynamic AP limit based on SmartZone inventory
            query_payload =  {'page': 0, 'start': 0, 'limit': 1000}
            api_url = f"{self.vsz_api_url}wsg/api/public/{self.vsz_api_ver}/query/ap"

            r = self.vsz_api_session.post(api_url, json=query_payload, timeout=self.vsz_api_session_timeout)
            r.raise_for_status()

            data = r.json()
            # If the response is a dict and contains a 'list' key, return that.
            if isinstance(data, dict):
                return data.get('list', [])
            # If the response is already a list, return it.
            elif isinstance(data, list):
                return data
            else:
                return []
        except requests.exceptions.RequestException as err:
            logger.error(f"Retrieving AP data: {err}")
            return []

    def collect(self):
        """
        Collect metrics from SmartZone controller

        This method fetches data from the SmartZone API and processes it to generate
        Prometheus metric families for the following categories:

        1. Controller Metrics:
            - Retrieves controller information (e.g., model, serial number, uptime,
              hostname, version, and AP firmware version).
        2. AP Zones Metrics:
            - Retrieves zone inventory, which includes metrics such as total APs,
              APs in discovery state, connected APs, disconnected APs, rebooting APs,
              and total connected clients.
        3. AP Metrics:
            - Retrieves AP-specific data such as alerts, latencies (for both 2.4G and 5G),
              connected client counts for each band, and AP status.
            - The AP status metric is broken out into sub-metrics for each state (Online,
              Offline, and Flagged).
        """
        # Controller Metrics
        controllers = self.get_controller()
        controller_metrics = {
            'model':
                GaugeMetricFamily('smartzone_controller_model',
                'SmartZone controller model',
                labels=["id", "model"]),
            'serialNumber':
                GaugeMetricFamily('smartzone_controller_serial_number',
                'SmartZone controller serial number',
                labels=["id", "serialNumber"]),
            'uptimeInSec':
                CounterMetricFamily('smartzone_controller_uptime_seconds',
                'Controller uptime in sections',
                labels=["id"]),
            'hostName':
                GaugeMetricFamily('smartzone_controller_hostname',
                'Controller hostname',
                labels=["id", "hostName"]),
            'version':
                GaugeMetricFamily('smartzone_controller_version',
                'Controller version',
                labels=["id", "version"]),
            'apVersion':
                GaugeMetricFamily('smartzone_controller_ap_firmware_version',
                'Firmware version on controller APs',
                labels=["id", "apVersion"])
        }

        for controller in controllers:
            controller_id = controller.get('id')
            # Iterate directly over the keys in controller_metrics
            for key in controller_metrics.keys():
                if key == 'uptimeInSec':
                    controller_metrics[key].add_metric([controller_id], controller.get(key, 0))
                else:
                    # For non-numeric or string-only metrics, export a dummy value (1) with the extra info
                    extra = controller.get(key, 'unknown')
                    controller_metrics[key].add_metric([controller_id, extra], 1)

        for m in controller_metrics.values():
            yield m

        # AP Zones Metrics
        zones = self.get_zones()
        zone_metrics_labels = ['zone_name', 'zone_id']
        zone_metrics = {
            'totalAPs':
                GaugeMetricFamily('smartzone_zone_total_aps',
                'Total number of APs in zone',
                labels=zone_metrics_labels),
            'discoveryAPs':
                GaugeMetricFamily('smartzone_zone_discovery_aps',
                'Number of zone APs in discovery state',
                labels=zone_metrics_labels),
            'connectedAPs':
                GaugeMetricFamily('smartzone_zone_connected_aps',
                'Number of connected zone APs',
                labels=zone_metrics_labels),
            'disconnectedAPs':
                GaugeMetricFamily('smartzone_zone_disconnected_aps',
                'Number of disconnected zone APs',
                labels=zone_metrics_labels),
            'rebootingAPs':
                GaugeMetricFamily('smartzone_zone_rebooting_aps',
                'Number of zone APs in rebooting state',
                labels=zone_metrics_labels),
            'clients':
                GaugeMetricFamily('smartzone_zone_total_connected_clients',
                'Total number of connected clients in zone',
                labels=zone_metrics_labels)
        }

        for zone in zones:
            # Get the zone name and zone ID for labeling purposes
            zone_name = zone.get('zoneName', 'unknown')
            zone_id = zone.get('zoneId', 'unknown')

            # Iterate over the keys defined in zone_metrics
            for key in zone_metrics.keys():
                # Use the zone data for the corresponding metric key
                zone_metrics[key].add_metric([zone_name, zone_id], zone.get(key, 0))

        for m in zone_metrics.values():
            yield m

        # AP Metrics
        aps = self.get_aps()
        ap_metrics_labels = ['zone', 'ap_group', 'mac', 'serial', 'name', 'latitude', 'longitude']
        ap_metrics = {
            'alerts':
                GaugeMetricFamily('smartzone_ap_alerts',
                'Number of AP alerts',
                labels=ap_metrics_labels),
            'latency24G':
                GaugeMetricFamily('smartzone_ap_latency_24g_milliseconds',
                'AP latency on 2.4G channels in milliseconds',
                labels=ap_metrics_labels),
            'latency50G':
                GaugeMetricFamily('smartzone_ap_latency_5g_milliseconds',
                'AP latency on 5G channels in milliseconds',
                labels=ap_metrics_labels),
            'numClients24G':
                GaugeMetricFamily('smartzone_ap_connected_clients_24g',
                'Number of clients connected to 2.4G channels on this AP',
                labels=ap_metrics_labels),
            'numClients5G':
                GaugeMetricFamily('smartzone_ap_connected_clients_5g',
                'Number of clients connected to 5G channels on this AP',
                labels=ap_metrics_labels),
            'status': GaugeMetricFamily('smartzone_ap_status',
                'AP status',
                labels=[*ap_metrics_labels, 'status']),
        }

        for ap in aps:
            # Get deviceGps and format it for labeling purposes
            gps = ap.get('deviceGps')
            latitude, longitude = (gps.split(',')[0], gps.split(',')[1]) if gps and ',' in gps else ('none', 'none')

            # Iterate over the keys defined in ap_metrics
            for key in ap_metrics.keys():
                if key == 'status':
                    for state in ['Online', 'Offline', 'Flagged']:
                        value = 1 if ap.get(key) == str(state) else 0
                        ap_metrics[key].add_metric(
                            [
                                str(ap.get('zoneName', 'unknown')),
                                str(ap.get('apGroupName', 'unknown')),
                                str(ap.get('apMac', 'unknown')),
                                str(ap.get('serial', 'unknown')),
                                str(ap.get('deviceName', 'unknown')),
                                str(latitude),
                                str(longitude),
                                str(state)
                            ],
                            value
                        )
                else:
                    # For non-status metrics, if the value is missing, default to 0.
                    value = ap.get(key) if ap.get(key) is not None else 0
                    ap_metrics[key].add_metric(
                        [
                            str(ap.get('zoneName', 'unknown')),
                            str(ap.get('apGroupName', 'unknown')),
                            str(ap.get('apMac', 'unknown')),
                            str(ap.get('serial', 'unknown')),
                            str(ap.get('deviceName', 'unknown')),
                            str(latitude),
                            str(longitude)
                        ],
                        value
                    )

        for m in ap_metrics.values():
            yield m

def parse_args():
    """
    Parse command-line arguments for the Ruckus SmartZone exporter.

    Returns:
        argparse.Namespace: The parsed command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description='Ruckus SmartZone exporter for Prometheus'
    )
    # Required arguments
    req = parser.add_argument_group('required named arguments')
    req.add_argument('-u', '--user', required=True, help='SmartZone API user')
    req.add_argument('-p', '--password', required=True, help='SmartZone API password')
    req.add_argument('-t', '--target', required=True,
        help='Target URL and port to access SmartZone (e.g. https://smartzone.example.com:8443)'
    )

    # Optional arguments
    parser.add_argument('--insecure', action='store_false',
        help='Allow insecure SSL connections to SmartZone'
    )
    parser.add_argument('--port', type=int, default=9345,
        help='Port on which to expose metrics and web interface (default: 9345)'
    )

    return parser.parse_args()

def main():
    args = parse_args()
    port = args.port

    # Initialize and register the collector
    collector = SmartZoneCollector(args.target, args.user, args.password, args.insecure)
    REGISTRY.register(collector)

    # Start the HTTP server for Prometheus to scrape
    start_http_server(port)

    logger.info(f"Polling {args.target}. Listening on :::{port}")

    try:
        # Keep the process alive; metrics collection is triggered by scrape requests
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt, exiting...")
        exit(0)

if __name__ == "__main__":
    main()
