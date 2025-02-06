# requests used to fetch API data
import requests

# Allow for silencing insecure warnings from requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Builtin JSON module for testing - might not need later
import json

# Needed for sleep and exporter start/end time metrics
import time

# argparse module used for providing command-line interface
import argparse

# Prometheus modules for HTTP server & metrics
from prometheus_client import start_http_server, Summary
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily, REGISTRY


# Create SmartZoneCollector as a class - in Python3, classes inherit object as a base class
# Only need to specify for compatibility or in Python2

class SmartZoneCollector():

    def __init__(self, target, user, password, insecure):
        """
        Initializes a Session and tries to verify if already authenticated.
        Otherwise, logs in with provided credentials.
        """
        self._target = target.rstrip("/") + "/"  # ensure trailing slash for URL construction
        self.vsz_session = requests.Session()
        self.vsz_api_ver = "v5_0"                # API version
        self.vsz_session_timeout = 4             # API session timeout in seconds

        # If SSL verification is disabled, set verify to False and disable warnings.
        if not insecure:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            self.vsz_session.verify = False
        else:
            self.vsz_session.verify = True

        try:
            # Check if session cookie is still valid
            resp = self.vsz_session.get(
                f'{self._target}wsg/api/public/{self.vsz_api_ver}/session',
                timeout=self.vsz_session_timeout
            )

            if not resp.ok:
                # If not valid, log in
                credentials = {
                    'username': user,
                    'password': password
                }
                login_resp = self.vsz_session.post(
                    f'{self._target}wsg/api/public/{self.vsz_api_ver}/session',
                    json=credentials,
                    timeout=self.vsz_session_timeout
                )
                login_resp.raise_for_status()
                # Update session headers (this header will be sent on all subsequent requests)
                self.vsz_session.headers.update({
                    'Content-Type': 'application/json;charset=UTF-8'
                })
        except requests.exceptions.RequestException as err:
            print(f"Failed to initialize SmartZone session: {err}")

    def get_metrics(self, metrics, api_path):
        # Save the metric names for later use in collect()
        self._statuses = list(metrics.keys())
        if 'query' in api_path:
            # For APs, use POST and API query to reduce the number of requests and improve performance
            # To-do: set dynamic AP limit based on SmartZone inventory
            raw = {'page': 0, 'start': 0, 'limit': 1000}
            r = self.vsz_session.post(
                f'{self._target}wsg/api/public/{self.vsz_api_ver}/{api_path}',
                json=raw,
                timeout=self.vsz_session_timeout
            )
        else:
            r = self.vsz_session.get(
                f'{self._target}wsg/api/public/{self.vsz_api_ver}/{api_path}',
                timeout=self.vsz_session_timeout
            )

        return r.json()

    def collect(self):

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

        zone_metrics = {
            'totalAPs':
                GaugeMetricFamily('smartzone_zone_total_aps',
                'Total number of APs in zone',
                labels=["zone_name","zone_id"]),
            'discoveryAPs':
                GaugeMetricFamily('smartzone_zone_discovery_aps',
                'Number of zone APs in discovery state',
                labels=["zone_name","zone_id"]),
            'connectedAPs':
                GaugeMetricFamily('smartzone_zone_connected_aps',
                'Number of connected zone APs',
                labels=["zone_name","zone_id"]),
            'disconnectedAPs':
                GaugeMetricFamily('smartzone_zone_disconnected_aps',
                'Number of disconnected zone APs',
                labels=["zone_name","zone_id"]),
            'rebootingAPs':
                GaugeMetricFamily('smartzone_zone_rebooting_aps',
                'Number of zone APs in rebooting state',
                labels=["zone_name","zone_id"]),
            'clients':
                GaugeMetricFamily('smartzone_zone_total_connected_clients',
                'Total number of connected clients in zone',
                labels=["zone_name","zone_id"])
                }

        ap_metrics = {
            'alerts':
                GaugeMetricFamily('smartzone_ap_alerts',
                'Number of AP alerts',
                labels=["zone","ap_group","mac","name","lat","long"]),
            'latency24G':
                GaugeMetricFamily('smartzone_ap_latency_24g_milliseconds',
                'AP latency on 2.4G channels in milliseconds',
                labels=["zone","ap_group","mac","name","lat","long"]),
            'latency50G':
                GaugeMetricFamily('smartzone_ap_latency_5g_milliseconds',
                'AP latency on 5G channels in milliseconds',
                labels=["zone","ap_group","mac","name","lat","long"]),
            'numClients24G':
                GaugeMetricFamily('smartzone_ap_connected_clients_24g',
                'Number of clients connected to 2.4G channels on this AP',
                labels=["zone","ap_group","mac","name","lat","long"]),
            'numClients5G':
                GaugeMetricFamily('smartzone_ap_connected_clients_5g',
                'Number of clients connected to 5G channels on this AP',
                labels=["zone","ap_group","mac","name","lat","long"]),
            'status':
                GaugeMetricFamily('smartzone_ap_status',
                'AP status',
                labels=["zone","ap_group","mac","name","status","lat","long"])
                }

        # Get SmartZone controller metrics
        for c in self.get_metrics(controller_metrics, 'controller')['list']:
            id = c['id']
            for s in self._statuses:
                if s == 'uptimeInSec':
                     controller_metrics[s].add_metric([id], c.get(s))
                # Export a dummy value for string-only metrics
                else:
                     extra = c[s]
                     controller_metrics[s].add_metric([id, extra], 1)

        for m in controller_metrics.values():
            yield m

        # Get SmartZone inventory per zone
        # For each zone captured from the query:
        # - Grab the zone name and zone ID for labeling purposes
        # - Loop through the statuses in statuses
        # - For each status, get the value for the status in each zone and add to the metric
        for zone in self.get_metrics(zone_metrics, 'system/inventory')['list']:
            zone_name = zone['zoneName']
            zone_id = zone['zoneId']
            for s in self._statuses:
                zone_metrics[s].add_metric([zone_name, zone_id], zone.get(s))

        for m in zone_metrics.values():
            yield m

        # Get SmartZone AP metrics
        # Generate the metrics based on the values
        for ap in self.get_metrics(ap_metrics, 'query/ap')['list']:
            gps = ap.get('deviceGps')
            lat, long = (gps.split(',')[0], gps.split(',')[1]) if gps and ',' in gps else ('none', 'none')

            for s in self._statuses:
                # 'Status' is a string value only, so we can't export the default value
                if s == 'status':
                    state_name = ['Online','Offline','Flagged']
                    # By default set value to 0 and increase to 1 to reflect current state
                    # Similar to how node_exporter handles systemd states
                    for n in state_name:
                        value = 0
                        if ap.get(s) == str(n):
                            value = 1
                        # Wrap the zone and group names in str() to avoid issues with None values at export time
                        ap_metrics[s].add_metric([str(ap['zoneName']), str(ap['apGroupName']), ap['apMac'], ap['deviceName'], n, lat, long], value)
                else:
                    if ap.get(s) is not None:
                        ap_metrics[s].add_metric([str(ap['zoneName']), str(ap['apGroupName']), ap['apMac'], ap['deviceName'], lat, long], ap.get(s))
                    # Return 0 for metrics with values of None
                    else:
                        ap_metrics[s].add_metric([str(ap['zoneName']), str(ap['apGroupName']), ap['apMac'], ap['deviceName'], lat, long], 0)

        for m in ap_metrics.values():
            yield m


# Function to parse command line arguments and pass them to the collector
def parse_args():
    parser = argparse.ArgumentParser(description='Ruckus SmartZone exporter for Prometheus')

    # Use add_argument() method to specify options
    # By default argparse will treat any arguments with flags (- or --) as optional
    # Rather than make these required (considered bad form), we can create another group for required options
    required_named = parser.add_argument_group('required named arguments')
    required_named.add_argument('-u', '--user', help='SmartZone API user', required=True)
    required_named.add_argument('-p', '--password', help='SmartZone API password', required=True)
    required_named.add_argument('-t', '--target', help='Target URL and port to access SmartZone, e.g. https://smartzone.example.com:8443', required=True)

    # Add store_false action to store true/false values, and set a default of True
    parser.add_argument('--insecure', action='store_false', help='Allow insecure SSL connections to Smartzone')

    # Specify integer type for the listening port
    parser.add_argument('--port', type=int, default=9345, help='Port on which to expose metrics and web interface (default=9345)')

    # Now that we've added the arguments, parse them and return the values as output
    return parser.parse_args()

def main():
    try:
        args = parse_args()
        port = int(args.port)
        REGISTRY.register(SmartZoneCollector(args.target, args.user, args.password, args.insecure))
        # Start HTTP server on specified port
        start_http_server(port)
        if args.insecure == False:
             print('WARNING: Connection to {} may not be secure.'.format(args.target))
        print("Polling {}. Listening on ::{}".format(args.target, port))
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(" Keyboard interrupt, exiting...")
        exit(0)


if __name__ == "__main__":
    main()
