from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS
from datetime import datetime

# Define your InfluxDB credentials
class Influx:

    def __init__(self):
        token = "S_ZBrSC-qw2_JC3H7uOa6kYIlBnO4LrmtBjY-U7FqT_CJ1a16iNL0x2ioeS76ocnNPuT-Wlj9mc6IP1zEQYlhw=="
        self.org = "INNOVWHIZ"
        self.bucket = "a652fd6c8bd3299f"
        url = "http://localhost:8086"

        # Create a client
        self.client = InfluxDBClient(url=url, token=token, org=self.org)

    def write(self, data:dict)
        # Create the write API
        write_api = self.client.write_api(write_options=SYNCHRONOUS)

        # Example data in dictionary format
        # data = {
        #     'time': datetime.now().isoformat(),
        #     'src_ip': '192.168.1.1',
        #     'dst_ip': '255.255.255.255',
        #     'packet_len': 316
        # }

        # Prepare the point
        point = Point("network_traffic") \
            .tag("src_ip", data["src_ip"]) \
            .tag("dst_ip", data["dst_ip"]) \
            .field("packet_len", data["packet_len"]) \
            .time(data["time"], WritePrecision.NS)

        # Write the point to the bucket
        write_api.write(bucket=self.bucket, org=self.org, record=point)

    def eXit(self):
        # Close the client
        self.client.close()
