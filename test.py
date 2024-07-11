from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client .client.write_api import SYNCHRONOUS
from datetime import datetime

token = "S_ZBrSC-qw2_JC3H7uOa6kYIlBnO4LrmtBjY-U7FqT_CJ1a16iNL0x2ioeS76ocnNPuT-Wlj9mc6IP1zEQYlhw=="
org = "NetFlow"
bucket = "test 2"
url = "http://localhost:8086"
measurement = 'Network Traffic 005'

client = InfluxDBClient(url=url, token=token, org=org)

def write():

    write_api = client.write_api(write_options=SYNCHRONOUS)

    data_list = [
            {'time': '2024-07-11T13:54:55.021079', 'src.ip': '2401:4900:1c8f:21bd:6460:e934:34a:f4d3', 'dst.ip': '2603:1040:a06:3::4', 'protocol': 'tcp', 'src.port': 61456, 'dst.port': 443, 'size': 74, 'flag': 'ACK', 'ttl': -1},
            {'time': '2024-07-11T13:54:55.095765', 'src.ip': '2603:1040:a06:3::4', 'dst.ip': '2401:4900:1c8f:21bd:6460:e934:34a:f4d3', 'protocol': 'tcp', 'src.port': 443, 'dst.port': 61456, 'size': 101, 'flag': 'PSH ACK', 'ttl': -1},
            {'time': '2024-07-11T13:54:55.139418', 'src.ip': '2401:4900:1c8f:21bd:6460:e934:34a:f4d3', 'dst.ip': '2603:1040:a06:3::4', 'protocol': 'tcp', 'src.port': 61456, 'dst.port': 443, 'size': 74, 'flag': 'ACK', 'ttl': -1},
            {'time': '2024-07-11T13:54:55.433432', 'src.ip': '192.168.1.4', 'dst.ip': '239.255.255.250', 'protocol': 'udp', 'src.port': 58204, 'dst.port': 1900, 'size': 217, 'flag': '', 'ttl': 1},
            {'time': '2024-07-11T13:54:56.057737', 'src.ip': '192.168.1.2', 'dst.ip': '35.186.224.35', 'protocol': 'tcp', 'src.port': 61875, 'dst.port': 443, 'size': 82, 'flag': 'PSH ACK', 'ttl': 128},
            {'time': '2024-07-11T13:54:56.064458', 'src.ip': '35.186.224.35', 'dst.ip': '192.168.1.2', 'protocol': 'tcp', 'src.port': 443, 'dst.port': 61875, 'size': 54, 'flag': 'ACK', 'ttl': 123},
            {'time': '2024-07-11T13:54:38.064295', 'src.ip': '192.168.1.1', 'dst.ip': '192.168.1.2', 'protocol': 'icmp', 'src.port': 62044, 'dst.port': 443, 'size': 590, 'flag': '', 'ttl': 64},
            {'time': '2024-07-11T13:54:38.064295', 'src.ip': '192.168.1.1', 'dst.ip': '192.168.1.2', 'protocol': 'icmp', 'src.port': 62044, 'dst.port': 443, 'size': 590, 'flag': '', 'ttl': 64}
        ]

    for data in data_list:
        time = str(datetime.now().isoformat())
        point = Point(measurement) \
            .time(data['time'], WritePrecision.NS) \
            .tag("src.ip", data['src.ip']) \
            .tag("dst.ip", data['dst.ip']) \
            .tag("protocol", data['protocol']) \
            .field("src.port", data['src.port']) \
            .field("dst.port", data['dst.port']) \
            .field("size", data['size']) \
            .field("flag", data['flag']) \
            .field("ttl", data['ttl'])

        write_api.write(bucket=bucket, record=point)

def read():

    query_api = client.query_api()

    query = f'''
    from(bucket: "{bucket}")
    |> range(start: -30d)
    |> filter(fn: (r) => r._measurement == "{measurement}")
    '''

    tables = query_api.query(query)

    for table in tables:
        print(table)
        for row in table.records:
            print (row.values)

write()

read()

client.close()