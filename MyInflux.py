from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS
from datetime import datetime

class Influx:

    def __init__(self):
        token = "S_ZBrSC-qw2_JC3H7uOa6kYIlBnO4LrmtBjY-U7FqT_CJ1a16iNL0x2ioeS76ocnNPuT-Wlj9mc6IP1zEQYlhw=="
        self.org = "NetFlow"
        self.bucket = "test"
        url = "http://localhost:8086"
        self.measurement = 'Network Traffic 2'

        self.client = InfluxDBClient(url=url, token=token, org=self.org)

    def write(self, data:dict):
        write_api = self.client.write_api(write_options=SYNCHRONOUS)

        self.point = Point(self.measurement) \
            .tag("src.ip", data['src.ip']) \
            .tag("dst.ip", data['dst.ip']) \
            .tag("protocol", data['protocol']) \
            .field("src.port", data['src.port']) \
            .field("dst.port", data['dst.port']) \
            .field("size", data['size']) \
            .field("flag", data['flag']) \
            .field("ttl", data['ttl'])

        write_api.write(bucket=self.bucket, org=self.org, record=self.point)
        print('Data written...')

    # NEEDS ALTERATION ACORDING TO ML NEEDS
    def read(self):
        query_api = self.client.query_api()

        query = f'''
        from(bucket: "{self.bucket}")
        |> range(start: -30d)
        |> filter(fn: (r) => r._measurement == "{self.measurement}")
        '''

        tables = query_api.query(query)

        for table in tables:
            print(table)
            for row in table.records:
                print (row.values)

    def eXit(self):
        self.client.close()
