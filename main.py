import scapy.all as sc
from SQL import SQL
import time
import Miscellaneous as m
import Alerts
import Model_Integration as ModelInt
from geo import Geo

sql = SQL('packets')
if sql.table_existence_handler():
    sql.table_reset()

sql3, geo = SQL('geo'), Geo('4a80dc2e1e6bec')
if sql3.table_existence_handler():
    sql3.table_reset()

# data dictionary parameters
protocol, sport, dport, flag, ttl, type = 'protocol', 'sport', 'dport', 'flag', 'ttl', 'type'

def packet_callback(packet):

    global serial
    serial += 1
    
    layers = [str(packet[layer]) for layer in packet.layers()]
    for i in range(0, len(layers)-1):
        layers[i] = layers[i].replace(layers[i+1],'').strip(' / ')
    
    def get_tcp_flags(flags:str) -> str:
        tcp_flags = {'F': "FIN", 'S': "SYN", 'R': "RST", 'P': "PSH", 'A': "ACK", 'U': "URG", 'E': "ECE", 'C': "CWR"}
        return ' '.join(tuple(tcp_flags[flag] for flag in flags))

    def error_handling(packet, layers, parameter:str):
        if parameter == ttl:
            try: return packet[layers[1]].ttl
            except: return -1
        elif parameter in (sport, dport):
            try: return packet['ICMP'].sport, packet['ICMP'].dport
            except: return 0, 0

    def protocol_difference(packet, layers) -> dict:
        pr0t0c0l = layers[2]
        if 'TCP' in pr0t0c0l:
            return {protocol:'tcp', sport:packet['TCP'].sport, dport:packet['TCP'].dport, flag:get_tcp_flags(packet['TCP'].flags), ttl:error_handling(packet, layers, ttl)}
        elif 'UDP' in pr0t0c0l:
            return {protocol:'udp', sport:packet['UDP'].sport, dport:packet['UDP'].dport, flag:'VAIBS', ttl:error_handling(packet, layers, ttl)}
        elif 'ICMP ' in pr0t0c0l:
            return {protocol:'icmp', type:packet['ICMP'].type, sport:error_handling(packet, layers, sport)[0], dport:error_handling(packet, layers, dport)[1], flag:'VAIBS', ttl:error_handling(packet, layers, ttl)}

    parameters = protocol_difference(packet, layers)
    try:
        data = {
            'serial': serial,
            'time': time.time()*1000,
            'src_ip': packet[layers[1]].src,
            'src_port': parameters[sport],
            'dst_ip': packet[layers[1]].dst,
            'dst_port': parameters[dport],
            'proto': parameters[protocol],
            'flag': parameters[flag],
            'ttl': parameters[ttl],
            'size': len(packet),
            'alert': 0,
        }
    except:
        serial -= 1
        return None

    sql.write(data)
    # print(data)
    
    # DETECT ANOMALIES USING MACHINE MODEL
    if ModelInt.run(data):
        sql.update_alert(data['serial'], 'unknown')

    # attack_dic = {
    #     1: 'Blacklist',
    #     2: 'DoS'
    # }

    # print(data)

    attack = alert.check(data)
    if attack:
        location = geo.fetch_json_data(data['dst_ip'])
        if 'loc' in location.keys():
            lat, long = location['loc'].split(',')
            geo_data = {'ip':location['ip'], 'org':location['org'], 'latitude':float(lat), 'longitude':float(long)}
            sql3.write(geo_data)
            # print(location if location else None)
        sql.update_alert(data['serial'], 'Blacklist Detected')

serial = 0
interface, sniff_filter = 'Wi-Fi', 'tcp or udp or icmp'
# interface, sniff_filter = 'Wi-Fi', 'icmp'
# interface, sniff_filter = 'VMware Network Adapter VMnet8', 'tcp or udp or icmp'
alert = Alerts.Alert()
sc.sniff(iface=interface, filter=sniff_filter, prn=packet_callback, store=0)