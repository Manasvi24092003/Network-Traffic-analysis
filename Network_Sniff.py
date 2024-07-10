import scapy.all as sc
import json
import time
import re

JSON_FILE = 'Network_packets.json'

def get_tcp_flags(flags:str) -> list:
    tcp_flags = {'F': "FIN", 'S': "SYN", 'R': "RST", 'P': "PSH", 'A': "ACK", 'U': "URG", 'E': "ECE", 'C': "CWR"}
    return tuple(tcp_flags[flag] for flag in flags)

def packet_callback(packet):

    # time_stamp = time.ctime(packet.time)

    layers = [str(packet[layer]) for layer in packet.layers()]
    for i in range(0, len(layers)-1):
        layers[i] = layers[i].replace(layers[i+1],'').strip(' / ')

    def protocol_difference(packet, layers) -> dict:
        protocol = layers[2]
        try:
            ttl = packet[layers[1]].ttl
        except:
            ttl = None
        if 'TCP' in protocol:
            return {'protocol':'tcp', 'sport':packet['TCP'].sport, 'dport':packet['TCP'].dport, 'flag':get_tcp_flags(packet['TCP'].flags), 'ttl':ttl}
        elif 'UDP' in protocol:
            return {'protocol':'udp', 'sport':packet['UDP'].sport, 'dport':packet['UDP'].dport, 'flag':None, 'ttl':ttl}
        elif 'ICMP' in protocol:
            return {'protocol':'icmp', 'type':packet['ICMP'].type, 'dport':packet['UDP'].dport, 'flag':None, 'ttl':ttl}

    parameters = protocol_difference(packet, layers)
    data = {
        'time': time.ctime(packet.time),
        'src.ip': packet[layers[1]].src,
        'dst.ip': packet[layers[1]].dst,
        'protocol': parameters['protocol'],
        'src.port': parameters['sport'],
        'dst.port': parameters['dport'],
        'length': len(packet),
        'flag': parameters['flag'],
        'ttl': parameters['ttl']
    }
    print(data)

def packet_dictionary(packet):
    return None

sc.sniff(prn=packet_callback, store=0, filter='tcp or udp or icmp')