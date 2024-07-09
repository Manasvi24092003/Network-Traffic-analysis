import scapy.all as sc
import re

def packet_callback(packet):
    print(parse_packet_command(packet))

# completed
def parse_packet_command(packet) -> tuple:
    s, flag_raised, heads = packet.command(), False, list()
    temp_heads = tuple(i.split('(')[0] for i in s.split('/') if not re.search(r'\\', i))
    for head in temp_heads:
        if flag_raised:
            break
        elif head == 'Raw' and not flag_raised:
            flag_raised = True
        heads.append(head)
    return tuple(heads)

sc.sniff(prn=packet_callback, store=0)
