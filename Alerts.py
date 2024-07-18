class Alert:

    def __init__(self):
        with open('blacklist.txt', 'r') as f:
            self.black_ips = [i.split()[0] for  i in f.readlines()]

    def check(self, data:dict) -> int:
        if data['src_ip'] in self.black_ips or data['dst_ip'] in self.black_ips:
            return 1
        return 0

