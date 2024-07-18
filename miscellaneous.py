import csv
import os
import ipaddress

def write_dict_to_csv(data):
    file = 'output.csv'
    file_exists = os.path.isfile(file) and os.path.getsize(file) > 0
    headers = data.keys()
    with open(file, 'a', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=headers)
        if not file_exists:
            writer.writeheader()
        writer.writerow(data)

def fetch_all_ip_files():
    def is_valid_ip(ip_str):
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    for file in os.listdir('IP Blacklist'):
        with open('blacklist.txt', 'a') as f1:
            with open(os.path.join('IP Blacklist', file), 'r') as f2:
                data = f2.readlines()
                new_data = [i.split()[0].split('/')[0] for i in data]
            for i in new_data:
                if is_valid_ip(i):
                    f1.write(i + '\n')