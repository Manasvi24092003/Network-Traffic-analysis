import csv
import os

def write_dict_to_csv(filename, data):

    file_exists = os.path.isfile(filename) and os.path.getsize(filename) > 0

    headers = data.keys()
    
    with open(filename, 'a', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=headers)
        
        if not file_exists:
            writer.writeheader()
        
        writer.writerow(data)