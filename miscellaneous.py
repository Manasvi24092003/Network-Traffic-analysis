import csv
import os

def write_dict_to_csv(data):

    file = 'output.csv'

    file_exists = os.path.isfile(file) and os.path.getsize(file) > 0

    headers = data.keys()
    
    with open(file, 'a', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=headers)
        
        if not file_exists:
            writer.writeheader()
        
        writer.writerow(data)