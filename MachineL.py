data = dict()

def send(d) -> dict:
    global data
    data = d

if __name__ == '__main__':
    while True:
        print(data)
