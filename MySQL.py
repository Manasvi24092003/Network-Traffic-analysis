import mysql.connector as sql

class SQL:

    def __init__(self):
        self.database, self.table = 'grafanadb', 'packets'
        self.con = sql.connect(host='localhost', username='root', password='root', database=self.database)
        self.cur = self.con.cursor()
    
    def table_existence_handler(self):
        self.cur.execute(f'SHOW TABLES LIKE "{self.table}"')
        if not self.cur.fetchone():
            query = f'CREATE TABLE {self.table} (serial MEDIUMINT, time TEXT, src_ip TEXT, src_port MEDIUMINT, dst_ip TEXT, dst_port MEDIUMINT, proto TINYTEXT, flag TINYTEXT, ttl MEDIUMINT,size MEDIUMINT, alert TINYINT);'
            self.cur.execute(query)
            self.con.commit()
            return False
        return True

    def table_reset(self):
        query = f'DELETE FROM {self.table}'
        self.cur.execute(query)
        self.con.commit()

    def write(self, data):
        query = f'INSERT INTO {self.table} VALUES ({data['serial']}, "{data['time']}", "{data['src_ip']}", {data['src_port']}, "{data['dst_ip']}", {data['dst_port']}, "{data['proto']}", "{data['flag']}", {data['ttl']}, {data['size']}, {data['alert']});'
        self.cur.execute(query)
        self.con.commit()
    
    def update_alert(self, serial):
        query = f'UPDATE packets SET alert=1 WHERE serial={serial}'
        self.cur.execute(query)
        self.con.commit()

