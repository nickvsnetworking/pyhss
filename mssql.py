import pymssql

try:
    server = {'username' : 'sa', 'password' : 'thisisthepasswordforMSSQL99#!', 'server' : '127.0.0.1', 'database' : 'hlr'}
    conn = pymssql.connect(server['server'], server['username'], server['password'], server['database'], as_dict=True, autocommit=True)
    cursor = conn.cursor()
except:
    #If failed to connect to server
    sys.exit()
input("Waiting...")


#def GetSubscriberInfo(self, imsi):
imsi = '001010000000003'
cursor.execute('SELECT * FROM imsi WHERE IMSI=%s', str(imsi))
for row in cursor:
    print(row)
    return row

conn.close()
