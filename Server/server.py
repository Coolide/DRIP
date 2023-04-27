import sqlite3
import hashlib
from cryptography.fernet import Fernet
from os.path import exists
from fastapi import FastAPI
import string
import secrets
import socket
import time
import uvicorn
from json import dumps

app = FastAPI()
LIVE_ENTITIES = []

# Create the database tables if they do not exist
def initialise_database():
    #Create the key
    if not exists('./key.pem'):
        with open('./key.pem', 'wb') as file:
            file.write(Fernet.generate_key())


    connection = sqlite3.connect('registry.db')
    cursor = connection.cursor()

    cursor.execute(""" 
    CREATE TABLE IF NOT EXISTS certificate_authority(
    ID INTEGER PRIMARY KEY,
    public_key TEXT,
    hashed_ID TEXT,
    address TEXT,
    entity_type TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS registered_entities(
    hashed_ID TEXT PRIMARY KEY
    )
    """)

    cursor.execute(""" 
    CREATE TABLE IF NOT EXISTS private_lookup(
    UAS_ID TEXT PRIMARY KEY,
    Entity_ID TEXT,
    Registry_ID TEXT,
    Serial_Num TEXT
    )
    """)

    cursor.execute(""" 
    CREATE TABLE IF NOT EXISTS public_lookup(
    UAS_ID TEXT PRIMARY KEY,
    operator_name TEXT,
    emergency_num TEXT,
    date_of_birth TEXT
    )
    """)

    connection.commit()
    cursor.close()
    if connection:
        connection.close()
    return

def encrypt(message):
    return 

def send_message(address, message):
    with open("./key.pem", "rb") as file:
        k = file.read()
    key = Fernet(k)

    encrypted_message = key.encrypt(message.encode())

    port = 8001
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    time.sleep(1)
    s.sendto(encrypted_message, (address, port))
    print("SENT HASHED MESSAGE to {}:{}".format(address,port))
    s.close()

@app.get('/generate-hash/{encrypted}')
def send_hashed_ID(encrypted):
    with open("./key.pem", "rb") as file:
        k = file.read()
    key = Fernet(k)
    #decrypt the message
    raw = key.decrypt(encrypted).decode().split(",") #address, mac, serial
    print(raw)
    hashed_ID = generate_hashed_ID(raw[1], raw[2])
    print("HASHED ID GENERATED:" + hashed_ID)
    send_message(raw[0], hashed_ID)
    connection = sqlite3.connect('registry.db')
    cursor = connection.cursor()
    cursor.execute("""
    INSERT OR IGNORE INTO registered_entities
    (hashed_ID)
    VALUES ('{}')            
    """.format(hashed_ID))
    connection.commit()
    cursor.close()
    if connection:
        connection.close()
    return {"Success"}

@app.get('/test/{encrypted}')
def test_http(encrypted):
    with open("./key.pem", "rb") as file:
        k = file.read()
    key = Fernet(k)
    #decrypt the message
    raw = key.decrypt(encrypted).decode()
    print(raw)
    return {"Success"}

#hashed_ID, address, entity_type
@app.get('/request-go-live/{encrypted}')
def go_live(encrypted):
    with open("./key.pem", "rb") as file:
        k = file.read()
    key = Fernet(k)
    #decrypt the message
    raw = key.decrypt(encrypted).decode().split(",") #hashed_ID, address, entity_type
    print(raw)
    connection = sqlite3.connect('registry.db')
    cursor = connection.cursor()
    cursor.execute("""
    SELECT * FROM registered_entities WHERE hashed_ID = '{}'
    """.format(raw[0]))
    result = cursor.fetchall()
    cursor.close()
    if len(result) > 0:
        LIVE_ENTITIES.append(tuple((raw[0], raw[1], raw[2])))
        print(LIVE_ENTITIES)
        return {"Success"}
    else:
        return {"No authorised"}

@app.get('/get-registered-entities')
def get_registered_entities():
    with open("./key.pem", "rb") as file:
        k = file.read()
    key = Fernet(k)
    connection = sqlite3.connect('registry.db')
    cursor = connection.cursor()
    cursor.execute("""
    SELECT * from certificate_authority
    """)
    result = cursor.fetchall()
    cursor.close()
    if connection:
        connection.close()
    message = str({"result" : result})
    return key.encrypt(message.encode())

#public_key, hashed_ID, address, entity_type
@app.get('/register-entity/{encrypted}')
def add_certificate(encrypted):
    connection = sqlite3.connect('registry.db')
    cursor = connection.cursor()
    cursor.execute("SELECT * from certificate_authority")
    result = cursor.fetchall()
    print(result)
    count = len(result)
    ID_num = count + 1
    cursor.execute("SELECT * from registered_entities")
    result = cursor.fetchall()
    print(result)
    with open("./key.pem", "rb") as file:
        k = file.read()
    key = Fernet(k)
    #decrypt the message
    raw = key.decrypt(encrypted).decode().split(",") # ID, public_key, hashed_ID, address, entity_type
    print(raw)
    cursor.execute("""
            INSERT INTO certificate_authority
            (ID, public_key, hashed_ID, address, entity_type)
            VALUES ({},'{}','{}', '{}', '{}')
            """.format(ID_num, raw[0], raw[1], raw[2], raw[3]))
    connection.commit()
    cursor.close()
    if connection:
        connection.close()
    return {"Success"}


#{UAS_ID}/{entity_ID}/{registry_ID}/{serial_Num}
@app.get('/add-private-info/{encrypted}')
def add_private_info(encrypted):
    #Load symmetric key
    with open("./key.pem", "rb") as file:
        k = file.read()
    key = Fernet(k)
    #decrypt the message
    raw = key.decrypt(encrypted).decode().split(",")
    print("this is what im gonna add to private: {}".format(raw))
    connection = sqlite3.connect('registry.db', timeout=5)
    cursor = connection.cursor()
    cursor.execute("""
    INSERT OR IGNORE INTO private_lookup
    (UAS_ID, Entity_ID, Registry_ID, Serial_Num)
    VALUES ('{}','{}','{}','{}')
    """.format(raw[0], raw[1], raw[2], raw[3]))
    connection.commit()
    cursor.close()
    if connection:
        connection.close()
    return {"Success"}

#{UAS_ID}/{operator_name}/{emergency_num}/{date_of_birth}
@app.get('/add-public-info/{encrypted}')
def add_public_info(encrypted):
    #Load symmetric key
    with open("./key.pem", "rb") as file:
        k = file.read()
    key = Fernet(k)
    #decrypt the message
    raw = key.decrypt(encrypted).decode().split(",")
    connection = sqlite3.connect('registry.db', timeout=5)
    cursor = connection.cursor()
    cursor.execute("""
    INSERT OR IGNORE INTO public_lookup
    (UAS_ID, operator_name, emergency_num, date_of_birth)
    VALUES ('{}','{}',{},'{}')            
    """.format(raw[0], raw[1], raw[2], raw[3]))
    connection.commit()
    cursor.close()
    if connection:
        connection.close()
    return {"Success"}


#{UAS_ID}
@app.get('/public-lookup/{encrypted}')
def public_lookup(encrypted):
    # #Load symmetric key
    # with open("./key.pem", "rb") as file:
    #     k = file.read()
    # key = Fernet(k)
    # #decrypt the message
    # raw = key.decrypt(encrypted).decode()
    connection = sqlite3.connect('registry.db')
    cursor = connection.cursor()
    cursor.execute(""" 
    SELECT * FROM public_lookup WHERE UAS_ID = '{}'
    """.format(encrypted))
    result = cursor.fetchall()
    cursor.close()
    if connection:
        connection.close()
    if len(result) != 0:
        return {"result" : result}
    else:
        return {"result" : "No information found."}

#{UAS_ID}/{authentication_token}
@app.get('/private-lookup/{encrypted}')
def private_lookup(encrypted):
    # #Load symmetric key
    # with open("./key.pem", "rb") as file:
    #     k = file.read()
    # key = Fernet(k)
    # #decrypt the message
    # raw = key.decrypt(encrypted).decode()
    #validate authentication token here
    raw = encrypted.split(",")
    if int(raw[1]) > 10: #temporary test check - out of scope of study...
        connection = sqlite3.connect('registry.db')
        cursor = connection.cursor()
        cursor.execute("""
        SELECT * FROM private_lookup WHERE UAS_ID = {}
        """.format(raw[0]))
        result = cursor.fetchall()
        cursor.close()
        if connection:
            connection.close()
        if len(result) != 0:
            return {"result" : result}
        else:
            return {"result" : "No information found"}
    else:
        return {"result" : "Not authorised to access this information."}

@app.get('/get-certificate/{address}')
def get_certificate(address):
    connection = sqlite3.connect('registry.db')
    cursor = connection.cursor()
    cursor.execute("""
    SELECT public_key FROM certificate_authority WHERE address = '{}'
    """.format(address))
    result = cursor.fetchall()
    cursor.close()
    if connection:
        connection.close()
    if len(result) != 0:
        return {"result" : result}
    else:
        return {"result" : "No certificate record found for {}".format(address)}


#Populate the certificate authority database with a dummy entry
def debug_populate_registered_entities():
    with open("./key.pem", "rb") as file:
        k = file.read()
    key = Fernet(k)
    key.decrypt(get_registered_entities()).decode()
    count = len(['result'])
    ID = count + 1

    connection = sqlite3.connect('registry.db')
    cursor = connection.cursor()
    cursor.execute("""
    INSERT INTO certificate_authority
    (ID, public_key, hashed_ID ,address ,entity_type)
    VALUES ({},'test_public_key','test_hashhh','test','drone')            
    """.format(ID))
    connection.commit()
    cursor.close()
    
def generate_two_digits():
    digits = string.digits
    random = ''
    for _ in range(2):
        random += secrets.choice(digits)
    return random

def generate_flight_session_key():
    digits = string.ascii_uppercase + string.digits
    session_key = ''
    for _ in range(32):
        session_key += secrets.choice(digits)
    return session_key

def get_local_IP():
    host_name = socket.gethostname()
    address = socket.gethostbyname(host_name)
    return address

def generate_hashed_ID(mac_address, serial):
    message  = '{}|{}|{}'.format(mac_address,serial,generate_two_digits()).encode()
    print(message)
    hashed_ID = hashlib.sha256(message).hexdigest()
    return hashed_ID

def run():
    debug_populate_registered_entities()
    print(generate_hashed_ID('fe80::fc0d:eac5:582b', 'MCNRKD006566495'))
    return

if __name__ == '__main__':
    initialise_database()
    uvicorn.run("server:app", host="169.254.236.79", port=8000, log_level="info", reload=True)
    # uvicorn.run("server:app", host="192.168.102.1", port=8000, log_level="info", reload=True)
    run()