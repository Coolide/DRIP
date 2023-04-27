import rsa
from os.path import exists
import hmac
import threading
import hashlib
import requests
import psutil
from cryptography.fernet import Fernet
import time
import socket
import subprocess
import re
import uuid
import time
from sys import platform

URL = 'http://169.254.236.79:8000' #server address
LOCAL_URL = '169.254.103.14' #drone address
OBSERVER_ADDRESS = '169.254.236.79' #predefined observer address
hashed = ''

#Drone config info
UAS_ID = '999'
serial_num = 'new'
entity_ID = '0009'
registry_ID = '1234'
operator_name = 'Jacob'
emergency_num = '07842'
date_of_birth = '19/10/1997'

#Loads information before drone operation
def initialise():
    #Create the key pair
    if not exists('./public.pem') and not exists('./private.pem'):
        public_key, private_key = rsa.newkeys(2048)
        print('Created new public and private keys...')
        with open('public.pem', 'wb') as file:
            file.write(public_key.save_pkcs1('PEM'))
        with open('private.pem', 'wb') as file:
            file.write(private_key.save_pkcs1('PEM'))
    #Load symmetric key
    with open("./key.pem", "rb") as file:
        k = file.read()
    key = Fernet(k)
    
    #Register information to the server and certificate authority
    with open('public.pem', 'rb') as p:
        public_key = rsa.PublicKey.load_pkcs1(p.read())

    #Get the Hashed ID
    generate_info = '{},{},{}'.format(LOCAL_URL,get_mac_address(),get_serial_num()).encode()
    print("GENERATE INFO:" + str(generate_info))
    encrypted_generate_info = key.encrypt(generate_info)

    url = '{}/generate-hash/{}'.format(URL,encrypted_generate_info.decode())
    thread = threading.Thread(target=send_request, args=(url,))
    thread.start()

    #listen for returned Hash ID
    UDP_IP = "0.0.0.0"
    UDP_PORT = 8001
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((UDP_IP, UDP_PORT))
    data = ''
    print("####### Server is listening #######")
    data, _ = s.recvfrom(1024)
    print("RECIEVED INFO:" + data.decode())
    s.close()
    global hashed
    hashed = key.decrypt(data).decode()
    time.sleep(1)
    
    with open('public.pem', 'rb') as p_file:
        public_key = str(p_file.read().decode()).replace("-----BEGIN RSA PUBLIC KEY-----", "").replace("-----END RSA PUBLIC KEY-----", "").replace("\n", "")
    #result = requests.get('{}/register-entity/{}/{}'.format(URL,'drone',get_mac_address()))
    print(public_key)
    register_entity_info = '{},{},{},{}'.format(public_key, hashed, LOCAL_URL, 'drone').encode()
    encrypted_register_entity_info = key.encrypt(register_entity_info)
    result = requests.get('{}/register-entity/{}'.format(URL,encrypted_register_entity_info.decode()))
    print("RESULT OF RERGISTERING ENTITY:" + str(result))
    time.sleep(2)
    
    #Add private information
    add_private_info = '{},{},{},{}'.format(UAS_ID,entity_ID,registry_ID,serial_num).encode()
    encrpyted_private_info = key.encrypt(add_private_info)
    result = requests.get('{}/add-private-info/{}'.format(URL,encrpyted_private_info.decode()))
    print("RESULT OF ADDING PRIVATE INFO:" + str(result))
    time.sleep(2)
    
    #Add public information
    add_public_info = '{},{},{},{}'.format(UAS_ID,operator_name,emergency_num,date_of_birth).encode()
    encrpyted_public_info = key.encrypt(add_public_info)
    result = requests.get('{}/add-public-info/{}'.format(URL,encrpyted_public_info.decode()))
    print("RESULT OF ADDING PUBLIC INFO:" + str(result))

def send_request(url):
    requests.get(url)

def go_live():
    #Load symmetric key
    with open("./key.pem", "rb") as file:
        k = file.read()
    key = Fernet(k)
    go_live_info = '{},{},{}'.format(hashed,LOCAL_URL,'drone').encode()
    print(go_live_info)
    encrypted_go_live_info = key.encrypt(go_live_info)
    result = requests.get('{}/request-go-live/{}'.format(URL, encrypted_go_live_info.decode()))
    return

#Encrypts the plain text into cipher text using the public key into utf-8
def encrpyt(message):
    with open('public.pem', 'rb') as p_file:
        public_key = rsa.PublicKey.load_pkcs1(p_file.read())
    encryptped_message = rsa.encrypt(message.encode(), public_key)
    return encryptped_message

#Decrypts a message using the private key into utf-8
def decrypt(message):
    with open('private.pem', 'rb') as p_file:
        private_key = rsa.PrivateKey.load_pkcs1(p_file.read())
    decrypted_message = rsa.decrypt(message, private_key)
    return decrypted_message

#Creates the hashed message using a message authentication code (MAC)
def hash(session_key, message):
    session_key = session_key.encode()
    message = message.encode()
    hashed_message = hmac.new(session_key, message, hashlib.sha256)
    return hashed_message.hexdigest()

#Gets the WiFi mac address of the device
def get_mac_address(): # mac||serialnumber||random
    mac_address = ''
    if get_platform() == 'windows':
        mac_address = psutil.net_if_addrs()['WiFi'][0].address
    elif get_platform() == 'linux':
        mac_address = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
    return mac_address

#Send the continous data using UDP socket
def send_message(address, message):
    port = 8008
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(str(message).encode(), (address, port))

#Send a message at a rate of 10 ticks per second.
def continous_messaging():
    while True:
        message = get_data()
        print("Sending '{}' to '{}'".format(message, OBSERVER_ADDRESS))
        send_message(OBSERVER_ADDRESS,message)
        time.sleep(0.1)
    return

#Simulated data
def get_data():
    data = {
        "dynamic" : {
            "Location vector" : [51.619732, -3.879636, 1.0001],
            "Ground speed(mph)" : 9,
            "Angle" : 38.21,
            "Timestamp" : "20/03/2023 9:53AM",
            "Status" : "In operation"
        },
        "static" : {
            "UAS_ID" : 999,
            "Serial Number" : '',
            "Registry ID" : ''
            }
    }
    return data

#Get local IP address of the drone
def get_local_IP():
    host_name = socket.gethostname()
    address = socket.gethostbyname(host_name)
    return address

#Is the drone running on Windows or Linux?
def get_platform():
    os = ''
    if platform == "linux" or platform == "linux2":
        os = 'linux'
    elif platform == "win32":
        os = 'windows'
    return os

def get_serial_num():
    num = ''
    if get_platform() == 'windows':
        raw = subprocess.check_output('wmic bios get serialnumber').decode("utf-8")
        serial = re.search(r'SerialNumber\s*([A-Z0-9]*)',raw)
        num = serial.group(1)
    elif get_platform() == 'linux':
        #cmd = "sudo dmidecode -t system | grep Serial"
        #output = subprocess.check_output(cmd, shell=True).decode().strip()
        #num = output.split(":")[1].strip().replace(" ", "")
        num = "0000000000000000"
        try:
            f = open('/proc/cpuinfo','r')
            for line in f:
                if line[0:6]=='Serial':
                    cpuserial = line[10:26]
            f.close()
        except:
            num = "ERROR000000000"
        return num

def run():
    # initialise()
    time.sleep(1)
    # go_live()
    print(get_local_IP())
    continous_messaging()


if __name__ == '__main__':
    run()
