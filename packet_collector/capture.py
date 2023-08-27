import pyshark
from pymongo import MongoClient
from datetime import datetime
import configparser

config = configparser.ConfigParser()
config.read('conf.ini')

BATCH_SIZE = int(config['default']['batch_size'])
INTERFACE = config['default']['network_interface']

# MongoDB setup
HOST = config['mongo']['host']
PORT = int(config['mongo']['port'])
DB = config['mongo']['db']
COLLECTION = config['mongo']['collection']

client = MongoClient(HOST, PORT)
db = client[DB]
collection = db[COLLECTION]

packets = []

def packet_callback(packet):
    # Create a payload from packet data
    packet_dict = {
        'timestamp': datetime.strptime(str(packet.sniff_time), '%Y-%m-%d %H:%M:%S.%f'),  # Adjust the format string as needed
        'length': int(packet.length), 
        'highest_layer': packet.highest_layer
        }

    # Check if the packet contains IP layer information
    if 'IP' in packet:
        packet_dict['src_ip'] = packet.ip.src
        packet_dict['dest_ip'] = packet.ip.dst

    packets.append(packet_dict)

    # Insert into MongoDB
    if len(packets) >= BATCH_SIZE:
        collection.insert_many(packets)
        print(f"Inserted {len(packets)} packets")
        packets.clear()


print("Starting Capture")
# Live capture setup
capture = pyshark.LiveCapture(interface=INTERFACE)
# capture = pyshark.LiveCapture()

# Apply packet capture
try:
    for packet in capture.sniff_continuously():
        packet_callback(packet)
finally:
    if(packets):
        collection.insert_many(packets)

    capture.close()
    client.close()

