from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient
from bson import json_util
import configparser

config = configparser.ConfigParser()
config.read('conf.ini')

MONGO_HOST = config['mongo']['host']
MONGO_PORT = int(config['mongo']['port'])
MONGO_DB = config['mongo']['db']
MONGO_COLLECTION = config['mongo']['collection']

FLASK_HOST = config['flask']['host']
FLASK_PORT = int(config['flask']['port'])

app = Flask(__name__)
CORS(app)

client = MongoClient(MONGO_HOST, MONGO_PORT)
db = client[MONGO_DB]
collection = db[MONGO_COLLECTION]

@app.route('/distinct_layers', methods=['GET'])
def get_distinct_packet_layers():
    layers = list(collection.distinct("highest_layer"))
    return jsonify(layers)

@app.route('/packets', methods=['GET'])
def get_packets():
    layer = request.args.get('layer', default=None)
    before_date = request.args.get('before_date', default=None)
    after_date = request.args.get('after_date', default=None)
    limit = int(request.args.get('limit', default=0))

    query = {}
    if layer:
        query['highest_layer'] = layer
    if before_date:
        query['timestamp'] = {'$lt': before_date}
    if after_date:
        query['timestamp'] = {'$gt': after_date}

    # Aggregation pipeline to group packets by intervals (e.g., by minute)
    pipeline = [
        {"$match": query},
        {"$group": {
            "_id": {
                "year": {"$year": "$timestamp"},
                "month": {"$month": "$timestamp"},
                "day": {"$dayOfMonth": "$timestamp"},
                "hour": {"$hour": "$timestamp"},
                "minute": {"$minute": "$timestamp"},
            },
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id": 1}}
    ]
    
    packets = list(collection.aggregate(pipeline))
    if limit:
        packets = packets[:limit]

    return json_util.dumps(packets)

@app.route('/network_graph', methods=['GET'])
def network_graph():
    pipeline = [
        {
            "$group": {
                "_id": {
                    "src_ip": "$src_ip",
                    "dest_ip": "$dest_ip",
                    "highest_layer": "$highest_layer"
                },
                "count": {"$sum": 1}
            }
        }
    ]

    aggregated_data = list(collection.aggregate(pipeline))

    nodes_set = set()
    links = []

    for entry in aggregated_data:
        src_ip = entry["_id"].get("src_ip", "Unknown")
        dest_ip = entry["_id"].get("dest_ip", "Unknown")
        highest_layer = entry["_id"].get("highest_layer", "Unknown")

        if highest_layer != "IP":  # Change as needed
            nodes_set.add(src_ip)
            nodes_set.add(dest_ip)
            links.append({"source": src_ip, "target": dest_ip})

    nodes = [{"id": node} for node in nodes_set]

    graph = {
        "nodes": nodes,
        "links": links
    }

    return jsonify(graph)

@app.route('/top_talkers', methods=['GET'])
def get_top_talkers():
    layer = request.args.get('layer', default=None)
    before_date = request.args.get('before_date', default=None)
    after_date = request.args.get('after_date', default=None)
    limit = int(request.args.get('limit', default=0))

    query = {}
    if layer:
        query['highest_layer'] = layer
    if before_date:
        query['timestamp'] = {'$lt': before_date}
    if after_date:
        query['timestamp'] = {'$gt': after_date}

    pipeline = [
        {"$match": {"src_ip": {"$exists": True}, "dest_ip": {"$exists": True}}},
        {"$match": query},
        {"$group": {
            "_id": {
                "src_ip": "$src_ip",
                "dest_ip": "$dest_ip",
            },
            "total_length": {"$sum": "$length"}
        }},
        {"$sort": {"total_length": -1}}
    ]


    top_talkers = list(collection.aggregate(pipeline))

    # Format the data as needed
    formatted_data = [{"name": f"{entry['_id']['src_ip']} to {entry['_id']['dest_ip']}", "value": entry["total_length"]} for entry in top_talkers]

    if limit:
        formatted_data = formatted_data[:limit]

    return jsonify(formatted_data)

@app.route('/protocol_distribution', methods=['GET'])
def get_protocol_distribution():
    pipeline = [
        {"$group": {
            "_id": "$highest_layer",
            "count": {"$sum": 1}
        }},
        {"$sort": {"count": -1}}
    ]

    protocol_data = list(collection.aggregate(pipeline))
    
    # Format the data for the frontend
    formatted_data = [{"protocol": entry["_id"], "value": entry["count"]} for entry in protocol_data]

    return jsonify(formatted_data)


if __name__ == '__main__':
    app.run(
        host=FLASK_HOST,
        port=FLASK_PORT,
        debug=True
        )
