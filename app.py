import requests
from flask import Flask, jsonify, request
from packetSniffer import pkt_sniffer, set_active, get_packets, clear_packets, set_filters
from threading import Thread
from time import sleep

app = Flask(__name__)


@app.route('/start', methods=['POST'])
def start_sniff_api():
    data = request.get_json()
    set_filters(data)
    sleep(1)
    set_active(True)
    Thread(target=pkt_sniffer).start()
    return 'started'


@app.route('/stop')
def stop_sniff_api():
    set_active(False)
    return 'stopped'


@app.route('/get_packets')
def return_packets():
    packets = jsonify(get_packets())
    clear_packets()
    return packets


if __name__ == '__main__':
    app.run()
