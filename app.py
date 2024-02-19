from flask import Flask

from packetSniffer import *
app = Flask(__name__)


@app.route('/')
def hello_world():  # put application's code here

    return 'Hello World!'


@app.route('/start')
def start_sniff_api():  # put application's code here
    start_scan()
    return 'started'


@app.route('/stop')
def stop_sniff_api():  # put application's code here
    stop_scan()
    return 'stopped'


if __name__ == '__main__':
    app.run()
