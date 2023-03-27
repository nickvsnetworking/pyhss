import yaml
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

class PyHssProvisioner:
    def __init__(self, config_file):
        with open(config_file, 'r') as file:
            self.config = yaml.safe_load(file)

        self.hss_hosts = self.config.get('geored', {}).get('sync_endpoints', [])
        self.provisioning_key = self.config.get('hss', {}).get('provisioning_key', '')
        self.webhook_subscribers = []

    def ping(self, host):
        try:
            response = requests.get(f"{host}/oam/ping", timeout=3)
            if response.status_code == 200 and response.json().get('result') == 'OK':
                return True
        except requests.exceptions.RequestException:
            pass
        return False

    def forward_request(self, method, path, headers, data=None):
        headers['Provisioning-Key'] = self.provisioning_key
        responses = []

        for host in self.hss_hosts:
            if not self.ping(host):
                return (500, {'error': 'Unreachable host', 'host': host})

            endpoint = f"{host}/{path}"
            response = requests.request(method, endpoint, headers=headers, json=data)

            if response.status_code // 100 != 2:
                return (500, {'error': 'Non-2xx response', 'host': host, 'status_code': response.status_code})

            responses.append(response.json())

        return (200, responses)

    def forward_request_to_all(self, method, path, headers, data=None):
        headers['Provisioning-Key'] = self.provisioning_key

        for host in self.hss_hosts:
            if self.ping(host):
                endpoint = f"{host}/{path}"
                response = requests.request(method, endpoint, headers=headers, json=data)
                self.notify_webhook_subscribers(response)

    def notify_webhook_subscribers(self, response):
        for subscriber in self.webhook_subscribers:
            requests.post(subscriber, json=response.json())

provisioner = PyHssProvisioner('config.yaml')

@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
def handle_request(path):
    method = request.method
    headers = dict(request.headers)
    data = None

    if method in ['POST', 'PUT', 'PATCH']:
        data = request.get_json(force=True)

    print("Sending data")
    status_code, response = provisioner.forward_request(method, path, headers, data)
    if status_code == 200:
        provisioner.forward_request_to_all(method, 'updates', headers, data)
    return jsonify(response), status_code


@app.route('/webhook', methods=['POST'])
def register_webhook():
    url = request.get_json().get('url')
    if url:
        provisioner.webhook_subscribers.append(url)
        return jsonify({'result': 'OK'}), 200
    else:
        return jsonify({'error': 'Invalid request'}), 400

if __name__ == '__main__':
    app.run(debug=True, port=7080)