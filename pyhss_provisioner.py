import yaml
import requests
import json
from pprint import pprint
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from typing import Dict, List
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

pyhss_provisioner = FastAPI()

class PyHssProvisioner:
    def __init__(self, config_file):
        with open(config_file, 'r') as file:
            self.config = yaml.safe_load(file)

        self.hss_hosts = self.config.get('geored', {}).get('sync_endpoints', [])
        self.provisioning_key = self.config.get('hss', {}).get('provisioning_key', '')
        self.webhook_subscribers = self.config.get('webhooks', [])

        self.session = requests.Session()
        retries = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["GET", "POST", "PUT", "PATCH", "DELETE"]
        )
        self.session.mount("http://", HTTPAdapter(max_retries=retries))

    def build_response_body(self, host, status, data=None, failure=False):
        response_body = {
                "host": host,
                "status": status,
                "data": data if data else {},
                "failure": failure
            }
        return response_body

    def ping(self, host):
        try:
            response = self.session.get(f"{host}/oam/ping", timeout=3)
            return self.build_response_body(host, response.status_code, response.json(), False)
        except Exception:
            return self.build_response_body(host, 500, "Unreachable", True)

    def forward_requests(self, method, path, headers, data=None):
        headers['Provisioning-Key'] = self.provisioning_key
        responses = []
        host_alive_check_list = []
        failed_hosts = []

        for host in self.hss_hosts:
            host_alive_check_list.append(self.ping(host))
        
            for host_alive_check in host_alive_check_list:
                if host_alive_check['status'] != 200:
                    failed_hosts.append(host_alive_check)
        
            if len(failed_hosts) > 0:
                return (500, {"responses": failed_hosts})

            endpoint = f"{host}/{path}"
            try:
                response = self.session.request(method, endpoint, headers=headers, json=data)
                response_model = self.build_response_body(host, response.status_code, response.json(), False)
            except requests.exceptions.RequestException:
                failed_hosts.append(host)
                response_model = self.build_response_body(host, response.status_code, response.json(), False)
                continue

            if response.status_code // 100 != 2:
                failed_hosts.append(host)
                response_model = self.build_response_body(host, response.status_code, response.json(), False)
                continue

            if len(failed_hosts) > 0:
                return failed_hosts

            responses.append(response_model)

        return (200, {"responses": responses})


    def forward_request_to_all(self, method, path, headers, data=None):
        headers['Provisioning-Key'] = self.provisioning_key

        for host in self.hss_hosts:
            if self.ping(host):
                endpoint = f"{host}/{path}"
                try:
                    response = self.session.request(method, endpoint, headers=headers, json=data)
                except requests.exceptions.RequestException:
                    continue

                self.notify_webhook_subscribers(response)

    def notify_webhook_subscribers(self, update_response):
        update_notification = json.dumps({"notification": update_response})
        for subscriber in self.webhook_subscribers:
            try:
                self.session.post(subscriber, json=update_notification)
            except requests.exceptions.RequestException:
                print(f"Error: Failed to send notification to {subscriber}")
                continue

provisioner = PyHssProvisioner('config.yaml')

class WebhookUrl(BaseModel):
    url: str

@pyhss_provisioner.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def handle_request(request: Request, path: str):
    method = request.method
    headers = dict(request.headers)
    data = None

    if method in ['POST', 'PUT', 'PATCH']:
        data = await request.json()

    status_code, response = provisioner.forward_requests(method, path, headers, data)
    pprint(response)
    provisioner.notify_webhook_subscribers(response)
    return response