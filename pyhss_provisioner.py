import yaml
import httpx
from httpx import AsyncClient
import json
from pprint import pprint
from fastapi.responses import JSONResponse
from fastapi import FastAPI, Request
from pydantic import BaseModel
from typing import Dict, List

pyhss_provisioner = FastAPI(
    title="PyHSS Provisioner",
    description="Centralized provisioner, supporting multiple PyHSS endpoints.",
    version="1.0.0",
)

class PyHssProvisioner:
    def __init__(self, config_file):
        with open(config_file, 'r') as file:
            self.config = yaml.safe_load(file)

        self.hss_hosts = self.config.get('geored', {}).get('sync_endpoints', [])
        self.provisioning_key = self.config.get('hss', {}).get('provisioning_key', '')
        self.webhook_subscribers = self.config.get('webhooks', [])

    def build_response_body(self, host, status, data=None, failed=False):
        response_body = {
            "host": host,
            "status": status,
            "data": data if data else {},
            "failed": failed
        }
        return response_body

    async def ping(self, host):
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{host}/oam/ping", timeout=3)
            return self.build_response_body(host, response.status_code, response.json(), False)
        except Exception:
            return self.build_response_body(host, 500, "Unreachable", True)

    async def forward_requests(self, method, path, headers, data=None):
        headers['Provisioning-Key'] = self.provisioning_key
        ping_responses = []
        operation_responses = []

        # Ping all hosts first to ensure all are live before proceeding with operations.
        for host in self.hss_hosts:
            host_alive_check = await self.ping(host)
            if host_alive_check['status'] != 200:
                failed_response = self.build_response_body(host, host_alive_check['status'], host_alive_check['data'], True)
                ping_responses.append(failed_response)

        # If one or more host failed a ping check, cancel the operation and return the status of all hosts.
        if any(response['failed'] for response in ping_responses):
            return (500, {"responses": ping_responses})

        for host in self.hss_hosts:
            endpoint = f"{host}/{path}"
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.request(method, endpoint, headers=headers, json=data, timeout=2)
                response_data = response.json() if 'application/json' in response.headers.get('Content-Type', '') else {}
                if response.status_code // 100 != 2:  # Check if the response is not a 2xx status code
                    response_model = self.build_response_body(host, response.status_code, response_data, True)  # Set 'failed' to True
                    operation_responses.append(response_model)
                    break
                else:
                    response_model = self.build_response_body(host, response.status_code, response_data, False)
                    operation_responses.append(response_model)
            except httpx.RequestError as E:
                response_model = self.build_response_body(host, 500, "Unknown Error", True)  # Set 'failed' to True
                operation_responses.append(response_model)
                break

        # If any of the responses['failed'] is True, send back 500 along with the responses dict.
        # Else, just send back our responses from the PyHSS APIs.
        if any(response['failed'] for response in operation_responses):
            return (500, {"responses": operation_responses})
        else:
            return (200, {"responses": operation_responses})


    async def notify_webhook_subscribers(self, update_response):
        update_notification = json.dumps({"notification": update_response})
        for subscriber in self.webhook_subscribers:
            try:
                async with httpx.AsyncClient() as client:
                    await client.post(subscriber, json=update_notification, timeout=1)
            except httpx.RequestError:
                print(f"Error: Failed to send notification to {subscriber}")
                continue


provisioner = PyHssProvisioner('config.yaml')

class WebhookUrl(BaseModel):
    url: str

async def handle_request(request: Request, path: str):
    method = request.method
    headers = dict(request.headers)
    data = None

    if method in ['POST', 'PUT', 'PATCH']:
        data = await request.json()

    status_code, response = await provisioner.forward_requests(method, path, headers, data)
    await provisioner.notify_webhook_subscribers(response)

    return JSONResponse(content=response, status_code=status_code)

methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]

for method in methods:
    pyhss_provisioner.add_api_route(
        path="/{path:path}",
        endpoint=handle_request,
        methods=[method],
        name=f"handle_request_{method.lower()}",
    )
