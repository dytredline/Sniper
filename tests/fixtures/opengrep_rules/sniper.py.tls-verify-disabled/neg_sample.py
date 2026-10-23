import requests

def get(u):
    return requests.get(u, verify=True, timeout=5)
