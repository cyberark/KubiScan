# config.py

class Config:
    api_client = None

def set_api_client(client):
    Config.api_client = client

def get_api_client():
    return Config.api_client
