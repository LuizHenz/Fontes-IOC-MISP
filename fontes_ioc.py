import requests
import json

FEEDS = {
    "AlienVault OTX": {
        "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
        "api_key": "f2d15b8b25ace89c2a2485c35e3208be0f70bba740bff19e8b43880ba5978c40",
        "headers": {
            "X-OTX-API-KEY": "f2d15b8b25ace89c2a2485c35e3208be0f70bba740bff19e8b43880ba5978c40",
        }
    },
    "URLhaus Recent URLs": {
        "url": "https://urlhaus-api.abuse.ch/v1/urls/recent/",
    },
    "URLhaus Recent Payloads": {
        "url": "https://urlhaus-api.abuse.ch/v1/payloads/recent/",
    }
}

def fetch_data(feed_name, config):
    
    print(f"Buscando dados do feed: {feed_name}")
    try:
        if "headers" in config:
            headers = config.get("headers", {})
            response = requests.get(config["url"], headers=headers)
        elif "payload" in config:
            response = requests.post(config["url"], data=config["payload"])
        else:
            response = requests.get(config["url"])

        if response.status_code == 200:
            return response.json()
        else:
            print(f"Erro ao buscar dados do feed {feed_name}: {response.status_code}")
            return None
    except Exception as e:
        print(f"Erro na requisição para o feed {feed_name}: {e}")
        return None

def save_data_to_single_file(output_file, all_data):
    with open(output_file, "w") as f:
        json.dump(all_data, f, indent=4)
    print(f"Todos os dados foram salvos em {output_file}")

def main():
    all_data = {}
    for feed_name, config in FEEDS.items():
        data = fetch_data(feed_name, config)
        if data:
            all_data[feed_name] = data

    save_data_to_single_file("all_feeds_data.json", all_data)

if __name__ == "__main__":
    main()
