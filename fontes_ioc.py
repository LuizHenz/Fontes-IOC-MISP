import requests
import json

# Configuração da API para cada feed
FEEDS = {
    "AlienVault OTX": {
        "url": "https://otx.alienvault.com/api/v1/indicators",
        "api_key": "SEU_API_KEY",
        "headers": {
            "X-OTX-API-KEY": "SEU_API_KEY",
        }
    },
    "URLhaus": {
        "url": "https://urlhaus.abuse.ch/api/",
        "payload": {"query": "get_recent"},
    },
    "Feodo Tracker": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    },
    "Spamhaus": {
        "url": "https://www.spamhaus.org/drop/drop.txt",
    },
    "Emerging Threats": {
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    },
    "Malware Patrol": {
        "url": "https://www.malwarepatrol.net/api/feed/",
        "api_key": "SEU_API_KEY",
        "params": {"format": "json"},
    },
    "VirusTotal": {
        "url": "https://www.virustotal.com/api/v3/feeds",
        "api_key": "SEU_API_KEY",
        "headers": {
            "x-apikey": "SEU_API_KEY",
        }
    }
}

def fetch_data(feed_name, config):
    """
    Função para buscar os dados de cada feed.
    """
    print(f"Buscando dados do feed: {feed_name}")
    try:
        if "api_key" in config:
            headers = config.get("headers", {})
            params = config.get("params", {})
            response = requests.get(config["url"], headers=headers, params=params)
        elif "payload" in config:
            response = requests.post(config["url"], data=config["payload"])
        else:
            response = requests.get(config["url"])

        if response.status_code == 200:
            return response.text
        else:
            print(f"Erro ao buscar dados do feed {feed_name}: {response.status_code}")
            return None
    except Exception as e:
        print(f"Erro na requisição para o feed {feed_name}: {e}")
        return None

def save_data(feed_name, data):
    """
    Salva os dados coletados de cada feed em um arquivo JSON.
    """
    file_name = f"{feed_name.replace(' ', '_').lower()}_data.json"
    with open(file_name, "w") as f:
        json.dump(data, f, indent=4)
    print(f"Dados salvos em {file_name}")

def main():
    for feed_name, config in FEEDS.items():
        data = fetch_data(feed_name, config)
        if data:
            if feed_name in ["Spamhaus", "Emerging Threats"]:
                # Para feeds baseados em texto puro, converte para lista
                data = data.splitlines()
            elif feed_name == "Feodo Tracker":
                data = json.loads(data)  # Feodo retorna JSON
            else:
                try:
                    data = json.loads(data)  # Tenta carregar JSON como padrão
                except json.JSONDecodeError:
                    print(f"Os dados do feed {feed_name} não estão em formato JSON.")
            save_data(feed_name, data)

if __name__ == "__main__":
    main()
