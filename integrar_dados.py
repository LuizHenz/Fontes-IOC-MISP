import requests
import json
import os
from pymisp import MISPEvent, ExpandedPyMISP
from dotenv import load_dotenv

FEEDS = {
    "AlienVault OTX": {
        "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
        "api_key": "f2d15b8b25ace89c2a2485c35e3208be0f70bba740bff19e8b43880ba5978c40",
        "headers": {
            "X-OTX-API-KEY": "f2d15b8b25ace89c2a2485c35e3208be0f70bba740bff19e8b43880ba5978c40",
        }
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

def generate_external_analysis():
    all_data = {}
    for feed_name, config in FEEDS.items():
        data = fetch_data(feed_name, config)
        if data:
            all_data[feed_name] = data

    save_data_to_single_file("all_feeds_data.json", all_data)
    return all_data

def format_to_misp_model():

    dados = generate_external_analysis()

    events = []

    for result in dados['AlienVault OTX']["results"]:
			
        event = {
            "org_id": 1,
            "info": result["name"],
            "description": result["description"],
            "date": result["created"].split("T")[0],
            "analysis": 2,
            "distribution": 1,
            "threat_level_id": 2,
            "tlp": result["tlp"],
            "attributes": []
        }

        for indicator in result["indicators"]:
            attribute = {
                "type": get_misp_type(indicator["type"]),
                "category": "External analysis",
                "value": indicator["indicator"]
            }
            event["attributes"].append(attribute)

        events.append(event)
    return events

def get_misp_type(indicator_type):
		mapping = {
			"FileHash-MD5": "md5",
			"FileHash-SHA1": "sha1",
			"FileHash-SHA256": "sha256",
			"URL" : "url",
			"CVE": "vulnerability",
			"hostname": "hostname",
			"IPv4": "ip-src",
			"domain": "domain"
		}
		return mapping.get(indicator_type, "other")


def main(misp_instance):

    events = format_to_misp_model()

    for e in events:
			
        event = MISPEvent()

        event.info = e['info']
        event.date = e['date']
        event.analysis = e['analysis']
        event.distribution = e['distribution']
        event.org_id = e['org_id']
        event.threat_level_id = e['threat_level_id']
        event.add_tag(f'tlp:{e['tlp']}')

        event.add_attribute(type='text', category='External analysis', value=e['description'])
            
        for attr in e['attributes']:
            event.add_attribute(type=attr['type'], category=attr['category'], value=attr['value'])

        response = misp_instance.add_event(event)



if __name__ == "__main__":

    load_dotenv()

    MISP_URL = os.environ.get('MISP_URL')
    MISP_KEY = os.environ.get('MISP_KEY')
    MISP_VERIFY_CERT = False

    #Se caso houver certificado mudar a variável MISP_VERIFY_CERT para uma que aponte para o certificado
    misp = ExpandedPyMISP(MISP_URL, MISP_KEY, MISP_VERIFY_CERT)

    try:
        main(misp)
    except Exception as e:
        print("Error to create event", str(e))