import os
import json
import urllib.request
from urllib.parse import urlparse

from elasticsearch import Elasticsearch
from datetime import datetime, timedelta, timezone

# Get latest C2 / phising domain lists
urllib.request.urlretrieve("https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt", "openphish.txt")
with open("openphish.txt", "r") as f:
    phishing_domains = { urlparse(line.strip()).netloc for line in f.readlines() if line.strip() }

phishing_domains.add("google.com")  # Remove empty entries if any
print(len(phishing_domains))  # Print first 10 domains for verification

# Get Elasticsearch configuration from environment variables file
env_file = '../elk/.env'
if os.path.isfile(env_file):
    with open(env_file) as f:
        for line in f:
            if line.strip() and not line.startswith('#'):
                key, value = line.strip().split('=', 1)
                os.environ[key] = value

ES_HOST = "https://localhost:9200"
ES_USER = "elastic"
ES_PASSWORD = os.getenv('ELASTIC_PASSWORD', None)
ES_CA_CERT = "../elk/installation_scripts/ca.crt"

# Initialize Elasticsearch client with optional authentication and SSL settings
es_kwargs = {
    'hosts': [ES_HOST],
    'verify_certs': True,
    'ca_certs': ES_CA_CERT,
    'basic_auth': (ES_USER, ES_PASSWORD)
}

es = Elasticsearch(**es_kwargs)

# Calculate the date range
days = 90
end_time = datetime.now(timezone.utc)
start_time = end_time - timedelta(days=days)

# Format timestamps for Elasticsearch (ISO 8601)
start_timestamp = start_time.isoformat().replace('+00:00', 'Z')
end_timestamp = end_time.isoformat().replace('+00:00', 'Z')

# Define the query for Sysmon DNS events
query = {
    "query": {
        "bool": {
            "must": [
                {
                    "match": {
                        "event.code": 22  # Sysmon Event ID 22 = DNS Query
                    }
                },
                {
                    "range": {
                        "@timestamp": {
                            "gte": start_timestamp,
                            "lte": end_timestamp
                        }
                    }
                }
            ]
        }
    },
    "sort": ["_doc"],
    "_source": [
        "@timestamp",
        "event.code",
        "dns.question.name",
        "process.pid",
        "process.name",
        "process.executable",
        "host.hostname"
    ]
}

dns_events = []
page_size = 2000

# Create a Point in Time for consistent pagination
pit_response = es.open_point_in_time(index="*", keep_alive="1m")
pit_id = pit_response['id']

search_after = None
page_count = 0

while True:
    page_count += 1
    
    # Prepare pagination parameters
    search_query = query.copy()
    search_query['size'] = page_size
    search_query['pit'] = {'id': pit_id, 'keep_alive': '1m'}
    
    if search_after:
        search_query['search_after'] = search_after
    
    # Remove index from body since we're using PIT
    if 'index' in search_query:
        del search_query['index']
    
    # Execute the search
    response = es.search(body=search_query)
    
    # Extract hits
    hits = response['hits']['hits']
    if not hits:
        break
    
    for hit in hits:
        if hit["_source"].get("dns", {}).get("question", {}).get("name", "") in phishing_domains:
            print(f'Houston, we have a problem! Detected DNS query to known phishing/C2 domain: {hit["_source"]["dns"]["question"]["name"]}')
            dns_events.append(hit)

    
    print(f"Retrieved page {page_count} ({len(hits)} events)")
    
    # Prepare search_after for next page
    search_after = hits[-1]['sort']
    
    # Update PIT ID
    pit_id = response['pit_id']

# Close the Point in Time
es.close_point_in_time(body={'id': pit_id})

print(f"Retrieved {len(dns_events)} total DNS query events from the last {days} days")
    
