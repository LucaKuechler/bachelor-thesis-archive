from datetime import datetime, timedelta
from custom_types import DataFileHandler, Rule
from alive_progress import alive_bar
from constants import (
    ELASTIC_USERNAME,
    ELASTIC_PASSWORD,
    ELASTIC_URL,
    ELASTIC_INDEX,
    DAYS_AGO,
)
from elasticsearch import Elasticsearch

def _search_total_amount(es: Elasticsearch, oh: DataFileHandler) -> None:
    start_time, end_time, _ = oh.get_malware_execution_time()
    start_time = datetime.utcfromtimestamp(start_time / 1000).isoformat()
    end_time = datetime.utcfromtimestamp(end_time / 1000).isoformat()

    query = {
        "query": {
            "bool": {
                "must": [
                    {"query_string": {"query": "event.dataset:windows.sysmon_operational"}},
                    {"range": {"@timestamp": {"gte": start_time, "lte": end_time}}},
                ]
            }
        },
        "_source": False,
        "size": 0,
    }

    resp = es.search(index=ELASTIC_INDEX, body=query)  # type: ignore
    DataFileHandler.elastic_event_total = resp["hits"]["total"]["value"]


def _send_search_request(es: Elasticsearch, rule: str, oh: DataFileHandler) -> int:
    start_time, end_time, _ = oh.get_malware_execution_time()
    # start_time = (datetime.now() - timedelta(days=DAYS_AGO)).isoformat()  # 7 days ago
    # end_time = datetime.now().isoformat()
    start_time = datetime.utcfromtimestamp(start_time / 1000).isoformat()
    end_time = datetime.utcfromtimestamp(end_time / 1000).isoformat()

    query = {
        "query": {
            "bool": {
                "must": [
                    {"query_string": {"query": rule}},
                    {"range": {"@timestamp": {"gte": start_time, "lte": end_time}}},
                ]
            }
        },
        "_source": False,
        "size": 0,
    }

    resp = es.search(index=ELASTIC_INDEX, body=query)  # type: ignore
    print(resp)
    return resp["hits"]["total"]["value"]


def run_elasticsearch_jobs(oh: DataFileHandler, rules: list[Rule]) -> None:
    es = Elasticsearch(
        ELASTIC_URL,
        basic_auth=(ELASTIC_USERNAME, ELASTIC_PASSWORD),
        verify_certs=False,
    )

    if not es.ping():
        raise Exception(f"Can't connect to Elasticsearch instance.")

    _search_total_amount(es, oh)

    print(f"\nProcessing {len(rules)} Elasticsearch Queries:")
    with alive_bar(len(rules)) as bar:
        for rule in rules:
            event_count = _send_search_request(es, rule.rule, oh)
            oh.write_elastic(event_count, rule.title)
            bar()
