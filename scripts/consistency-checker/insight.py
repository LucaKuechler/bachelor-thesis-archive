import json
import time
from requests import Session, Response
from custom_types import DataFileHandler, Rule
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from constants import INSIGHT_URL, INSIGHT_API_KEY
from insight_helper import *


def perform_query(qid: str, s: Session, start_time, end_time) -> Response:
    try:
        resp = poll_request_to_completion(
            s,
            s.get(
                f"{INSIGHT_URL}query/saved_query/{qid}",
                headers={"x-api-key": INSIGHT_API_KEY},
                params={"from": start_time, "to": end_time},
            ),
        )
        return resp

    except RateLimitedException as e:
        print(
            f"Log Search API Key was rate limited. Sleeping for {e.secs_until_reset} seconds"
        )
        time.sleep(e.secs_until_reset)
        return perform_query(qid, s, start_time, end_time)


def _list_saved_queries(s: Session) -> list[dict[str, str]]:
    resp = s.get(
        f"{INSIGHT_URL}/query/saved_queries",
        headers={"x-api-key": INSIGHT_API_KEY},
    )

    if resp.status_code != 200:
        print("Error: could not load saved queries.")
        exit(-1)

    return resp.json()["saved_queries"]


def _save_query(rule: Rule, s: Session) -> str:
    saved_query = {
        "saved_query": {
            "name": rule.title[-32:],
            "leql": {
                "statement": f"where({rule.rule}) calculate(count)",
            },
            "logs": ["830d8eb6-0bab-4b76-a924-bc1fcb18ade7"],
        }
    }
    # saved_query = {
    #     "saved_query": {
    #         "name": rule.title[-32:],
    #         "leql": {
    #             "statement": f"where({rule.rule}) calculate(count)",
    #             "during": {
    #                 # "time_range": "last 5 minutes",
    #                 "from": 1705542398561,
    #                 "to": 1705598818561,
    #             },
    #         },
    #         "logs": ["c5b3eba2-ad70-4ca4-b5ec-7a18930746dd"],
    #     }
    # }

    resp = s.post(
        f"{INSIGHT_URL}query/saved_queries",
        headers={"x-api-key": INSIGHT_API_KEY},
        json=saved_query,
    )

    if resp.status_code != 201:
        print("Error - Rule has not been saved: ", rule.title, resp.content)

    return resp.json()["saved_query"]["id"]


def run_insight_search_jobs(oh: DataFileHandler, rules: list[Rule]):
    """
    Execute the stored searches.
    """
    session = Session()
    session.mount(
        INSIGHT_URL,
        HTTPAdapter(
            max_retries=(
                # Handles rate limiting by default, by sleeping until the limit has reset before retrying.
                Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
            )
        ),
    )

    start_time, end_time, _ = oh.get_malware_execution_time()
    for rule in rules:
        query_results_page = perform_query(rule.id, session, start_time, end_time)

        # while has_next_page(query_results_page):
        #     try:
        #         query_results_page = poll_request_to_completion(
        #             session, get_next_page_of_results(session, query_results_page)
        #         )
        #         #print(json.dumps(query_results_page.json(), indent=4))
        #     except RateLimitedException as e:
        #         print(
        #             f"Log Search API Key was rate limited. Sleeping for {e.secs_until_reset} seconds"
        #         )
        #         time.sleep(e.secs_until_reset)

        # print(
        #     f"Rule: {rule.title} has | {query_results_page.json()['search_stats']['events_matched']} | detections and | {query_results_page.json()['search_stats']['events_all']} | events in total."
        # )

        oh.write_insight(
            query_results_page.json()["search_stats"]["events_matched"],
            query_results_page.json()["search_stats"]["events_all"],
            rule.title,
        )


def initial_insight(rules: list[Rule]):
    """
    Save searches to the siem and read out ids.
    """
    session = Session()
    session.mount(
        INSIGHT_URL,
        HTTPAdapter(
            max_retries=(
                # Handles rate limiting by default, by sleeping until the limit has reset before retrying.
                Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
            )
        ),
    )

    # list all queries that are stored inside insightIDR by name and id.
    queries = {
        query.get("name"): query.get("id") for query in _list_saved_queries(session)
    }

    for rule in rules:
        # check if rule title is found in saved queries from insight_idr
        query_id = queries.get(rule.title[-32:])

        # if rule is not in queries it needs to be saved
        if not query_id:
            print(f"Created Query for rule: {rule.title}")
            query_id = _save_query(rule, session)

        rule.id = query_id

    session.close()
