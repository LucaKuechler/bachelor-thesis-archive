import requests
from datetime import datetime, timedelta
from alive_progress import alive_bar
from custom_types import SplunkSearchJob, DataFileHandler, Rule
from constants import SPLUNK_USERNAME, SPLUNK_PASSWORD, SPLUNK_URL, DAYS_AGO
import time
import requests

from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def send_query_to_splunk(search_query: str, oh: DataFileHandler) -> str:
    start_time, end_time, _ = oh.get_malware_execution_time()
    earliest_time = datetime.utcfromtimestamp(start_time / 1000).strftime("%Y-%m-%dT%H:%M:%S")
    latest_time = datetime.utcfromtimestamp(end_time / 1000).strftime("%Y-%m-%dT%H:%M:%S")

    post_data = {
        "search": "search source=\"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\" " + search_query,
        "earliest_time": earliest_time,
        "latest_time": latest_time,
        "output_mode": "json",
    }

    request_url = f"{SPLUNK_URL}/servicesNS/{SPLUNK_USERNAME}/search/search/jobs"

    resp = requests.post(
        request_url,
        data=post_data,
        verify=False,
        auth=(SPLUNK_USERNAME, SPLUNK_PASSWORD),
    )

    if not resp.ok:
        raise Exception(
            f"Invalid HTML response, StatusCode: {resp.status_code} and Error: {resp.text}"
        )

    return resp.json().get("sid")


def validate_all_jobs(
    started_jobs: list[SplunkSearchJob], oh: DataFileHandler, bar
) -> list[SplunkSearchJob]:
    time.sleep(10)

    requote_url = (
        f"{SPLUNK_URL}/servicesNS/{SPLUNK_USERNAME}/search/search/jobs?output_mode=json"
    )
    resp = requests.get(
        requote_url, verify=False, auth=(SPLUNK_USERNAME, SPLUNK_PASSWORD)
    )

    if not resp.ok:
        raise Exception("Invalid HTML response")

    res = resp.json()
    if not res.get("entry"):
        raise Exception("Invalid Json response")

    for entry in res["entry"]:
        state: str = entry["content"]["dispatchState"]
        job_id: str = entry["content"]["sid"]
        event_count: int = entry["content"]["eventCount"]

        for x in started_jobs:
            if job_id == x.job_id and state == "DONE":
                started_jobs.remove(x)
                oh.write_splunk(event_count, x.title)
                bar()

    return started_jobs


def validate_job_by_id(job_id: str) -> int:
    requote_url = f"{SPLUNK_URL}/servicesNS/{SPLUNK_USERNAME}/search/search/jobs/{job_id}?output_mode=json"
    resp = requests.get(
        requote_url, verify=False, auth=(SPLUNK_USERNAME, SPLUNK_PASSWORD)
    )

    if not resp.ok:
        raise Exception("Invalid HTML response")

    res = resp.json()
    if not res.get("entry"):
        raise Exception("Invalid Json response")

    state: str = res["entry"][0]["content"]["dispatchState"]
    event_count: int = res["entry"][0]["content"]["eventCount"]

    if state == "DONE":
        return event_count

    return -1


def splunk_job_validation_handler(
    started_jobs: list[SplunkSearchJob], oh: DataFileHandler
) -> None:
    print(f"Processing {len(started_jobs)} Splunk Queries:")

    # 1) first get all jobs after certain timeout
    with alive_bar(len(started_jobs)) as bar:
        open_jobs: list[SplunkSearchJob] = validate_all_jobs(
            started_jobs.copy(), oh, bar
        )

        # 2) check status for all jobs that were not done after the first request
        for ssj in open_jobs:
            event_count = validate_job_by_id(ssj.job_id)
            if event_count > -1:
                oh.write_splunk(event_count, ssj.title)
                open_jobs.remove(ssj)
                bar()

    print("")


def run_splunk_search_jobs(oh: DataFileHandler, rules: list[Rule]) -> None:
    started_jobs: list[SplunkSearchJob] = []

    # send a query for each rule to the splunk server
    for rule in rules:
        job_id = send_query_to_splunk(rule.rule, oh)
        started_jobs.append(SplunkSearchJob(job_id=job_id, title=rule.title))

    # run till all splunk jobs have been finished.
    splunk_job_validation_handler(started_jobs, oh)
