import time
from requests import Session, Response
from constants import INSIGHT_API_KEY


class RateLimitedException(Exception):
    def __init__(self, message: str, secs_until_reset: int):
        super().__init__(message)
        self.secs_until_reset = secs_until_reset


def is_query_in_progress(query_response: Response) -> bool:
    if "links" not in query_response.json():
        return False
    elif "Next" in [link["rel"] for link in query_response.json()["links"]]:
        return False
    elif "Self" in [link["rel"] for link in query_response.json()["links"]]:
        return True
    raise Exception(
        "LogSearch query returned an invalid response body according to their spec "
        '- contains a "links" object, which does not contain a link with either '
        '"rel" equal to "Next" or "Self"'
    )


def poll_request_to_completion(
    logsearch_session: Session, query_in_progress_response: Response
) -> Response:
    """
    "continuation" polls expire after 10 seconds, so we must not wait too long between
    requests. However we must not poll too frequently for long-running queries or we
    risk being rate limited.
    """
    if query_in_progress_response.status_code == 429:
        secs_until_reset = query_in_progress_response.headers.get("X-RateLimit-Reset")
        raise RateLimitedException(
            f"Log Search API Key was rate limited. Seconds until rate limit reset: {secs_until_reset}",
            int(secs_until_reset),
        )

    if not is_query_in_progress(query_in_progress_response):
        return query_in_progress_response

    poll_delay_secs = 0.5
    max_poll_delay_secs = 6
    links = {
        link["rel"]: link["href"] for link in query_in_progress_response.json()["links"]
    }
    while "Self" in links:
        time.sleep(poll_delay_secs)

        resp = logsearch_session.get(
            links["Self"], headers={"x-api-key": INSIGHT_API_KEY}
        )

        if resp.status_code == 429:
            secs_until_reset = resp.headers.get("X-RateLimit-Reset")
            raise RateLimitedException(
                f"Log Search API Key was rate limited. Seconds until rate limit reset: {secs_until_reset}",
                int(secs_until_reset),
            )

        if not is_query_in_progress(resp):
            return resp

        poll_delay_secs = min(poll_delay_secs * 2, max_poll_delay_secs)
        links = {link["rel"]: link["href"] for link in resp.json()["links"]}


def has_next_page(query_response: Response) -> bool:
    return "links" in query_response.json() and "Next" in [
        link["rel"] for link in query_response.json()["links"]
    ]


def get_next_page_of_results(logsearch_session: Session, resp: Response) -> Response:
    links = {link["rel"]: link["href"] for link in resp.json()["links"]}
    return logsearch_session.get(links["Next"], headers={"x-api-key": INSIGHT_API_KEY})
