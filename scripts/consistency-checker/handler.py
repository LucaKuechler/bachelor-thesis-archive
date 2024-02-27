from custom_types import RuleReader, Rule, DataFileHandler
from splunk import run_splunk_search_jobs
from elastic import run_elasticsearch_jobs
from insight import run_insight_search_jobs


def handle_all(oh: DataFileHandler, reader: RuleReader) -> None:
    print("\n\n")

    # execute and validate search queries
    run_splunk_search_jobs(oh, reader.splunk_rules)

    # execute and validate search queries
    run_elasticsearch_jobs(oh, reader.elastic_rules)

    # execute and validate search queries
    run_insight_search_jobs(oh, reader.insight_rules)


def handle_splunk(oh: DataFileHandler, rules: list[Rule]) -> None:
    print("\n\n")
    # execute and validate search queries
    run_splunk_search_jobs(oh, rules)


def handle_elasticsearch(oh: DataFileHandler, rules: list[Rule]) -> None:
    print("\n\n")

    # execute and validate search queries
    run_elasticsearch_jobs(oh, rules)


def handle_insight(oh: DataFileHandler, rules: list[Rule]) -> None:
    print("\n\n")

    run_insight_search_jobs(oh, rules)
