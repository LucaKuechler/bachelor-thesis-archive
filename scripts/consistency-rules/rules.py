from typing import Any
from sigma.collection import SigmaRule
from sigma.backends.insight_idr import InsightIDRBackend

from sigma.backends.splunk import SplunkBackend
from sigma.pipelines.splunk import splunk_windows_pipeline

from sigma.backends.elasticsearch import LuceneBackend
from sigma.pipelines.elasticsearch import ecs_windows


def generate_insightidr_rule(rule: SigmaRule) -> Any:
    return InsightIDRBackend().convert_rule(rule)[0]


def generate_splunk_rule(rule: SigmaRule) -> Any:
    return SplunkBackend(splunk_windows_pipeline()).convert_rule(rule)[0]


def generate_elastic_rule(rule: SigmaRule) -> Any:
    return LuceneBackend(ecs_windows()).convert_rule(rule)[0]
