import json
import shutil
from pydantic import BaseModel
from pathlib import Path
from rich.console import Console
from rich.style import Style
from rich.table import Table

console = Console()


class Rule(BaseModel):
    title: str
    rule: str
    id: str = ""


class SplunkSearchJob(BaseModel):
    job_id: str
    title: str


class RuleReader:
    splunk_rules: list[Rule] = []
    elastic_rules: list[Rule] = []
    insight_rules: list[Rule] = []

    def __init__(self) -> None:
        pass

    @classmethod
    def read_from_file(cls, fp) -> None:
        with open(fp, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not data.get("rules"):
            raise Exception("Invalid json file given.")

        for rule in data["rules"]:
            cls.splunk_rules.append(Rule(title=rule["name"], rule=rule["splunk"]))
            cls.elastic_rules.append(Rule(title=rule["name"], rule=rule["elastic"]))
            cls.insight_rules.append(Rule(title=rule["name"], rule=rule["insightidr"]))


class OutputRow(BaseModel):
    splunk_event_count: int = -1
    elastic_event_count: int = -1
    insight_event_count: int = -1


class DataFileHandler:
    rows: dict[str, OutputRow] = {}
    insight_event_total: int = 0
    splunk_event_total: int = 0
    elastic_event_total: int = 0

    def __init__(self, number_of_malware: str, fp: str, malware_fp: str):
        self.number_of_malware = number_of_malware
        self.fp = fp
        self.malware_fp = malware_fp

    def get_malware_execution_time(self):
        # read out malware.json to get hash for malware number
        with open(self.malware_fp, "r") as file:
            samples = json.load(file)

        # read out data file to get malware execution times
        with open(self.fp, "r") as file:
            malware_hash = samples[self.number_of_malware]["sha256"]
            malware_infos = json.load(file)["samples"]

            for info in malware_infos:
                if info.get("hash") == malware_hash:
                    return info["start_time"], info["end_time"], malware_hash

        print("Files are not consistent")
        exit(-1)

    @classmethod
    def write_splunk(cls, event_count: int, title: str) -> None:
        # if already present in dict
        if cls.rows.get(title):
            cls.rows[title].splunk_event_count = event_count
            return

        cls.rows[title] = OutputRow(
            splunk_event_count=event_count,
        )

    @classmethod
    def write_insight(cls, event_count: int, events_total: int, title: str) -> None:
        cls.insight_event_total = events_total

        # if already present in dict
        if cls.rows.get(title):
            cls.rows[title].insight_event_count = event_count
            return

        cls.rows[title] = OutputRow(
            insight_event_count=event_count,
        )

    @classmethod
    def write_elastic(cls, event_count: int, title: str) -> None:
        # if already present in dict
        if cls.rows.get(title):
            cls.rows[title].elastic_event_count = event_count
            return

        cls.rows[title] = OutputRow(
            elastic_event_count=event_count,
        )

    def output(self) -> None:
        # if file path does not exist
        if not Path(self.fp).exists():
            print("Output filepath does not exsist!")
            exit(-1)

        # backup before editing
        shutil.copy2(self.fp, "/tmp/data2.json")

        # read out old data from data.json
        with open(self.fp, "r") as file:
            samples = json.load(file)

        sorted_keys = sorted(self.rows.keys())
        for i, sample in enumerate(samples["samples"]):
            _, _, hash = self.get_malware_execution_time()

            if sample.get("hash") == hash:
                samples["samples"][i][
                    "i_events_total"
                ] = DataFileHandler.insight_event_total
                samples["samples"][i][
                    "e_events_total"
                ] = DataFileHandler.elastic_event_total
                samples["samples"][i][
                    "s_events_total"
                ] = DataFileHandler.splunk_event_total

                for key in sorted_keys:
                    value = DataFileHandler.rows[key]
                    samples["samples"][i]["rules"].append(
                        {
                            "title": key,
                            "e": value.elastic_event_count,
                            "s": value.splunk_event_count,
                            "i": value.insight_event_count,
                        }
                    )

                with open(self.fp, "w") as file:
                    json.dump(samples, file)

    @classmethod
    def print(cls) -> None:
        print("\n\n")
        table = Table(
            show_header=True,
            title=f"(Total: insight={cls.insight_event_total} elastic={cls.elastic_event_total} splunk=0) Results:",
            padding=1,
        )
        table.add_column("Rule", justify="right", no_wrap=True)
        table.add_column("Splunk", justify="center")
        table.add_column("Elastic", justify="center")
        table.add_column("InsightIDR", justify="center")

        hit: int = 0
        miss: int = 0

        # sort keys alphabetic
        sorted_keys = sorted(cls.rows.keys())

        for key in sorted_keys:
            value = cls.rows[key]

            # create a set containing all values
            my_set = set(
                [
                    value.splunk_event_count,
                    value.elastic_event_count,
                    value.insight_event_count,
                ]
            )

            # 1.case all the same
            if len(my_set) == 1:
                table.add_row(
                    key,
                    str(value.splunk_event_count),
                    str(value.elastic_event_count),
                    str(value.insight_event_count),
                    style=Style(color="white", bgcolor="green", bold=True),
                )
                hit += 1

            elif len(my_set) == 3:
                table.add_row(
                    key,
                    str(value.splunk_event_count),
                    str(value.elastic_event_count),
                    str(value.insight_event_count),
                    style=Style(color="white", bgcolor="red", bold=True),
                )
                miss += 1

            # 3. case two systems are the same
            elif len(my_set) == 2:
                table.add_row(
                    key,
                    str(value.splunk_event_count),
                    str(value.elastic_event_count),
                    str(value.insight_event_count),
                    style=Style(color="white", bgcolor="yellow", bold=True),
                )

            else:
                print("something went wrong using the set!")

        console.print(table)
        print(f"\n\nTotal: {len(cls.rows)}\t Matches: {hit}\t Misses: {miss}")
