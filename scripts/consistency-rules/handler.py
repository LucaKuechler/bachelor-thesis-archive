import os
from rich import print
from rich.console import Console

console = Console()
import json
import subprocess
from pathlib import Path
from custom_errors import SIGMARulePathMissingError
from constants import (
    SIGMA_RULE_FILEPATH,
)
import rules
from copy import deepcopy
from sigma.rule import SigmaRule
from sigma.validation import SigmaValidator
from sigma.plugins import InstalledSigmaPlugins

plugins = InstalledSigmaPlugins.autodiscover()
validators = plugins.validators
rule_validator = SigmaValidator(validators.values())  # type: ignore


def _find_all_yaml_files(filepath) -> list[Path]:
    root_dir = Path(filepath)
    found_files: list[Path] = []

    for file in root_dir.rglob("*" + ".yml"):
        found_files.append(file)

    for file in root_dir.rglob("*" + ".yaml"):
        found_files.append(file)

    return found_files


def _validate_sigma_rule(filepath: Path):
    with open(filepath, "r") as f:
        rule = SigmaRule.from_yaml(f.read())
        issues = rule_validator.validate_rule(rule)

        if len(issues) != 0:
            print(f"Invalid file {filepath}")
            return None, filepath

        return rule, filepath


def _handle_collect_sigma_rule_files():
    # check if given path exists if not return nothing
    if not os.path.isdir(SIGMA_RULE_FILEPATH):
        raise SIGMARulePathMissingError(
            f"The path {SIGMA_RULE_FILEPATH} does not exist. Please mount the rules as volume into it."
        )

    # collect all yaml files in that path
    files = _find_all_yaml_files(SIGMA_RULE_FILEPATH)

    console.print(":postbox: Total rules: ", len(files), style="bold green")

    # validate each rule an only continue with those
    # who are valid sigma rules
    for i, file in enumerate(files, start=1):
        yield file
        console.print(
            f":white_heavy_check_mark: Rules left: {(len(files)-i):00002}",
            style="bold green",
            end="\r",
        )


def handle_generation_request() -> None:
    with open("output/rules.json", "w", encoding="utf-8") as f:
        out = {"rules": []}

        # create a list that contains all sigma rules in the given path
        # also include rules from subfolders.
        for rule in _handle_collect_sigma_rule_files():
            # if not valid rule skip
            sigma_rule, filepath = _validate_sigma_rule(rule)
            if not sigma_rule:
                continue

            try: 
                # generate sigma rule
                out["rules"].append(
                    {
                        "name": sigma_rule.title,
                        "splunk": rules.generate_splunk_rule(deepcopy(sigma_rule)),
                        "elastic": rules.generate_elastic_rule(deepcopy(sigma_rule)),
                        "insightidr": rules.generate_insightidr_rule(deepcopy(sigma_rule)),
                    }
                )
            except Exception as e:
                print("Error in rule: ", sigma_rule.title, e, filepath)
                continue


        # create output file
        f.writelines(json.dumps(out, indent=4))
