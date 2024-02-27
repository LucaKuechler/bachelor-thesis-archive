import argparse
import json
import time
import shutil
from pathlib import Path
from datetime import datetime, timedelta
from rich.console import Console

console = Console()


def init_checks(output_file: Path):
    data_json = {"samples": []}

    if output_file.exists():
        shutil.copy2(output_file, "/tmp/data.json")
        return

    with open(output_file, "w") as file:
        file.write(json.dumps(data_json, indent=4))


def add_malware_to_output(hash: str, signature: str, output_file: Path) -> None:
    with open(output_file, "r") as file:
        data = json.load(file)

    # Update the desired key with the new value
    for i, sample in enumerate(data["samples"]):
        # if malware is already present ask to overwrite
        if sample.get("hash") == hash:
            tmp = input(
                f"Are u sure you want to overwrite the informations for the hash value {hash}. (y/n)"
            )

            # dont overwrite
            if tmp != "y":
                break

            # overwrite
            current_dt = datetime.now()
            future_dt = current_dt + timedelta(minutes=2)
            data["samples"][i] = {
                "hash": hash,
                "start_time": int(current_dt.timestamp() * 1000),
                "end_time": int(future_dt.timestamp() * 1000),
                "signature": signature,
                "e_events_total": 0,
                "s_events_total": 0,
                "i_events_total": 0,
                "rules": [],
            }

            break
    else:
        current_dt = datetime.now()
        future_dt = current_dt + timedelta(minutes=2)
        data["samples"].append(
            {
                "hash": hash,
                "start_time": int(current_dt.timestamp() * 1000),
                "end_time": int(future_dt.timestamp() * 1000),
                "signature": signature,
                "e_events_total": 0,
                "s_events_total": 0,
                "i_events_total": 0,
                "rules": [],
            }
        )

    # Write the updated JSON data back to the file
    with open(output_file, "w") as f:
        f.write(json.dumps(data, indent=4))


def get_malware_by_number(number: str, malware_file: Path) -> tuple[str, str]:
    with open(malware_file, "r") as f:
        malware_samples = json.load(f)
        sample = malware_samples.get(number)
        return sample.get("sha256"), sample.get("signature")


def main(number_of_malware: str) -> None:
    # check if file exists if not create it with boilerplate output
    out = Path("./data.json")
    init_checks(out)

    # select the number from malware.json
    hash, signature = get_malware_by_number(
        number_of_malware, Path("../consistency-malware/output/malware.json")
    )

    # add sample inside the json data file
    # if rules already exist ask if really overwrite it.
    add_malware_to_output(hash, signature, out)

    # timer for two minutes
    seconds = 0
    while seconds < 120:
        console.print(
            f":stopwatch:  Time: {seconds+1}/120",
            style="bold green",
            end="\r",
        )
        time.sleep(1)
        seconds += 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="ProgramName",
        description="What the program does",
        epilog="Text at the bottom of help",
    )

    parser.add_argument("-n", "--number", type=str, required=True)
    args = parser.parse_args()

    main(args.number)
