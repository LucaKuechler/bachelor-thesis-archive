import argparse
from pydantic import BaseModel


class CArguments(BaseModel):
    output_fp: str
    input_fp: str
    number: str
    malware_fp: str


def init_arg_parser() -> CArguments:
    parser = argparse.ArgumentParser(description=f"Consistency check for SIGMA")

    parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="Output file for the generated report.",
    )

    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help=f"Input file which contains generated queries.",
    )

    parser.add_argument(
        "-n",
        "--number",
        type=str,
        required=True,
        help=f"Number of malware to analyze.",
    )

    parser.add_argument(
        "-m",
        "--malware",
        type=str,
        required=True,
        help=f"Input file for malware numeration.",
    )

    args = parser.parse_args()

    return CArguments(
        output_fp=args.output,
        input_fp=args.input,
        number=args.number,
        malware_fp=args.malware,
    )
