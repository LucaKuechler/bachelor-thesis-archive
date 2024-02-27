"""
    Description: Simple web interface to convert SIGMA files to different output formats.
"""
from handler import handle_generation_request


def main() -> None:
    handle_generation_request()

if __name__ == "__main__":
    main()
