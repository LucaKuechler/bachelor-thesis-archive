import custom_menu
from arguments import init_arg_parser, CArguments
from custom_types import RuleReader, DataFileHandler
from pyfiglet import Figlet
from termcolor import colored
from pyfiglet import figlet_format
from insight import initial_insight


def main(args: CArguments) -> None:
    print((colored(figlet_format("Consistent", font="stop"), color="light_magenta")))

    # read data from input json file
    reader = RuleReader()
    reader.read_from_file(args.input_fp)
    initial_insight(reader.insight_rules)

    # create output handler
    oh = DataFileHandler(args.number, args.output_fp, args.malware_fp)

    # Create the menu
    custom_menu.create_menu(oh, reader)


if __name__ == "__main__":
    main(init_arg_parser())
