import handler
import atexit
from custom_types import RuleReader, DataFileHandler

from consolemenu import ConsoleMenu
from consolemenu.items import FunctionItem


def on_exit(oh: DataFileHandler):
    oh.print()
    oh.output()


def create_menu(oh: DataFileHandler, reader: RuleReader) -> None:
    # Create the menu
    menu = ConsoleMenu(
        "Analyse Consistency Of SIGMA Rules", exit_menu_char="x", clear_screen=False
    )

    splunk_callback = FunctionItem(
        "Analyse Splunk Queries",
        handler.handle_splunk,
        [oh, reader.splunk_rules],
        menu_char="s",
        should_exit=True,
    )
    elastic_callback = FunctionItem(
        "Analyse ElasticSearch Queries",
        handler.handle_elasticsearch,
        [oh, reader.elastic_rules],
        menu_char="e",
        should_exit=True,
    )
    insight_callback = FunctionItem(
        "Analyse InsightIDR Queries",
        handler.handle_insight,
        [oh, reader.insight_rules],
        menu_char="q",
        should_exit=True,
    )
    all_callback = FunctionItem(
        "Analyse All", handler.handle_all, [oh, reader], menu_char="a", should_exit=True
    )

    menu.append_item(splunk_callback)
    menu.append_item(elastic_callback)
    menu.append_item(insight_callback)
    menu.append_item(all_callback)
    atexit.register(on_exit, (oh))
    menu.show()
