#  Copyright 2021- imbus AG
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import argparse
import json
import os
import sys
import time
import traceback
from abc import ABC, abstractmethod
from collections import OrderedDict
from pathlib import Path
from re import fullmatch
from typing import Any

from questionary import print as pprint

from .config_model import (
    ACTION_TYPES,
    CliReporterConfig,
    ExecutionJsonResultsImportOptions,
    ExecutionXmlResultsImportOptions,
    TestCycleJsonReportOptions,
    TestCycleXMLReportOptions,
)
from .log import logger

BLUE_ITALIC = "#06c8ff italic"

BLUE_BOLD_ITALIC = "#06c8ff bold italic"


class Colors:
    """ANSI color codes"""

    BLACK = "\033[0;30m"
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    BROWN = "\033[0;33m"
    BLUE = "\033[0;34m"
    PURPLE = "\033[0;35m"
    CYAN = "\033[0;36m"
    LIGHT_GRAY = "\033[0;37m"
    DARK_GRAY = "\033[1;30m"
    LIGHT_RED = "\033[1;31m"
    LIGHT_GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    LIGHT_BLUE = "\033[1;34m"
    LIGHT_PURPLE = "\033[1;35m"
    LIGHT_CYAN = "\033[1;36m"
    LIGHT_WHITE = "\033[1;37m"
    BOLD = "\033[1m"
    FAINT = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    NEGATIVE = "\033[7m"
    CROSSED = "\033[9m"
    END = "\033[0m"
    # cancel SGR codes if we don't write to a terminal
    if not __import__("sys").stdout.isatty():
        for _ in dir():
            if isinstance(_, str) and _[0] != "_":
                locals()[_] = ""
    elif __import__("platform").system() == "Windows":
        kernel32 = __import__("ctypes").windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        del kernel32


TYPICAL_XML_IMPORT_CONFIG: ExecutionXmlResultsImportOptions = ExecutionXmlResultsImportOptions(
    fileName="",
    reportRootUID=None,
    ignoreNonExecutedTestCases=True,
    defaultTester=None,
    checkPaths=True,
    filters=None,
    discardTesterInformation=True,
    useExistingDefect=True,
)

XmlImportConfig = {
    "Typical": TYPICAL_XML_IMPORT_CONFIG,
    "<CUSTOM>": False,
}

TYPICAL_JSON_IMPORT_CONFIG: ExecutionJsonResultsImportOptions = ExecutionJsonResultsImportOptions(
    fileName="",
    reportRootUID=None,
    useExistingDefect=True,
    ignoreNonExecutedTestCases=True,
    checkPaths=True,
    discardTesterInformation=True,
    defaultTester=None,
    filters=None,
)

JsonImportConfig = {
    "Typical": TYPICAL_JSON_IMPORT_CONFIG,
    "<CUSTOM>": False,
}

ITEP_EXPORT_CONFIG = TestCycleXMLReportOptions(
    exportAttachments=True,
    exportDesignData=True,
    characterEncoding="utf-16",
    suppressFilteredData=True,
    exportExpandedData=True,
    exportDescriptionFields=True,
    outputFormattedText=False,
    exportExecutionProtocols=False,
    filters=[],
    reportRootUID=None,
)

XmlExportConfig: dict[str, TestCycleXMLReportOptions | bool] = {
    "Itep Export": ITEP_EXPORT_CONFIG,
    "iTorx Export (execution)": TestCycleXMLReportOptions(
        exportAttachments=True,
        exportDesignData=True,
        characterEncoding="utf-8",
        suppressFilteredData=True,
        exportExpandedData=True,
        exportDescriptionFields=True,
        outputFormattedText=True,
        exportExecutionProtocols=False,
        filters=[],
        reportRootUID=None,
    ),
    "iTorx Export (continue|view)": TestCycleXMLReportOptions(
        exportAttachments=True,
        exportDesignData=True,
        characterEncoding="utf-8",
        suppressFilteredData=True,
        exportExpandedData=True,
        exportDescriptionFields=True,
        outputFormattedText=True,
        exportExecutionProtocols=True,
        filters=[],
        reportRootUID=None,
    ),
    "<CUSTOM>": False,
}

JsonExportConfig = {
    "iTorx Export (execution)": TestCycleJsonReportOptions(
        treeRootUID=None,
        basedOnExecution=True,
        suppressFilteredData=True,
        suppressNotExecutable=True,
        suppressEmptyTestThemes=True,
        filters=[],
    ),
    "<CUSTOM>": False,
}

parser = argparse.ArgumentParser()
parser.add_argument(
    "-c",
    "--config",
    help="Path to a config json file to execute pre-set actions based on the given configuration.",
    type=str,
)
parser.add_argument(
    "-s",
    "--server",
    help="TestBench Server address (hostname:port).",
    type=str,
    default="",
)
parser.add_argument("--login", help="Users Login.", type=str, default="")
parser.add_argument("--password", help="Users Password.", type=str, default="")
parser.add_argument("--session", help="Session Token", type=str, default="")
parser.add_argument(
    "-p",
    "--project",
    help="Project name to be exported <OPTIONAL if --type is 'i'>.",
    type=str,
    default="",
)
parser.add_argument(
    "-v",
    "--version",
    help="Test Object Version name to be exported <OPTIONAL if --type is 'i'>.",
    type=str,
    default="",
)
parser.add_argument(
    "-y",
    "--cycle",
    help="Test Cycle name to be exported <OPTIONAL>",
    type=str,
    default="",
)
parser.add_argument(
    "--tovKey",
    help="Test Object Version key to be exported <OPTIONAL>. If set overrides names.",
    type=str,
    default="",
)
parser.add_argument(
    "--cycleKey",
    help="Test Cycle key to be exported <OPTIONAL>. If set overrides names.",
    type=str,
    default="",
)
parser.add_argument(
    "-u",
    "--uid",
    help="Root UID to be exported <OPTIONAL, Default = ROOT>",
    type=str,
    default="ROOT",
)
parser.add_argument(
    "-t",
    "--type",
    help="'e' for Export <default>, 'i' for Import",
    type=str,
    choices=["e", "i"],
    default="e",
)
parser.add_argument("--manual", help="Switch to force manual mode.", action="store_true")
parser.add_argument(
    "path",
    nargs="?",
    help="Input- and Output-Path for xml reports <OPTIONAL, Default = report.zip>.",
    type=str,
    default="report.zip",
)


def close_program():
    print("Closing program.")
    sys.exit(0)


def get_configuration(config_file_path: str):
    logger.info("Trying to read config file")
    try:
        with Path(config_file_path).open() as config_file:
            return CliReporterConfig.from_dict(json.load(config_file))
    except OSError:
        logger.error("Could not open file")
        logger.debug(traceback.format_exc())
        close_program()
    except json.JSONDecodeError as e:
        logger.error("Could not parse config file as JSON.")
        logger.debug(e)
        close_program()


def add_numbering_to_cycle(cycle_structure):
    root_key = 0
    tse_dict = {}
    for test_structure_element in cycle_structure:
        if "TestTheme_structure" in test_structure_element:
            key = "TestTheme_structure"
        elif "TestCaseSet_structure" in test_structure_element:
            key = "TestCaseSet_structure"
        elif "Root_structure" in test_structure_element:
            key = "Root_structure"
            root_key = test_structure_element[key]["key"]["serial"]
            test_structure_element[key]["numbering"] = "-1"
        else:
            raise KeyError(f"Unexpected Test Structure Element! : {test_structure_element}")

        tse_serial = test_structure_element[key]["key"]["serial"]
        tse_parent_serial = test_structure_element[key]["parentPK"]["serial"]

        if tse_serial not in tse_dict:
            tse_dict[tse_serial] = {"tse": test_structure_element, "childs": {}}
        else:
            tse_dict[tse_serial]["tse"] = test_structure_element

        if tse_parent_serial not in tse_dict:
            tse_dict[tse_parent_serial] = {
                "tse": None,
                "childs": {int(test_structure_element[key]["orderPos"]): tse_dict[tse_serial]},
            }
        else:
            tse_dict[tse_parent_serial]["childs"][int(test_structure_element[key]["orderPos"])] = tse_dict[
                tse_serial
            ]

        tse_dict[tse_parent_serial]["childs"] = OrderedDict(
            sorted(tse_dict[tse_parent_serial]["childs"].items())
        )
    root = tse_dict[root_key]
    add_numbering_to_childs(root["childs"].values(), None)
    return root


def add_numbering_to_childs(child_list, parent_numbering):
    parent_numbering = f"{parent_numbering}." if parent_numbering else ""
    for index, child in enumerate(child_list):
        test_structure_element = child["tse"]
        key = (
            "TestTheme_structure"
            if "TestTheme_structure" in test_structure_element
            else "TestCaseSet_structure"
        )
        current_numbering = f"{parent_numbering}{index + 1}"
        test_structure_element[key]["numbering"] = current_numbering
        if len(child["childs"]) > 0:
            add_numbering_to_childs(child["childs"].values(), current_numbering)


def rotate(li):
    if len(li) > 1:
        return li[1:] + li[:1]
    return li


def pretty_print(*print_statements: dict):
    try:
        for statement in print_statements:
            pprint(
                statement.get("value", ""),
                style=statement.get("style", None),
                end=statement.get("end", "\r\n"),
            )
    except Exception:
        print("".join([statement["value"] for statement in print_statements]))


def get_project_by_name(projects, project_name):
    for project in projects:
        if project["name"] == project_name:
            return project
    raise ValueError(f"Project '{project_name}' not found.")


def get_tov_by_name(tovs, tov_name):
    for tov in tovs:
        if tov["name"] == tov_name:
            return tov
    raise ValueError(f"TOV '{tov_name}' not found.")


def get_cycle_by_name(cycles, cycle_name):
    for cycle in cycles:
        if cycle["name"] == cycle_name:
            return cycle
    raise ValueError(f"Cycle '{cycle_name}' not found.")


def get_project_keys(
    projects: dict,
    project_name: str,
    tov_name: str,
    cycle_name: str | None = None,
):
    cycle_key = None
    project = get_project_by_name(projects["projects"], project_name)
    project_key = project["key"]["serial"]
    tov = get_tov_by_name(project["testObjectVersions"], tov_name)
    tov_key = tov["key"]["serial"]
    if cycle_name:
        cycle = get_cycle_by_name(tov["testCycles"], cycle_name)
        cycle_key = cycle["key"]["serial"]
    pretty_print(
        {"value": "PROJECT_KEY: ", "end": None},
        {"value": f"{project_key}", "style": BLUE_BOLD_ITALIC, "end": None},
        {"value": ", TOV_Key: ", "end": None},
        {"value": f"{tov_key}", "style": BLUE_BOLD_ITALIC, "end": None},
        {"value": ", CYCLE_KEY: ", "end": None},
        {"value": f"{cycle_key}", "style": BLUE_BOLD_ITALIC},
    )
    return project_key, tov_key, cycle_key


def pretty_print_tov_scope(selected_tov):
    pretty_print(
        {"value": "TOV Scope:", "end": None},
        {"value": f"{selected_tov['name']}", "style": BLUE_BOLD_ITALIC},
    )


def pretty_print_cycle_scope(selected_cycle):
    pretty_print(
        {"value": "Cycle Scope:", "end": None},
        {"value": f"{selected_cycle['scope']}", "style": BLUE_BOLD_ITALIC},
    )


def pretty_print_project_tree_selection(
    selected_project: dict, selected_tov: dict, selected_cycle: dict | str
):
    print("  Selection:")
    pretty_print_project_selection(selected_project)
    pretty_print_tov_selection(selected_tov)
    if selected_cycle != "NO_EXEC":
        pretty_print_cycle_selection(selected_cycle)


def pretty_print_project_selection(selected_project):
    pretty_print(
        {
            "value": f"{' ' * 4 + selected_project['name']: <50}",
            "style": BLUE_BOLD_ITALIC,
            "end": None,
        },
        {"value": "  projectKey: ", "end": None},
        {
            "value": f"{selected_project['key']['serial']: >15}",
            "style": BLUE_BOLD_ITALIC,
        },
    )


def pretty_print_tov_selection(selected_tov):
    pretty_print(
        {
            "value": f"{' ' * 6 + selected_tov['name']: <50}",
            "style": BLUE_BOLD_ITALIC,
            "end": None,
        },
        {"value": "  tovKey:     ", "end": None},
        {
            "value": f"{selected_tov['key']['serial']: >15}",
            "style": BLUE_BOLD_ITALIC,
        },
    )


def pretty_print_cycle_selection(selected_cycle):
    pretty_print(
        {
            "value": f"{' ' * 8 + selected_cycle['name']: <50}",
            "style": BLUE_BOLD_ITALIC,
            "end": None,
        },
        {"value": "  cycleKey:   ", "end": None},
        {
            "value": f"{selected_cycle['key']['serial']: >15}",
            "style": BLUE_BOLD_ITALIC,
        },
    )


def pretty_print_test_cases(test_cases: dict[str, Any]):
    print("   Test Cases:")
    if not test_cases.get("equal_lists"):
        _pretty_print_test_cases_spec(test_cases)
    _pretty_print_test_cases_exec(test_cases)
    print()


def _pretty_print_test_cases_spec(test_cases):
    print("    Specification:")
    pretty_print(
        {
            "value": f"{' Nr.  ': >10}",
            "end": None,
        },
        {
            "value": f"{'UniqueID': <35}",
            "end": None,
        },
        {"value": f"{'testCaseSpecificationKey': >25}"},
    )
    for index, (uid, tc) in enumerate(test_cases["spec"].items()):
        pretty_print(
            {
                "value": f"{str(index + 1) + '  ': >10}",
                "style": BLUE_ITALIC,
                "end": None,
            },
            {
                "value": f"{uid: <35}",
                "style": BLUE_ITALIC,
                "end": None,
            },
            {
                "value": f"{tc['testCaseSpecificationKey']['serial']: >25}",
                "style": BLUE_BOLD_ITALIC,
            },
        )


def _pretty_print_test_cases_exec(test_cases):
    print("    Execution:")
    pretty_print(
        {
            "value": f"{' Nr.  ': >10}",
            "end": None,
        },
        {
            "value": f"{'UniqueID': <35}",
            "end": None,
        },
        {
            "value": f"{'testCaseSpecificationKey': >25}",
            "end": None,
        },
        {"value": f"{'testCaseExecutionKey': >25}"},
    )
    for index, (uid, tc) in enumerate(test_cases["exec"].items()):
        pretty_print(
            {
                "value": f"{str(index + 1) + '  ': >10}",
                "style": BLUE_ITALIC,
                "end": None,
            },
            {
                "value": f"{uid: <35}",
                "style": BLUE_ITALIC,
                "end": None,
            },
            {
                "value": f"{tc['paramCombPK']['serial']: >25}",
                "style": BLUE_BOLD_ITALIC,
                "end": None,
            },
            {
                "value": f"{tc['testCaseExecutionKey']['serial']: >25}",
                "style": BLUE_BOLD_ITALIC,
            },
        )


def pretty_print_tse_information(tse, typ, info):
    print("  Selection:")
    pretty_print(
        {
            "value": f"{' ' * 4 + typ: <40}",
            "style": BLUE_BOLD_ITALIC,
            "end": None,
        },
        {"value": f"{typ + 'Key:': <18}", "end": None},
        {
            "value": f"{info['key']['serial']: >21}",
            "style": BLUE_BOLD_ITALIC,
        },
        {
            "value": f"{' ' * 6 + info['numbering'] + ' [' + info['uniqueID'] + ']': <40}",
            "style": BLUE_BOLD_ITALIC,
            "end": None,
        },
        {"value": f"{'Specification_key:':<18}", "end": None},
        {
            "value": f"{tse['spec']['Specification_key']['serial']: >21}",
            "style": BLUE_BOLD_ITALIC,
        },
        {
            "value": f"{' ' * 4: <40}",
            "style": BLUE_BOLD_ITALIC,
            "end": None,
        },
        {"value": f"{'Automation_key:':<18}", "end": None},
        {
            "value": f"{tse['aut']['Automation_key']['serial']: >21}",
            "style": BLUE_BOLD_ITALIC,
        },
    )
    if tse.get("exec"):
        pretty_print(
            {
                "value": f"{'': <40}",
                "style": BLUE_BOLD_ITALIC,
                "end": None,
            },
            {"value": f"{'Execution_key:':<18}", "end": None},
            {
                "value": f"{tse['exec']['Execution_key']['serial']: >21}",
                "style": BLUE_BOLD_ITALIC,
            },
        )


def pretty_print_success_message(prefix: str, value: Any, suffix: str):
    logger.debug(f"{prefix} {value} {suffix}")
    pretty_print(
        {"value": f"{prefix} ", "end": None},
        {
            "value": str(value),
            "style": "#06c8ff bold italic",
            "end": None,
        },
        {"value": f" {suffix}"},
    )


def pretty_print_progress_bar(mode: str, handled: int, total: int, percentage: int):
    if total is not None and handled is not None:
        completed_length = int(percentage / 2)  # Each 2% is one character
        bar = "#" * completed_length + "-" * (50 - completed_length)
        print(
            f"{mode}: {Colors.BLUE}[{bar}]{Colors.END} {handled}/{total} "
            f"{Colors.DARK_GRAY}({percentage}%){Colors.END}",
            end="\r",
        )


def resolve_server_name(server: str) -> str:
    if fullmatch(r"([\w\-.]+):(\d{1,5})", server):
        resolved_server = f"https://{server}/api/"
    elif fullmatch(r"([\w\-.]+)", server):
        resolved_server = f"https://{server}:9445/api/"
    elif fullmatch(r"https?://([\w\-.]+):(\d{1,5})/api/", server):
        resolved_server = server
    else:
        raise ValueError(f"Server name '{server}' is not valid.")
    return resolved_server


def spinner():
    if os.name != "posix":
        return ["_", "_", "_", "-", "`", "`", "'", "`", "-", "_", "_", "_"]
    return [
        "⢀⠀",
        "⡀⠀",
        "⠄⠀",
        "⢂⠀",
        "⡂⠀",
        "⠅⠀",
        "⢃⠀",
        "⡃⠀",
        "⠍⠀",
        "⢋⠀",
        "⡋⠀",
        "⠍⠁",
        "⢋⠁",
        "⡋⠁",
        "⠍⠉",
        "⠋⠉",
        "⠋⠉",
        "⠉⠙",
        "⠉⠙",
        "⠉⠩",
        "⠈⢙",
        "⠈⡙",
        "⢈⠩",
        "⡀⢙",
        "⠄⡙",
        "⢂⠩",
        "⡂⢘",
        "⠅⡘",
        "⢃⠨",
        "⡃⢐",
        "⠍⡐",
        "⢋⠠",
        "⡋⢀",
        "⠍⡁",
        "⢋⠁",
        "⡋⠁",
        "⠍⠉",
        "⠋⠉",
        "⠋⠉",
        "⠉⠙",
        "⠉⠙",
        "⠉⠩",
        "⠈⢙",
        "⠈⡙",
        "⠈⠩",
        "⠀⢙",
        "⠀⡙",
        "⠀⠩",
        "⠀⢘",
        "⠀⡘",
        "⠀⠨",
        "⠀⢐",
        "⠀⡐",
        "⠀⠠",
        "⠀⢀",
        "⠀⡀",
        "⠀⠀",
    ]


def delay():
    if os.name == "nt":
        return 0.1
    return 0.02


def spin_spinner(message: str):
    try:
        for cursor in spinner():
            print(
                f"{message} {cursor}",
                end="\r",
            )
            time.sleep(delay())
    except UnicodeEncodeError:
        pass


class AbstractAction(ABC):
    def __init__(self, parameters: Any = None):
        self.parameters = parameters or {}
        self.report_tmp_name: str | bool = ""
        self.job_id = ""

    def prepare(self, connection_log) -> bool:
        return True

    @abstractmethod
    def trigger(self, connection_log) -> bool:
        raise NotImplementedError

    def wait(self, connection_log) -> bool:
        return True

    def poll(self, connection_log) -> bool:
        return True

    def finish(self, connection_log) -> bool:
        return True

    def export(self):
        return ACTION_TYPES[type(self).__name__](self.parameters)  # type: ignore
