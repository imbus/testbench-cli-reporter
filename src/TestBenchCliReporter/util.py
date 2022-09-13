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
from re import fullmatch
from typing import Any, Dict, Optional

from questionary import print as pprint

from .config_model import (
    CliReporterConfig,
    ExecutionResultsImportOptions,
    ExportAction,
    ImportAction,
    TestCycleXMLReportOptions,
)
from .log import logger

BLUE_ITALIC = "#06c8ff italic"

BLUE_BOLD_ITALIC = "#06c8ff bold italic"

ImportConfig = {
    "Typical": ExecutionResultsImportOptions(
        fileName="",
        reportRootUID=None,
        ignoreNonExecutedTestCases=True,
        defaultTester=None,
        checkPaths=True,
        filters=None,
        discardTesterInformation=True,
        useExistingDefect=True,
    ),
    "<CUSTOM>": False,
}


XmlExportConfig = {
    "Itep Export": TestCycleXMLReportOptions(
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
    ),
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
    "<CUSTOM>": None,
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
        with open(config_file_path, "r") as config_file:
            return CliReporterConfig.from_dict(json.load(config_file))
    except IOError as e:
        logger.error("Could not open file")
        logger.debug(traceback.format_exc())
        close_program()
    except json.JSONDecodeError as e:
        logger.error("Could not parse config file as JSON.")
        logger.debug(e)
        close_program()


def add_numbering_to_cycle(cycle_structure):
    root_key = 0
    tse_dict = dict()
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
            tse_dict[tse_serial] = {"tse": test_structure_element, "childs": dict()}
        else:
            tse_dict[tse_serial]["tse"] = test_structure_element

        if tse_parent_serial not in tse_dict:
            tse_dict[tse_parent_serial] = {
                "tse": None,
                "childs": {int(test_structure_element[key]["orderPos"]): tse_dict[tse_serial]},
            }
        else:
            tse_dict[tse_parent_serial]["childs"][
                int(test_structure_element[key]["orderPos"])
            ] = tse_dict[tse_serial]

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
        if "TestTheme_structure" in test_structure_element:
            key = "TestTheme_structure"
        else:
            key = "TestCaseSet_structure"
        current_numbering = f"{parent_numbering}{index+1}"
        test_structure_element[key]["numbering"] = current_numbering
        if len(child["childs"]) > 0:
            add_numbering_to_childs(child["childs"].values(), current_numbering)


def rotate(li):
    if len(li) > 1:
        return li[1:] + li[:1]
    else:
        return li


def pretty_print(*print_statements: dict):
    try:
        for statement in print_statements:
            pprint(
                statement.get("value"),
                style=statement.get("style", None),
                end=statement.get("end", "\r\n"),
            )
    except Exception:
        print("".join([statement["value"] for statement in print_statements]))


def get_project_keys(
    projects: Dict,
    project_name: str,
    tov_name: str,
    cycle_name: Optional[str] = None,
):
    project_key = None
    tov_key = None
    cycle_key = None
    for project in projects["projects"]:
        if project["name"] == project_name:
            project_key = project["key"]["serial"]
            for tov in project["testObjectVersions"]:
                if tov["name"] == tov_name:
                    project["testObjectVersions"] = [tov]
                    tov_key = tov["key"]["serial"]
                    if cycle_name:
                        for cycle in tov["testCycles"]:
                            if cycle["name"] == cycle_name:
                                project["testObjectVersions"][0]["testCycles"] = cycle
                                cycle_key = cycle["key"]["serial"]
                                break
                        break
            break
    if not project_key:
        raise ValueError(f"Project '{project_name}' not found.")
    if not tov_key:
        raise ValueError(f"TOV '{tov_name}' not found in project '{project_name}'.")
    if not cycle_key and cycle_name:
        raise ValueError(
            f"Cycle '{cycle_name}' not found in TOV '{tov_name}' in project '{project_name}'."
        )
    pretty_print(
        {"value": f"PROJECT_KEY: ", "end": None},
        {"value": f"{project_key}", "style": BLUE_BOLD_ITALIC, "end": None},
        {"value": f", TOV_Key: ", "end": None},
        {"value": f"{tov_key}", "style": BLUE_BOLD_ITALIC, "end": None},
        {"value": f", CYCLE_KEY: ", "end": None},
        {"value": f"{cycle_key}", "style": BLUE_BOLD_ITALIC},
    )
    return project_key, tov_key, cycle_key


def pretty_print_project_selection(selected_project, selected_tov, selected_cycle):
    print("  Selection:")
    pretty_print(
        {
            "value": f"{' ' * 4 + selected_project['name']: <50}",
            "style": BLUE_BOLD_ITALIC,
            "end": None,
        },
        {"value": f"  projectKey: ", "end": None},
        {
            "value": f"{selected_project['key']['serial']: >15}",
            "style": BLUE_BOLD_ITALIC,
        },
        {
            "value": f"{' ' * 6 + selected_tov['name']: <50}",
            "style": BLUE_BOLD_ITALIC,
            "end": None,
        },
        {"value": f"  tovKey:     ", "end": None},
        {
            "value": f"{selected_tov['key']['serial']: >15}",
            "style": BLUE_BOLD_ITALIC,
        },
    )
    if selected_cycle != "NO_EXEC":
        pretty_print(
            {
                "value": f"{' ' * 8 + selected_cycle['name']: <50}",
                "style": BLUE_BOLD_ITALIC,
                "end": None,
            },
            {"value": f"  cycleKey:   ", "end": None},
            {
                "value": f"{selected_cycle['key']['serial']: >15}",
                "style": BLUE_BOLD_ITALIC,
            },
        )


def pretty_print_test_cases(test_cases: Dict[str, Any]):
    print("   Test Cases:")
    if not test_cases.get('equal_lists'):
        _pretty_print_test_cases_spec(test_cases)
    _pretty_print_test_cases_exec(test_cases)
    print()


def _pretty_print_test_cases_spec(test_cases):
    print(f"    Specification:")
    pretty_print(
        {
            "value": f"{' Nr.  ': >10}",
            "end": None,
        },
        {
            "value": f"{'UniqueID': <35}",
            "end": None,
        },
        {"value": f"{'testCaseSpecificationKey' : >25}"},
    )
    for index, (uid, tc) in enumerate(test_cases['spec'].items()):
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
                "value": f"{tc['testCaseSpecificationKey']['serial'] : >25}",
                "style": BLUE_BOLD_ITALIC,
            },
        )


def _pretty_print_test_cases_exec(test_cases):
    print(f"    Execution:")
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
            "value": f"{'testCaseSpecificationKey' : >25}",
            "end": None,
        },
        {"value": f"{'testCaseExecutionKey' : >25}"},
    )
    for index, (uid, tc) in enumerate(test_cases['exec'].items()):
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
                "value": f"{tc['paramCombPK']['serial'] : >25}",
                "style": BLUE_BOLD_ITALIC,
                "end": None,
            },
            {
                "value": f"{tc['testCaseExecutionKey']['serial'] : >25}",
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
        {"value": f"{typ + 'Key:' : <18}", "end": None},
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


def resolve_server_name(server):
    if fullmatch(r"([\w\-.]+)(:\d{1,5})", server):
        resolved_server = f"https://{server}/api/1/"
    elif fullmatch(r"([\w\-.]+)", server):
        resolved_server = f"https://{server}:9443/api/1/"
    elif fullmatch(r"https?://([\w\-.]+)(:\d{1,5})/api/1/", server):
        resolved_server = server
    else:
        raise ValueError(f"Server name '{server}' is not valid.")
    return resolved_server


def spinner():
    if os.name != "posix":
        return ["_", "_", "_", "-", "`", "`", "'", "´", "-", "_", "_", "_"]
    else:
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
    else:
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


ACTION_TYPES = {"ImportExecutionResults": ImportAction, "ExportXMLReport": ExportAction}


class AbstractAction(ABC):
    def __init__(self, parameters: Optional[dict] = None):
        self.parameters = parameters or {}
        self.report_tmp_name = ""
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
        return ACTION_TYPES[type(self).__name__](self.parameters)
