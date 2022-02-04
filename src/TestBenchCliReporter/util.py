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

# from __future__ import annotations
import sys
import argparse
from typing import Dict, Optional

from questionary import print as pprint
from TestBenchCliReporter import questions
import json
from collections import OrderedDict

ImportConfig = {
    "Typical": {
        "ignoreNonExecutedTestCases": True,
        "checkPaths": True,
        "discardTesterInformation": True,
        "useExistingDefect": True,
    },
    "<CUSTOM>": False,
}


XmlExportConfig = {
    "Itep Export": {
        "exportAttachments": True,
        "exportDesignData": True,
        "characterEncoding": "utf-16",
        "suppressFilteredData": True,
        "exportExpandedData": True,
        "exportDescriptionFields": True,
        "outputFormattedText": False,
        "exportExecutionProtocols": False,
    },
    "iTorx Export (execution)": {
        "exportAttachments": True,
        "exportDesignData": True,
        "characterEncoding": "utf-8",
        "suppressFilteredData": True,
        "exportExpandedData": True,
        "exportDescriptionFields": True,
        "outputFormattedText": True,
        "exportExecutionProtocols": False,
    },
    "iTorx Export (continue|view)": {
        "exportAttachments": True,
        "exportDesignData": True,
        "characterEncoding": "utf-8",
        "suppressFilteredData": True,
        "exportExpandedData": True,
        "exportDescriptionFields": True,
        "outputFormattedText": True,
        "exportExecutionProtocols": True,
    },
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
parser.add_argument(
    "--manual", help="Switch to force manual mode.", action="store_true"
)
parser.add_argument(
    "path",
    nargs="?",
    help="Input- and Output-Path for xml reports <OPTIONAL, Default = report.zip>.",
    type=str,
    default="report.zip",
)


def choose_action():
    return questions.ask_for_next_action()


def close_program():
    print("Closing program.")
    sys.exit(0)


def get_configuration(config_file_path: str):
    print("Trying to read config file")
    try:
        with open(config_file_path, "r") as config_file:
            return json.load(config_file)
    except IOError:
        print("Could not open file")
        close_program()
    except json.JSONDecodeError:
        print("Could not parse config file as JSON.")
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
            raise KeyError(
                f"Unexpected Test Structure Element! : {test_structure_element}"
            )

        tse_serial = test_structure_element[key]["key"]["serial"]
        tse_parent_serial = test_structure_element[key]["parentPK"]["serial"]

        if tse_serial not in tse_dict:
            tse_dict[tse_serial] = {"tse": test_structure_element, "childs": dict()}
        else:
            tse_dict[tse_serial]["tse"] = test_structure_element

        if tse_parent_serial not in tse_dict:
            tse_dict[tse_parent_serial] = {
                "tse": None,
                "childs": {
                    int(test_structure_element[key]["orderPos"]): tse_dict[tse_serial]
                },
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
        {"value": f"{project_key}", "style": "#06c8ff bold italic", "end": None},
        {"value": f", TOV_Key: ", "end": None},
        {"value": f"{tov_key}", "style": "#06c8ff bold italic", "end": None},
        {"value": f", CYCLE_KEY: ", "end": None},
        {"value": f"{cycle_key}", "style": "#06c8ff bold italic"},
    )
    return project_key, tov_key, cycle_key


def pretty_print_project_selection(selected_project, selected_tov, selected_cycle):
    print("  Selection:")
    pretty_print(
        {
            "value": f"{' ' * 4 + selected_project['name']: <50}",
            "style": "#06c8ff bold italic",
            "end": None,
        },
        {"value": f"  projectKey: ", "end": None},
        {
            "value": f"{selected_project['key']['serial']: >15}",
            "style": "#06c8ff bold italic",
        },
        {
            "value": f"{' ' * 6 + selected_tov['name']: <50}",
            "style": "#06c8ff bold italic",
            "end": None,
        },
        {"value": f"  tovKey:     ", "end": None},
        {
            "value": f"{selected_tov['key']['serial']: >15}",
            "style": "#06c8ff bold italic",
        },
    )
    if selected_cycle != "NO_EXEC":
        pretty_print(
            {
                "value": f"{' ' * 8 + selected_cycle['name']: <50}",
                "style": "#06c8ff bold italic",
                "end": None,
            },
            {"value": f"  cycleKey:   ", "end": None},
            {
                "value": f"{selected_cycle['key']['serial']: >15}",
                "style": "#06c8ff bold italic",
            },
        )


def pretty_print_tse_information(tse, typ, info):
    print("  Selection:")
    pretty_print(
        {
            "value": f"{' ' * 2 + typ: <40}",
            "style": "#06c8ff bold italic",
            "end": None,
        },
        {"value": f"{typ + 'Key:' : <18}", "end": None},
        {
            "value": f"{info['key']['serial']: >21}",
            "style": "#06c8ff bold italic",
        },
        {
            "value": f"{' ' * 4 + info['numbering'] + ' [' + info['uniqueID'] + ']': <40}",
            "style": "#06c8ff bold italic",
            "end": None,
        },
        {"value": f"{'Specification_key:':<18}", "end": None},
        {
            "value": f"{tse['spec']['Specification_key']['serial']: >21}",
            "style": "#06c8ff bold italic",
        },
        {
            "value": f"{' ' * 4: <40}",
            "style": "#06c8ff bold italic",
            "end": None,
        },
        {"value": f"{'Automation_key:':<18}", "end": None},
        {
            "value": f"{tse['aut']['Automation_key']['serial']: >21}",
            "style": "#06c8ff bold italic",
        },
    )
    if tse.get("exec"):
        pretty_print(
            {
                "value": f"{'': <40}",
                "style": "#06c8ff bold italic",
                "end": None,
            },
            {"value": f"{'Execution_key:':<18}", "end": None},
            {
                "value": f"{tse['exec']['Execution_key']['serial']: >21}",
                "style": "#06c8ff bold italic",
            },
        )
