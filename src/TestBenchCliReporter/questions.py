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

import os
from os.path import abspath, dirname, isdir, isfile
from re import fullmatch, sub
from typing import Callable, Dict, List, Union

from questionary import Choice, Style, checkbox, confirm
from questionary import print as pprint
from questionary import select, unsafe_prompt

from . import actions, util
from .log import logger
from .util import ImportConfig, XmlExportConfig

custom_style_fancy = Style(
    [
        ("qmark", "#fac731 bold"),
        ("question", "bold"),
        ("answer", "#06c8ff bold italic"),
        ("pointer", "#673ab7 bold"),
        ("highlighted", "#34AC5E bold"),
        ("selected", "#0abf5b"),
        ("separator", "#cc5454"),
        ("instruction", ""),
        ("text", ""),
        ("disabled", "#858585 italic"),
    ]
)


def selection_prompt(
    message: str,
    choices: List[Choice],
    no_valid_option_message: str = None,
    style: Style = custom_style_fancy,
    default=None,
):
    valid_choices = [choice for choice in choices if not choice.disabled]
    if valid_choices:
        return select(
            message=message,
            choices=choices,
            style=style,
            default=default,
        ).unsafe_ask()
    else:
        raise ValueError(no_valid_option_message)


def confirm_prompt(
    message: str,
    style: Style = custom_style_fancy,
    default: bool = False,
):
    return confirm(
        message=message,
        style=style,
        default=default,
    ).unsafe_ask()


def checkbox_prompt(
    message: str,
    choices: List[Choice],
    no_valid_option_message: str = None,
    style: Style = custom_style_fancy,
):
    valid_choices = [choice for choice in choices if not choice.disabled]
    if valid_choices:
        return checkbox(
            message=message,
            choices=choices,
            style=style,
        ).unsafe_ask()
    else:
        logger.info(no_valid_option_message)
        return []


def text_prompt(
    message: str,
    type: str = "text",
    validation: Callable[[str], bool] = lambda val: val != "",
    style: Style = custom_style_fancy,
    default: str = "",
    filter: Callable[[str], str] = lambda val: val,
):
    question = [
        {
            "type": type,
            "name": "sole_question",
            "message": message,
            "validate": validation,
            "style": style,
            "default": default,
            "filter": filter,
        }
    ]

    return unsafe_prompt(question)["sole_question"]


def ask_for_test_bench_credentials(server="", login="", pwd="") -> dict:
    return {
        "server_url": ask_for_test_bench_server_url(server),
        "verify": False,  # ask_for_ssl_verification_option(), #ToDo Hier könnten optional Certificate geprüft werden
        "loginname": ask_for_testbench_loginname(login),
        "password": ask_for_testbench_password(pwd),
    }


def ask_for_test_bench_server_url(default="") -> str:
    server_url = text_prompt(
        message="Enter the TestBench server address and port <host:port>:",
        validation=lambda text: True
        if fullmatch(r"(https?://)?([\w\-.\d]+)(:\d{1,5})?(/api/1/)?", text)
        else f"Server '{text}' is not valid! ",
        default=default,
        filter=lambda raw: sub(
            r"(^https?://)?([\w\-.\d]+)(:\d{1,5})?(/api/1/?)?$",
            r"https://\2\3/api/1/",
            sub(r"^([\w\-.\d]+)$", r"\1:9443", raw),
        ),
    )
    print(server_url)
    return server_url


def ask_for_ssl_verification_option() -> Union[bool, str]:
    verification_option = selection_prompt(
        message="Select how the certificate of the TestBench server should be verified.",
        choices=[
            Choice("Do not verify the certificate at all.", False),
            Choice("Automatically verify the certificate.", True),
            Choice("Provide a path to a local certificate file for verification.", "path"),
        ],
    )

    if verification_option == "path":
        return ask_for_certificate_path()
    else:
        return verification_option


def ask_for_certificate_path() -> str:
    return text_prompt(
        message="Provide the path to the certificate.",
        type="path",
        validation=lambda path: True
        if isfile(path) and os.access(path, os.R_OK)
        else f"Path '{path}' is not a file or not readable.",
    )


def ask_for_testbench_loginname(default="") -> str:
    return text_prompt(
        message="Enter your login name:",
        default=default,
    )


def ask_for_testbench_password(default="") -> str:
    return text_prompt(
        message="Enter your password:",
        type="password",
        validation=None,
        default=default,
    )


def ask_to_select_project(all_projects: dict, default=None) -> dict:
    choices = [Choice(project["name"], project) for project in all_projects["projects"]]
    return selection_prompt(
        message="Select a project.",
        choices=choices,
        no_valid_option_message="No project available.",
        default=next((x for x in choices if x.title == default), None),
    )


def ask_to_select_tov(project: dict, default=None) -> dict:
    choices = [Choice(tov["name"], tov) for tov in project["testObjectVersions"]]
    return selection_prompt(
        message="Select a test object version.",
        choices=choices,
        no_valid_option_message="No test object version available.",
        default=next((x for x in choices if x.title == default), None),
    )


def ask_to_select_cycle(tov: dict, default=None, export=False) -> dict:
    choices = [Choice("<NO TEST CYCLE>", "NO_EXEC")] if export else []
    choices.extend([Choice(cycle["name"], cycle) for cycle in tov["testCycles"]])
    return selection_prompt(
        message="Select a test cycle.",
        choices=choices,
        no_valid_option_message="No test cycle available.",
        default=next((x for x in choices if x.title == default), None),
    )


def ask_to_select_filters(all_filters: List[dict]) -> List:
    if selection_prompt("Activate Filters:", choices=[Choice("No", False), Choice("Yes", True)]):
        all_filters_sorted = sorted(all_filters, key=lambda filter: filter["name"].casefold())

        return checkbox_prompt(
            message="Provide a set of filters.",
            choices=[
                Choice(filter["name"], {"name": filter["name"], "type": filter["type"]})
                for filter in all_filters_sorted
            ],
            no_valid_option_message="No filters available.",
        )
    return []


def ask_to_config_report():
    selection = selection_prompt(
        "Select Report Configuration:",
        choices=[Choice(config_name, config) for config_name, config in XmlExportConfig.items()],
    )
    if not selection:
        selection = {
            "exportAttachments": [Choice("True", True), Choice("False", False)],
            "exportDesignData": [Choice("True", True), Choice("False", False)],
            "characterEncoding": [Choice("UTF-16", "utf-16"), Choice("UTF-8", "utf-8")],
            "suppressFilteredData": [Choice("True", True), Choice("False", False)],
            "exportExpandedData": [Choice("True", True), Choice("False", False)],
            "exportDescriptionFields": [Choice("True", True), Choice("False", False)],
            "outputFormattedText": [Choice("False", False), Choice("True", True)],
            "exportExecutionProtocols": [Choice("False", False), Choice("True", True)],
        }
        pprint("  {", style="bold")
        for key, value in selection.items():
            selection[key] = selection_prompt(f'   "{key}": ', value)
        pprint("  }", style="bold")
    return selection


def ask_to_config_import():
    selection = selection_prompt(
        "Select Import Configuration:",
        choices=[Choice(config_name, config) for config_name, config in ImportConfig.items()],
    )
    if not selection:
        selection = {
            "ignoreNonExecutedTestCases": [
                Choice("True", True),
                Choice("False", False),
            ],
            "checkPaths": [Choice("True", True), Choice("False", False)],
            "discardTesterInformation": [Choice("True", True), Choice("False", False)],
            "useExistingDefect": [Choice("True", True), Choice("False", False)],
        }
        pprint("  {", style="bold")
        for key, value in selection.items():
            selection[key] = selection_prompt(f'   "{key}": ', value)
        pprint("  }", style="bold")
    return selection


def ask_for_output_path(default: str = "report.zip") -> str:
    output_path = text_prompt(
        message=f"Provide the output path [{default}]:",
        type="path",
        validation=lambda path: True
        if ((isdir(path) or isfile(path)) and os.access(path, os.W_OK))
        or os.access(dirname(abspath(path)), os.W_OK)
        else f"Path '{path}' does not exist or is not writeable.",
        filter=lambda path: os.path.join(path, default) if isdir(path or ".") else path,
    )
    pprint(f"Output Path: ", end=None)
    pprint(f"{output_path}", style="#06c8ff bold italic")
    return abspath(output_path)


def ask_for_input_path() -> str:
    return text_prompt(
        message="Provide the input path [report.zip]:",
        type="path",
        validation=lambda path: True
        if (isfile(path) and os.access(path, os.R_OK))
        or (isfile("report.zip") and os.access("report.zip", os.R_OK))
        else f"'{path}' is not a file or not readable.",
        filter=lambda path: "report.zip" if not path else path,
    )


def ask_for_action_after_failed_login() -> str:
    return selection_prompt(
        message="What do you want to do?",
        choices=[
            Choice("Retry password entry.", "retry_password"),
            Choice("Log in as different user.", "change_user"),
            Choice("Log in to other server.", "change_server"),
            Choice("Quit.", "quit"),
        ],
    )


def ask_for_action_after_failed_server_connection() -> str:
    return selection_prompt(
        message="What do you want to do?",
        choices=[
            Choice("Try same credentials using different server URL.", "retry_server"),
            Choice("Re-enter server URL and credentials.", "change_server"),
            Choice("Quit.", "quit"),
        ],
    )


def ask_for_action_after_login_timeout() -> str:
    return selection_prompt(
        message="What do you want to do?",
        choices=[
            Choice("Try again.", "retry"),
            Choice("Try same credentials using different server URL.", "retry_server"),
            Choice("Re-enter server URL and credentials.", "change_server"),
            Choice("Quit.", "quit"),
        ],
    )


def ask_for_next_action():
    return selection_prompt(
        message="What do you want to do?",
        choices=[
            Choice("Export XML Report", actions.ExportXMLReport()),
            Choice("Import execution results", actions.ImportExecutionResults()),
            Choice("Browser Projects", actions.BrowseProjects()),
            Choice("Write history to config file", actions.ExportActionLog()),
            Choice("Change connection", actions.ChangeConnection()),
            Choice("Quit", actions.Quit()),
        ],
    )


def ask_to_select_default_tester(all_testers: List[dict]) -> Dict[str, str]:
    all_testers_sorted = sorted(
        all_testers, key=lambda tester: tester["value"]["user-name"].casefold()
    )

    return selection_prompt(
        message="What do you want to do?",
        choices=[Choice("<No Tester>", False)]
        + [
            Choice(tester["value"]["user-name"], tester["value"]["user-login"])
            for tester in all_testers_sorted
        ],
        no_valid_option_message="No tester available.",
    )


def ask_to_select_report_root_uid(cycle_structure: List[dict]):
    cycle_structure_tree = util.add_numbering_to_cycle(cycle_structure)
    selected_uid = navigate_in_cycle_stucture(cycle_structure_tree)
    return selected_uid


def navigate_in_cycle_stucture(theme_structure):
    if "Root_structure" in theme_structure["tse"]:
        choices = [Choice("<SELECT ALL>", "ROOT")]
    else:
        te = theme_structure["tse"][
            "TestTheme_structure"
            if "TestTheme_structure" in theme_structure["tse"]
            else "TestCaseSet_structure"
        ]
        choices = [
            Choice(
                f"<SELECT> {te['numbering']} {te['name']} [{te['uniqueID']}]",
                te["uniqueID"],
            )
        ]

    for element in theme_structure["childs"].values():
        if "TestTheme_structure" in element["tse"]:
            te = element["tse"]["TestTheme_structure"]
            prefix = "TT"
        else:
            te = element["tse"]["TestCaseSet_structure"]
            prefix = "TCS"
        choices.append(Choice(f"{prefix}: {te['numbering']} {te['name']}", element))
    if "Root_structure" not in theme_structure["tse"]:
        choices.append(Choice("<BACK>", "BACK"))

    selection = None
    while not isinstance(selection, str):
        selection = selection_prompt(
            message="Please select an element to be used as the root of the report.",
            choices=choices,
            no_valid_option_message="No element available to be used as the root of the report.",
        )
        if not isinstance(selection, str):
            selection = navigate_in_cycle_stucture(selection)
        if isinstance(selection, str) and selection != "BACK":
            return selection
