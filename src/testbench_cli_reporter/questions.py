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
from collections.abc import Callable
from pathlib import Path
from re import fullmatch, sub

from questionary import Choice, Style, checkbox, confirm, select, unsafe_prompt
from questionary import print as pprint

from . import actions, util
from .config_model import (
    AutomationCSVField,
    ExecutionCSVField,
    ExecutionJsonResultsImportOptions,
    ExecutionXmlResultsImportOptions,
    Permission,
    ProjectCSVReportOptions,
    SpecificationCSVField,
    TestCycleJsonReportOptions,
    TestCycleXMLReportOptions,
)
from .log import logger
from .util import AbstractAction, JsonExportConfig, JsonImportConfig, XmlExportConfig, XmlImportConfig

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


def isfile(filepath: str | Path) -> bool:
    return Path(filepath).is_file()


def isdir(filepath: str | Path) -> bool:
    return Path(filepath).is_dir()


def dirname(filepath: str | Path) -> str:
    return str(Path(filepath).parent)


def abspath(filepath: str | Path) -> str:
    return str(Path(filepath).resolve().absolute())


def selection_prompt(
    message: str,
    choices: list[Choice],
    no_valid_option_message: str | None = None,
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
            use_jk_keys=False,
            use_search_filter=True,
        ).unsafe_ask()
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
    choices: list[Choice],
    no_valid_option_message: str | None = None,
    style: Style = custom_style_fancy,
):
    valid_choices = [choice for choice in choices if not choice.disabled]
    if valid_choices:
        return checkbox(
            message=message,
            choices=choices,
            style=style,
            use_jk_keys=False,
            use_search_filter=True,
        ).unsafe_ask()
    logger.info(no_valid_option_message)
    return []


def text_prompt(  # noqa: PLR0913
    message: str,
    type: str = "text",  # noqa: A002
    validation: Callable[[str], bool | str] | None = lambda val: bool(val),
    style: Style = custom_style_fancy,
    default: str = "",
    filter: Callable[[str], str] = lambda val: val,  # noqa: A002
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


def ask_for_test_bench_credentials(server="", login="", pwd="", session="") -> dict:
    return {
        "server_url": ask_for_test_bench_server_url(server),
        "verify": False,  # ask_for_ssl_verification_option() #TODO
        "loginname": ask_for_testbench_loginname(login),
        "password": ask_for_testbench_password(pwd),
        "sessionToken": session,
    }


def ask_for_test_bench_server_url(default="") -> str:
    server_url = text_prompt(
        message="Enter the TestBench server address:",
        validation=lambda text: (
            True
            if fullmatch(r"(https?://)?([\w\-.\d]+)(:\d{1,5})?(/api/)?", text)
            else f"Server '{text}' is not valid! "
        ),
        default=default,
        filter=lambda raw: sub(
            r"(^https?://)?([\w\-.\d]+)(:\d{1,5})?(/api/?)?$",
            r"https://\2\3/api/",
            sub(r"^([\w\-.\d]+)$", r"\1:9443", raw),
        ),
    )
    if not isinstance(server_url, str):
        raise ValueError("Unexpected text_prompt result.")
    print(server_url)
    return server_url


def ask_for_ssl_verification_option() -> bool | str:
    verification_option: bool | str = selection_prompt(
        message="Select how the certificate of the TestBench server should be verified.",
        choices=[
            Choice("Do not verify the certificate at all.", False),
            Choice("Automatically verify the certificate.", True),
            Choice("Provide a path to a local certificate file for verification.", "path"),
        ],
    )

    if verification_option == "path":
        return ask_for_certificate_path()
    return verification_option


def ask_for_certificate_path() -> str:
    certificate_path = text_prompt(
        message="Provide the path to the certificate.",
        type="path",
        validation=lambda path: (
            True
            if isfile(path) and os.access(path, os.R_OK)
            else f"Path '{path}' is not a file or not readable."
        ),
    )
    if not isinstance(certificate_path, str):
        raise ValueError("Unexpected text_prompt result.")
    return certificate_path


def ask_for_testbench_loginname(default="") -> str:
    loginname = text_prompt(
        message="Enter your login name:",
        default=default,
    )
    if not isinstance(loginname, str):
        raise ValueError("Unexpected text_prompt result.")
    return loginname


def ask_for_testbench_password(default="") -> str:
    password = text_prompt(
        message="Enter your password:",
        type="password",
        validation=None,
        default=default,
    )
    if not isinstance(password, str):
        raise ValueError("Unexpected text_prompt result.")
    return password


def ask_for_action_after_session_terminated(current_login: str | None, server_url: str) -> str:
    who = f"for '{current_login}' " if current_login else ""
    action = selection_prompt(
        message=f"Session was terminated by the server {who}on {server_url}\nWhat do you want to do?",
        choices=[
            Choice("Login again with same credentials.", "relogin_same"),
            Choice("Login as different user.", "change_user"),
            Choice("Login to other server.", "change_server"),
            Choice("Quit.", "quit"),
        ],
    )
    if not isinstance(action, str):
        raise ValueError("Unexpected selection_prompt result")
    return action


def ask_to_select_project(all_projects: dict, default=None) -> dict:
    choices = [Choice(project["name"], project) for project in all_projects["projects"]]
    project: dict = selection_prompt(
        message="Select a project.",
        choices=choices,
        no_valid_option_message="No project available.",
        default=next((x for x in choices if x.title == default), None),
    )
    return project


def ask_to_select_projects(all_projects: dict, default=None) -> list[dict]:
    choices = [Choice(project["name"], project) for project in all_projects["projects"]]
    if selection_prompt("Select multiple projects?", choices=[Choice("No", False), Choice("Yes", True)]):
        projects: list = checkbox_prompt(
            message="Select project(s) with space.",
            choices=choices,
            no_valid_option_message="No project available.",
        )
        return projects
    project: dict = selection_prompt(
        message="Select a project.",
        choices=choices,
        no_valid_option_message="No project available.",
        default=next((x for x in choices if x.title == default), None),
    )
    return [project]


def ask_to_select_tov(project: dict, default=None) -> dict:
    choices = [Choice(tov["name"], tov) for tov in project["testObjectVersions"]]
    tov: dict = selection_prompt(
        message="Select a test object version.",
        choices=choices,
        no_valid_option_message="No test object version available.",
        default=next((x for x in choices if x.title == default), None),
    )
    return tov


def ask_to_select_tovs(project: dict, default=None) -> list[dict]:
    if selection_prompt(
        "Select multiple test object version?", choices=[Choice("No", False), Choice("Yes", True)]
    ):
        tovs: list = checkbox_prompt(
            message="Select test object version(s) with space.",
            choices=[Choice(tov["name"], tov) for tov in project["testObjectVersions"]],
            no_valid_option_message="No test object version available.",
        )
        return tovs
    return [ask_to_select_tov(project, default)]


def ask_to_select_cycle(tov: dict, default=None, export=False) -> dict:
    choices = [Choice("<NO TEST CYCLE>", "NO_EXEC")] if export else []
    choices.extend([Choice(cycle["name"], cycle) for cycle in tov["testCycles"]])
    test_cycle: dict = selection_prompt(
        message="Select a test cycle.",
        choices=choices,
        no_valid_option_message="No test cycle available.",
        default=next((x for x in choices if x.title == default), None),
    )
    return test_cycle


def ask_to_select_cycles(tov: dict, default=None, export=False) -> list[dict]:
    choices = [Choice(cycle["name"], cycle) for cycle in tov["testCycles"]]
    if choices and selection_prompt(
        "Select multiple test cycle(s)?", choices=[Choice("No", False), Choice("Yes", True)]
    ):
        test_cycles: list = checkbox_prompt(
            message="Select test cycle(s) with space.",
            choices=choices,
            no_valid_option_message="No test cycle available.",
        )
        return test_cycles
    choices = [Choice("<NO TEST CYCLE>", "NO_EXEC")] if export else []
    choices.extend([Choice(cycle["name"], cycle) for cycle in tov["testCycles"]])
    test_cycle: dict = selection_prompt(
        message="Select a test cycle.",
        choices=choices,
        no_valid_option_message="No test cycle available.",
        default=next((x for x in choices if x.title == default), None),
    )
    return [test_cycle]


def ask_to_select_filters(all_filters: list[dict]) -> list:
    if selection_prompt("Activate Filters:", choices=[Choice("No", False), Choice("Yes", True)]):
        all_filters_sorted = sorted(all_filters, key=lambda fltr: fltr["name"].casefold())

        filters: list = checkbox_prompt(
            message="Provide a set of filters.",
            choices=[
                Choice(fltr["name"], {"name": fltr["name"], "filterType": fltr["type"]})
                for fltr in all_filters_sorted
            ],
            no_valid_option_message="No filters available.",
        )
        return filters
    return []


def ask_to_config_xml_report():
    selection = selection_prompt(
        "Select Report Configuration:",
        choices=[Choice(config_name, config) for config_name, config in XmlExportConfig.items()],
    )
    if not selection:
        custom_choices = {
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
        choices: dict[str, str] = {}
        for key, value in custom_choices.items():
            choices[key] = selection_prompt(f'   "{key}": ', value)
        pprint("  }", style="bold")
        selection = TestCycleXMLReportOptions(reportRootUID=None, filters=[], **choices)  # type: ignore
    return selection


def ask_to_config_json_report() -> TestCycleJsonReportOptions:
    selection = selection_prompt(
        "Select Report Configuration:",
        choices=[Choice(config_name, config) for config_name, config in JsonExportConfig.items()],
    )
    if not selection:
        custom_choices = {
            "basedOnExecution": [Choice("True", True), Choice("False", False)],
            "suppressFilteredData": [Choice("True", True), Choice("False", False)],
            "suppressNotExecutable": [Choice("True", True), Choice("False", False)],
            "suppressEmptyTestThemes": [Choice("True", True), Choice("False", False)],
        }
        pprint("  {", style="bold")
        for key, value in custom_choices.items():
            custom_choices[key] = selection_prompt(f'   "{key}": ', value)
        pprint("  }", style="bold")
        selection = TestCycleJsonReportOptions(treeRootUID=None, filters=[], **custom_choices)  # type: ignore
    return selection  # type: ignore


def ask_to_config_csv_report() -> ProjectCSVReportOptions:
    selected_fields = checkbox_prompt(
        message="Select Specification fields to be exported.",
        choices=[Choice(field.name, field) for field in SpecificationCSVField],
    )
    selected_fields.extend(
        checkbox_prompt(
            message="Select Execution fields to be exported.",
            choices=[Choice(field.name, field) for field in ExecutionCSVField],
        )
    )
    selected_fields.extend(
        checkbox_prompt(
            message="Select Automation fields to be exported.",
            choices=[Choice(field.name, field) for field in AutomationCSVField],
        )
    )
    show_user_full_name = confirm_prompt(
        message="Show users full name?",
        default=True,
    )
    character_encoding = selection_prompt(
        message="Select character encoding:",
        choices=[
            Choice("UTF-8", "utf-8"),
            Choice("UTF-16", "utf-16"),
            Choice("Windows-1252", "windows-1252"),
        ],
        default="utf-8",
    )
    return ProjectCSVReportOptions(
        [],
        showUserFullName=show_user_full_name,
        characterEncoding=character_encoding,
        fields=selected_fields,
    )


def ask_to_config_xml_import() -> ExecutionXmlResultsImportOptions:
    selection = selection_prompt(
        "Select Import Configuration:",
        choices=[Choice(config_name, config) for config_name, config in XmlImportConfig.items()],
    )
    if isinstance(selection, ExecutionXmlResultsImportOptions):
        return selection
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
    return ExecutionXmlResultsImportOptions.from_dict(selection)


def ask_to_config_json_import() -> ExecutionJsonResultsImportOptions:
    selection = selection_prompt(
        "Select Import Configuration:",
        choices=[Choice(config_name, config) for config_name, config in JsonImportConfig.items()],
    )
    if isinstance(selection, ExecutionJsonResultsImportOptions):
        return selection
    selection = {
        "UseExistingDefect": [Choice("True", True), Choice("False", False)],
        "IgnoreNonExecutedTestCases": [Choice("True", True), Choice("False", False)],
        "CheckPaths": [Choice("True", True), Choice("False", False)],
        "DiscardTesterInformation": [Choice("True", True), Choice("False", False)],
    }
    pprint("  {", style="bold")
    for key, value in selection.items():
        selection[key] = selection_prompt(f'   "{key}": ', value)
    pprint("  }", style="bold")
    return ExecutionJsonResultsImportOptions.from_dict(selection)


def ask_for_output_path(default: str = "report.zip", allow_dir: bool = False) -> str:
    output_path = text_prompt(
        message=f"Provide the output path [{default}]:",
        type="path",
        validation=lambda path: (
            True
            if ((isdir(path) or isfile(path)) and os.access(path, os.W_OK))
            or os.access(dirname(abspath(path)), os.W_OK)
            else f"Path '{path}' does not exist or is not writeable."
        ),
        filter=lambda path: str(Path(path) / default) if isdir(path or ".") and not allow_dir else path,
    )
    pprint("Output Path: ", end=None)
    pprint(f"{output_path}", style="#06c8ff bold italic")
    return abspath(output_path)


def ask_for_input_path() -> str:
    input_path = text_prompt(
        message="Provide the input path [report.zip]:",
        type="path",
        validation=lambda path: (
            True
            if (isfile(path) and os.access(path, os.R_OK))
            or (not path and isfile("report.zip") and os.access("report.zip", os.R_OK))
            else f"'{path}' is not a file or not readable."
        ),
        filter=lambda path: path if path else "report.zip",
    )
    if not isinstance(input_path, str):
        return "report.zip"
    return input_path


def ask_for_action_after_failed_login() -> str:
    action = selection_prompt(
        message="What do you want to do?",
        choices=[
            Choice("Retry password entry.", "retry_password"),
            Choice("Log in as different user.", "change_user"),
            Choice("Log in to other server.", "change_server"),
            Choice("Quit.", "quit"),
        ],
    )
    if not isinstance(action, str):
        raise ValueError("Unexpected selection_prompt result")
    return action


def ask_for_action_after_failed_server_connection() -> str:
    action = selection_prompt(
        message="What do you want to do?",
        choices=[
            Choice("Try same credentials using different server URL.", "retry_server"),
            Choice("Re-enter server URL and credentials.", "change_server"),
            Choice("Quit.", "quit"),
        ],
    )
    if not isinstance(action, str):
        raise ValueError("Unexpected selection_prompt result")
    return action


def ask_for_action_after_login_timeout() -> str:
    action = selection_prompt(
        message="What do you want to do?",
        choices=[
            Choice("Try again.", "retry"),
            Choice("Try same credentials using different server URL.", "retry_server"),
            Choice("Re-enter server URL and credentials.", "change_server"),
            Choice("Quit.", "quit"),
        ],
    )
    if not isinstance(action, str):
        raise ValueError("Unexpected selection_prompt result")
    return action


def ask_for_main_action(server_version: list[int] | None = None, is_admin: bool = False) -> AbstractAction:
    tb_4_actions = [
        Choice("Export JSON Report", actions.ExportJSONReport),
        Choice("Import JSON execution results", actions.ImportJSONExecutionResults),
    ]
    tb_306_actions = [
        Choice("Export CSV Report", actions.ExportCSVReport),
    ]
    common_actions = [
        Choice("Export XML Report", actions.ExportXMLReport),
        Choice("Import XML execution results", actions.ImportXMLExecutionResults),
    ]
    admin_actions = [
        Choice("▶ Administrator Actions", actions.OpenAdminMenu),
    ]
    unlogged_actions = [
        Choice("Browser Projects", actions.BrowseProjects),
        Choice("Write history to config file", actions.ExportActionLog),
        Choice("Change connection", actions.ChangeConnection),
        Choice("Quit", actions.Quit),
    ]
    choices = []
    if server_version and server_version > [4]:
        choices.extend(tb_4_actions)
    if server_version and server_version >= [3, 0, 6, 2]:
        choices.extend(tb_306_actions)
    choices.extend(common_actions)
    if is_admin:
        choices.extend(admin_actions)
    choices.extend(unlogged_actions)
    main_action = selection_prompt(  # type: ignore
        message="What do you want to do?",
        choices=choices,
    )()
    if isinstance(main_action, actions.OpenAdminMenu):
        return ask_for_admin_action()
    return main_action  # type: ignore


def ask_for_admin_action() -> AbstractAction:
    choices = [
        Choice("Export Server Logs", actions.ExportServerLogs),
        Choice("Export Project Users", actions.ExportProjectMembers),
        Choice("Request JWT Token", actions.RequestJWT),
        Choice("◀︎ Back", actions.Back),
    ]
    return selection_prompt(  # type: ignore
        message="What do you want to do?",
        choices=choices,
    )()


def ask_to_select_default_tester(all_testers: list[dict]) -> str | None:
    all_testers_sorted = sorted(all_testers, key=lambda tester: tester["value"]["user-name"].casefold())

    choices = [Choice("<No Tester>", False)] + [
        Choice(tester["value"]["user-name"], tester["value"]["user-login"]) for tester in all_testers_sorted
    ]

    default_tester = selection_prompt(
        message="What do you want to do?",
        choices=choices,
        no_valid_option_message="No tester available.",
    )

    if default_tester is False:
        return None

    if not isinstance(default_tester, str):
        raise ValueError("Unexpected selection_prompt result")

    return default_tester


def ask_to_select_tree_element() -> bool:
    return bool(
        selection_prompt(
            "Select report root from test theme tree?",
            choices=[Choice("No", False), Choice("Yes", True)],
        )
    )


def ask_to_select_report_root_uid(cycle_structure: list[dict]):
    cycle_structure_tree = util.add_numbering_to_cycle(cycle_structure)
    return navigate_in_cycle_stucture(cycle_structure_tree)


def navigate_in_cycle_stucture(theme_structure):
    if "Root_structure" in theme_structure["tse"]:
        choices = [Choice("<SELECT ALL>", "ROOT")]
    else:
        te = theme_structure["tse"][
            (
                "TestTheme_structure"
                if "TestTheme_structure" in theme_structure["tse"]
                else "TestCaseSet_structure"
            )
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
        if isinstance(selection, str) and selection not in ("BACK", "ROOT"):
            return selection
    return None


def ask_to_select_permissions() -> list[Permission]:
    all_permissions = sorted([p.value for p in Permission], key=str.casefold)
    selected: list[str] = checkbox_prompt(
        message="Select permissions for the JWT (optional):",
        choices=[Choice(p, p) for p in all_permissions],
        no_valid_option_message="No permissions available.",
    )
    return [Permission(p) for p in selected]
