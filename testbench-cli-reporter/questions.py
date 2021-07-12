from __future__ import annotations
from questionary import print as qprint
from questionary import select, checkbox, unsafe_prompt
from questionary import Style
from questionary import Choice
import actions
import util

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
    choices: list[Choice],
    no_valid_option_message: str = None,
    style: dict = custom_style_fancy,
):
    valid_choices = [choice for choice in choices if not choice.disabled]
    if valid_choices:
        return select(
            message=message,
            choices=choices,
            style=style,
        ).unsafe_ask()
    else:
        raise ValueError(no_valid_option_message)


def checkbox_prompt(
    message: str,
    choices: list[Choice],
    no_valid_option_message: str = None,
    style: dict = custom_style_fancy,
):
    valid_choices = [choice for choice in choices if not choice.disabled]
    if valid_choices:
        return checkbox(
            message=message,
            choices=choices,
            style=style,
        ).unsafe_ask()
    else:
        print(no_valid_option_message)
        return []


def text_prompt(
    message: str,
    type: str = "text",
    validation: function = lambda val: val != "",
    style: Style = custom_style_fancy,
):
    question = [
        {
            "type": type,
            "name": "sole_question",
            "message": message,
            "validate": validation,
            "style": style,
        }
    ]

    return unsafe_prompt(question)["sole_question"]


def ask_for_test_bench_credentials() -> dict[str, str | bool, str, str]:
    return {
        "server_url": ask_for_test_bench_server_url(),
        "verify": ask_for_ssl_verification_option(),
        "username": ask_for_test_bench_username(),
        "password": ask_for_test_bench_password(),
    }


def ask_for_test_bench_server_url() -> dict[str]:
    return text_prompt(
        message="Enter the URL of the TestBench server you want to connect to.",
    )


def ask_for_ssl_verification_option() -> bool | str:
    verification_option = selection_prompt(
        message="Select how the certificate of the TestBench server should be verified.",
        choices=[
            Choice("Automatically verify the certificate.", True),
            Choice(
                "Provide a path to a local certificate file for verification.", "path"
            ),
            Choice("Do not verify the certificate at all.", False),
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
    )


def ask_for_test_bench_username() -> dict[str]:
    return text_prompt(
        message="Enter your user name.",
    )


def ask_for_test_bench_password() -> dict[str]:
    return text_prompt(
        message="Enter your password.",
        type="password",
        validation=None,
    )


def ask_to_select_project(all_projects: dict) -> dict[str]:
    return selection_prompt(
        message="Select a project.",
        choices=[
            Choice(project["name"], project) for project in all_projects["projects"]
        ],
        no_valid_option_message="No project available.",
    )


def ask_to_select_tov(project: dict) -> dict[str]:
    return selection_prompt(
        message="Select a test object version.",
        choices=[Choice(tov["name"], tov) for tov in project["testObjectVersions"]],
        no_valid_option_message="No test object version available.",
    )


def ask_to_select_cycle(tov: dict) -> dict[str]:
    return selection_prompt(
        message="Select a test cycle.",
        choices=[Choice(cycle["name"], cycle) for cycle in tov["testCycles"]],
        no_valid_option_message="No test cycle available.",
    )


def ask_to_select_filters(all_filters: dict) -> list[str]:
    all_filters_sorted = sorted(
        all_filters, key=lambda filter: filter["name"].casefold()
    )

    return checkbox_prompt(
        message="Provide a set of filters (optional).",
        choices=[
            Choice(filter["name"], {"name": filter["name"], "type": filter["type"]})
            for filter in all_filters_sorted
        ],
        no_valid_option_message="No filters available.",
    )


def ask_for_output_path() -> list[str]:
    return text_prompt(
        message="Provide the output path.",
        type="path",
    )


def ask_for_input_path() -> list[str]:
    return text_prompt(
        message="Provide the input path.",
        type="path",
    )


def ask_for_action_after_failed_login() -> dict[str]:
    return selection_prompt(
        message="What do you want to do?",
        choices=[
            Choice("Retry password entry.", "retry_password"),
            Choice("Log in as different user.", "change_user"),
            Choice("Log in to other server.", "change_server"),
            Choice("Quit.", "quit"),
        ],
    )


def ask_for_action_after_failed_server_connection() -> dict[str]:
    return selection_prompt(
        message="What do you want to do?",
        choices=[
            Choice("Try same credentials using different server URL.", "retry_server"),
            Choice("Re-enter server URL and credentials.", "change_server"),
            Choice("Quit.", "quit"),
        ],
    )


def ask_for_action_after_login_timeout() -> dict[str]:
    return selection_prompt(
        message="What do you want to do?",
        choices=[
            Choice("Try again.", "retry"),
            Choice("Try same credentials using different server URL.", "retry_server"),
            Choice("Re-enter server URL and credentials.", "change_server"),
            Choice("Quit.", "quit"),
        ],
    )


def ask_for_next_action() -> dict[actions.Action]:
    return selection_prompt(
        message="What do you want to do?",
        choices=[
            Choice("Export XML Report", actions.ExportXMLReport()),
            Choice("Import execution results", actions.ImportExecutionResults()),
            Choice("Export actions", actions.ExportActionLog()),
            Choice("Change connection", actions.ChangeConnection()),
            Choice("Quit", actions.Quit()),
        ],
    )


def ask_to_select_default_tester(all_testers: dict) -> dict[str]:
    all_testers_sorted = sorted(
        all_testers, key=lambda tester: tester["value"]["user-name"].casefold()
    )

    return selection_prompt(
        message="What do you want to do?",
        choices=[
            Choice(tester["value"]["user-name"], tester["value"]["user-login"])
            for tester in all_testers_sorted
        ],
        no_valid_option_message="No tester available.",
    )


def ask_to_select_report_root_uid(cycle_structure: dict):
    ordered_cycle_structure = util.create_ordered_cycle_structure(cycle_structure)

    return selection_prompt(
        message="Please select an element to be used as the root of the report.",
        choices=[
            Choice(
                ".".join([str(subindex) for subindex in element["index"]])
                + " "
                + element["name"],
                element["uniqueID"],
            )
            for element in ordered_cycle_structure
        ],
        no_valid_option_message="No element available to be used as the root of the report.",
    )
