from __future__ import annotations
from questionary import print as qprint
from questionary import prompt as qprompt
from questionary import Style
from questionary import Choice
import actions

custom_style_fancy = Style(
    [
        ('qmark', '#fac731 bold'),
        ('question', 'bold'),
        ('answer', '#06c8ff bold italic'),
        ('pointer', '#673ab7 bold'),
        ('highlighted', '#34AC5E bold'),
        ('selected', '#0abf5b'),
        ('separator', '#cc5454'),
        ('instruction', ''),
        ('text', ''),
        ('disabled', '#858585 italic'),
    ]
)

def prompt(questions):
    return qprompt(questions, style=custom_style_fancy)

def ask_for_test_bench_credentials() -> dict[str, str, str]:
    return ask_for_test_bench_server_url() | ask_for_test_bench_username() | ask_for_test_bench_password()

def ask_for_test_bench_server_url() -> dict[str]:
    question = [
        {
            'type': 'text',
            'name': 'server_url',
            'message': 'Enter the URL of the TestBench server you want to connect to.',
            'validate': lambda val: val != "",
        },
    ]

    return prompt(question)

def ask_for_test_bench_username() -> dict[str]:
    question = [
        {
            'type': 'text',
            'name': 'username',
            'message': 'Enter your user name.',
            'validate': lambda val: val != "",
        },
    ]

    return prompt(question)

def ask_for_test_bench_password() -> dict[str]:
    question = [
        {
            'type': 'password',
            'name': 'password',
            'message': 'Enter your password.',
            'validate': lambda val: val != "",
        }
    ]

    return prompt(question)

def ask_to_select_project(all_projects: dict) -> dict[str]:
    question = [
        {
            'type': 'select',
            'name': 'project',
            'message': 'Select a project.',
            'choices': [Choice(project["name"], project) for project in all_projects["projects"]]
        },
    ]

    return prompt(question)

def ask_to_select_tov(project: dict) -> dict[str]:
    question = [
        {
            'type': 'select',
            'name': 'tov',
            'message': 'Select a test object version.',
            'choices': [Choice(tov["name"], tov) for tov in project["testObjectVersions"]]
        }
    ]

    return prompt(question)

def ask_to_select_cycle(tov: dict) -> dict[str]:
    question = [
        {
            'type': 'select',
            'name': 'cycle',
            'message': 'Select a test cycle.',
            'choices': [Choice(cycle["name"], cycle) for cycle in tov["testCycles"]]
        }
    ]

    return prompt(question)

def ask_to_enter_report_root_uid() -> dict[str]:
    question = [
        {
            'type': 'text',
            'name': 'uid',
            'message': 'Provide a report root UID.',
            'validate': lambda val: val != "",
        }
    ]

    return prompt(question)

def ask_to_select_filters(all_filters: dict) -> list[str]:
    all_filters_sorted = sorted(all_filters, key=lambda filter: filter["name"].casefold())

    question = [
        {
            'type': 'checkbox',
            'name': 'filters',
            'message': 'Provide a set of filters (optional).',
            'choices': [Choice(filter["name"], {"name": filter["name"], "type": filter["type"]}) for filter in all_filters_sorted],
        }
    ]

    return prompt(question)

def ask_for_output_path() -> list[str]:
    question = [
        {
            'type': 'path',
            'name': 'output_path',
            'message': 'Provide the output path.',
            'validate': lambda val: val != "",
        }
    ]

    return prompt(question)

def ask_for_action_after_failed_login() -> dict[str]:
    question = [        
        {
            'type': 'select',
            'name': 'action',
            'message': 'What do you want to do?',
            'choices': [
                Choice('Retry password entry.', 'retry_password'),
                Choice('Log in as different user.', 'change_user'),
                Choice('Log in to other server.', 'change_server'),
                Choice('Quit.', 'quit'),
            ]
        },
    ]

    return prompt(question)

def ask_for_action_after_failed_server_connection() -> dict[str]:
    question = [        
        {
            'type': 'select',
            'name': 'action',
            'message': 'What do you want to do?',
            'choices': [
                Choice('Try same credentials using different server URL.', 'retry_server'),
                Choice('Re-enter server URL and credentials.', 'change_server'),
                Choice('Quit.', 'quit'),
            ]
        },
    ]

    return prompt(question)

def ask_for_next_action() -> dict[actions.Action]:
    choices = [
        Choice('Export an XML Report', 'export')
    ]

    question = [
        {
            'type': 'select',
            'name': 'action',
            'message': 'What do you want to do?',
            'choices': [
                Choice('Export XML Report', actions.ExportXMLReport()),
                Choice('Export actions', actions.ExportActionLog()),
                Choice('Change connection', actions.ChangeConnection()),
                Choice('Quit', actions.Quit()),
            ]
        }
    ]

    return prompt(question)