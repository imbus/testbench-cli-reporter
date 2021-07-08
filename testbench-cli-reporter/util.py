from __future__ import annotations
import sys
import requests
import questions
import testbench
import actions
import json
from collections import Counter

def login() -> testbench.Connection:
    credentials = questions.ask_for_test_bench_credentials()
    
    while True:
        connection = testbench.Connection(**credentials)
        try:
            if connection.check_is_working():
                return connection

        except requests.HTTPError: 
            print("Invalid login credentials.")
            action = questions.ask_for_action_after_failed_login()
            if action == "retry_password":
                credentials['password'] = questions.ask_for_test_bench_password()
            elif action == "change_user":
                credentials['username'] = questions.ask_for_test_bench_username()
                credentials['password'] = questions.ask_for_test_bench_password()
            elif action == "change_server":
                credentials = questions.ask_for_test_bench_credentials()
            else:
                close_program()

        except (requests.ConnectionError, requests.exceptions.MissingSchema):
            print("Invalid server url.")            
            action = questions.ask_for_action_after_failed_server_connection()
            if action == "retry_server":
                credentials['server_url'] = questions.ask_for_test_bench_server_url()
            elif action == "change_server":
                credentials = questions.ask_for_test_bench_credentials()
            else:
                close_program()

        except requests.exceptions.Timeout:
            print("No connection could be established due to timeout.")
            action = questions.ask_for_action_after_login_timeout()
            if action == "retry":
                pass
            elif action == "retry_server":
                credentials['server_url'] = questions.ask_for_test_bench_server_url()
            elif action == "change_server":
                credentials = questions.ask_for_test_bench_credentials()
            else:
                close_program()

def choose_action() -> actions.Action:
    return questions.ask_for_next_action()

def close_program():
    print("Closing program.")
    sys.exit(0)

def get_configuration(config_file_path: str):
    print("Trying to read config file")
    try:
        with open(config_file_path, 'r') as config_file:
            configuration = json.load(config_file)
    except IOError:
        print("Could not open file")
        close_program()
    except json.JSONDecodeError:
        print("Could not parse config file as JSON.")
        close_program()

    return configuration

def create_ordered_cycle_structure(cycle_structure: list[dict[dict]]):
    simplified_cycle_structure = [element.get("TestTheme_structure", element.get("TestCaseSet_structure", element.get("Root_structure"))) for element in cycle_structure]
    sorted_cycle_structure = sorted(simplified_cycle_structure, key=lambda element: int(element['orderPos']))

    all_element_keys = set(element["key"]["serial"] for element in sorted_cycle_structure)
    elements_in_higher_hierarchy_levels = []
    elements_in_current_hierarchy_level = []
    elements_in_lower_hierarchy_levels = []
    element_position_counter = Counter()

    # root element
    for element in sorted_cycle_structure:
        if element["parentPK"]["serial"] not in all_element_keys:
            elements_in_current_hierarchy_level.append(element)
            element_position_counter[element["parentPK"]["serial"]] += 1
            element["index"] = ()
        else:
            elements_in_lower_hierarchy_levels.append(element)

    # other elements
    while elements_in_lower_hierarchy_levels:
        elements_in_higher_hierarchy_levels.extend(elements_in_current_hierarchy_level)
        elements_in_previous_hierarchy_level = elements_in_current_hierarchy_level
        element_pks_in_previous_hierarchy_level = [element["key"]["serial"] for element in elements_in_previous_hierarchy_level]
        elements_in_current_hierarchy_level = []
        remaining_elements_in_lower_hierarchy_levels = []
        element_position_counter = Counter()
        for element in elements_in_lower_hierarchy_levels:
            if element["parentPK"]["serial"] in element_pks_in_previous_hierarchy_level:
                elements_in_current_hierarchy_level.append(element)
                element_position_counter[element["parentPK"]["serial"]] += 1
                element["index"] = next(parent for parent in elements_in_previous_hierarchy_level if parent["key"]["serial"] == element["parentPK"]["serial"])['index'] + (element_position_counter[element["parentPK"]["serial"]], )
            else:
                remaining_elements_in_lower_hierarchy_levels.append(element)
        elements_in_lower_hierarchy_levels = remaining_elements_in_lower_hierarchy_levels
    
    elements_in_higher_hierarchy_levels.extend(elements_in_current_hierarchy_level)
    elements_in_higher_hierarchy_levels.pop(0)  # remove root element as it cannot be used as basis for report creation
    
    return sorted(elements_in_higher_hierarchy_levels, key=lambda element: [subindex for subindex in element["index"]])