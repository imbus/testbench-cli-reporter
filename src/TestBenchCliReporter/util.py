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

from __future__ import annotations
import sys

import requests
from TestBenchCliReporter import questions
from TestBenchCliReporter import testbench
from TestBenchCliReporter import actions
import json
from collections import OrderedDict


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
                credentials["password"] = questions.ask_for_testbench_password()
            elif action == "change_user":
                credentials["loginname"] = questions.ask_for_testbench_loginname()
                credentials["password"] = questions.ask_for_testbench_password()
            elif action == "change_server":
                credentials = questions.ask_for_test_bench_credentials()
            else:
                close_program()

        except (requests.ConnectionError, requests.exceptions.MissingSchema):
            print("Invalid server url.")
            action = questions.ask_for_action_after_failed_server_connection()
            if action == "retry_server":
                credentials["server_url"] = questions.ask_for_test_bench_server_url()
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
                credentials["server_url"] = questions.ask_for_test_bench_server_url()
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
        with open(config_file_path, "r") as config_file:
            configuration = json.load(config_file)
    except IOError:
        print("Could not open file")
        close_program()
    except json.JSONDecodeError:
        print("Could not parse config file as JSON.")
        close_program()

    return configuration


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
