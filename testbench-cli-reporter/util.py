from __future__ import annotations
import sys
import requests
import questions
import testbench
import actions
import json

def login() -> testbench.Connection:
    credentials = questions.ask_for_test_bench_credentials()
    
    while True:
        connection = testbench.Connection(**credentials)
        try:
            if connection.check_is_working():
                return connection

        except requests.HTTPError: 
            print("Invalid login credentials.")
            action = questions.ask_for_action_after_failed_login()['action']
            if action == "retry_password":
                credentials['password'] = questions.ask_for_test_bench_password()['password']
            elif action == "change_user":
                credentials['username'] = questions.ask_for_test_bench_username()['username']
                credentials['password'] = questions.ask_for_test_bench_password()['password']
            elif action == "change_server":
                credentials = questions.ask_for_test_bench_credentials()
            else:
                close_program()

        except (requests.ConnectionError, requests.exceptions.MissingSchema):
            print("Invalid server url.")            
            action = questions.ask_for_action_after_failed_server_connection()['action']
            if action == "retry_server":
                credentials['server_url'] = questions.ask_for_test_bench_server_url()['server_url']
            elif action == "change_server":
                credentials = questions.ask_for_test_bench_credentials()
            else:
                close_program()

def choose_action() -> actions.Action:
    return questions.ask_for_next_action()['action']

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