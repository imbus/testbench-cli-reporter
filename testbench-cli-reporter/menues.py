import questions
import testbench
import requests
import sys

def login_menu():    
    credentials = questions.ask_for_test_bench_credentials()
    quit = False
    
    while quit is False:
        tb_connection = testbench.Connection(**credentials)
        try:
            if tb_connection.check_is_working():
                project_selection_menu(tb_connection)
                return

        except requests.HTTPError as e: 
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
                quit = True

        except (requests.ConnectionError, requests.exceptions.MissingSchema) as e:
            print("Invalid server url.")            
            action = questions.ask_for_action_after_failed_server_connection()['action']
            if action == "retry_server":
                credentials['server_url'] = questions.ask_for_test_bench_server_url()['server_url']
            elif action == "change_server":
                credentials = questions.ask_for_test_bench_credentials()
            else:
                quit = True

def project_selection_menu(tb_connection: testbench.Connection):
    all_projects = tb_connection.get_all_projects().json()
    selected_project = questions.ask_to_select_project(all_projects)
    print(f"selected project with uid {selected_project}")