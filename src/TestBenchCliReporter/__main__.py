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

from re import fullmatch
from time import sleep
from typing import Optional

from TestBenchCliReporter.testbench import (
    ConnectionLog,
    Connection,
    spin_spinner,
    login,
)
from TestBenchCliReporter.util import (
    rotate,
    close_program,
    get_configuration,
    choose_action,
    parser,
)
from TestBenchCliReporter.actions import Action
from requests.exceptions import Timeout

__version__ = "1.0.1"


def main():
    arg = parser.parse_args()
    try:
        if arg.config:
            configuration = get_configuration(arg.config)
            print("Config file found")
            run_automatic_mode(
                configuration, loginname=arg.login, password=arg.password
            )
        elif (
            arg.server
            and arg.login
            and arg.password
            and (
                (arg.project and arg.version)
                or arg.tovKey
                or arg.cycleKey
                or arg.type == "i"
            )
            and not arg.manual
        ):
            server = resolve_server_name(arg.server)

            configuration = {
                "configuration": [
                    {
                        "server_url": server,
                        "verify": False,
                        "loginname": arg.login,
                        "password": arg.password,
                        "actions": [],
                    }
                ]
            }
            if arg.type == "e":
                configuration["configuration"][0]["actions"].append(
                    {
                        "type": "ExportXMLReport",
                        "parameters": {
                            "projectPath": [
                                e for e in [arg.project, arg.version, arg.cycle] if e
                            ],
                            "cycleKey": arg.cycleKey,
                            "tovKey": arg.tovKey,
                            "reportRootUID": arg.uid,
                            "filters": [],
                            "outputPath": arg.path,
                        },
                    }
                )
            else:
                configuration["configuration"][0]["actions"].append(
                    {
                        "type": "ImportExecutionResults",
                        "parameters": {
                            "projectPath": [
                                e for e in [arg.project, arg.version, arg.cycle] if e
                            ],
                            "cycleKey": arg.cycleKey,
                            "tovKey": arg.tovKey,
                            "reportRootUID": arg.uid,
                            "defaultTester": None,
                            "filters": [],
                            "inputPath": arg.path,
                        },
                    }
                )
            print("Arguments found")
            run_automatic_mode(configuration)
        else:
            server = resolve_server_name(arg.server) if arg.server else ""
            configuration = {
                "configuration": [
                    {
                        "server_url": server,
                        "verify": False,
                        "loginname": arg.login,
                        "password": arg.password,
                    }
                ]
            }
            print("No config file given")
            run_manual_mode(configuration)
    except KeyboardInterrupt:
        close_program()


def resolve_server_name(server):
    if fullmatch(r"([\w\-.\d]+)(:\d{1,5})", server):
        server = f"https://{server}/api/1/"
    elif fullmatch(r"([\w\-.\d]+)", server):
        server = f"https://{server}:9443/api/1/"
    elif fullmatch(r"https?://([\w\-.\d]+)(:\d{1,5})/api/1/", server):
        server = server
    else:
        raise ValueError(f"Server name '{server}' is not valid.")
    return server


def run_manual_mode(configuration: dict = {}):
    print("Starting manual mode")
    connection_log = ConnectionLog()

    while True:
        config = configuration.get("configuration", [{}])[0]
        server = config.get("server_url", "")
        loginname = config.get("loginname", "")
        pwd = config.get("password", "")
        active_connection = login(server, loginname, pwd)
        connection_log.add_connection(active_connection)
        next_action = choose_action()
        while next_action is not None:
            try:
                preparation_success = next_action.prepare(connection_log)
                if preparation_success:
                    if next_action.trigger(connection_log):
                        if next_action.wait(connection_log):
                            if next_action.finish(connection_log):
                                active_connection.add_action(next_action)
            except KeyError as e:
                print(f"key {str(e)} not found")
                print(f"Aborted action")

            except ValueError as e:
                print(str(e))
                print("Aborted action")

            except KeyboardInterrupt:
                print("Action aborted by user interrupt.")

            except Timeout:
                print("Action aborted due to timeout.")

            active_connection = connection_log.active_connection
            next_action = choose_action()


def run_automatic_mode(
    configuration: dict, loginname: Optional[str] = None, password: Optional[str] = None
):
    print("Run Automatic Mode")
    connection_queue = ConnectionLog()
    try:
        for connection_data in configuration["configuration"]:
            connection = Connection(**connection_data)
            if loginname:
                connection.loginname = loginname
            if password:
                connection.password = password
            connection_queue.add_connection(connection)

        job_counter = 0
        for i in range(len(connection_queue.connections)):
            while connection_queue.active_connection.actions_to_trigger:
                action_to_trigger = (
                    connection_queue.active_connection.actions_to_trigger[0]
                )
                action = Action(
                    action_to_trigger["type"], action_to_trigger["parameters"]
                )
                try:
                    action.trigger(connection_queue)
                    connection_queue.active_connection.actions_to_wait_for.append(
                        action
                    )
                    job_counter += 1
                except AssertionError as e:
                    print(e)
                finally:
                    connection_queue.active_connection.actions_to_trigger.remove(
                        action_to_trigger
                    )
                sleep(0.05)
            connection_queue.next()

        print(
            f"{job_counter} jobs started at {len(connection_queue.connections)} server(s)."
        )

        while True:
            active_connection = connection_queue.active_connection

            spin_spinner("Wait for Jobs to be finished.")
            for i in range(len(active_connection.actions_to_wait_for)):
                action_to_wait_for = active_connection.actions_to_wait_for[0]
                if action_to_wait_for.poll(connection_queue):
                    active_connection.actions_to_finish.append(action_to_wait_for)
                    active_connection.actions_to_wait_for.remove(action_to_wait_for)
                else:
                    active_connection.actions_to_wait_for = rotate(
                        active_connection.actions_to_wait_for
                    )

            for i in range(len(active_connection.actions_to_finish)):
                action_to_finish = active_connection.actions_to_finish[0]
                if action_to_finish.finish(connection_queue):
                    active_connection.action_log.append(action_to_finish)
                    active_connection.actions_to_finish.remove(action_to_finish)
                else:
                    active_connection.actions_to_finish = rotate(
                        active_connection.actions_to_finish
                    )

            if (
                len(active_connection.actions_to_trigger)
                + len(active_connection.actions_to_wait_for)
                + len(active_connection.actions_to_finish)
                == 0
            ):
                connection_queue.remove(active_connection)
            if connection_queue.len > 1:
                connection_queue.next()
            elif connection_queue.len == 0:
                break

    except KeyError as e:
        # TODO proper error handling
        print(f"key {str(e)} not found")


if __name__ == "__main__":
    main()
