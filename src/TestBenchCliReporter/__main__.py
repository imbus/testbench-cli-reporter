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

import argparse
from re import fullmatch
from time import sleep
from typing import Optional

from TestBenchCliReporter.testbench import ConnectionLog, Connection
from TestBenchCliReporter import util
from TestBenchCliReporter import actions
from requests.exceptions import Timeout

__version__ = "1.0.rc2"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c",
        "--config",
        help="Path to a config file to execute pre-set actions based on the given configuration.",
        type=str,
    )
    parser.add_argument(
        "-s",
        "--server",
        help="TestBench Server address (hostname:port)",
        type=str,
    )
    parser.add_argument(
        "--loginname",
        help="Users Login (only if config file is given)",
        type=str,
    )
    parser.add_argument(
        "--password",
        help="Users Password (only if config file is given)",
        type=str,
    )
    parser.add_argument(
        "-p",
        "--project",
        help="Project name to be exported",
        type=str,
    )
    parser.add_argument(
        "-v",
        "--version",
        help="Test Object Version name to be exported",
        type=str,
    )
    parser.add_argument(
        "-y",
        "--cycle",
        help="Test Cycle name to be exported",
        type=str,
    )
    parser.add_argument(
        "-u",
        "--uid",
        help="Root UID to be exported",
        type=str,
    )
    parser.add_argument(
        "-t",
        "--type",
        help="'e' for Export (default), 'i' for Import",
        type=str,
        choices=["e", "i"],
        default="e",
    )
    parser.add_argument(
        "path",
        nargs="?",
        help="Input- and Output-Path for xml reports.",
        type=str,
        default="report.zip",
    )
    arg = parser.parse_args()
    try:
        if arg.config:
            configuration = util.get_configuration(arg.config)
            print("Config file found")
            run_automatic_mode(configuration)
        elif (
            arg.server
            and arg.loginname
            and arg.password
            and arg.project
            and arg.version
        ):
            if fullmatch(r"([\w\-.\d]+)(:\d{1,5})", arg.server):
                server = f"https://{arg.server}/api/1/"
            elif fullmatch(r"([\w\-.\d]+)", arg.server):
                server = f"https://{arg.server}:9443/api/1/"
            elif fullmatch(r"https?://([\w\-.\d]+)(:\d{1,5})/api/1/", arg.server):
                server = arg.server
            else:
                raise ValueError(f"Server name '{arg.server}' is not valid.")

            configuration = {
                "configuration": [
                    {
                        "server_url": server,
                        "verify": False,
                        "loginname": arg.loginname,
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
                            "reportRootUID": arg.uid if arg.uid else "ROOT",
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
                            "reportRootUID": arg.uid if arg.uid else "ROOT",
                            "defaultTester": None,
                            "filters": [],
                            "inputPath": arg.path,
                        },
                    }
                )
            print("Arguments found")
            run_automatic_mode(configuration)
        else:
            print("No config file given")
            run_manual_mode()
    except KeyboardInterrupt:
        util.close_program()


def run_manual_mode():
    print("Starting manual mode")
    connection_log = ConnectionLog()

    while True:
        active_connection = util.login()
        connection_log.add_connection(active_connection)
        next_action = util.choose_action()
        while next_action is not None:
            try:
                preparation_success = next_action.prepare(connection_log)
                if preparation_success:
                    next_action.trigger(connection_log)
                    next_action.poll(connection_log)
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

            active_connection = connection_log.active_connection()
            next_action = util.choose_action()


def run_automatic_mode(
    configuration: dict, loginname: Optional[str] = None, password: Optional[str] = None
):
    print("Run Automatic Mode")
    connection_log = ConnectionLog()
    try:
        for connection_data in configuration["configuration"]:
            active_connection = Connection(**connection_data)
            if loginname:
                active_connection.loginname = loginname
            if password:
                active_connection.password = password
            connection_log.add_connection(active_connection)
            for action_data in connection_data["actions"]:
                next_action = actions.Action.create_instance_of_action(
                    action_data["type"], action_data["parameters"]
                )
                sleep(0.1)
                next_action.trigger(connection_log)
                next_action.poll(connection_log)
                if next_action.finish(connection_log):
                    active_connection.add_action(next_action)
                active_connection = connection_log.active_connection()  # ToDo why?

    except KeyError as e:
        # TODO proper error handling
        print(f"key {str(e)} not found")


if __name__ == "__main__":
    main()
