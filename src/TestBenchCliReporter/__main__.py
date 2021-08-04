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
from TestBenchCliReporter.testbench import ConnectionLog, Connection
from TestBenchCliReporter import util
from TestBenchCliReporter import actions
from requests.exceptions import Timeout

__version__ = "1.0.rc2"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c",
        "--configFile",
        help="Path to a config file to execute pre-set actions based on the given configuration.",
        type=str,
    )
    arguments = parser.parse_args()
    try:
        if arguments.configFile is not None:
            configuration = util.get_configuration(arguments.configFile)
            print("Config file found")
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
                    execution_success = next_action.execute(connection_log)
                    if execution_success:
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


def run_automatic_mode(configuration: dict):
    print("Run Automatic Mode")
    connection_log = ConnectionLog()
    try:
        for connection_data in configuration["configuration"]:
            active_connection = Connection(**connection_data)
            connection_log.add_connection(active_connection)
            for action_data in connection_data["actions"]:
                next_action = actions.Action.create_instance_of_action(
                    action_data["type"], action_data["parameters"]
                )
                execution_success = next_action.execute(connection_log)
                if execution_success:
                    active_connection.add_action(next_action)
                active_connection = connection_log.active_connection()

    except KeyError as e:
        # TODO proper error handling
        print(f"key {str(e)} not found")


if __name__ == "__main__":
    main()
