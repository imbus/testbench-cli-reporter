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

from .util import (
    close_program,
    get_configuration,
    parser,
    resolve_server_name,
)
from .execution import run_manual_mode, run_automatic_mode

__version__ = "1.0.2"


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


if __name__ == "__main__":
    main()
