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
import base64

from .config_model import (
    CliReporterConfig,
    Configuration,
    ExportAction,
    ExportParameters,
    ImportAction,
    ImportParameters,
)
from .execution import run_automatic_mode, run_manual_mode
from .util import close_program, get_configuration, parser, resolve_server_name

__version__ = "1.2.0"


def main():
    arg = parser.parse_args()
    try:
        if arg.config:
            cli_config = get_configuration(arg.config)
            print("Config file found")
            run_automatic_mode(cli_config, loginname=arg.login, password=arg.password)
        elif (
            arg.server
            and arg.login
            and arg.password
            and ((arg.project and arg.version) or arg.tovKey or arg.cycleKey or arg.type == "i")
            and not arg.manual
        ):
            server = resolve_server_name(arg.server)

            cli_config = CliReporterConfig(
                configuration=[
                    Configuration(
                        server_url=server,
                        verify=False,
                        basicAuth=base64.b64encode(
                            f"{arg.login}:{arg.password}".encode("utf-8")
                        ).decode(),
                        actions=[],
                    )
                ]
            )
            if arg.type == "e":
                cli_config.configuration[0].actions.append(
                    ExportAction(
                        ExportParameters(
                            outputPath=arg.path,
                            projectPath=[e for e in [arg.project, arg.version, arg.cycle] if e],
                            tovKey=arg.tovKey,
                            cycleKey=arg.cycleKey,
                            reportRootUID=arg.uid,
                            filters=[],
                        )
                    )
                )
            else:
                cli_config.configuration[0].actions.append(
                    ImportAction(
                        ImportParameters(
                            inputPath=arg.path,
                            projectPath=[e for e in [arg.project, arg.version, arg.cycle] if e],
                            cycleKey=arg.cycleKey,
                            reportRootUID=arg.uid,
                            defaultTester=None,
                            filters=[],
                        )
                    )
                )
            print("Arguments found")
            run_automatic_mode(cli_config)
        else:
            server = resolve_server_name(arg.server) if arg.server else ""
            cli_config = CliReporterConfig(
                configuration=[
                    Configuration(
                        server_url=server,
                        verify=False,
                        loginname=arg.login,
                        password=arg.password,
                        actions=[],
                    )
                ]
            )
            print("No config file given")
            run_manual_mode(cli_config)
    except KeyboardInterrupt:
        close_program()


if __name__ == "__main__":
    main()
