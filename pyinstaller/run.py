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

from testbench_cli_reporter.config_model import (
    CliReporterConfig,
    Configuration,
    ExportXmlAction,
    ExportXmlParameters,
    ImportXMLAction,
    ImportXmlParameters,
    loggingConfig,
)
from testbench_cli_reporter.execution import run_automatic_mode, run_manual_mode
from testbench_cli_reporter.util import (
    ITEP_EXPORT_CONFIG,
    TYPICAL_XML_IMPORT_CONFIG,
    close_program,
    get_configuration,
    parser,
    resolve_server_name,
)


def main():
    arg = parser.parse_args()
    try:
        if arg.config:
            cli_config = get_configuration(arg.config)
            print("Config file found")
            run_automatic_mode(
                cli_config, loginname=arg.login, password=arg.password, sessionToken=arg.session
            )
        elif (
            arg.server
            and ((arg.login and arg.password) or arg.session)
            and ((arg.project and arg.version) or arg.tovKey or arg.cycleKey or arg.type == "i")
            and not arg.manual
        ):
            server = resolve_server_name(arg.server)
            config = Configuration(
                server_url=server,
                verify=False,
                basicAuth=(
                    base64.b64encode(f"{arg.login}:{arg.password}".encode()).decode()
                    if arg.login and arg.password
                    else None
                ),
                sessionToken=arg.session,
                actions=[],
            )

            cli_config = CliReporterConfig(
                configuration=[config],
                loggingConfiguration=loggingConfig.from_dict({}),
            )
            if arg.type == "e":
                export_config = ITEP_EXPORT_CONFIG
                export_config.reportRootUID = arg.uid if arg.uid else None
                cli_config.configuration[0].actions.append(  # type: ignore
                    ExportXmlAction(
                        ExportXmlParameters(
                            outputPath=arg.path,
                            projectPath=[e for e in [arg.project, arg.version, arg.cycle] if e],
                            tovKey=arg.tovKey,
                            cycleKey=arg.cycleKey,
                            report_config=export_config,
                        )
                    )
                )
            else:
                import_config = TYPICAL_XML_IMPORT_CONFIG
                import_config.reportRootUID = arg.uid if arg.uid else None
                cli_config.configuration[0].actions.append(  # type: ignore
                    ImportXMLAction(
                        ImportXmlParameters(
                            inputPath=arg.path,
                            projectPath=[e for e in [arg.project, arg.version, arg.cycle] if e],
                            cycleKey=arg.cycleKey,
                            importConfig=import_config,
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
                        sessionToken=arg.session,
                        actions=[],
                    )
                ],
                loggingConfiguration=loggingConfig.from_dict({}),
            )
            print("No config file given")
            run_manual_mode(cli_config)
    except KeyboardInterrupt:
        close_program()


if __name__ == "__main__":
    main()
