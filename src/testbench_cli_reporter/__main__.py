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
import re
from collections.abc import Iterable
from copy import deepcopy
from dataclasses import dataclass

import click

from .config_model import (
    BaseAction,
    CliReporterConfig,
    Configuration,
    ExportCsvAction,
    ExportCsvParameters,
    ExportJsonAction,
    ExportJsonParameters,
    ExportServerLogsAction,
    ExportServerLogsParameters,
    ExportXmlAction,
    ExportXmlParameters,
    FilteringOptions,
    ImportJSONAction,
    ImportJsonParameters,
    ImportXMLAction,
    ImportXmlParameters,
    JWTDataOptions,
    Key,
    Permission,
    ProjectCSVReportOptions,
    ProjectCSVReportScope,
    RequestJWTAction,
    loggingConfig,
)
from .execution import run_automatic_mode, run_manual_mode
from .util import (
    ITEP_EXPORT_CONFIG,
    TYPICAL_JSON_IMPORT_CONFIG,
    TYPICAL_XML_IMPORT_CONFIG,
    JsonExportConfig,
    close_program,
    get_configuration,
    load_filtering_options,
    resolve_server_name,
    set_cli_defaults,
)

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}

PERMISSION_NAMES = ", ".join(sorted(permission.value for permission in Permission))
_PERMISSION_SPLITTER = re.compile(r"[|,]")


@dataclass
class ConnectionDetails:
    server_url: str
    verify: bool
    basic_auth: str | None
    session_token: str | None
    login: str | None
    password: str | None


def _connection_options(func):
    options = [
        click.option("-s", "--server", default=None, help="TestBench server address (hostname[:port])."),
        click.option("--login", default=None, help="Login name for authentication."),
        click.option("--password", default=None, help="Password for authentication."),
        click.option("--session", default=None, help="Existing session token."),
        click.option("--verify", is_flag=True, help="Verify TLS certificates."),
    ]
    for option in reversed(options):
        func = option(func)
    return func


def _merge_connection_options(  # noqa: PLR0913
    ctx: click.Context,
    server: str | None,
    login: str | None,
    password: str | None,
    session: str | None,
    verify: bool | None,
) -> tuple[str, str | None, str | None, str | None, bool]:
    parent = ctx.find_object(dict) or {}
    merged_server = server or parent.get("server") or ""
    merged_login = login or parent.get("login") or None
    merged_password = password or parent.get("password") or None
    merged_session = session or parent.get("session") or None
    merged_verify = verify if verify is not None else parent.get("verify", False)
    return merged_server, merged_login, merged_password, merged_session, bool(merged_verify)


def _prepare_connection_details(
    server: str,
    login: str | None,
    password: str | None,
    session: str | None,
    verify: bool,
) -> ConnectionDetails:
    if not server:
        raise click.UsageError("Please provide a server via --server.")
    try:
        server_url = resolve_server_name(server)
    except ValueError as exc:  # pragma: no cover - handled by click
        raise click.UsageError(str(exc)) from exc

    if session:
        return ConnectionDetails(server_url, verify, None, session, None, None)
    if login and password:
        credentials = base64.b64encode(f"{login}:{password}".encode()).decode()
        return ConnectionDetails(server_url, verify, credentials, None, login, password)
    raise click.UsageError("Provide --login/--password or an existing --session token.")


def _build_cli_config(details: ConnectionDetails, actions: Iterable[BaseAction]) -> CliReporterConfig:
    configuration = Configuration(
        server_url=details.server_url,
        verify=details.verify,
        basicAuth=details.basic_auth,
        sessionToken=details.session_token,
        loginname=details.login,
        password=details.password,
        actions=list(actions),
    )
    return CliReporterConfig(
        configuration=[configuration],
        loggingConfiguration=loggingConfig.from_dict({}),
    )


def _parse_permission_inputs(values: tuple[str, ...]) -> list[Permission]:
    normalized: set[str] = {
        chunk.strip() for value in values for chunk in _PERMISSION_SPLITTER.split(value) if chunk.strip()
    }
    invalid: set[str] = set()
    permissions: list[Permission] = []
    for chunk in normalized:
        try:
            permissions.append(Permission(chunk))
        except ValueError:
            invalid.add(chunk)
    if invalid:
        invalid_list = ", ".join(sorted(invalid))
        raise click.BadParameter(f"Unknown permission(s): {invalid_list}.", param_hint="--permission")
    return permissions


def _run_automatic_action(details: ConnectionDetails, action: BaseAction) -> None:
    cli_config = _build_cli_config(details, [action])
    run_automatic_mode(
        cli_config,
        loginname=details.login,
        password=details.password,
        sessionToken=details.session_token,
    )


def _parse_filtering_option(value: str | None, param_hint: str) -> FilteringOptions | None:
    try:
        return load_filtering_options(value)
    except ValueError as exc:
        raise click.BadParameter(str(exc), param_hint=param_hint) from exc


@click.group(context_settings=CONTEXT_SETTINGS, invoke_without_command=True)
@click.option(
    "-c",
    "--config",
    type=click.Path(dir_okay=False),
    default=None,
    help="Path to a config JSON file.",
)
@click.option("-s", "--server", default="", help="TestBench server address (hostname[:port]).")
@click.option("--session", default="", help="Existing session token.")
@click.option("--login", default="", help="Login name for authentication.")
@click.option("--password", default="", help="Password for authentication.")
@click.option("--project", default="", help="Default project.")
@click.option("--version", default="", help="Default test object version.")
@click.option("--cycle", default="", help="Default test cycle.")
@click.option("--manual", is_flag=True, help="Force manual mode.")
@click.option("--verify", is_flag=True, help="Verify TLS certificates.")
@click.pass_context
def cli(  # noqa: PLR0913
    ctx: click.Context,
    config: str | None,
    server: str,
    login: str,
    password: str,
    session: str,
    verify: bool,
    manual: bool,
    project: str,
    version: str,
    cycle: str,
) -> None:
    ctx.ensure_object(dict)
    ctx.obj.update(
        {
            "server": server,
            "login": login or None,
            "password": password or None,
            "session": session or None,
            "verify": verify,
        }
    )
    set_cli_defaults({"project": project or None, "version": version or None, "cycle": cycle or None})

    if ctx.invoked_subcommand is not None:
        if manual:
            raise click.UsageError("--manual cannot be combined with commands.")
        return None

    try:
        if config:
            click.echo("Config file found")
            cli_config = get_configuration(config)
            if not manual:
                return run_automatic_mode(
                    cli_config,
                    loginname=login or None,
                    password=password or None,
                    sessionToken=session or None,
                )
            run_manual_mode(cli_config)
            return None

        click.echo("No config file given")
        server_url = ""
        if server:
            try:
                server_url = resolve_server_name(server)
            except ValueError as exc:  # pragma: no cover - handled by click
                raise click.UsageError(str(exc)) from exc
        cli_config = CliReporterConfig(
            configuration=[
                Configuration(
                    server_url=server_url,
                    verify=verify,
                    loginname=login or "",
                    password=password or "",
                    sessionToken=session or "",
                    actions=[],
                )
            ],
            loggingConfiguration=loggingConfig.from_dict({}),
        )
        run_manual_mode(cli_config)
    except KeyboardInterrupt:  # pragma: no cover - manual interruption
        close_program()


@cli.command("export-xml")
@_connection_options
@click.option("-p", "--project", default=None, help="Project name.")
@click.option("-v", "--version", default=None, help="Test object version name.")
@click.option("-y", "--cycle", default=None, help="Test cycle name.")
@click.option("--project-key", default=None, help="Project key. IGNORED")
@click.option("--tov-key", default=None, help="Test object version key.")
@click.option("--cycle-key", default=None, help="Test cycle key.")
@click.option("-u", "--uid", default=None, help="Report root UID.")
@click.option("--filtering", default=None, help="FilteringOptions payload as base64 encoded JSON.")
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False, writable=True),
    default="report.zip",
    show_default=True,
    help="Output zip file path.",
)
@click.pass_context
def export_xml(  # noqa: PLR0913
    ctx: click.Context,
    server: str | None,
    login: str | None,
    password: str | None,
    session: str | None,
    verify: bool | None,
    project: str | None,
    version: str | None,
    cycle: str | None,
    project_key: str | None,
    tov_key: str | None,
    cycle_key: str | None,
    uid: str,
    filtering: str | None,
    output: str,
) -> None:
    server, login, password, session, verify = _merge_connection_options(
        ctx, server, login, password, session, verify
    )
    details = _prepare_connection_details(server, login, password, session, verify)
    project_path = [value for value in [project, version, cycle] if value]
    if not (project_path or tov_key or cycle_key):
        raise click.UsageError(
            "Provide --project/--version[/--cycle] or specify --tov-key / --cycle-key for export-xml."
        )
    export_config = deepcopy(ITEP_EXPORT_CONFIG)
    export_config.reportRootUID = uid or None
    if filtering_options := _parse_filtering_option(filtering, "--filtering"):
        export_config.filters = filtering_options.get_applied_filters()
    parameters = ExportXmlParameters(
        outputPath=output,
        projectPath=project_path or None,
        tovKey=tov_key or None,
        cycleKey=cycle_key or None,
        report_config=export_config,
    )
    _run_automatic_action(details, ExportXmlAction(parameters=parameters))


@cli.command("import-xml")
@_connection_options
@click.option(
    "-i",
    "--input",
    "input_path",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Path to the XML results zip file.",
)
@click.option("-u", "--uid", default="ROOT", show_default=True, help="Report root UID.")
@click.option("--filtering", default=None, help="FilteringOptions payload as base64 encoded JSON.")
@click.pass_context
def import_xml(  # noqa: PLR0913
    ctx: click.Context,
    server: str | None,
    login: str | None,
    password: str | None,
    session: str | None,
    verify: bool | None,
    input_path: str,
    uid: str,
    filtering: str | None,
) -> None:
    server, login, password, session, verify = _merge_connection_options(
        ctx, server, login, password, session, verify
    )
    details = _prepare_connection_details(server, login, password, session, verify)
    import_config = deepcopy(TYPICAL_XML_IMPORT_CONFIG)
    import_config.reportRootUID = uid or None
    if filtering_options := _parse_filtering_option(filtering, "--filtering"):
        import_config.filters = filtering_options.get_applied_filters()
    parameters = ImportXmlParameters(
        inputPath=input_path,
        importConfig=import_config,
    )
    _run_automatic_action(details, ImportXMLAction(parameters=parameters))


@cli.command("export-json")
@_connection_options
@click.option("-p", "--project", default=None, help="Project name.")
@click.option("-v", "--version", default=None, help="Test object version name.")
@click.option("-y", "--cycle", default=None, help="Test cycle name.")
@click.option("--project-key", default=None, help="Project key.")
@click.option("--tov-key", default=None, help="Test object version key.")
@click.option("--cycle-key", default=None, help="Test cycle key.")
@click.option("-u", "--uid", default=None, help="Tree root UID.")
@click.option("--filtering", default=None, help="FilteringOptions payload as base64 encoded JSON.")
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False, writable=True),
    default="json-report.zip",
    show_default=True,
    help="Output zip file path.",
)
@click.pass_context
def export_json(  # noqa: PLR0913
    ctx: click.Context,
    server: str | None,
    login: str | None,
    password: str | None,
    session: str | None,
    verify: bool | None,
    project: str | None,
    version: str | None,
    cycle: str | None,
    project_key: str | None,
    tov_key: str | None,
    cycle_key: str | None,
    uid: str | None,
    filtering: str | None,
    output: str,
) -> None:
    server, login, password, session, verify = _merge_connection_options(
        ctx, server, login, password, session, verify
    )
    details = _prepare_connection_details(server, login, password, session, verify)
    project_path = [value for value in [project, version, cycle] if value]
    if not (project_key or project_path):
        raise click.UsageError("Provide --project-key or --project/--version[/--cycle] for export-json.")
    report_config = JsonExportConfig["iTorx Export (execution)"]
    if uid:
        report_config.treeRootUID = uid
    if filtering_options := _parse_filtering_option(filtering, "--filtering"):
        report_config.filters = filtering_options.get_applied_filters()
    parameters = ExportJsonParameters(
        outputPath=output,
        projectPath=project_path or None,
        projectKey=project_key or None,
        tovKey=tov_key or None,
        cycleKey=cycle_key or None,
        report_config=report_config,
    )
    _run_automatic_action(details, ExportJsonAction(parameters=parameters))


@cli.command("import-json")
@_connection_options
@click.option(
    "-i",
    "--input",
    "input_path",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Path to the JSON results zip file.",
)
@click.option("-u", "--uid", default=None, help="Report root UID.")
@click.option("--filtering", default=None, help="FilteringOptions payload as base64 encoded JSON.")
@click.pass_context
def import_json(  # noqa: PLR0913
    ctx: click.Context,
    server: str | None,
    login: str | None,
    password: str | None,
    session: str | None,
    verify: bool | None,
    input_path: str,
    uid: str | None,
    filtering: str | None,
) -> None:
    server, login, password, session, verify = _merge_connection_options(
        ctx, server, login, password, session, verify
    )
    details = _prepare_connection_details(server, login, password, session, verify)
    import_config = deepcopy(TYPICAL_JSON_IMPORT_CONFIG)
    import_config.reportRootUID = uid or None
    if filtering_options := _parse_filtering_option(filtering, "--filtering"):
        import_config.filters = filtering_options.get_applied_filters()
    parameters = ImportJsonParameters(
        inputPath=input_path,
        importConfig=import_config,
    )
    _run_automatic_action(details, ImportJSONAction(parameters=parameters))


@cli.command("export-csv")
@_connection_options
@click.option("--project-key", required=True, help="Project key.")
@click.option("--tov-key", required=True, help="Test object version key.")
@click.option("--cycle-key", multiple=True, help="Test cycle key (repeatable).")
@click.option("-u", "--uid", default=None, help="Report root UID.")
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False, writable=True),
    default="csv_report.zip",
    show_default=True,
    help="Output zip file path.",
)
@click.pass_context
def export_csv(  # noqa: PLR0913
    ctx: click.Context,
    server: str | None,
    login: str | None,
    password: str | None,
    session: str | None,
    verify: bool | None,
    project_key: str,
    tov_key: str,
    cycle_key: tuple[str, ...],
    uid: str | None,
    output: str,
) -> None:
    server, login, password, session, verify = _merge_connection_options(
        ctx, server, login, password, session, verify
    )
    details = _prepare_connection_details(server, login, password, session, verify)
    scope = ProjectCSVReportScope(
        tovKey=Key(tov_key),
        reportRootUID=uid or None,
        cycleKeys=[Key(value) for value in cycle_key],
    )
    report_config = ProjectCSVReportOptions(scopes=[scope])
    parameters = ExportCsvParameters(
        outputPath=output,
        projectKey=project_key,
        report_config=report_config,
    )
    _run_automatic_action(details, ExportCsvAction(parameters=parameters))


@cli.command("export-logs")
@_connection_options
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False, writable=True),
    default="server_logs.zip",
    show_default=True,
    help="Output zip file path.",
)
@click.pass_context
def export_logs(  # noqa: PLR0913
    ctx: click.Context,
    server: str | None,
    login: str | None,
    password: str | None,
    session: str | None,
    verify: bool | None,
    output: str,
) -> None:
    server, login, password, session, verify = _merge_connection_options(
        ctx, server, login, password, session, verify
    )
    details = _prepare_connection_details(server, login, password, session, verify)
    parameters = ExportServerLogsParameters(outputPath=output)
    _run_automatic_action(details, ExportServerLogsAction(parameters=parameters))


@cli.command(
    "gen-jwt",
    help="Generate a JWT for the current session.",
    epilog=f"Available permissions: {PERMISSION_NAMES}.",
)
@_connection_options
@click.option(
    "--permission",
    multiple=True,
    help="Permission to include in the token (repeatable, accepts comma or '|' separated lists).",
)
@click.option("--project-key", default=None, help="Project key.")
@click.option("--tov-key", default=None, help="Test object version key.")
@click.option("--cycle-key", default=None, help="Test cycle key.")
@click.option("--subject", default=None, help="Subject claim for the token.")
@click.option("--expires", type=int, default=None, help="Token expiry in seconds.")
@click.pass_context
def gen_jwt(  # noqa: PLR0913
    ctx: click.Context,
    server: str | None,
    login: str | None,
    password: str | None,
    session: str | None,
    verify: bool | None,
    permission: tuple[str, ...],
    project_key: str | None,
    tov_key: str | None,
    cycle_key: str | None,
    subject: str | None,
    expires: int | None,
) -> None:
    """Generate a JWT for the current session."""
    server, login, password, session, verify = _merge_connection_options(
        ctx, server, login, password, session, verify
    )
    details = _prepare_connection_details(server, login, password, session, verify)
    parameters = JWTDataOptions(
        projectKey=project_key or None,
        tovKey=tov_key or None,
        cycleKey=cycle_key or None,
        permissions=_parse_permission_inputs(permission),
        subject=subject or None,
        expiresAfterSeconds=expires,
    )
    _run_automatic_action(details, RequestJWTAction(parameters=parameters))


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
