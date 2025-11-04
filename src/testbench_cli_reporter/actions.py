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
import contextlib
import csv
import json
import re
import sys
import traceback
from pathlib import Path
from time import monotonic
from typing import TYPE_CHECKING, Any, Optional
from xml.etree import ElementTree as ET
from zipfile import ZipFile

from . import questions

if TYPE_CHECKING:
    from .testbench import Connection, ConnectionLog
from .config_model import (
    ExportCsvParameters,
    ExportJsonParameters,
    ExportServerLogsParameters,
    ExportXmlParameters,
    ImportJsonParameters,
    ImportXmlParameters,
    JWTDataOptions,
    Key,
    ProjectCSVReportScope,
)
from .log import logger
from .util import (
    ITEP_EXPORT_CONFIG,
    TYPICAL_JSON_IMPORT_CONFIG,
    TYPICAL_XML_IMPORT_CONFIG,
    AbstractAction,
    get_cli_defaults,
    get_project_keys,
    pretty_print_cycle_selection,
    pretty_print_project_selection,
    pretty_print_project_tree_selection,
    pretty_print_success_message,
    pretty_print_test_cases,
    pretty_print_tov_selection,
    pretty_print_tse_information,
)


class UnloggedAction(AbstractAction):
    def export(self):
        return None

    def trigger(self, active_connection):
        raise NotImplementedError("Trigger method not supported for UnloggedAction")

    def trigger_connections(self, connection_log: "ConnectionLog") -> bool:
        raise NotImplementedError


class ExportXMLReport(AbstractAction):
    def __init__(self, parameters: ExportXmlParameters | dict[str, Any] | None = None):
        if isinstance(parameters, ExportXmlParameters):
            exp_parameters = parameters
        elif parameters is None:
            exp_parameters = ExportXmlParameters("report.zip")
        else:
            exp_parameters = ExportXmlParameters.from_dict(parameters or {})
        super().__init__()
        self.parameters: ExportXmlParameters = exp_parameters
        self.filters: list = []
        self.start_time: float = 0

    def prepare(self, active_connection: "Connection") -> bool:
        all_projects = active_connection.get_all_projects()
        selected_project = questions.ask_to_select_project(all_projects)
        selected_tov = questions.ask_to_select_tov(selected_project)
        self.parameters.tovKey = str(selected_tov["key"]["serial"])
        self.parameters.projectPath = [
            selected_project["name"],
            selected_tov["name"],
        ]
        selected_cycle = questions.ask_to_select_cycle(selected_tov, export=True)
        pretty_print_project_tree_selection(selected_project, selected_tov, selected_cycle)
        if selected_cycle == "NO_EXEC":
            self.parameters.cycleKey = None
            tttree_structure = active_connection.get_tov_structure(self.parameters.tovKey)
        else:
            self.parameters.cycleKey = str(selected_cycle["key"]["serial"])
            self.parameters.projectPath.append(selected_cycle["name"])
            tttree_structure = active_connection.get_test_cycle_structure(self.parameters.cycleKey)
        report_root_uid = questions.ask_to_select_report_root_uid(tttree_structure)
        all_filters = active_connection.get_all_filters()
        filters = questions.ask_to_select_filters(all_filters)
        self.parameters.report_config = questions.ask_to_config_xml_report()
        self.parameters.report_config.reportRootUID = report_root_uid
        self.parameters.report_config.filters = filters
        self.parameters.outputPath = questions.ask_for_output_path()

        return True

    def trigger(self, active_connection: "Connection") -> bool:
        if (not self.parameters.cycleKey or self.parameters.cycleKey == "0") and (
            not self.parameters.tovKey
            and self.parameters.projectPath is not None
            and len(self.parameters.projectPath) >= 2  # noqa: PLR2004
        ):
            all_projects = active_connection.get_all_projects()
            (
                _project_key,
                self.parameters.tovKey,
                self.parameters.cycleKey,
            ) = get_project_keys(all_projects, *self.parameters.projectPath)
        self.job_id = active_connection.trigger_xml_report_generation(
            self.parameters.tovKey or "",
            self.parameters.cycleKey or "",
            self.parameters.report_config or ITEP_EXPORT_CONFIG,
        )
        self.start_time = monotonic()
        return bool(self.job_id)

    def wait(self, active_connection: "Connection") -> bool:
        try:
            self.report_tmp_name = active_connection.wait_for_tmp_xml_report_name(self.job_id)
            return bool(self.report_tmp_name)
        except KeyError:
            logger.debug(traceback.format_exc())
            return False

    def poll(self, active_connection: "Connection") -> bool:
        result = active_connection.get_exp_job_result(self.job_id)
        if result is not None:
            self.report_tmp_name = result
        return bool(result)

    def finish(self, active_connection: "Connection") -> bool:
        report = active_connection.get_xml_report_data(str(self.report_tmp_name))
        with Path(self.parameters.outputPath).open("wb") as output_file:
            output_file.write(report)
        pretty_print_success_message("Report", Path(self.parameters.outputPath).resolve(), "was generated")
        logger.info(f"    Time elapsed: {monotonic() - self.start_time:.2f} seconds")
        return True


class ExportCSVReport(AbstractAction):
    def __init__(self, parameters: ExportCsvParameters | dict[str, Any] | None = None):
        if isinstance(parameters, ExportCsvParameters):
            exp_parameters = parameters
        elif parameters is None:
            exp_parameters = ExportCsvParameters("report.zip", "")
        else:
            exp_parameters = ExportCsvParameters.from_dict(parameters or {})
        super().__init__()
        self.parameters: ExportCsvParameters = exp_parameters
        self.filters: list = []
        self.start_time: float = 0

    def prepare(self, active_connection: "Connection") -> bool:
        all_projects = active_connection.get_all_projects()
        selected_project = questions.ask_to_select_project(all_projects)
        pretty_print_project_selection(selected_project)
        self.parameters.projectKey = selected_project["key"]["serial"]
        selected_tovs = questions.ask_to_select_tovs(selected_project)
        scopes = []
        for selected_tov in selected_tovs:
            print(f"{'-' * 33} Selected TOV {'-' * 33}")
            pretty_print_tov_selection(selected_tov)
            report_scope = ProjectCSVReportScope(Key(str(selected_tov["key"]["serial"])))
            selected_cycles = questions.ask_to_select_cycles(selected_tov, export=True)
            if selected_cycles == ["NO_EXEC"] or not selected_cycles:
                report_scope.cycleKeys = []
                tttree_structure = active_connection.get_tov_structure(report_scope.tovKey.serial)
            else:
                [pretty_print_cycle_selection(selected_cycle) for selected_cycle in selected_cycles]
                report_scope.cycleKeys = [
                    Key(str(selected_cycle["key"]["serial"])) for selected_cycle in selected_cycles
                ]
                tttree_structure = active_connection.get_test_cycle_structure(
                    report_scope.cycleKeys[0].serial
                )
            if questions.ask_to_select_tree_element():
                report_scope.reportRootUID = questions.ask_to_select_report_root_uid(tttree_structure)
                for tse in tttree_structure:
                    info, typ = self.get_test_structure_element_info(tse)
                    if info.get("uniqueID") == report_scope.reportRootUID:
                        pretty_print_tse_information(tse, typ, info)

            scopes.append(report_scope)
        self.parameters.report_config = questions.ask_to_config_csv_report()
        self.parameters.report_config.scopes = scopes
        self.parameters.outputPath = questions.ask_for_output_path()

        return True

    def get_test_structure_element_info(self, tse):
        # TODO: sollte mal in utils ausgelagert werden, da mehrfach implementiert
        for key, value in tse.items():
            if re.match(r".*_structure$", key):
                return value, re.sub(r"_structure$", "", key)
        raise ValueError(f"Unknown Element Type: {tse!s}")

    # TODO: Hier weiter machen!!!
    def trigger(self, active_connection: "Connection") -> bool:
        self.job_id = active_connection.trigger_csv_report_generation(
            project_key=self.parameters.projectKey,
            report_config=self.parameters.report_config,
        )
        self.start_time = monotonic()
        return bool(self.job_id)

    def wait(self, active_connection: "Connection") -> bool:
        try:
            self.report_tmp_name = active_connection.wait_for_tmp_csv_report_name(self.job_id)
            return bool(self.report_tmp_name)
        except KeyError:
            logger.debug(traceback.format_exc())
            return False

    def poll(self, active_connection: "Connection") -> bool:
        result = active_connection.get_exp_job_result(self.job_id)
        if result is not None:
            self.report_tmp_name = result
        return bool(result)

    def finish(self, active_connection: "Connection") -> bool:
        report = active_connection.get_csv_report_data(str(self.report_tmp_name))
        with Path(self.parameters.outputPath).open("wb") as output_file:
            output_file.write(report)
        pretty_print_success_message("Report", Path(self.parameters.outputPath).resolve(), "was generated")
        logger.info(f"    Time elapsed: {monotonic() - self.start_time:.2f} seconds")
        return True


class ExportJSONReport(AbstractAction):
    def __init__(self, parameters: ExportJsonParameters | dict[str, Any] | None = None):
        if isinstance(parameters, ExportJsonParameters):
            exp_parameters = parameters
        elif parameters is None:
            exp_parameters = ExportJsonParameters("json-report.zip")
        else:
            exp_parameters = ExportJsonParameters.from_dict(parameters or {})
        super().__init__()
        self.parameters: ExportJsonParameters = exp_parameters
        self.filters: list = []
        self.start_time: float = 0

    def prepare(self, active_connection: "Connection") -> bool:
        all_projects = active_connection.get_all_projects()
        selected_project = questions.ask_to_select_project(all_projects)
        selected_tov = questions.ask_to_select_tov(selected_project)
        self.parameters.tovKey = str(selected_tov["key"]["serial"])
        self.parameters.projectPath = [
            selected_project["name"],
            selected_tov["name"],
        ]
        selected_cycle = questions.ask_to_select_cycle(selected_tov, export=True)
        pretty_print_project_tree_selection(selected_project, selected_tov, selected_cycle)
        if selected_cycle == "NO_EXEC":
            self.parameters.cycleKey = None
            tttree_structure = active_connection.get_tov_structure(self.parameters.tovKey)
        else:
            self.parameters.cycleKey = str(selected_cycle["key"]["serial"])
            self.parameters.projectPath.append(selected_cycle["name"])
            tttree_structure = active_connection.get_test_cycle_structure(self.parameters.cycleKey)
        report_root_uid = questions.ask_to_select_report_root_uid(tttree_structure)
        all_filters = active_connection.get_all_filters()
        filters = questions.ask_to_select_filters(all_filters)
        self.parameters.report_config = questions.ask_to_config_json_report()
        self.parameters.report_config.treeRootUID = report_root_uid
        self.parameters.report_config.filters = filters
        self.parameters.outputPath = questions.ask_for_output_path()

        return True

    def trigger(self, active_connection: "Connection") -> bool:
        if (
            not self.parameters.projectKey
            and self.parameters.projectPath
            and len(self.parameters.projectPath) >= 1
        ):
            self.parameters.projectKey = active_connection.get_project_key_new_play(
                self.parameters.projectPath[0]
            )
        if not self.parameters.projectKey:
            raise ValueError("Invalid Config! 'projectKey' missing.")

        if (
            not self.parameters.tovKey
            and not self.parameters.cycleKey
            and self.parameters.projectPath
            and len(self.parameters.projectPath) >= 2  # noqa: PLR2004
        ):
            self.parameters.tovKey = active_connection.get_tov_key_new_play(
                self.parameters.projectKey, self.parameters.projectPath[1]
            )
        if not self.parameters.tovKey and not self.parameters.cycleKey:
            raise ValueError("Invalid Config! 'tovKey' and 'cycleKey' missing.")

        if (
            not self.parameters.cycleKey
            and self.parameters.projectPath
            and len(self.parameters.projectPath) == 3  # noqa: PLR2004
        ):
            self.parameters.cycleKey = active_connection.get_cycle_key_new_play(
                self.parameters.projectKey, self.parameters.tovKey, self.parameters.projectPath[2]
            )
        self.job_id = active_connection.trigger_json_report_generation(
            project_key=self.parameters.projectKey,
            tov_key=self.parameters.tovKey,
            cycle_key=self.parameters.cycleKey,
            report_config=self.parameters.report_config,
        )
        self.start_time = monotonic()
        return bool(self.job_id)

    def wait(self, active_connection: "Connection") -> bool:
        if not self.parameters.projectKey:
            raise ValueError("Invalid Config! 'projectKey' missing.")
        try:
            self.report_tmp_name = active_connection.wait_for_tmp_json_report_name(
                self.parameters.projectKey, self.job_id
            )
            return bool(self.report_tmp_name)
        except KeyError:
            logger.debug(traceback.format_exc())
            return False

    def poll(self, active_connection: "Connection") -> bool:
        if not self.parameters.projectKey or not self.job_id:
            raise ValueError("Invalid Config! 'projectKey' or 'job_id' missing.")
        result = active_connection.get_exp_json_job_result(self.parameters.projectKey, self.job_id)
        self.report_tmp_name = result.report_name or ""
        return result.completion

    def finish(self, active_connection: "Connection") -> bool:
        if not self.parameters.projectKey:
            raise ValueError("Invalid Config! 'projectKey' missing.")
        if not self.report_tmp_name or not isinstance(self.report_tmp_name, str):
            raise ValueError("Invalid Config! 'report_tmp_name' missing or not str.")
        report = active_connection.get_json_report_data(self.parameters.projectKey, self.report_tmp_name)
        with Path(self.parameters.outputPath).open("wb") as output_file:
            output_file.write(report)
        pretty_print_success_message("Report", Path(self.parameters.outputPath).resolve(), "was generated")
        logger.info(f"    Time elapsed: {monotonic() - self.start_time:.2f} seconds")
        return True


class ImportXMLExecutionResults(AbstractAction):
    def __init__(self, parameters: ImportXmlParameters | dict[str, Any] | None = None):
        if isinstance(parameters, ImportXmlParameters):
            imp_parameters = parameters
        elif parameters is None:
            imp_parameters = ImportXmlParameters("result.zip")
        else:
            imp_parameters = ImportXmlParameters.from_dict(parameters)
        super().__init__()
        self.parameters: ImportXmlParameters = imp_parameters
        self.start_time: float = 0

    def prepare(self, active_connection: "Connection") -> bool:
        self.parameters.inputPath = questions.ask_for_input_path()
        project = version = cycle = None
        with contextlib.suppress(Exception):
            project, version, cycle = self.get_project_path_from_report()

        all_projects = active_connection.get_all_projects()
        selected_project = questions.ask_to_select_project(all_projects, default=project)
        selected_tov = questions.ask_to_select_tov(selected_project, default=version)
        selected_cycle = questions.ask_to_select_cycle(selected_tov, default=cycle)
        pretty_print_project_tree_selection(selected_project, selected_tov, selected_cycle)
        self.parameters.cycleKey = str(selected_cycle["key"]["serial"])
        cycle_structure = active_connection.get_test_cycle_structure(self.parameters.cycleKey)
        report_root_uid = questions.ask_to_select_report_root_uid(cycle_structure)
        available_testers = active_connection.get_all_testers_of_project(selected_project["key"]["serial"])
        default_tester = questions.ask_to_select_default_tester(available_testers)
        all_filters = active_connection.get_all_filters()
        filters = questions.ask_to_select_filters(all_filters)
        self.parameters.importConfig = questions.ask_to_config_xml_import()
        self.parameters.importConfig.reportRootUID = report_root_uid
        self.parameters.importConfig.filters = filters
        self.parameters.importConfig.defaultTester = default_tester
        return True

    def get_project_path_from_report(self) -> list:
        with ZipFile(self.parameters.inputPath) as zip_file:
            xml = ET.fromstring(zip_file.read("report.xml"))
            project_element = xml.find("./header/project")
            project = project_element.get("name") if project_element is not None else ""
            version_element = xml.find("./header/version")
            version = version_element.get("name") if version_element is not None else ""
            cycle_element = xml.find("./header/cycle")
            cycle = cycle_element.get("name") if cycle_element is not None else ""
            return [project, version, cycle]

    def trigger(self, active_connection: "Connection") -> bool:
        if not self.parameters.cycleKey:
            if len(self.parameters.projectPath or []) != 3:  # noqa: PLR2004
                self.parameters.projectPath = self.get_project_path_from_report()
                if (
                    self.parameters.projectPath[0]
                    and self.parameters.projectPath[1]
                    and not self.parameters.projectPath[2]
                ):
                    raise ValueError(
                        "Report is missing cycle information. TOV based reports can not be imported."
                    )
            self.set_cycle_key_from_path(active_connection)

        with Path(self.parameters.inputPath).open("rb") as execution_report:
            execution_report_base64 = base64.b64encode(execution_report.read()).decode()

        serverside_file_name = active_connection.upload_execution_xml_results(execution_report_base64)
        if not self.parameters.cycleKey:
            raise ValueError("Invalid Config! 'cycleKey' missing.")
        if serverside_file_name:
            self.job_id = active_connection.trigger_execution_xml_results_import(
                self.parameters.cycleKey,
                serverside_file_name,
                self.parameters.importConfig or TYPICAL_XML_IMPORT_CONFIG,
            )
            self.start_time = monotonic()
            return True
        return False

    def set_cycle_key_from_path(self, active_connection: "Connection"):
        all_projects = active_connection.get_all_projects()
        if (
            isinstance(self.parameters.projectPath, list) and len(self.parameters.projectPath) == 3  # noqa: PLR2004
        ):
            (
                _project_key,
                _tov_key,
                self.parameters.cycleKey,
            ) = get_project_keys(all_projects, *self.parameters.projectPath)
        if not self.parameters.cycleKey:
            raise ValueError("Invalid Config! 'cycleKey' missing.")

    def wait(self, active_connection: "Connection") -> bool:
        self.report_tmp_name = active_connection.wait_for_execution_xml_results_import_to_finish(self.job_id)
        return bool(self.report_tmp_name)

    def poll(self, active_connection: "Connection") -> bool:
        result = active_connection.get_imp_job_result(self.job_id)
        if result is not None:
            self.report_tmp_name = result
        return bool(result)

    def finish(self, active_connection: "Connection") -> bool:
        if self.report_tmp_name:
            pretty_print_success_message("Report", Path(self.parameters.inputPath).resolve(), "was imported")
            logger.info(f"    Time elapsed: {monotonic() - self.start_time:.2f} seconds")
            return True
        return False


class ImportJSONExecutionResults(AbstractAction):
    def __init__(self, parameters: ImportJsonParameters | dict[str, Any] | None = None):
        if isinstance(parameters, ImportJsonParameters):
            imp_parameters = parameters
        elif parameters is None:
            imp_parameters = ImportJsonParameters("result.zip")
        else:
            imp_parameters = ImportJsonParameters.from_dict(parameters)
        super().__init__()
        self.parameters: ImportJsonParameters = imp_parameters
        self.start_time: float = 0

    def prepare(self, active_connection: "Connection") -> bool:
        self.parameters.inputPath = questions.ask_for_input_path()
        project = version = cycle = None
        with contextlib.suppress(Exception):
            project, version, cycle = self.get_project_path_from_report()

        all_projects = active_connection.get_all_projects()
        selected_project = questions.ask_to_select_project(all_projects, default=project)
        selected_tov = questions.ask_to_select_tov(selected_project, default=version)
        selected_cycle = questions.ask_to_select_cycle(selected_tov, default=cycle)
        pretty_print_project_tree_selection(selected_project, selected_tov, selected_cycle)
        self.parameters.projectKey = selected_project["key"]["serial"]
        self.parameters.cycleKey = str(selected_cycle["key"]["serial"])
        cycle_structure = active_connection.get_test_cycle_structure(self.parameters.cycleKey)
        report_root_uid = questions.ask_to_select_report_root_uid(cycle_structure)
        available_testers = active_connection.get_all_testers_of_project(selected_project["key"]["serial"])
        default_tester = questions.ask_to_select_default_tester(available_testers)
        all_filters = active_connection.get_all_filters()
        filters = questions.ask_to_select_filters(all_filters)
        self.parameters.importConfig = questions.ask_to_config_json_import()
        self.parameters.importConfig.reportRootUID = report_root_uid
        self.parameters.importConfig.filters = filters
        self.parameters.importConfig.defaultTester = default_tester
        return True

    def get_project_path_from_report(self) -> list:
        with ZipFile(self.parameters.inputPath) as zip_file:
            project_info: dict = json.load(zip_file.open("project.json"))
            return [
                project_info.get("name", ""),
                project_info.get("projectContext", {}).get("tovName", ""),
                project_info.get("projectContext", {}).get("cycleName", ""),
            ]

    def get_project_scope_from_report(self) -> dict:
        with ZipFile(self.parameters.inputPath) as zip_file:
            manifest_info: dict = json.load(zip_file.open("manifest.json"))
            report_creation = manifest_info.get("reportCreation", {})
            scope = report_creation.get("scope", {})
            return {
                "project_key": scope.get("projectKey", None),
                "tov_key": scope.get("tovKey", None),
                "cycle_key": scope.get("cycleKey", None),
            }

    def trigger(self, active_connection: "Connection") -> bool:
        if not self.parameters.cycleKey:
            if len(self.parameters.projectPath or []) != 3:  # noqa: PLR2004
                scope = self.get_project_scope_from_report()
                self.parameters.projectKey = scope.get("project_key")
                self.parameters.cycleKey = scope.get("cycle_key")
        elif not self.parameters.projectKey:
            raise ValueError("Invalid Config! 'projectKey' missing.")

        with Path(self.parameters.inputPath).open("rb") as execution_report:
            serverside_file_name = active_connection.upload_execution_json_results(
                self.parameters.projectKey, execution_report
            )
        if not self.parameters.cycleKey:
            raise ValueError("Invalid Config! 'cycleKey' missing.")
        if serverside_file_name:
            self.job_id = active_connection.trigger_execution_json_results_import(
                project_key=self.parameters.projectKey,
                cycle_key=self.parameters.cycleKey,
                serverside_file_name=serverside_file_name,
                import_config=self.parameters.importConfig or TYPICAL_JSON_IMPORT_CONFIG,
            )
            self.start_time = monotonic()
            return True
        return False

    def set_cycle_key_from_path(self, active_connection: "Connection"):
        all_projects = active_connection.get_all_projects()
        if (
            isinstance(self.parameters.projectPath, list) and len(self.parameters.projectPath) == 3  # noqa: PLR2004
        ):
            (
                self.parameters.projectKey,
                _tov_key,
                self.parameters.cycleKey,
            ) = get_project_keys(all_projects, *self.parameters.projectPath)
        if not self.parameters.cycleKey:
            raise ValueError("Invalid Config! 'cycleKey' missing.")
        if not self.parameters.projectKey:
            raise ValueError("Invalid Config! 'projectKey' missing.")

    def wait(self, active_connection: "Connection") -> bool:
        if not self.parameters.projectKey or not self.job_id:
            raise ValueError("Invalid Config! 'projectKey' or 'job_id' missing.")
        self.report_tmp_name = active_connection.wait_for_execution_json_results_import_to_finish(
            project_key=self.parameters.projectKey, job_id=self.job_id
        )
        return self.report_tmp_name

    def poll(self, active_connection: "Connection") -> bool:
        if not self.parameters.projectKey or not self.job_id:
            raise ValueError("Invalid Config! 'projectKey' or 'job_id' missing.")
        result = active_connection.get_imp_json_job_result(
            project_key=self.parameters.projectKey, job_id=self.job_id
        )
        self.report_tmp_name = result.completion
        return result.completion

    def finish(self, active_connection: "Connection") -> bool:
        if self.report_tmp_name:
            pretty_print_success_message(
                "JSON-Report", Path(self.parameters.inputPath).resolve(), "was imported"
            )
            logger.info(f"    Time elapsed: {monotonic() - self.start_time:.2f} seconds")
            return True
        return False


class ExportServerLogs(AbstractAction):
    def __init__(self, parameters: ExportServerLogsParameters | dict[str, Any] | None = None):
        if isinstance(parameters, ExportServerLogsParameters):
            exp_parameters = parameters
        elif parameters is None:
            exp_parameters = ExportServerLogsParameters("server_logs.zip")
        else:
            exp_parameters = ExportServerLogsParameters.from_dict(parameters or {})
        super().__init__()
        self.parameters: ExportServerLogsParameters = exp_parameters

    def prepare(self, active_connection: "Connection") -> bool:
        self.parameters.outputPath = questions.ask_for_output_path("server_logs.zip")
        return True

    def trigger(self, active_connection: "Connection") -> bool:
        return True

    def finish(self, active_connection: "Connection") -> bool:
        self.start_time: float = 0
        try:
            server_logs = active_connection.get_server_logs()
            with Path(self.parameters.outputPath).open("wb") as output_file:
                output_file.write(server_logs)
            pretty_print_success_message(
                "Server Logs", Path(self.parameters.outputPath).resolve(), "were generated"
            )
            logger.info(f"    Time elapsed: {monotonic() - self.start_time:.2f} seconds")
            return True
        except Exception as e:
            logger.error(f"An error occurred while exporting server logs: {e!s}")
            return False


class RequestJWT(AbstractAction):
    """
    Logged admin action: configure JWT options (permissions optional), call server,
    and print token + expiry.
    """

    def __init__(self, parameters: JWTDataOptions | dict[str, object] | None = None):
        params = (
            parameters
            if isinstance(parameters, JWTDataOptions)
            else JWTDataOptions.from_dict(parameters or {})
        )
        super().__init__(params)
        self.parameters: JWTDataOptions = params
        self._jwt_response: dict | None = None

    def prepare(self, active_connection: "Connection") -> bool:
        selected_perms = questions.ask_to_select_permissions()
        project_key = questions.text_prompt("Project Key (optional):", default="", validation=None)
        tov_key = questions.text_prompt("TOV Key (optional):", default="", validation=None)
        cycle_key = questions.text_prompt("Cycle Key (optional):", default="", validation=None)
        subject = questions.text_prompt(
            "Subject (optional, default 'Testbench'):", default="", validation=None
        )
        exp = questions.text_prompt(
            "Expires after seconds (optional, default 86400):", default="", validation=None
        )

        self.parameters.permissions = selected_perms
        self.parameters.projectKey = project_key or None
        self.parameters.tovKey = tov_key or None
        self.parameters.cycleKey = cycle_key or None
        self.parameters.subject = subject or None
        self.parameters.expiresAfterSeconds = int(exp) if (exp.strip().isdigit()) else None
        return True

    def trigger(self, active_connection: "Connection") -> bool:
        self._jwt_response = active_connection.request_jwt(
            permissions=self.parameters.permissions,
            projectKey=self.parameters.projectKey,
            tovKey=self.parameters.tovKey,
            cycleKey=self.parameters.cycleKey,
            subject=self.parameters.subject,
            expiresAfterSeconds=self.parameters.expiresAfterSeconds,
        )
        self.job_id = "jwt"
        return True

    def finish(self, active_connection: "Connection") -> bool:
        if not self._jwt_response:
            return False
        token = self._jwt_response.get("accessToken", "")
        expires_at = self._jwt_response.get("expiresAt", "")
        if token:
            print("\nJWT token:\n")
            print(token)
            if expires_at:
                print(f"\nExpires At: {expires_at}")
            return True
        return False


class ExportProjectMembers(UnloggedAction):
    def prepare(self, active_connection: "Connection") -> bool:
        all_projects = active_connection.get_all_projects()
        selected_projects = questions.ask_to_select_projects(all_projects)
        if not selected_projects:
            print("No projects selected. Aborting action.")
            return False
        if len(selected_projects) == 1:
            self.parameters["outputPath"] = questions.ask_for_output_path(
                f"{selected_projects[0]['name']}_members.csv"
            )
        else:
            self.parameters["outputPath"] = questions.ask_for_output_path("project_members/")
        self.parameters["selected_projects"] = selected_projects
        pretty_print_success_message("", len(selected_projects), "projects selected")
        return True

    def trigger_connections(self, connection_log: "ConnectionLog") -> bool:
        selected_projects = self.parameters.get("selected_projects", [])
        project_members = {}

        for project in selected_projects:
            members = connection_log.active_connection.get_project_members(project["key"]["serial"])
            project_members[project["name"]] = [self._format_member_data(member) for member in members]

        self._write_members_to_files(selected_projects, project_members)
        return True

    def _format_member_data(self, member: dict) -> dict:
        """Format member data for CSV export."""
        member_value = member["value"]
        roles = member_value["membership"]["roles"]

        return {
            "User Name": member_value["user-name"],
            "User Login": member_value["user-login"],
            "Test Manager": self._has_role(roles, "Test Manager"),
            "Test Designer": self._has_role(roles, "Test Designer"),
            "Test Programmer": self._has_role(roles, "Test Programmer"),
            "Tester": self._has_role(roles, "Tester"),
            "Read-Only": self._has_role(roles, "Read Only"),
        }

    def _has_role(self, roles: list, role_name: str) -> bool:
        """Check if a specific role exists in the list of roles."""
        return any(role_name in role for role in roles)

    def _write_members_to_files(self, selected_projects: list, project_members: dict) -> None:
        """Write project members to CSV files."""
        if len(selected_projects) == 1:
            self._write_single_project_file(selected_projects[0]["name"], project_members)
        else:
            self._write_multiple_project_files(project_members)

    def _write_single_project_file(self, project_name: str, project_members: dict) -> None:
        """Write members of a single project to CSV file."""
        project_path = Path(self.parameters["outputPath"])
        project_path.parent.mkdir(parents=True, exist_ok=True)
        with project_path.open("w", encoding="utf-8") as output_file:
            self._write_project_members_to_csv(project_members[project_name], output_file)
        pretty_print_success_message("Project members successfully written to:\n", project_path.resolve(), "")

    def _write_multiple_project_files(self, project_members: dict) -> None:
        """Write members of multiple projects to separate CSV files."""
        export_dir = Path(self.parameters["outputPath"])
        for project_name, members in project_members.items():
            project_path = export_dir / f"{project_name}_members.csv"
            project_path.parent.mkdir(parents=True, exist_ok=True)
            with project_path.open("w", encoding="utf-8") as output_file:
                self._write_project_members_to_csv(members, output_file)
        pretty_print_success_message(
            "Project members successfully written to directory:\n", export_dir.resolve(), ""
        )

    def _write_project_members_to_csv(self, members, output_file):
        writer = csv.DictWriter(
            output_file,
            fieldnames=[
                "User Name",
                "User Login",
                "Test Manager",
                "Test Designer",
                "Test Programmer",
                "Tester",
                "Read-Only",
            ],
            delimiter=";",
            quoting=csv.QUOTE_MINIMAL,
        )
        writer.writeheader()
        writer.writerows(members)


class BrowseProjects(UnloggedAction):
    def prepare(self, active_connection: "Connection") -> bool:
        defaults = get_cli_defaults()
        project = defaults.get("project") or ""
        version = defaults.get("version") or ""
        cycle = defaults.get("cycle") or ""
        all_projects = active_connection.get_all_projects()
        selected_project = questions.ask_to_select_project(all_projects, default=project)
        selected_tov = questions.ask_to_select_tov(selected_project, default=version)
        selected_cycle = questions.ask_to_select_cycle(selected_tov, default=cycle, export=True)
        pretty_print_project_tree_selection(selected_project, selected_tov, selected_cycle)
        if selected_cycle == "NO_EXEC":
            tttree_structure = active_connection.get_tov_structure(selected_tov["key"]["serial"])
        else:
            tttree_structure = active_connection.get_test_cycle_structure(selected_cycle["key"]["serial"])
        selected_uid = questions.ask_to_select_report_root_uid(tttree_structure)
        for tse in tttree_structure:
            info, typ = self.get_test_structure_element_info(tse)
            if info.get("uniqueID") == selected_uid:
                pretty_print_tse_information(tse, typ, info)
                if typ == "TestCaseSet":
                    test_cases = active_connection.get_test_cases(tse)
                    pretty_print_test_cases(test_cases)
        return True

    def get_test_structure_element_info(self, tse):
        for key, value in tse.items():
            if re.match(r".*_structure$", key):
                return value, re.sub(r"_structure$", "", key)
        raise ValueError(f"Unknown Element Type: {tse!s}")

    def trigger_connections(self, connection_log: "ConnectionLog") -> bool:
        return True


class ExportActionLog(UnloggedAction):
    def prepare(self, active_connection: "Connection"):
        self.parameters["outputPath"] = questions.ask_for_output_path("config.json")
        return True

    def trigger_connections(self, connection_log: "ConnectionLog") -> bool:
        try:
            connection_log.export_as_json(self.parameters["outputPath"])
            pretty_print_success_message(
                "Config", str(Path(self.parameters["outputPath"]).resolve()), "was generated"
            )
            return True
        except KeyError as e:
            print(f"KeyError {e!s}")
        except Exception as e:
            print(f"An error occurred: {e!s}")
        return False


class ChangeConnection(UnloggedAction):
    def prepare(self, active_connection: "Connection"):
        from .testbench import login  # noqa: PLC0415

        self.parameters["newConnection"] = login()
        return True

    def trigger_connections(self, connection_log: "ConnectionLog") -> bool:
        connection_log.active_connection.close()
        connection_log.add_connection(self.parameters["newConnection"])
        return True


class Quit(UnloggedAction):
    def trigger_connections(self, connection_log: Optional["ConnectionLog"] = None):
        print("Closing program.")
        sys.exit(0)


class Back(UnloggedAction):
    def trigger_connections(self, connection_log: Optional["ConnectionLog"] = None):
        return True


class OpenAdminMenu(UnloggedAction):
    def trigger_connections(self, connection_log: Optional["ConnectionLog"] = None):
        return True


ACTION_CLASSES: dict[str, type[AbstractAction]] = {
    "ExportXMLReport": ExportXMLReport,
    "ExportJSONReport": ExportJSONReport,
    "ExportCSVReport": ExportCSVReport,
    "ImportXMLExecutionResults": ImportXMLExecutionResults,
    "ImportJSONExecutionResults": ImportJSONExecutionResults,
    "ExportServerLogs": ExportServerLogs,
    "RequestJWT": RequestJWT,
}


def Action(class_name: str, parameters: dict[str, str]) -> AbstractAction:  # noqa: N802
    action_class = ACTION_CLASSES.get(class_name)
    if action_class is None:
        raise TypeError(f"Unknown or unsupported automated action class: {class_name}")
    return action_class(parameters)
