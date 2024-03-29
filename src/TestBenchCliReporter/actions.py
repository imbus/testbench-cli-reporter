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
import re
import sys
import traceback
from pathlib import Path
from typing import Any, Dict, List, Union
from xml.etree import ElementTree
from zipfile import ZipFile

from . import questions, testbench
from .config_model import ExportParameters, ImportParameters
from .log import logger
from .testbench import ConnectionLog
from .util import (
    TYPICAL_IMPORT_CONFIG,
    AbstractAction,
    XmlExportConfig,
    close_program,
    get_project_keys,
    parser,
    pretty_print_project_selection,
    pretty_print_success_message,
    pretty_print_test_cases,
    pretty_print_tse_information,
)


class UnloggedAction(AbstractAction):
    def export(self):
        return None


class ExportXMLReport(AbstractAction):
    def __init__(self, parameters: Union[ExportParameters, Dict[str, Any], None] = None):
        if parameters and isinstance(parameters, ExportParameters):
            exp_parameters = parameters
        elif parameters is None:
            exp_parameters = ExportParameters("report.zip")
        else:
            exp_parameters = ExportParameters.from_dict(parameters or {})
        super().__init__()
        self.parameters: ExportParameters = exp_parameters
        self.filters = []

    def prepare(self, connection_log: ConnectionLog) -> bool:
        all_projects = connection_log.active_connection.get_all_projects()
        selected_project = questions.ask_to_select_project(all_projects)
        selected_tov = questions.ask_to_select_tov(selected_project)
        self.parameters.tovKey = selected_tov["key"]["serial"]
        self.parameters.projectPath = [
            selected_project["name"],
            selected_tov["name"],
        ]
        selected_cycle = questions.ask_to_select_cycle(selected_tov, export=True)
        pretty_print_project_selection(selected_project, selected_tov, selected_cycle)
        if selected_cycle == "NO_EXEC":
            self.parameters.cycleKey = None
            tttree_structure = connection_log.active_connection.get_tov_structure(
                self.parameters.tovKey
            )
        else:
            self.parameters.cycleKey = selected_cycle["key"]["serial"]
            self.parameters.projectPath.append(selected_cycle["name"])
            tttree_structure = connection_log.active_connection.get_test_cycle_structure(
                self.parameters.cycleKey
            )
        self.parameters.reportRootUID = questions.ask_to_select_report_root_uid(tttree_structure)
        all_filters = connection_log.active_connection.get_all_filters()
        self.parameters.filters = questions.ask_to_select_filters(all_filters)
        self.filters = self.parameters.filters
        self.parameters.report_config = questions.ask_to_config_report()
        self.parameters.outputPath = questions.ask_for_output_path()

        return True

    def trigger(self, connection_log: ConnectionLog) -> Union[bool, str]:
        if (not self.parameters.cycleKey or self.parameters.cycleKey == "0") and (
            not self.parameters.tovKey and len(self.parameters.projectPath) >= 2  # noqa: PLR2004
        ):
            all_projects = connection_log.active_connection.get_all_projects()
            (
                project_key,
                self.parameters.tovKey,
                self.parameters.cycleKey,
            ) = get_project_keys(all_projects, *self.parameters.projectPath)

        self.job_id = connection_log.active_connection.trigger_xml_report_generation(
            self.parameters.tovKey,
            self.parameters.cycleKey,
            self.parameters.reportRootUID or "ROOT",
            self.parameters.filters or [],
            self.parameters.report_config or XmlExportConfig["Itep Export"],
        )
        return self.job_id

    def wait(self, connection_log: ConnectionLog) -> bool:
        try:
            self.report_tmp_name = connection_log.active_connection.wait_for_tmp_xml_report_name(
                self.job_id
            )
            return bool(self.report_tmp_name)
        except KeyError:
            logger.debug(traceback.format_exc())
            return False

    def poll(self, connection_log: ConnectionLog) -> bool:
        result = connection_log.active_connection.get_exp_job_result(self.job_id)
        if result is not None:
            self.report_tmp_name = result
        return bool(result)

    def finish(self, connection_log: ConnectionLog) -> bool:
        report = connection_log.active_connection.get_xml_report_data(self.report_tmp_name)
        with Path(self.parameters.outputPath).open("wb") as output_file:
            output_file.write(report)
        pretty_print_success_message(
            "Report", Path(self.parameters.outputPath).resolve(), "was generated"
        )
        return True


def Action(class_name: str, parameters: Dict[str, str]) -> AbstractAction:  # noqa: N802
    try:
        return globals()[class_name](parameters)
    except AttributeError:
        logger.error(f"Failed to create class {class_name}")
        close_program()


class ImportExecutionResults(AbstractAction):
    def __init__(self, parameters: Union[ImportParameters, Dict[str, Any], None] = None):
        if parameters and isinstance(parameters, ImportParameters):
            imp_parameters = parameters
        elif parameters is None:
            imp_parameters = ImportParameters("result.zip")
        else:
            imp_parameters = ImportParameters.from_dict(parameters)
        super().__init__()
        self.parameters: ImportParameters = imp_parameters

    def prepare(self, connection_log: ConnectionLog) -> bool:
        self.parameters.inputPath = questions.ask_for_input_path()
        project = version = cycle = None
        with contextlib.suppress(Exception):
            project, version, cycle = self.get_project_path_from_report()

        all_projects = connection_log.active_connection.get_all_projects()
        selected_project = questions.ask_to_select_project(all_projects, default=project)
        selected_tov = questions.ask_to_select_tov(selected_project, default=version)
        selected_cycle = questions.ask_to_select_cycle(selected_tov, default=cycle)
        pretty_print_project_selection(selected_project, selected_tov, selected_cycle)
        self.parameters.cycleKey = selected_cycle["key"]["serial"]
        cycle_structure = connection_log.active_connection.get_test_cycle_structure(
            self.parameters.cycleKey
        )
        self.parameters.reportRootUID = questions.ask_to_select_report_root_uid(cycle_structure)
        available_testers = connection_log.active_connection.get_all_testers_of_project(
            selected_project["key"]["serial"]
        )
        self.parameters.defaultTester = questions.ask_to_select_default_tester(available_testers)
        all_filters = connection_log.active_connection.get_all_filters()
        self.parameters.filters = questions.ask_to_select_filters(all_filters)
        self.parameters.importConfig = questions.ask_to_config_import()
        return True

    def get_project_path_from_report(self) -> List:
        with ZipFile(self.parameters.inputPath) as zip_file:
            xml = ElementTree.fromstring(zip_file.read("report.xml"))
            project_element = xml.find("./header/project")
            project = project_element.get("name") if project_element is not None else ""
            version_element = xml.find("./header/version")
            version = version_element.get("name") if version_element is not None else ""
            cycle_element = xml.find("./header/cycle")
            cycle = cycle_element.get("name") if cycle_element is not None else ""
            return [project, version, cycle]

    def trigger(self, connection_log: ConnectionLog) -> bool:
        if not self.parameters.cycleKey:
            if len(self.parameters.projectPath or []) != 3:  # noqa: PLR2004
                self.parameters.projectPath = self.get_project_path_from_report()
            self.set_cycle_key_from_path(connection_log)

        with Path(self.parameters.inputPath).open("rb") as execution_report:
            execution_report_base64 = base64.b64encode(execution_report.read()).decode()

        serverside_file_name = connection_log.active_connection.upload_execution_results(
            execution_report_base64
        )
        if not self.parameters.cycleKey:
            raise ValueError("Invalid Config! 'cycleKey' missing.")
        if serverside_file_name:
            self.job_id = connection_log.active_connection.trigger_execution_results_import(
                self.parameters.cycleKey,
                self.parameters.reportRootUID or "ROOT",
                serverside_file_name,
                self.parameters.defaultTester,
                self.parameters.filters or [],
                self.parameters.importConfig or TYPICAL_IMPORT_CONFIG,
            )
            return True
        return False

    def set_cycle_key_from_path(self, connection_log: ConnectionLog):
        all_projects = connection_log.active_connection.get_all_projects()
        if (
            isinstance(self.parameters.projectPath, list)
            and len(self.parameters.projectPath) == 3  # noqa: PLR2004
        ):
            (
                project_key,
                tov_key,
                self.parameters.cycleKey,
            ) = get_project_keys(all_projects, *self.parameters.projectPath)
        if not self.parameters.cycleKey:
            raise ValueError("Invalid Config! 'cycleKey' missing.")

    def wait(self, connection_log: ConnectionLog) -> bool:
        self.report_tmp_name = (
            connection_log.active_connection.wait_for_execution_results_import_to_finish(
                self.job_id
            )
        )
        return bool(self.report_tmp_name)

    def poll(self, connection_log: ConnectionLog) -> bool:
        result = connection_log.active_connection.get_imp_job_result(self.job_id)
        if result is not None:
            self.report_tmp_name = result
        return bool(result)

    def finish(self, connection_log: ConnectionLog) -> bool:
        if self.report_tmp_name:
            pretty_print_success_message(
                "Report", Path(self.parameters.inputPath).resolve(), "was imported"
            )
            return True
        return False


class BrowseProjects(UnloggedAction):
    def prepare(self, connection_log: ConnectionLog) -> bool:
        arg = parser.parse_args()
        project = arg.project
        version = arg.version
        cycle = arg.cycle
        all_projects = connection_log.active_connection.get_all_projects()
        selected_project = questions.ask_to_select_project(all_projects, default=project)
        selected_tov = questions.ask_to_select_tov(selected_project, default=version)
        selected_cycle = questions.ask_to_select_cycle(selected_tov, default=cycle, export=True)
        pretty_print_project_selection(selected_project, selected_tov, selected_cycle)
        if selected_cycle == "NO_EXEC":
            tttree_structure = connection_log.active_connection.get_tov_structure(
                selected_tov["key"]["serial"]
            )
        else:
            tttree_structure = connection_log.active_connection.get_test_cycle_structure(
                selected_cycle["key"]["serial"]
            )
        selected_uid = questions.ask_to_select_report_root_uid(tttree_structure)
        for tse in tttree_structure:
            info, typ = self.get_test_structure_element_info(tse)
            if info.get("uniqueID") == selected_uid:
                pretty_print_tse_information(tse, typ, info)
                if typ == "TestCaseSet":
                    test_cases = connection_log.active_connection.get_test_cases(tse)
                    pretty_print_test_cases(test_cases)
        return True

    def get_test_structure_element_info(self, tse):
        for key, value in tse.items():
            if re.match(r".*_structure$", key):
                return value, re.sub(r"_structure$", "", key)
        raise ValueError(f"Unknown Element Type: {str(tse)}")

    def trigger(self, connection_log: ConnectionLog) -> bool:
        return True


class ExportActionLog(UnloggedAction):
    def prepare(self, connection_log: ConnectionLog):
        self.parameters["outputPath"] = questions.ask_for_output_path("config.json")
        return True

    def trigger(self, connection_log: ConnectionLog) -> bool:
        try:
            connection_log.export_as_json(self.parameters["outputPath"])
            pretty_print_success_message(
                "Config", str(Path(self.parameters["outputPath"]).resolve()), "was generated"
            )
            return True
        except KeyError as e:
            print(f"{str(e)}")
            return False


class ChangeConnection(UnloggedAction):
    def prepare(self, connection_log: ConnectionLog):
        self.parameters["newConnection"] = testbench.login()
        return True

    def trigger(self, connection_log: ConnectionLog) -> bool:
        connection_log.active_connection.close()
        connection_log.add_connection(self.parameters["newConnection"])
        return True


class Quit(UnloggedAction):
    def trigger(self, connection_log=None):
        print("Closing program.")
        sys.exit(0)
