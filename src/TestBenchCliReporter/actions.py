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

from __future__ import annotations

from typing import Dict, Optional, Union
from zipfile import ZipFile
from abc import ABC, abstractmethod
from os import path
from xml.etree import ElementTree as ET
import sys
import base64
from TestBenchCliReporter import questions
from TestBenchCliReporter import util
from TestBenchCliReporter import testbench
from questionary import print


def Action(class_name: str, parameters: dict[str, str]) -> AbstractAction:
    try:
        return globals()[class_name](parameters)
    except AttributeError:
        print(f"Failed to create class {class_name}")
        util.close_program()


class AbstractAction(ABC):
    def __init__(self, parameters: Optional[Dict] = None):
        self.parameters = parameters or {}
        self.report_tmp_name = ""
        self.job_id = ""

    def prepare(self, connection_log: testbench.ConnectionLog) -> bool:
        return True

    @abstractmethod
    def trigger(self, connection_log: testbench.ConnectionLog) -> bool:
        raise NotImplementedError

    def wait(self, connection_log: testbench.ConnectionLog) -> bool:
        return True

    def poll(self, connection_log: testbench.ConnectionLog) -> bool:
        return True

    def finish(self, connection_log: testbench.ConnectionLog) -> bool:
        return True

    def export(self):
        return {"type": type(self).__name__, "parameters": self.parameters}


class UnloggedAction(AbstractAction):
    def export(self):
        return None


class ExportXMLReport(AbstractAction):
    def prepare(self, connection_log: testbench.ConnectionLog) -> bool:
        all_projects = connection_log.active_connection.get_all_projects()
        selected_project = questions.ask_to_select_project(all_projects)
        selected_tov = questions.ask_to_select_tov(selected_project)
        self.parameters["tovKey"] = selected_tov["key"]["serial"]
        self.parameters["projectPath"] = [
            selected_project["name"],
            selected_tov["name"],
        ]
        selected_cycle = questions.ask_to_select_cycle(selected_tov, export=True)
        print("  Selection:")

        print(
            f"{' '*4 + selected_project['name']: <50}",
            style="#06c8ff bold italic",
            end=None,
        )
        print(f"  projectKey: ", end=None)
        print(f"{selected_project['key']['serial']: >15}", style="#06c8ff bold italic")

        print(
            f"{' '*6 + selected_tov['name']: <50}",
            style="#06c8ff bold italic",
            end=None,
        )
        print(f"  tovKey:     ", end=None)
        print(f"{selected_tov['key']['serial']: >15}", style="#06c8ff bold italic")
        if selected_cycle == "NO_EXEC":
            self.parameters["cycleKey"] = None
            tttree_structure = connection_log.active_connection.get_tov_structure(
                self.parameters["tovKey"]
            )
        else:
            print(
                f"{' '*8 + selected_cycle['name']: <50}",
                style="#06c8ff bold italic",
                end=None,
            )
            print(f"  cycleKey:   ", end=None)
            print(
                f"{selected_cycle['key']['serial']: >15}", style="#06c8ff bold italic"
            )
            self.parameters["cycleKey"] = selected_cycle["key"]["serial"]
            self.parameters["projectPath"].append(selected_cycle["name"])
            tttree_structure = (
                connection_log.active_connection.get_test_cycle_structure(
                    self.parameters["cycleKey"]
                )
            )
        self.parameters["reportRootUID"] = questions.ask_to_select_report_root_uid(
            tttree_structure
        )
        all_filters = connection_log.active_connection.get_all_filters()
        self.parameters["filters"] = questions.ask_to_select_filters(all_filters)
        self.parameters["report_config"] = questions.ask_to_config_report()
        self.parameters["outputPath"] = questions.ask_for_output_path()

        return True

    def trigger(self, connection_log: testbench.ConnectionLog) -> bool:
        if not self.parameters.get("cycleKey"):
            if (
                not self.parameters.get("tovKey")
                and len(self.parameters["projectPath"]) >= 2
            ):
                all_projects = connection_log.active_connection.get_all_projects()
                (
                    project_key,
                    self.parameters["tovKey"],
                    self.parameters["cycleKey"],
                ) = util.get_project_keys(all_projects, *self.parameters["projectPath"])

        try:
            self.job_id = (
                connection_log.active_connection.trigger_xml_report_generation(
                    self.parameters.get("tovKey"),
                    self.parameters.get("cycleKey"),
                    self.parameters["reportRootUID"],
                    self.parameters["filters"],
                    self.parameters["report_config"],
                )
            )
            return True
        except KeyError as e:
            print(f"{str(e)}")
            return False
            # TODO handle missing parameters

    def wait(self, connection_log: testbench.ConnectionLog) -> Union[bool, str]:
        try:
            self.report_tmp_name = (
                connection_log.active_connection.wait_for_tmp_xml_report_name(
                    self.job_id
                )
            )
            return self.report_tmp_name
        except KeyError as e:
            print(f"{str(e)}")
            return False

    def poll(self, connection_log: testbench.ConnectionLog) -> bool:
        result = connection_log.active_connection.get_exp_job_result(self.job_id)
        if result is not None:
            self.report_tmp_name = result
        return result

    def finish(self, connection_log: testbench.ConnectionLog) -> bool:
        try:
            report = connection_log.active_connection.get_xml_report_data(
                self.report_tmp_name
            )
            with open(self.parameters["outputPath"], "wb") as output_file:
                output_file.write(report)
            print(f"Report ", end=None)
            print(
                f'{path.abspath(self.parameters["outputPath"])}',
                style="#06c8ff bold italic",
                end=None,
            )
            print(f" was generated")
            return True
        except KeyError as e:
            print(f"{str(e)}")
            return False
            # TODO handle missing parameters


class ImportExecutionResults(AbstractAction):
    def prepare(self, connection_log: testbench.ConnectionLog) -> bool:
        self.parameters["inputPath"] = questions.ask_for_input_path()
        project = version = cycle = None
        try:
            zip_file = ZipFile(self.parameters["inputPath"])
            xml = ET.fromstring(zip_file.read("report.xml"))
            project = xml.find("./header/project").get("name")
            version = xml.find("./header/version").get("name")
            cycle = xml.find("./header/cycle").get("name")
        except:
            pass
        all_projects = connection_log.active_connection.get_all_projects()
        selected_project = questions.ask_to_select_project(
            all_projects, default=project
        )
        selected_tov = questions.ask_to_select_tov(selected_project, default=version)
        self.parameters["cycleKey"] = questions.ask_to_select_cycle(
            selected_tov, default=cycle
        )["key"]["serial"]
        cycle_structure = connection_log.active_connection.get_test_cycle_structure(
            self.parameters["cycleKey"]
        )
        self.parameters["reportRootUID"] = questions.ask_to_select_report_root_uid(
            cycle_structure
        )
        available_testers = connection_log.active_connection.get_all_testers_of_project(
            selected_project["key"]["serial"]
        )
        self.parameters["defaultTester"] = questions.ask_to_select_default_tester(
            available_testers
        )
        all_filters = connection_log.active_connection.get_all_filters()
        self.parameters["filters"] = questions.ask_to_select_filters(all_filters)
        self.parameters["importConfig"] = questions.ask_to_config_import()
        return True

    def trigger(self, connection_log: testbench.ConnectionLog) -> bool:
        with open(self.parameters["inputPath"], "rb") as execution_report:
            execution_report_base64 = base64.b64encode(execution_report.read()).decode()

        serverside_file_name = (
            connection_log.active_connection.upload_execution_results(
                execution_report_base64
            )
        )
        if serverside_file_name:
            self.job_id = (
                connection_log.active_connection.trigger_execution_results_import(
                    self.parameters["cycleKey"],
                    self.parameters["reportRootUID"],
                    serverside_file_name,
                    self.parameters["defaultTester"],
                    self.parameters["filters"],
                    self.parameters["importConfig"],
                )
            )
            return True

    def wait(self, connection_log: testbench.ConnectionLog) -> bool:
        self.report_tmp_name = connection_log.active_connection.wait_for_execution_results_import_to_finish(
            self.job_id
        )
        return self.report_tmp_name

    def poll(self, connection_log: testbench.ConnectionLog) -> bool:
        result = connection_log.active_connection.get_imp_job_result(self.job_id)
        if result is not None:
            self.report_tmp_name = result
        return result

    def finish(self, connection_log: testbench.ConnectionLog) -> bool:
        if self.report_tmp_name:
            print(f"Report ", end=None)
            print(
                f'{path.abspath(self.parameters["inputPath"])}',
                style="#06c8ff bold italic",
                end=None,
            )
            print(f" was imported")
            return True


class ExportActionLog(UnloggedAction):
    def prepare(self, connection_log: testbench.ConnectionLog):
        self.parameters["outputPath"] = questions.ask_for_output_path("config.json")
        return True

    def trigger(self, connection_log: testbench.ConnectionLog) -> bool:
        try:
            connection_log.export_as_json(self.parameters["outputPath"])
            print(f"Config ", end=None)
            print(
                f'{path.abspath(self.parameters["outputPath"])}',
                style="#06c8ff bold italic",
                end=None,
            )
            print(f" was generated")
            return True
        except KeyError as e:
            print(f"{str(e)}")
            return False


class ChangeConnection(UnloggedAction):
    def prepare(self, connection_log: testbench.ConnectionLog):
        self.parameters["newConnection"] = util.login()
        return True

    def trigger(self, connection_log: testbench.ConnectionLog) -> bool:
        connection_log.active_connection.close()
        connection_log.add_connection(self.parameters["newConnection"])
        return True


class Quit(UnloggedAction):
    def trigger(self, connection_log: testbench.ConnectionLog = None):
        print("Closing program.")
        sys.exit(0)
