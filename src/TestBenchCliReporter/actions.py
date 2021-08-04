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

from zipfile import ZipFile
from abc import ABC, abstractmethod
from os import path
from xml.etree import ElementTree as ET
import sys
import base64
import requests
from TestBenchCliReporter import questions
from TestBenchCliReporter import util
from TestBenchCliReporter import testbench
from questionary import print


class Action(ABC):
    def __init__(self, parameters: dict = None):
        if parameters is None:
            self.parameters = {}
        else:
            self.parameters = parameters

    @staticmethod
    def create_instance_of_action(class_name: str, parameters: dict[str, str]):
        try:
            class_ = globals()[class_name]
            class_instance = class_(parameters)
            return class_instance
        except AttributeError:
            print(f"Failed to create class {class_name}")
            util.close_program()

    def prepare(self, connection_log: testbench.ConnectionLog) -> bool:
        return True

    @abstractmethod
    def execute(self, connection_log: testbench.ConnectionLog) -> bool:
        raise NotImplementedError

    def export(self):
        return {"type": type(self).__name__, "parameters": self.parameters}


class UnloggedAction(Action):
    def export(self):
        return None


class ExportXMLReport(Action):
    def prepare(self, connection_log: testbench.ConnectionLog) -> bool:
        all_projects = connection_log.active_connection().get_all_projects()
        selected_project = questions.ask_to_select_project(all_projects)
        selected_tov = questions.ask_to_select_tov(selected_project)
        self.parameters["tovKey"] = selected_tov["key"]["serial"]
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
            tttree_structure = connection_log.active_connection().get_tov_structure(
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
            tttree_structure = (
                connection_log.active_connection().get_test_cycle_structure(
                    self.parameters["cycleKey"]
                )
            )
        self.parameters["reportRootUID"] = questions.ask_to_select_report_root_uid(
            tttree_structure
        )
        all_filters = connection_log.active_connection().get_all_filters()
        self.parameters["filters"] = questions.ask_to_select_filters(all_filters)
        self.parameters["outputPath"] = questions.ask_for_output_path()

        return True

    def execute(self, connection_log: testbench.ConnectionLog) -> bool:
        try:
            report = connection_log.active_connection().get_xml_report(
                self.parameters["tovKey"],
                self.parameters["cycleKey"],
                self.parameters["reportRootUID"],
                self.parameters["filters"],
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


class ImportExecutionResults(Action):
    def prepare(self, connection_log: testbench.ConnectionLog) -> bool:
        self.parameters["inputPath"] = questions.ask_for_input_path()
        try:
            zip_file = ZipFile(self.parameters["inputPath"])
            xml = ET.fromstring(zip_file.read("report.xml"))
            project = xml.find("./header/project").get("name")
            version = xml.find("./header/version").get("name")
            cycle = xml.find("./header/cycle").get("name")
        except:
            pass
        all_projects = connection_log.active_connection().get_all_projects()
        selected_project = questions.ask_to_select_project(
            all_projects, default=project or None
        )
        selected_tov = questions.ask_to_select_tov(
            selected_project, default=version or None
        )
        self.parameters["cycleKey"] = questions.ask_to_select_cycle(
            selected_tov, default=cycle or None
        )["key"]["serial"]
        cycle_structure = connection_log.active_connection().get_test_cycle_structure(
            self.parameters["cycleKey"]
        )
        self.parameters["reportRootUID"] = questions.ask_to_select_report_root_uid(
            cycle_structure
        )
        available_testers = (
            connection_log.active_connection().get_all_testers_of_project(
                selected_project["key"]["serial"]
            )
        )
        self.parameters["defaultTester"] = questions.ask_to_select_default_tester(
            available_testers
        )
        all_filters = connection_log.active_connection().get_all_filters()
        self.parameters["filters"] = questions.ask_to_select_filters(all_filters)

        return True

    def execute(self, connection_log: testbench.ConnectionLog) -> bool:
        try:
            with open(self.parameters["inputPath"], "rb") as execution_report:
                execution_report_base64 = base64.b64encode(
                    execution_report.read()
                ).decode()

            success = connection_log.active_connection().import_execution_results(
                execution_report_base64,
                self.parameters["cycleKey"],
                self.parameters["reportRootUID"],
                self.parameters["defaultTester"],
                self.parameters["filters"],
            )
            return success
        except requests.RequestException as e:
            print("There was a problem with a request.")
            return False
        except IOError as e:
            print("Reading execution report failed.")
            return False
        except KeyError as e:
            print(f"Missing key {str(e)}")
            return False
            # TODO handle missing parameters


class ExportActionLog(UnloggedAction):
    def prepare(self, connection_log: testbench.ConnectionLog):
        self.parameters["outputPath"] = questions.ask_for_output_path("config.json")
        return True

    def execute(self, connection_log: testbench.ConnectionLog) -> bool:
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

    def execute(self, connection_log: testbench.ConnectionLog) -> bool:
        connection_log.active_connection().close()
        connection_log.add_connection(self.parameters["newConnection"])
        return True


class Quit(UnloggedAction):
    def execute(self, connection_log: testbench.ConnectionLog = None):
        print("Closing program.")
        sys.exit(0)
