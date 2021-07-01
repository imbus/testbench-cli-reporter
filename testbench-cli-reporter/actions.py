from __future__ import annotations
import testbench
from abc import ABC, abstractmethod
import sys
import questions
import util
import base64

class Action(ABC):
    def __init__(
        self,
        parameters: dict = None
    ):
        if parameters is None:
            self.parameters = {}
        else:
            self.parameters = parameters

    @staticmethod
    def create_instance_of_action(class_name: str, parameters: dict[str]):
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
        return {
            'type': type(self).__name__,
            'parameters': self.parameters
        }

class UnloggedAction(Action):
    def export(self):
        return None

class ExportXMLReport(Action):
    def prepare(self, connection_log: testbench.ConnectionLog) -> bool:        
        all_projects = connection_log.active_connection().get_all_projects()
        selected_project = questions.ask_to_select_project(all_projects)['project']
        selected_tov = questions.ask_to_select_tov(selected_project)['tov']
        self.parameters['cycleKey'] = questions.ask_to_select_cycle(selected_tov)['cycle']['key']['serial']
        self.parameters['reportRootUID'] = questions.ask_to_enter_report_root_uid()['uid']
        all_filters = connection_log.active_connection().get_all_filters()            
        self.parameters['filters'] = questions.ask_to_select_filters(all_filters)['filters']
        self.parameters['outputPath'] = questions.ask_for_output_path()['output_path']

        return True

    def execute(self, connection_log: testbench.ConnectionLog) -> bool:
        try:
            report = connection_log.active_connection().get_xml_report(self.parameters['cycleKey'], self.parameters['reportRootUID'], self.parameters['filters'])
            with open(self.parameters['outputPath'], 'wb') as output_file:
                output_file.write(report.content)
            print(f'Report {self.parameters["outputPath"]} was generated')
            return True
        except KeyError as e:
            print(f"{str(e)}")
            return False
            # TODO handle missing parameters


class ImportExecutionResults(Action):
    def prepare(self, connection_log: testbench.ConnectionLog) -> bool:    
        all_projects = connection_log.active_connection().get_all_projects()
        selected_project = questions.ask_to_select_project(all_projects)['project']
        selected_tov = questions.ask_to_select_tov(selected_project)['tov']
        self.parameters['cycleKey'] = questions.ask_to_select_cycle(selected_tov)['cycle']['key']['serial']
        self.parameters["inputPath"] = questions.ask_for_input_path()["input_path"]  
        self.parameters["reportRootUID"] = questions.ask_to_enter_report_root_uid()["uid"]
        available_testers = connection_log.active_connection().get_all_testers_of_project(selected_project['key']['serial'])
        self.parameters["defaultTester"] = questions.ask_to_select_default_tester(available_testers)["defaultTester"]
        all_filters = connection_log.active_connection().get_all_filters()            
        self.parameters['filters'] = questions.ask_to_select_filters(all_filters)['filters']

        return True

    def execute(self, connection_log: testbench.ConnectionLog) -> bool:
        try:
            with open(self.parameters['inputPath'], 'rb') as execution_report:
                execution_report_base64 = base64.b64encode(execution_report.read()).decode()

            success = connection_log.active_connection().import_execution_results(execution_report_base64, self.parameters["cycleKey"], self.parameters["reportRootUID"], self.parameters["defaultTester"], self.parameters["filters"])
            return success
        except IOError as e:
            print("Reading execution report failed.")
            return False
        except KeyError as e:
            print(f"Missing key {str(e)}")
            return False
            # TODO handle missing parameters

class ExportActionLog(UnloggedAction):
    def prepare(self, connection_log: testbench.ConnectionLog):
        self.parameters['outputPath'] = questions.ask_for_output_path()['output_path']
        return True

    def execute(self, connection_log: testbench.ConnectionLog) -> bool:
        connection_log.export_as_json(self.parameters['outputPath'])

class ChangeConnection(UnloggedAction):
    def prepare(self, connection_log: testbench.ConnectionLog):
        self.parameters["newConnection"] = util.login()
        return True

    def execute(self, connection_log: testbench.ConnectionLog) -> bool:
        connection_log.add_connection(self.parameters["newConnection"])
        return True

class Quit(UnloggedAction):
    def execute(self, connection_log: testbench.ConnectionLog = None):            
        print("Closing program.")
        sys.exit(0)