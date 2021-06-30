from __future__ import annotations
import testbench
from abc import ABC, abstractmethod
import sys
import questions
import util

class Action(ABC):
    def __init__(
        self,
    ):
        self.parameters = {}

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
    def execute(self, connection_log: testbench.ConnectionLog) -> bool:
        all_projects = connection_log.active_connection().get_all_projects()
        selected_project = questions.ask_to_select_project(all_projects)['project']
        selected_tov = questions.ask_to_select_tov(selected_project)['tov']
        self.parameters['cycleKey'] = questions.ask_to_select_cycle(selected_tov)['cycle']['key']['serial']
        self.parameters['reportRootUID'] = questions.ask_to_enter_report_root_uid()['uid']
        all_filters = connection_log.active_connection().get_all_filters()            
        self.parameters['filters'] = questions.ask_to_select_filters(all_filters)['filters']
        self.parameters['outputPath'] = questions.ask_for_output_path()['output_path']
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

class ExportActionLog(UnloggedAction):
    def execute(self, connection_log: testbench.ConnectionLog) -> bool:
        output_path = questions.ask_for_output_path()['output_path']
        connection_log.export_as_json(output_path)

class ChangeConnection(UnloggedAction):
    def execute(self, connection_log: testbench.ConnectionLog) -> bool:
        new_connection = util.login()
        connection_log.add_connection(new_connection)
        return True

class Quit(UnloggedAction):
    def execute(self, connection_log: testbench.ConnectionLog = None):            
        print("Closing program.")
        sys.exit(0)