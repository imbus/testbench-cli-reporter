from __future__ import annotations
import requests
import urllib3
import time
import actions
import json

class ConnectionLog:
    def __init__(
        self,
    ):
        self._connections: list[Connection] = []

    def active_connection(self) -> Connection:
        return self._connections[-1]

    def add_connection(self, new_connection: Connection):
        self._connections.append(new_connection)        

    def export_as_json(self, output_file_path: str):
        print("Generating JSON export")
        export_dict = {
            "configuration": [connection.export() for connection in self._connections]
        }

        with open(output_file_path, "w") as output_file:
            json.dump(export_dict, output_file, indent=4)

class Connection:
    def __init__(
        self,
        server_url: str,
        username: str,
        password: str,
    ):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.server_url = server_url
        self.username = username
        self.password = password
        self.action_log: list[actions.Action] = []
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.headers.update({
            'Content-Type': 'application/vnd.testbench+json; charset=utf-8'
        })
        #self.session.hooks = {
        #    'response': lambda r, *args, **kwargs: 
        #        r.raise_for_status()
        #}
        # TODO: timeout handling
        # TODO: use with for reliable session closing?
        # TODO: add id_ for selecting specific connections to actionlog?
        
    def export(self) -> dict:
        return {
                "server_url": self.server_url,
                "username": self.username,
                "password": self.password,
                "actions": [action_export for action_export in (action.export() for action in self.action_log) if action_export is not None],
        }
    
    def add_action(self, action: actions.Action):
        self.action_log.append(action)

    def check_is_identical(self, other: Connection) -> bool:
        if (    self.server_url == other.server_url
            and self.username == other.username
            and self.password == other.password
        ):
            return True
        else:
            return False

    def check_is_working(self) -> bool:
        response = self.session.get(
            self.server_url + 'projects',
            verify=False, # TODO: throws SSL error in test env if True
            params={
                "includeTOVs": "false",
                "includeCycles": "false",
        })

        response.json()
        
        return True
        
    def get_all_projects(self) -> dict:
        all_projects = self.session.get(
            self.server_url + 'projects',
            verify=False, # TODO: throws SSL error in test env if True
            params={
                "includeTOVs": "true",
                "includeCycles": "true"
            })

        return all_projects.json()

    def get_all_filters(self) -> dict:
        all_filters = self.session.get(
            self.server_url + 'filters',
            verify=False, # TODO: throws SSL error in test env if True
        )

        return all_filters.json()

    def get_xml_report(self, cycle_key: str, reportRootUID: str, filters: list[dict[str, str]] = []):
        job_id = self.trigger_xml_report_generation(cycle_key, reportRootUID, filters)
        report_tmp_name = self.wait_for_tmp_xml_report_name(job_id)
        report = self.get_xml_report_data(report_tmp_name)

        return report

    def trigger_xml_report_generation(self, cycle_key: str, reportRootUID: str, filters: list[dict[str, str]] = []):
        # TODO add max duration
        job_id = self.session.post(
            self.server_url + 'cycle/' + cycle_key + '/xmlReport',
            verify = False,
            json = {
                "exportAttachments": True,
                "exportDesignData": True,
                "characterEncoding": "utf-8",
                "suppressFilteredData": True,
                "filters": filters,  # TODO: check if filters work as intended
                "reportRootUID": reportRootUID,
                "exportExpandedData": True,
                "exportDescriptionFields": True,
                "outputFormattedText": False,
                "exportExecutionProtocols": False
            })

        return job_id.json()['jobID']

    def wait_for_tmp_xml_report_name(self, job_id: str):
        while (True): 
            report_generation_status = self.session.get(
                self.server_url + 'job/'+ job_id, 
                verify=False, 
            )
            print(f'Waiting until creation of XML report is complete ...')
            if (report_generation_status.json()['completion'] != None):
                break
            time.sleep(5)

        report_tmp_name = report_generation_status.json()['completion']['result']['Right']
        return report_tmp_name

    def get_xml_report_data(self, report_tmp_name: str):
        report = self.session.get(
            self.server_url + 'xmlReport/'+ report_tmp_name, 
            verify=False
        )

        return report

    def get_all_testers_of_project(self, project_key: str):
        return [member for member in self.get_all_members_of_project(project_key) if "Tester" in member['value']['membership']['roles']]

    def get_all_members_of_project(self, project_key: str):
        all_project_members = self.session.get(
            self.server_url + 'project/' + project_key + '/members',
            verify=False, # TODO: throws SSL error in test env if True
        )

        return all_project_members.json()

    def import_execution_results(self, results_file_base64: str, cycle_key: str, report_root_uid: str, default_tester: str, filters: list[dict[str, str]]):
        serverside_file_name = self.upload_execution_results(results_file_base64)
        job_id = self.trigger_execution_results_import(cycle_key, report_root_uid, serverside_file_name, default_tester, filters)
        success = self.wait_for_execution_results_import_to_finish(job_id)

        return success

    def upload_execution_results(self, results_file_base64: str):
        serverside_file_name = self.session.post(
            self.server_url + 'executionResultsUpload',
            verify=False, # TODO: throws SSL error in test env if True
            json={
                "data": results_file_base64,
            }
        )

        return serverside_file_name.json()["fileName"]

    def trigger_execution_results_import(self, cycle_key: str, report_root_uid: str, serverside_file_name: str, default_tester: str, filters: list[dict[str, str]]):
        job_id = self.session.post(
            self.server_url + 'cycle/' + cycle_key + '/executionResultsImport',
            verify=False, # TODO: throws SSL error in test env if True,
            headers={
                "Accept": "application/zip",
            },
            json={
                "reportRootUID": report_root_uid,
                "fileName": serverside_file_name,
                "ignoreNonExecutedTestCases": True,   
                "defaultTester": default_tester,
                "checkPaths": True,
                "filters": filters,
                "discardTesterInformation": True,
                "useExistingDefect": True
            }
        )

        return job_id.json()['jobID']

    def wait_for_execution_results_import_to_finish(self, job_id: str) -> bool:
        # TODO add max duration?
        while (True): 
            import_status = self.session.get(
                self.server_url + 'executionResultsImporterJob/'+ job_id, 
                verify=False, 
            )
            print(f'Waiting until import of execution results is done ...')
            if (import_status.json()['completion'] != None):
                break
            time.sleep(5)

        return True

    def get_test_cycle_structure(self, cycle_key: str):
        test_cycle_structure = self.session.get(
            self.server_url + 'cycle/' + cycle_key + '/structure',
            verify=False, # TODO: throws SSL error in test env if True,
        )

        return test_cycle_structure.json()