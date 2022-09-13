# coding=utf8
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
import dataclasses
import json
import traceback
from typing import Any, Dict, List, Optional, Union

import requests
import urllib3
from questionary import print as pprint

from . import questions
from .config_model import CliReporterConfig, Configuration, ExecutionResultsImportOptions
from .log import logger
from .util import AbstractAction, ImportConfig, XmlExportConfig, close_program, spin_spinner


class Connection:
    def __init__(
        self,
        server_url: str,
        verify: Union[bool, str],
        basicAuth: Optional[str] = None,
        loginname: Optional[str] = None,
        password: Optional[str] = None,
        job_timeout_sec: int = 4 * 60 * 60,
        connection_timeout_sec: int = None,
        actions: Optional[List] = None,
        **kwargs,
    ):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.server_url = server_url
        if basicAuth:
            credentials = base64.b64decode(basicAuth.encode()).decode("utf-8")
            self.loginname, self.password = credentials.split(":", 1)
        else:
            self.loginname = loginname
            self.password = password
        self.job_timeout_sec = job_timeout_sec
        self.action_log: List[AbstractAction] = []
        self.actions_to_trigger: List[dict] = actions or []
        self.actions_to_wait_for: List[AbstractAction] = []
        self.actions_to_finish: List[AbstractAction] = []
        self.connection_timeout = connection_timeout_sec
        self.verify_ssl = verify
        self._session = None

    @property
    def session(self):
        self._session = requests.Session()
        self._session.auth = (self.loginname, self.password)
        self._session.headers.update(
            {"Content-Type": "application/vnd.testbench+json; charset=utf-8"}
        )
        self._session.hooks = {"response": lambda r, *args, **kwargs: r.raise_for_status()}
        self._session.mount("http://", TimeoutHTTPAdapter(self.connection_timeout))
        self._session.mount("https://", TimeoutHTTPAdapter(self.connection_timeout))
        self._session.verify = self.verify_ssl
        return self._session

    def close(self):
        self.session.close()

    def export(self) -> Configuration:
        basic_auth = base64.b64encode(f"{self.loginname}:{self.password}".encode("utf-8")).decode()
        return Configuration(
            server_url=self.server_url,
            verify=self.session.verify,
            basicAuth=basic_auth,
            actions=[action.export() for action in self.action_log if action.export() is not None],
        )

    def add_action(self, action: AbstractAction):
        self.action_log.append(action)

    def check_is_identical(self, other) -> bool:
        if (
            self.server_url == other.server_url
            and self.loginname == other.loginname
            and self.password == other.password
        ):
            return True
        else:
            return False

    def check_is_working(self) -> bool:
        response = self.session.get(
            f"{self.server_url}projects",
            params={
                "includeTOVs": "false",
                "includeCycles": "false",
            },
        )

        response.json()

        return True

    def get_all_projects(self) -> Dict:
        all_projects = self.session.get(
            f"{self.server_url}projects",
            params={"includeTOVs": "true", "includeCycles": "true"},
        ).json()
        all_projects["projects"].sort(key=lambda proj: proj["name"].casefold())
        return all_projects

    def get_all_filters(self) -> List[dict]:
        all_filters = self.session.get(
            f"{self.server_url}filters",
        )

        return all_filters.json()

    def get_xml_report(
        self, tov_key: str, cycle_key: str, reportRootUID: str, filters=None
    ) -> bytes:
        if filters is None:
            filters = []
        job_id = self.trigger_xml_report_generation(tov_key, cycle_key, reportRootUID, filters)
        report_tmp_name = self.wait_for_tmp_xml_report_name(job_id)
        report = self.get_xml_report_data(report_tmp_name)

        return report

    def trigger_xml_report_generation(
        self,
        tov_key: str,
        cycle_key: str,
        reportRootUID: str,
        filters=None,
        report_config=None,
    ) -> str:
        if report_config is None:
            report_config = XmlExportConfig["Itep Export"]
        if filters is None:
            filters = []

        if reportRootUID and reportRootUID != "ROOT":
            report_config.reportRootUID = reportRootUID
        report_config.filters = filters
        if cycle_key and cycle_key != "0":
            response = self.session.post(
                f"{self.server_url}cycle/{cycle_key}/xmlReport",
                json=dataclasses.asdict(report_config),
            )
        else:
            response = self.session.post(
                f"{self.server_url}tovs/{tov_key}/xmlReport",
                json=dataclasses.asdict(report_config),
            )
        return response.json()["jobID"]

    def wait_for_tmp_xml_report_name(self, job_id: str) -> str:
        while True:
            report_generation_result = self.get_exp_job_result(job_id)
            if report_generation_result is not None:
                return report_generation_result
            spin_spinner("Waiting until creation of XML report is complete")

    def get_exp_job_result(self, job_id):
        report_generation_status = self.get_job_result("job/", job_id)
        if report_generation_status is None:
            return None
        result = report_generation_status["result"]
        if "Right" in result:
            return result["Right"]
        else:
            raise AssertionError(result)

    def get_job_result(self, path: str, job_id: str):
        report_generation_status = self.session.get(
            f"{self.server_url}{path}{job_id}",
        )
        return report_generation_status.json()["completion"]

    def get_xml_report_data(self, report_tmp_name: str) -> bytes:
        report = self.session.get(
            f"{self.server_url}xmlReport/{report_tmp_name}",
        )

        return report.content

    def get_all_testers_of_project(self, project_key: str) -> List[dict]:
        return [
            member
            for member in self.get_all_members_of_project(project_key)
            if "Tester" in member["value"]["membership"]["roles"]
        ]

    def get_all_members_of_project(self, project_key: str) -> List[dict]:
        all_project_members = self.session.get(
            f"{self.server_url}project/{project_key}/members",
        )

        return all_project_members.json()

    def upload_execution_results(self, results_file_base64: str) -> str:
        try:
            serverside_file_name = self.session.post(
                f"{self.server_url}executionResultsUpload",
                json={
                    "data": results_file_base64,
                },
            )
            return serverside_file_name.json()["fileName"]
        except requests.exceptions.RequestException as e:
            self.render_import_error(e)

    def trigger_execution_results_import(
        self,
        cycle_key: str,
        report_root_uid: str,
        serverside_file_name: str,
        default_tester: str,
        filters: List[Dict[str, str]],
        import_config: Optional[ExecutionResultsImportOptions] = None,
    ) -> str:
        if import_config is None:
            import_config = ImportConfig["Typical"]
        import_config.fileName = serverside_file_name
        import_config.filters = filters
        if default_tester:
            import_config.defaultTester = default_tester
        if report_root_uid and report_root_uid != "ROOT":
            import_config.reportRootUID = report_root_uid

        try:
            job_id = self.session.post(
                f"{self.server_url}cycle/{cycle_key}/executionResultsImport",
                headers={"Accept": "application/zip"},
                json=dataclasses.asdict(import_config),
            )
            return job_id.json()["jobID"]
        except requests.exceptions.HTTPError as e:
            self.render_import_error(e)
            raise e

    def wait_for_execution_results_import_to_finish(self, job_id: str) -> bool:
        try:
            while True:
                import_status = self.get_job_result("executionResultsImporterJob/", job_id)
                if import_status is not None:
                    break
                spin_spinner("Waiting until import of execution results is done")

            result = import_status["result"]

            if "Right" in result:
                return result["Right"]
            else:
                raise AssertionError(result)
        except requests.exceptions.RequestException as e:
            self.render_import_error(e)
            raise e

    def render_import_error(self, e):
        pprint("!!!ERROR DURING IMPORT!!!", style="#ff0e0e italic")
        pprint(f"Report was NOT imported")
        pprint(f"Error Code {e.response.status_code}")
        pprint(f"Error Message {e.response.text}")
        pprint(f"URL: {e.response.url}")

    def get_imp_job_result(self, job_id):
        report_import_status = self.get_job_result("executionResultsImporterJob/", job_id)
        if report_import_status is None:
            return None
        result = report_import_status["result"]
        if "Right" in result:
            return result["Right"]
        else:
            raise AssertionError(result)

    def get_test_cycle_structure(self, cycle_key: str) -> List[dict]:
        test_cycle_structure = self.session.get(
            f"{self.server_url}cycle/{cycle_key}/structure",
        )
        return test_cycle_structure.json()

    def get_tov_structure(self, tovKey: str) -> List[dict]:
        tov_structure = self.session.get(
            f"{self.server_url}tov/{tovKey}/structure",
        )
        return tov_structure.json()

    def get_test_cases(self, test_case_set_structure: Dict[str, Any]) -> Dict[str, Dict]:
        spec_test_cases = self.get_spec_test_cases(
            test_case_set_structure["TestCaseSet_structure"]["key"]["serial"],
            test_case_set_structure["spec"]["Specification_key"]["serial"],
        )
        test_cases = {tc["uniqueID"]: tc for tc in spec_test_cases}
        if not test_case_set_structure.get("exec"):
            return {"spec": test_cases}
        exec_test_cases = self.get_exec_test_cases(
            test_case_set_structure["TestCaseSet_structure"]["key"]["serial"],
            test_case_set_structure["exec"]["Execution_key"]["serial"],
        )
        test_cases_execs = {tc["uniqueID"]: tc for tc in exec_test_cases}
        equal_lists = False not in [
            test_cases.get(uid, {}).get('testCaseSpecificationKey')['serial']
            == tc['paramCombPK']['serial']
            for uid, tc in test_cases_execs.items()
        ]
        return {
            "spec": test_cases,
            "exec": test_cases_execs,
            "equal_lists": equal_lists,
        }

    def get_spec_test_cases(self, testCaseSetKey: str, specificationKey: str) -> List[dict]:
        spec_test_cases = self.session.get(
            f"{self.server_url}testCaseSets/"
            f"{testCaseSetKey}/specifications/"
            f"{specificationKey}/testCases",
        )
        return spec_test_cases.json()

    def get_exec_test_cases(self, testCaseSetKey: str, executionKey: str) -> List[dict]:
        exec_test_cases = self.session.get(
            f"{self.server_url}testCaseSets/"
            f"{testCaseSetKey}/executions/"
            f"{executionKey}/testCases",
        )
        return exec_test_cases.json()


def login(server="", login="", pwd="") -> Connection:
    if server and login and pwd:
        credentials = {
            "server_url": server,
            "verify": False,
            "loginname": login,
            "password": pwd,
        }
    else:
        credentials = questions.ask_for_test_bench_credentials(server, login, pwd)

    while True:
        connection = Connection(**credentials)
        try:
            if connection.check_is_working():
                return connection

        except requests.HTTPError:
            logger.error("Invalid login credentials.")
            logger.debug(traceback.format_exc())
            action = questions.ask_for_action_after_failed_login()
            if action == "retry_password":
                credentials["password"] = questions.ask_for_testbench_password()
            elif action == "change_user":
                credentials["loginname"] = questions.ask_for_testbench_loginname()
                credentials["password"] = questions.ask_for_testbench_password()
            elif action == "change_server":
                credentials = questions.ask_for_test_bench_credentials()
            else:
                close_program()

        except (requests.ConnectionError, requests.exceptions.MissingSchema):
            logger.error("Invalid server url.")
            logger.debug(traceback.format_exc())
            action = questions.ask_for_action_after_failed_server_connection()
            if action == "retry_server":
                credentials["server_url"] = questions.ask_for_test_bench_server_url()
            elif action == "change_server":
                credentials = questions.ask_for_test_bench_credentials()
            else:
                close_program()

        except requests.exceptions.Timeout:
            logger.error("No connection could be established due to timeout.")
            logger.debug(traceback.format_exc())
            action = questions.ask_for_action_after_login_timeout()
            if action == "retry":
                pass
            elif action == "retry_server":
                credentials["server_url"] = questions.ask_for_test_bench_server_url()
            elif action == "change_server":
                credentials = questions.ask_for_test_bench_credentials()
            else:
                close_program()


class TimeoutHTTPAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, timeout: Optional[int] = 60, *args, **kwargs):
        self.timeout = timeout
        super().__init__(*args, **kwargs)

    def send(self, *args, **kwargs):
        kwargs["timeout"] = self.timeout
        return super().send(*args, **kwargs)


class JobTimeout(requests.exceptions.Timeout):
    pass


class ConnectionLog:
    def __init__(self):
        self.connections: List[Connection] = []

    @property
    def len(self) -> int:
        return len(self.connections)

    @property
    def active_connection(self) -> Connection:
        return self.connections[-1]

    def next(self):
        self.connections = self.connections[1:] + self.connections[:1]

    def remove(self, connection):
        self.connections.remove(connection)

    def add_connection(self, new_connection: Connection):
        self.connections.append(new_connection)

    def export_as_json(self, output_file_path: str):
        logger.info("Generating JSON export")
        export_config = CliReporterConfig(
            configuration=[connection.export() for connection in self.connections]
        )

        with open(output_file_path, "w") as output_file:
            json.dump(dataclasses.asdict(export_config), output_file, indent=2)
