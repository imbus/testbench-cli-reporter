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

# from __future__ import annotations

import base64
import dataclasses
import json
import traceback
from pathlib import Path
from re import fullmatch
from typing import Any, Dict, List, Optional, Union

import requests  # type: ignore
import urllib3
from questionary import print as pprint

from . import questions
from .config_model import (
    CliReporterConfig,
    Configuration,
    ExecutionResultsImportOptions,
    FilterInfo,
)
from .log import logger
from .util import (
    TYPICAL_IMPORT_CONFIG,
    AbstractAction,
    XmlExportConfig,
    close_program,
    spin_spinner,
)


class Connection:
    def __init__(
        self,
        server_url: str,
        verify: Union[bool, str],
        sessionToken: Optional[str] = None,
        basicAuth: Optional[str] = None,
        loginname: Optional[str] = None,
        password: Optional[str] = None,
        job_timeout_sec: int = 4 * 60 * 60,
        connection_timeout_sec: Optional[int] = None,
        actions: Optional[List] = None,
        **kwargs,
    ):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.server_url = server_url
        url_matcher = fullmatch(
            r"(?P<protocol>https?)://(?P<host>[\w\-.]+):(?P<port>\d{1,5})/api/", server_url
        )
        self.server_protocol = url_matcher.group("protocol")
        self.server_host = url_matcher.group("host")
        self.server_port = url_matcher.group("port")
        self._server_legacy_port = None
        self.session_token = sessionToken

        if sessionToken:
            self.loginname = ""
            self.password = sessionToken
        elif basicAuth:
            credentials = base64.b64decode(basicAuth.encode()).decode("utf-8")
            self.loginname, self.password = credentials.split(":", 1)
        else:
            self.loginname = loginname or ""
            self.password = password or ""
        self.job_timeout_sec = job_timeout_sec
        self.action_log: List[AbstractAction] = []
        self.actions_to_trigger: List[dict] = actions or []
        self.actions_to_wait_for: List[AbstractAction] = []
        self.actions_to_finish: List[AbstractAction] = []
        self.connection_timeout = connection_timeout_sec
        self.verify_ssl = verify
        self._session = None
        self._legacy_session = None

    @property
    def session(self):
        if self._session:
            return self._session
        logger.info("Initializing session")
        self._session = requests.Session()
        logger.info("Session initialized")
        self._session.verify = self.verify_ssl
        self._session.headers.update(
            {
                "accept": "application/vnd.testbench+json",
                "Content-Type": "application/vnd.testbench+json; charset=utf-8",
            }
        )
        if not self.session_token:
            self.authenticate(self._session)
        self._session.headers.update({"Authorization": self.session_token})
        self._session.hooks = {"response": lambda r, *args, **kwargs: r.raise_for_status()}
        self._session.mount("http://", TimeoutHTTPAdapter(self.connection_timeout))
        self._session.mount("https://", TimeoutHTTPAdapter(self.connection_timeout))
        return self._session

    def authenticate(self, session: requests.Session):
        response = session.post(
            f"{self.server_url}login/session/v1",
            json={"login": self.loginname, "password": self.password, "force": True},
        )
        try:
            resp_dict = response.json()
            logger.info(f"Authenticated with session token: {resp_dict.get('sessionToken')}")
        except json.JSONDecodeError as e:
            raise requests.HTTPError(
                "Authentication failed\n"
                f"Status code: {response.status_code}\n"
                f"Response: {response.text}"
            ) from e
        self.session_token = resp_dict["sessionToken"]

    def get_loginname_from_server(self):
        response = self.session.get(f"{self.server_url}login/session/v1").json()
        self.loginname = response["login"]

    @property
    def server_legacy_port(self):
        if self._server_legacy_port:
            return self._server_legacy_port
        response = self.session.get(f"{self.server_url}serverLocations/v1").json()
        self._server_legacy_port = response["legacyPlayPort"]
        return self._server_legacy_port

    @property
    def server_legacy_url(self):
        return f"{self.server_protocol}://{self.server_host}:{self.server_legacy_port}/api/1/"

    @property
    def legacy_session(self):
        if self._legacy_session:
            return self._legacy_session
        logger.info("Initializing legacy session")
        if not self.session:
            raise RuntimeError("Session not initialized")
        self._legacy_session = requests.Session()
        logger.info("Legacy session initialized")
        self._legacy_session.verify = self.verify_ssl
        self._legacy_session.headers.update(
            {
                "accept": "application/vnd.testbench+json",
                "Content-Type": "application/vnd.testbench+json; charset=utf-8",
            }
        )
        if not self.session_token:
            self.authenticate(self._legacy_session)
        self.get_loginname_from_server()
        self._legacy_session.auth = (self.loginname, self.session_token)
        self._legacy_session.hooks = {"response": lambda r, *args, **kwargs: r.raise_for_status()}
        self._legacy_session.mount("http://", TimeoutHTTPAdapter(self.connection_timeout))
        self._legacy_session.mount("https://", TimeoutHTTPAdapter(self.connection_timeout))
        return self._legacy_session

    def close(self):
        self.session.close()

    def export(self) -> Configuration:
        basic_auth = base64.b64encode(f"{self.loginname}:{self.password}".encode()).decode()
        return Configuration(
            server_url=self.server_url,
            verify=self.session.verify,
            basicAuth=basic_auth,
            actions=[action.export() for action in self.action_log if action.export() is not None],
        )

    def add_action(self, action: AbstractAction):
        self.action_log.append(action)

    def check_is_identical(self, other) -> bool:
        return bool(
            self.server_url == other.server_url
            and self.loginname == other.loginname
            and self.password == other.password
        )

    def check_is_working(self) -> bool:
        response = self.session.get(f"{self.server_url}login/session/v1")
        response.json()
        legacy_response = self.legacy_session.get(f"{self.server_legacy_url}checkLogin")
        legacy_response.json()
        return True

    def get_project_key_new_play(self, project_name) -> str:
        all_projects = self.session.get(f"{self.server_url}projects/v1").json()
        for project in all_projects:
            if project["name"] == project_name:
                return project["key"]
        raise ValueError(f"Project {project_name} not found")

    def get_tov_key_new_play(self, project_key: str, tov_name: str) -> str:
        all_tovs = self.session.get(
            f"{self.server_url}projects/{project_key}/tovs/v1",
        ).json()
        for tov in all_tovs:
            if tov["name"] == tov_name:
                return tov["key"]
        raise ValueError(f"TOV {tov_name} not found")

    def get_cycle_key_new_play(self, project_key: str, tov_key: str, cycle_name: str) -> str:
        all_cycles = self.session.get(
            f"{self.server_url}projects/{project_key}/tovs/{tov_key}/cycles/v1",
        ).json()
        for cycle in all_cycles:
            if cycle["name"] == cycle_name:
                return cycle["key"]
        raise ValueError(f"Cycle {cycle_name} not found")

    def get_project_tree_new_play(self, project_key: str) -> dict:
        return self.session.get(
            f"{self.server_url}projects/{project_key}/tree/v1",
        ).json()

    def get_all_projects(self) -> Dict:
        all_projects = dict(
            self.legacy_session.get(
                f"{self.server_legacy_url}projects",
                params={"includeTOVs": "true", "includeCycles": "true"},
            ).json()
        )
        all_projects["projects"].sort(key=lambda proj: proj["name"].casefold())
        return all_projects

    def get_all_filters(self) -> List[dict]:
        all_filters = self.legacy_session.get(
            f"{self.server_legacy_url}filters",
        )

        return all_filters.json()

    def get_xml_report(
        self, tov_key: str, cycle_key: str, reportRootUID: str, filters=None
    ) -> bytes:
        if filters is None:
            filters = []
        job_id = self.trigger_xml_report_generation(tov_key, cycle_key, reportRootUID, filters)
        report_tmp_name = self.wait_for_tmp_xml_report_name(job_id)
        return self.get_xml_report_data(report_tmp_name)

    def trigger_json_report_generation(
        self,
        project_key: str,
        tov_key: Optional[str] = None,
        cycle_key: Optional[str] = None,
        reportRootUID: str = "ROOT",
        filters=None,
        report_config=None,
    ) -> str:
        if report_config is None:
            raise NotImplementedError
        if filters is None:
            filters = []

        if reportRootUID and reportRootUID != "ROOT":
            report_config.treeRootUID = reportRootUID
        report_config.filters = filters
        if cycle_key and cycle_key != "0" and project_key and project_key != "0":
            response = self.session.post(
                f"{self.server_url}projects/{project_key}/cycles/{cycle_key}/report/v1",
                json=dataclasses.asdict(report_config),
            ).json()
        elif tov_key and tov_key != "0" and project_key and project_key != "0":
            response = self.session.post(
                f"{self.server_url}projects/{project_key}/tovs/{tov_key}/report/v1",
                json=dataclasses.asdict(report_config),
            ).json()
        else:
            raise ValueError("Either tov_key or cycle_key must be provided")
        return response["jobID"]

    def wait_for_tmp_json_report_name(self, project_key: str, job_id: str) -> str:
        while True:
            report_generation_result = self.get_exp_json_job_result(project_key, job_id)
            if report_generation_result is not None:
                return report_generation_result
            spin_spinner("Waiting until creation of JSON report is complete")

    def get_exp_json_job_result(self, project_key: str, job_id: str):
        report_generation_status = self.session.get(
            f"{self.server_url}projects/{project_key}/report/job/{job_id}/v1",
        ).json()
        if not report_generation_status.get('completion'):
            return None
        result = report_generation_status.get('completion').get('result')
        logger.debug(result)
        if result.get('Success'):
            return result.get('Success').get('reportName')
        raise AssertionError(result.get('Failure').get('error'))

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
            response = self.legacy_session.post(
                f"{self.server_legacy_url}cycle/{cycle_key}/xmlReport",
                json=dataclasses.asdict(report_config),
            )
        else:
            response = self.legacy_session.post(
                f"{self.server_legacy_url}tovs/{tov_key}/xmlReport",
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
            logger.debug(result)
            return result["Right"]
        raise AssertionError(result)

    def get_job_result(self, path: str, job_id: str):
        report_generation_status = self.legacy_session.get(
            f"{self.server_legacy_url}{path}{job_id}",
        )
        return report_generation_status.json()["completion"]

    # GET /testCaseSets/{testCaseSetKey}/specifications/{specificationKey}/testCases
    def get_test_cases_of_specification(
        self, testcaseset_key: str, specification_key: str
    ) -> List[dict]:
        return self.legacy_session.get(
            f"{self.server_legacy_url}testCaseSets/{testcaseset_key}/specifications/{specification_key}/testCases",
        ).json()

    def get_xml_report_data(self, report_tmp_name: str) -> bytes:
        report = self.legacy_session.get(
            f"{self.server_legacy_url}xmlReport/{report_tmp_name}",
        )

        return report.content

    def get_json_report_data(self, project_key: str, report_tmp_name: str) -> bytes:
        report = self.session.get(
            f"{self.server_url}projects/{project_key}/report/{report_tmp_name}/v1",
        )
        return report.content

    def get_all_testers_of_project(self, project_key: str) -> List[dict]:
        return [
            member
            for member in self.get_all_members_of_project(project_key)
            if "Tester" in member["value"]["membership"]["roles"]
        ]

    def get_all_members_of_project(self, project_key: str) -> List[dict]:
        all_project_members = self.legacy_session.get(
            f"{self.server_legacy_url}project/{project_key}/members",
        )

        return all_project_members.json()

    # /api/projects/{projectKey}/cycles/{cycleKey}/structure/v1
    def post_project_cycle_structure(self, project_key, cycle_key, root_uid=None):
        return self.session.post(
            f"{self.server_url}projects/{project_key}/cycles/{cycle_key}/structure/v1",
            json={
                "treeRootUID": root_uid,
                "basedOnExecution": True,
                "suppressNotExecutable": True,
                "suppressEmptyTestThemes": True,
                "filters": [],
            },
        ).json()

    # /api/projects/{projectKey}/testThemes/{testThemeKey}/v1
    def get_project_test_theme(
        self, project_key, test_theme_key, specification_key=None, execution_key=None
    ):
        return self.session.get(
            f"{self.server_url}projects/{project_key}/testThemes/{test_theme_key}/v1",
            params={
                "specificationKey": specification_key,
                "executionKey": execution_key,
            },
        ).json()

    # /api/projects/{projectKey}/udfs/v1
    def get_project_udfs(self, project_key):
        return self.session.get(
            f"{self.server_url}projects/{project_key}/udfs/v1",
        ).json()

    # /api/projects/{projectKey}/cycles/{cycleKey}/requirements/v1
    def post_project_cycle_requirements(self, project_key, cycle_key, root_uid=None):
        return self.session.post(
            f"{self.server_url}projects/{project_key}/cycles/{cycle_key}/requirements/v1",
            json={
                "treeRootUID": root_uid,
                "suppressNotExecutable": True,
                "suppressEmptyTestThemes": True,
            },
        ).json()

    # /api/projects/{projectKey}/cycles/{cycleKey}/defects/v1
    def post_project_cycle_defects(self, project_key, cycle_key, root_uid=None):
        return self.session.post(
            f"{self.server_url}projects/{project_key}/cycles/{cycle_key}/defects/v1",
            json={"treeRootUID": root_uid},
        ).json()

    # /api/projects/{projectKey}/v1
    def get_project(self, project_key):
        return self.session.get(
            f"{self.server_url}projects/{project_key}/v1",
        ).json()

    # /api/projects/{projectKey}/testCaseSets/{testCaseSetKey}/v1:
    def get_project_test_case_set(
        self, project_key, test_case_set_key, specification_key=None, execution_key=None
    ):
        return self.session.get(
            f"{self.server_url}projects/{project_key}/testCaseSets/{test_case_set_key}/v1",
            params={
                "executionKey": execution_key,
            },
        ).json()

    #     /api/projects/{projectKey}/testCaseSets/{testCaseSetKey}/testCases/{testCaseSpecificationKey}/v1:
    def get_project_test_case(
        self, project_key, test_case_set_key, test_case_specification_key, execution_key=None
    ):
        return self.session.get(
            f"{self.server_url}projects/{project_key}/testCaseSets/{test_case_set_key}/testCases/{test_case_specification_key}/v1",
            params={
                "executionKey": execution_key,
            },
        ).json()

    def upload_execution_results(self, results_file_base64: str) -> str:
        try:
            serverside_file_name = self.legacy_session.post(
                f"{self.server_legacy_url}executionResultsUpload",
                json={
                    "data": results_file_base64,
                },
            )
            logger.debug(serverside_file_name.json())
            return serverside_file_name.json()["fileName"]
        except requests.exceptions.RequestException as e:
            self.render_import_error(e)

    def trigger_execution_results_import(
        self,
        cycle_key: str,
        report_root_uid: str,
        serverside_file_name: str,
        default_tester: str,
        filters: Union[List[FilterInfo], List[Dict[str, str]]],
        import_config: Optional[ExecutionResultsImportOptions] = None,
    ) -> str:
        if import_config is None:
            used_import_config = TYPICAL_IMPORT_CONFIG
        else:
            used_import_config = import_config
        used_import_config.fileName = serverside_file_name
        used_import_config.filters = filters
        if default_tester:
            used_import_config.defaultTester = default_tester
        if report_root_uid and report_root_uid != "ROOT":
            used_import_config.reportRootUID = report_root_uid

        try:
            job_id = self.legacy_session.post(
                f"{self.server_legacy_url}cycle/{cycle_key}/executionResultsImport",
                headers={"Accept": "application/zip"},
                json=dataclasses.asdict(used_import_config),
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
                return True
            raise AssertionError(result)
        except requests.exceptions.RequestException as e:
            self.render_import_error(e)
            raise e

    def render_import_error(self, e):
        pprint("!!!ERROR DURING IMPORT!!!", style="#ff0e0e italic")
        pprint("Report was NOT imported")
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
        raise AssertionError(result)

    def get_test_cycle_structure(self, cycle_key: str) -> List[dict]:
        test_cycle_structure = self.legacy_session.get(
            f"{self.server_legacy_url}cycle/{cycle_key}/structure",
        )
        return test_cycle_structure.json()

    def get_tov_structure(self, tovKey: str) -> List[dict]:
        tov_structure = self.legacy_session.get(
            f"{self.server_legacy_url}tov/{tovKey}/structure",
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
        spec_test_cases = self.legacy_session.get(
            f"{self.server_legacy_url}testCaseSets/"
            f"{testCaseSetKey}/specifications/"
            f"{specificationKey}/testCases",
        )
        return spec_test_cases.json()

    def get_exec_test_cases(self, testCaseSetKey: str, executionKey: str) -> List[dict]:
        exec_test_cases = self.legacy_session.get(
            f"{self.server_legacy_url}testCaseSets/"
            f"{testCaseSetKey}/executions/"
            f"{executionKey}/testCases",
        )
        return exec_test_cases.json()


def login(server="", login="", pwd="", session="") -> Connection:  # noqa: C901, PLR0912
    if server and (login and pwd) or session:
        credentials = {
            "server_url": server,
            "verify": False,
            "loginname": login,
            "password": pwd,
            "sessionToken": session,
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

        with Path(output_file_path).open("w") as output_file:
            json.dump(dataclasses.asdict(export_config), output_file, indent=2)
