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
import json
import time
import traceback
from dataclasses import asdict, dataclass
from io import BufferedReader
from pathlib import Path
from re import fullmatch
from typing import Any

import requests  # type: ignore
import urllib3

from . import questions
from .config_model import (
    CliReporterConfig,
    Configuration,
    ExecutionJsonResultsImportOptions,
    ExecutionXmlResultsImportOptions,
    ProjectCSVReportOptions,
    TestCycleJsonReportOptions,
    TestCycleXMLReportOptions,
)
from .log import logger
from .util import (
    BLUE_BOLD_ITALIC,
    ITEP_EXPORT_CONFIG,
    TYPICAL_JSON_IMPORT_CONFIG,
    TYPICAL_XML_IMPORT_CONFIG,
    AbstractAction,
    close_program,
    pretty_print,
    pretty_print_progress_bar,
    spin_spinner,
)


@dataclass
class JobProgress:
    completion: bool
    percentage: int | None = None
    total_items: int | None = None
    handled_items: int | None = None
    report_name: str | None = None


class Connection:
    def __init__(  # noqa: PLR0913
        self,
        server_url: str,
        verify: bool | str,
        sessionToken: str | None = None,
        basicAuth: str | None = None,
        loginname: str | None = None,
        password: str | None = None,
        job_timeout_sec: int = 4 * 60 * 60,
        connection_timeout_sec: int | None = None,
        actions: list | None = None,
        **kwargs,
    ):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.server_url = server_url
        url_matcher = fullmatch(
            r"(?P<protocol>https?)://(?P<host>[\w\-.]+):(?P<port>\d{1,5})/api/", server_url
        )
        if url_matcher is None:
            raise ValueError(f"Invalid server URL: {server_url}")
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
        self.action_log: list[AbstractAction] = []
        self.actions_to_trigger: list[dict] = actions or []
        self.actions_to_wait_for: list[AbstractAction] = []
        self.actions_to_finish: list[AbstractAction] = []
        self.connection_timeout = connection_timeout_sec
        self.verify_ssl = verify
        self.server_version: list[int] = []
        self.databaseVersion: str | None = None
        self.revision: str | None = None
        self._session = None
        self._legacy_session = None

    @property
    def is_testbench_4(self) -> bool:
        return bool(self.server_version and self.server_version >= [4])

    @property
    def session(self):
        if self._session:
            return self._session  # type: ignore
        logger.info("Initializing session")
        self._session = requests.Session()
        logger.info("Session initialized")
        self._session.verify = self.verify_ssl  # type: ignore
        self._session.headers.update(  # type: ignore
            {
                "accept": "application/vnd.testbench+json",
                "Content-Type": "application/vnd.testbench+json; charset=utf-8",
            }
        )
        self.read_server_version(self._session)
        if not self.session_token:
            self.authenticate(self._session)
        else:
            self._session.headers.update({"Authorization": self.session_token})  # type: ignore
        self._session.hooks = {"response": lambda r, *args, **kwargs: r.raise_for_status()}  # type: ignore
        self._session.mount("http://", TimeoutHTTPAdapter(self.connection_timeout))  # type: ignore
        self._session.mount("https://", TimeoutHTTPAdapter(self.connection_timeout))  # type: ignore
        return self._session

    def read_server_version(self, session: requests.Session) -> None:
        versions = {}
        try:
            response = session.get(f"{self.server_url}serverVersions/v1")
            response.raise_for_status()
            versions = response.json()
            self.server_version = [int(v) for v in versions.get("releaseVersion", "").split(".")]
        except requests.HTTPError:
            logger.debug(
                "Failed to read server version from "
                f"{self.server_url}/serverVersions/v1, trying {self.server_url}1/serverVersions"
            )
            try:
                response = session.get(f"{self.server_url}1/serverVersions")
                response.raise_for_status()
                versions = response.json()
                self.server_version = [int(v) for v in versions.get("version", "").split(".")]
            except requests.HTTPError as e:
                raise requests.HTTPError(
                    "Failed to read server version. Please check the server URL and connection."
                ) from e
        except Exception as e:
            raise e
        finally:
            self.databaseVersion = versions.get("databaseVersion")
            self.revision = versions.get("revision")
            if self.server_version:
                pretty_print(
                    {"value": "Server version: ", "end": None},
                    {
                        "value": f"{'.'.join(map(str, self.server_version))}",
                        "style": BLUE_BOLD_ITALIC,
                    },
                )
            if self.databaseVersion:
                pretty_print(
                    {"value": "Database version: ", "end": None},
                    {"value": f"{self.databaseVersion}", "style": BLUE_BOLD_ITALIC},
                )
            if self.revision:
                pretty_print(
                    {"value": "Revision: ", "end": None},
                    {"value": f"{self.revision}", "style": BLUE_BOLD_ITALIC},
                )

    def authenticate(self, session: requests.Session):
        try:
            if self.is_testbench_4:
                response = session.post(
                    f"{self.server_url}login/session/v1",
                    json={"login": self.loginname, "password": self.password, "force": True},
                )
                response.raise_for_status()
                resp_dict = response.json()
                self.session_token = resp_dict["sessionToken"]
                session.headers.update({"Authorization": self.session_token})
                logger.info(f"Authenticated with session token: {self.session_token}")
            else:
                self.session_token = self.password
                session.auth = (self.loginname, self.password)
                response = session.get(f"{self.server_url}1/checkLogin")
                response.raise_for_status()
                self._legacy_session = session
                logger.info("Authenticated")
        except (requests.HTTPError, json.JSONDecodeError, KeyError) as e:
            raise requests.HTTPError(
                f"Authentication failed\nStatus code: {response.status_code}\nResponse: {response.text}"
            ) from e

    def get_loginname_from_server(self):
        if self.loginname:
            return
        response = self.session.get(f"{self.server_url}login/session/v1").json()
        self.loginname = response["login"]

    @property
    def server_legacy_port(self):
        if not self.is_testbench_4:
            return self.server_port
        if self._server_legacy_port:
            return self._server_legacy_port  # type: ignore
        response = self.session.get(f"{self.server_url}serverLocations/v1").json()
        self._server_legacy_port = response["legacyPlayPort"]
        return self._server_legacy_port

    @property
    def server_legacy_url(self):
        return f"{self.server_protocol}://{self.server_host}:{self.server_legacy_port}/api/1/"

    @property
    def legacy_session(self):
        if self._legacy_session:
            return self._legacy_session  # type: ignore
        logger.info("Initializing legacy session")
        if not self.session:
            raise RuntimeError("Session not initialized")
        self._legacy_session = requests.Session()
        logger.info("Legacy session initialized")
        self._legacy_session.verify = self.verify_ssl  # type: ignore
        self._legacy_session.headers.update(  # type: ignore
            {
                "accept": "application/vnd.testbench+json",
                "Content-Type": "application/vnd.testbench+json; charset=utf-8",
            }
        )
        if not self.session_token:
            self.authenticate(self._legacy_session)
        self.get_loginname_from_server()
        self._legacy_session.auth = (self.loginname, self.session_token)  # type: ignore
        self._legacy_session.hooks = {"response": lambda r, *args, **kwargs: r.raise_for_status()}  # type: ignore
        self._legacy_session.mount("http://", TimeoutHTTPAdapter(self.connection_timeout))  # type: ignore
        self._legacy_session.mount("https://", TimeoutHTTPAdapter(self.connection_timeout))  # type: ignore
        return self._legacy_session

    def close(self):
        self.session.close()

    def export(self) -> Configuration:
        basic_auth = (
            base64.b64encode(f"{self.loginname}:{self.password}".encode()).decode()
            if self.loginname and self.password
            else None
        )
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
        session = self.session
        response = (
            session.get(f"{self.server_url}login/session/v1")
            if self.is_testbench_4
            else session.get(f"{self.server_url}1/checkLogin")
        )
        response.json()
        legacy_response = self.legacy_session.get(f"{self.server_legacy_url}checkLogin")
        legacy_response.json()
        return True

    def get_project_key_new_play(self, project_name) -> str:
        all_projects = self.session.get(f"{self.server_url}projects/v1").json()
        for project in all_projects:
            if project["name"] == project_name:
                return str(project["key"])
        raise ValueError(f"Project {project_name} not found")

    def get_tov_key_new_play(self, project_key: str, tov_name: str) -> str:
        all_tovs = self.session.get(
            f"{self.server_url}projects/{project_key}/tovs/v1",
        ).json()
        for tov in all_tovs:
            if tov["name"] == tov_name:
                return str(tov["key"])
        raise ValueError(f"TOV {tov_name} not found")

    def get_cycle_key_new_play(self, project_key: str, tov_key: str, cycle_name: str) -> str:
        all_cycles = self.session.get(
            f"{self.server_url}projects/{project_key}/tovs/{tov_key}/cycles/v1",
        ).json()
        for cycle in all_cycles:
            if cycle["name"] == cycle_name:
                return str(cycle["key"])
        raise ValueError(f"Cycle {cycle_name} not found")

    def get_project_tree_new_play(self, project_key: str) -> dict:
        project_tree: dict = self.session.get(
            f"{self.server_url}projects/{project_key}/tree/v1",
        ).json()
        return project_tree

    def get_all_projects(self) -> dict:
        all_projects = dict(
            self.legacy_session.get(
                f"{self.server_legacy_url}projects",
                params={"includeTOVs": "true", "includeCycles": "true"},
            ).json()
        )
        all_projects["projects"].sort(key=lambda proj: proj["name"].casefold())
        return all_projects

    def get_all_filters(self) -> list[dict]:
        all_filters: list[dict] = self.legacy_session.get(
            f"{self.server_legacy_url}filters",
        ).json()
        return all_filters

    def get_xml_report(self, tov_key: str, cycle_key: str, reportRootUID: str | None, filters=None) -> bytes:
        report_config = ITEP_EXPORT_CONFIG
        if filters is None:
            report_config.filters = []
        if reportRootUID and reportRootUID != "ROOT":
            report_config.reportRootUID = reportRootUID

        job_id = self.trigger_xml_report_generation(tov_key, cycle_key, report_config)
        report_tmp_name = self.wait_for_tmp_xml_report_name(job_id)
        return self.get_xml_report_data(report_tmp_name)

    def trigger_json_report_generation(
        self,
        project_key: str,
        tov_key: str | None = None,
        cycle_key: str | None = None,
        report_config: TestCycleJsonReportOptions | None = None,
    ) -> str:
        if report_config is None:
            raise AttributeError(
                "report_config must be provided for JSON report generation. "
                "Use TestCycleJsonReportOptions to create a report configuration."
            )
        if cycle_key and cycle_key != "0" and project_key and project_key != "0":
            response = self.session.post(
                f"{self.server_url}projects/{project_key}/cycles/{cycle_key}/report/v1",
                json=asdict(report_config),
            ).json()
        elif tov_key and tov_key != "0" and project_key and project_key != "0":
            response = self.session.post(
                f"{self.server_url}projects/{project_key}/tovs/{tov_key}/report/v1",
                json=asdict(report_config),
            ).json()
        else:
            raise ValueError("Either tov_key or cycle_key must be provided")
        return str(response["jobID"])

    def wait_for_tmp_json_report_name(self, project_key: str, job_id: str) -> str:
        while True:
            report_generation_result = self.get_exp_json_job_result(project_key, job_id)
            if report_generation_result.completion:
                print(" " * 80, end="\r")
                return report_generation_result.report_name or ""
            if (
                report_generation_result.handled_items
                and report_generation_result.total_items
                and report_generation_result.percentage
            ):
                pretty_print_progress_bar(
                    mode="Exporting",
                    handled=report_generation_result.handled_items,
                    total=report_generation_result.total_items,
                    percentage=report_generation_result.percentage,
                )
                time.sleep(0.1)
            else:
                spin_spinner("Waiting until creation of JSON report is complete")

    def get_exp_json_job_result(self, project_key: str, job_id: str) -> JobProgress:
        report_generation_status: dict = self.session.get(
            f"{self.server_url}projects/{project_key}/report/job/{job_id}/v1",
        ).json()
        progress = report_generation_status.get("progress")
        completion = report_generation_status.get("completion")
        if not completion:
            if not progress:
                return JobProgress(completion=False)
            total_items = progress.get("totalItemsCount")
            handled_items = progress.get("handledItemsCount")
            percentage = round(((handled_items / total_items) * 100) / 2) * 2
            return JobProgress(
                completion=False,
                percentage=percentage,
                total_items=total_items,
                handled_items=handled_items,
            )
        result = completion.get("result")
        logger.debug(result)
        if result.get("ReportingSuccess", result.get("Success")):
            return JobProgress(
                completion=True,
                report_name=result.get("ReportingSuccess", result.get("Success")).get("reportName"),
            )
        raise AssertionError(result.get("ReportingFailure", result.get("Failure")).get("error"))

    # GET /api/projects/{projectKey}/import/job/{jobId}/v1
    def wait_for_execution_json_results_import_to_finish(self, project_key: str, job_id: str) -> bool:
        try:
            while True:
                import_status = self.get_imp_json_job_result(project_key, job_id)
                if import_status.completion is True:
                    print(" " * 80, end="\r")
                    return import_status.completion
                if import_status.handled_items and import_status.total_items and import_status.percentage:
                    pretty_print_progress_bar(
                        mode="Importing",
                        handled=import_status.handled_items,
                        total=import_status.total_items,
                        percentage=import_status.percentage,
                    )
                    time.sleep(0.1)
                else:
                    spin_spinner("Waiting until creation of JSON report is complete")
        except requests.exceptions.RequestException as e:
            self.render_import_error(e)
            raise e

    # GET /api/projects/{projectKey}/import/job/{jobId}/v1
    def get_imp_json_job_result(self, project_key: str, job_id: str) -> JobProgress:
        report_import_status: dict = self.session.get(
            f"{self.server_url}projects/{project_key}/import/job/{job_id}/v1",
        ).json()
        progress = report_import_status.get("progress")
        completion = report_import_status.get("completion")
        if not completion:
            if not progress:
                return JobProgress(completion=False)
            total_items = progress.get("totalItemsCount")
            handled_items = progress.get("handledItemsCount")
            percentage = round(((handled_items / total_items) * 100) / 2) * 2
            return JobProgress(
                completion=False,
                percentage=percentage,
                total_items=total_items,
                handled_items=handled_items,
            )
        result = report_import_status.get("completion", {}).get("result", {})
        if result.get("ExecutionImportingSuccess"):
            return JobProgress(completion=True)
        raise AssertionError(result.get("ExecutionImportingFailure"))

    def trigger_xml_report_generation(
        self,
        tov_key: str,
        cycle_key: str,
        report_config: TestCycleXMLReportOptions | None = None,
    ) -> str:
        if report_config is None:
            report_config = ITEP_EXPORT_CONFIG
        if cycle_key and cycle_key != "0":
            response = self.legacy_session.post(
                f"{self.server_legacy_url}cycle/{cycle_key}/xmlReport",
                json=asdict(report_config),
            )
        else:
            response = self.legacy_session.post(
                f"{self.server_legacy_url}tovs/{tov_key}/xmlReport",
                json=asdict(report_config),
            )
        data = response.json()
        job_id = data.get("jobID")
        if not isinstance(job_id, str):
            raise ValueError("jobID is missing or not a string")
        return job_id

    def wait_for_tmp_xml_report_name(self, job_id: str) -> str:
        while True:
            report_generation_result = self.get_exp_job_result(job_id)
            if report_generation_result is not None:
                return report_generation_result
            spin_spinner("Waiting until creation of XML report is complete")

    def get_exp_job_result(self, job_id: str) -> str | None:
        report_generation_status = self.get_job_result("job/", job_id)
        if report_generation_status is None:
            return None
        result = report_generation_status["result"]
        if "Right" in result and isinstance(result["Right"], str):
            logger.debug(result)
            return result["Right"]
        raise AssertionError(result)

    def get_job_result(self, path: str, job_id: str):
        report_generation_status = self.legacy_session.get(
            f"{self.server_legacy_url}{path}{job_id}",
        )
        return report_generation_status.json()["completion"]

    def trigger_csv_report_generation(
        self,
        project_key: str,
        report_config: ProjectCSVReportOptions | None = None,
    ) -> str:
        if report_config is None:
            raise AttributeError(
                "report_config must be provided for CSV report generation. "
                "Use ProjectCSVReportOptions to create a report configuration."
            )
        response = self.legacy_session.post(
            f"{self.server_legacy_url}projects/{project_key}/csvReport",
            json=asdict(report_config),
        )
        data = response.json()
        job_id = data.get("jobID")
        if not isinstance(job_id, str):
            raise ValueError("jobID is missing or not a string")
        return job_id

    def wait_for_tmp_csv_report_name(self, job_id: str) -> str:
        while True:
            report_generation_result = self.get_exp_job_result(job_id)
            if report_generation_result is not None:
                return report_generation_result
            spin_spinner("Waiting until creation of CSV report is complete")

    # GET /testCaseSets/{testCaseSetKey}/specifications/{specificationKey}/testCases
    def get_test_cases_of_specification(self, testcaseset_key: str, specification_key: str) -> list[dict]:
        test_cases: list[dict] = self.legacy_session.get(
            f"{self.server_legacy_url}testCaseSets/{testcaseset_key}/specifications/{specification_key}/testCases",
        ).json()
        return test_cases

    def get_xml_report_data(self, report_tmp_name: str) -> bytes:
        report = self.legacy_session.get(
            f"{self.server_legacy_url}xmlReport/{report_tmp_name}",
        )
        content = report.content
        if not isinstance(content, bytes):
            raise TypeError("Expected bytes from response.content")
        return content

    def get_csv_report_data(self, report_tmp_name: str) -> bytes:
        report = self.legacy_session.get(
            f"{self.server_legacy_url}csvReport/{report_tmp_name}",
        )
        content = report.content
        if not isinstance(content, bytes):
            raise TypeError("Expected bytes from response.content")
        return content

    def get_json_report_data(self, project_key: str, report_tmp_name: str) -> bytes:
        report = self.session.get(
            f"{self.server_url}projects/{project_key}/report/{report_tmp_name}/v1",
        )
        content: bytes = report.content
        return content

    def get_all_testers_of_project(self, project_key: str) -> list[dict]:
        return [
            member
            for member in self.get_all_members_of_project(project_key)
            if "Tester" in member["value"]["membership"]["roles"]
        ]

    def get_all_members_of_project(self, project_key: str) -> list[dict]:
        all_project_members: list[dict] = self.legacy_session.get(
            f"{self.server_legacy_url}project/{project_key}/members",
        ).json()
        return all_project_members

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
    def get_project_test_theme(self, project_key, test_theme_key, specification_key=None, execution_key=None):
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

    # /api/projects/{projectKey}/testCaseSets/{testCaseSetKey}/testCases/{testCaseSpecificationKey}/v1:
    def get_project_test_case(
        self, project_key, test_case_set_key, test_case_specification_key, execution_key=None
    ):
        return self.session.get(
            f"{self.server_url}projects/{project_key}/testCaseSets/{test_case_set_key}/testCases/{test_case_specification_key}/v1",
            params={
                "executionKey": execution_key,
            },
        ).json()

    # post /executionResultsUpload
    def upload_execution_xml_results(self, results_file_base64: str) -> str:
        try:
            serverside_file_name = self.legacy_session.post(
                f"{self.server_legacy_url}executionResultsUpload",
                json={
                    "data": results_file_base64,
                },
            ).json()
            logger.debug(serverside_file_name)
            return str(serverside_file_name["fileName"])
        except requests.exceptions.RequestException as e:
            self.render_import_error(e)
            raise e

    # POST /api/projects/{projectKey}/executionResults/v1
    def upload_execution_json_results(
        self,
        project_key: str,
        results_file: BufferedReader,
    ) -> str:
        try:
            serverside_file_name = self.session.post(
                f"{self.server_url}projects/{project_key}/executionResults/v1",
                data=results_file,
            ).json()
            return str(serverside_file_name["fileName"])
        except requests.exceptions.RequestException as e:
            self.render_import_error(e)
            raise e

    def trigger_execution_xml_results_import(
        self,
        cycle_key: str,
        serverside_file_name: str,
        import_config: ExecutionXmlResultsImportOptions | None = None,
    ) -> str:
        used_import_config = TYPICAL_XML_IMPORT_CONFIG if import_config is None else import_config
        used_import_config.fileName = serverside_file_name
        if used_import_config.reportRootUID and used_import_config.reportRootUID == "ROOT":
            used_import_config.reportRootUID = None

        try:
            response = self.legacy_session.post(
                f"{self.server_legacy_url}cycle/{cycle_key}/executionResultsImport",
                headers={"Accept": "application/zip"},
                json=asdict(used_import_config),
            ).json()
            return str(response["jobID"])
        except requests.exceptions.HTTPError as e:
            self.render_import_error(e)
            raise e

    # POST /api/projects/{projectKey}/cycles/{cycleKey}/import/v1
    def trigger_execution_json_results_import(
        self,
        project_key: str,
        cycle_key: str,
        serverside_file_name: str,
        import_config: ExecutionJsonResultsImportOptions | None = None,
    ) -> str:
        used_import_config = TYPICAL_JSON_IMPORT_CONFIG if import_config is None else import_config
        used_import_config.fileName = serverside_file_name

        try:
            response = self.session.post(
                f"{self.server_url}projects/{project_key}/cycles/{cycle_key}/import/v1",
                json=asdict(used_import_config),
            ).json()
            return str(response["jobID"])
        except requests.exceptions.HTTPError as e:
            self.render_import_error(e)
            raise e

    def wait_for_execution_xml_results_import_to_finish(self, job_id: str) -> bool:
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
        pretty_print(
            {"value": "!!!ERROR DURING IMPORT!!!", "style": "#ff0e0e italic"},
            {"value": "Report was NOT imported"},
            {"value": f"Error Code {e.response.status_code}"},
            {"value": f"Error Message {e.response.text}"},
            {"value": f"URL: {e.response.url}"},
        )

    def get_imp_job_result(self, job_id):
        report_import_status = self.get_job_result("executionResultsImporterJob/", job_id)
        if report_import_status is None:
            return None
        result = report_import_status["result"]
        if "Right" in result:
            return result["Right"]
        raise AssertionError(result)

    def get_test_cycle_structure(self, cycle_key: str) -> list[dict]:
        test_cycle_structure: list[dict] = self.legacy_session.get(
            f"{self.server_legacy_url}cycle/{cycle_key}/structure",
        ).json()
        return test_cycle_structure

    def get_tov_structure(self, tovKey: str) -> list[dict]:
        tov_structure: list[dict] = self.legacy_session.get(
            f"{self.server_legacy_url}tov/{tovKey}/structure",
        ).json()
        return tov_structure

    def get_test_cases(self, test_case_set_structure: dict[str, Any]) -> dict[str, Any]:
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
            test_cases.get(uid, {}).get("testCaseSpecificationKey", {}).get("serial")
            == tc["paramCombPK"]["serial"]
            for uid, tc in test_cases_execs.items()
        ]
        return {
            "spec": test_cases,
            "exec": test_cases_execs,
            "equal_lists": equal_lists,
        }

    def get_spec_test_cases(self, testCaseSetKey: str, specificationKey: str) -> list[dict]:
        spec_test_cases = self.legacy_session.get(
            f"{self.server_legacy_url}testCaseSets/"
            f"{testCaseSetKey}/specifications/"
            f"{specificationKey}/testCases",
        ).json()
        if not isinstance(spec_test_cases, list) or not all(
            isinstance(item, dict) for item in spec_test_cases
        ):
            raise ValueError("spec_test_cases not in expected format")
        return spec_test_cases

    def get_exec_test_cases(self, testCaseSetKey: str, executionKey: str) -> list[dict]:
        exec_test_cases: list[dict] = self.legacy_session.get(
            f"{self.server_legacy_url}testCaseSets/{testCaseSetKey}/executions/{executionKey}/testCases",
        ).json()
        return exec_test_cases


def login(server="", login="", pwd="", session="") -> Connection:  # noqa: C901, PLR0912
    if server and ((login and pwd) or session):
        credentials = {
            "server_url": server,
            "verify": False,
            "loginname": login,
            "password": pwd,
            "sessionToken": session,
        }
    else:
        credentials = questions.ask_for_test_bench_credentials(server, login, pwd, session)

    while True:
        connection = Connection(**credentials)
        try:
            if connection.check_is_working():
                return connection

        except requests.HTTPError:
            logger.error("HTTP Error during login. See log file for more details.")
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
            logger.error("Connection Error. See log file for more details.")
            logger.debug(traceback.format_exc())
            action = questions.ask_for_action_after_failed_server_connection()
            if action == "retry_server":
                credentials["server_url"] = questions.ask_for_test_bench_server_url()
            elif action == "change_server":
                credentials = questions.ask_for_test_bench_credentials()
            else:
                close_program()

        except requests.exceptions.Timeout:
            logger.error("No connection could be established due to timeout. See log file for more details.")
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
    def __init__(self, timeout: int | None = 60, *args, **kwargs):
        self.timeout = timeout
        super().__init__(*args, **kwargs)

    def send(self, *args, **kwargs):
        kwargs["timeout"] = self.timeout
        return super().send(*args, **kwargs)


class JobTimeout(requests.exceptions.Timeout):
    pass


class ConnectionLog:
    def __init__(self):
        self.connections: list[Connection] = []

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
            json.dump(asdict(export_config), output_file, indent=2)
