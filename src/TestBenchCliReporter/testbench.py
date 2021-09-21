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

#from __future__ import annotations

import base64
from typing import Optional, Union, List, Dict
import requests
import urllib3
import time
from TestBenchCliReporter.actions import AbstractAction
from TestBenchCliReporter import questions
from TestBenchCliReporter.util import XmlExportConfig, ImportConfig, close_program
from questionary import print as pprint
import json
import os


def spinner():
    if os.name == "nt":
        return ["_", "_", "_", "-", "`", "`", "'", "´", "-", "_", "_", "_"]
    else:
        return [
            "⢀⠀",
            "⡀⠀",
            "⠄⠀",
            "⢂⠀",
            "⡂⠀",
            "⠅⠀",
            "⢃⠀",
            "⡃⠀",
            "⠍⠀",
            "⢋⠀",
            "⡋⠀",
            "⠍⠁",
            "⢋⠁",
            "⡋⠁",
            "⠍⠉",
            "⠋⠉",
            "⠋⠉",
            "⠉⠙",
            "⠉⠙",
            "⠉⠩",
            "⠈⢙",
            "⠈⡙",
            "⢈⠩",
            "⡀⢙",
            "⠄⡙",
            "⢂⠩",
            "⡂⢘",
            "⠅⡘",
            "⢃⠨",
            "⡃⢐",
            "⠍⡐",
            "⢋⠠",
            "⡋⢀",
            "⠍⡁",
            "⢋⠁",
            "⡋⠁",
            "⠍⠉",
            "⠋⠉",
            "⠋⠉",
            "⠉⠙",
            "⠉⠙",
            "⠉⠩",
            "⠈⢙",
            "⠈⡙",
            "⠈⠩",
            "⠀⢙",
            "⠀⡙",
            "⠀⠩",
            "⠀⢘",
            "⠀⡘",
            "⠀⠨",
            "⠀⢐",
            "⠀⡐",
            "⠀⠠",
            "⠀⢀",
            "⠀⡀",
            "⠀⠀",
        ]


def delay():
    if os.name == "nt":
        return 0.1
    else:
        return 0.02


def spin_spinner(message: str):
    for cursor in spinner():
        print(
            f"{message} {cursor}",
            end="\r",
        )
        time.sleep(delay())


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
        self.actions_to_trigger: List[Dict] = actions or []
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
        self._session.hooks = {
            "response": lambda r, *args, **kwargs: r.raise_for_status()
        }
        self._session.mount("http://", TimeoutHTTPAdapter(self.connection_timeout))
        self._session.mount("https://", TimeoutHTTPAdapter(self.connection_timeout))
        self._session.verify = self.verify_ssl
        return self._session

    def close(self):
        self.session.close()

    def export(self) -> dict:
        basic_auth = base64.b64encode(
            f"{self.loginname}:{self.password}".encode("utf-8")
        ).decode()
        return {
            "server_url": self.server_url,
            "verify": self.session.verify,
            "basicAuth": basic_auth,
            "actions": [
                action_export
                for action_export in (action.export() for action in self.action_log)
                if action_export is not None
            ],
        }

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
            self.server_url + "projects",
            params={
                "includeTOVs": "false",
                "includeCycles": "false",
            },
        )

        response.json()

        return True

    def get_all_projects(self) -> dict:
        all_projects = self.session.get(
            self.server_url + "projects",
            params={"includeTOVs": "true", "includeCycles": "true"},
        ).json()
        all_projects["projects"].sort(key=lambda proj: proj["name"].casefold())
        return all_projects

    def get_all_filters(self) -> list[dict]:
        all_filters = self.session.get(
            self.server_url + "filters",
        )

        return all_filters.json()

    def get_xml_report(
        self, tov_key: str, cycle_key: str, reportRootUID: str, filters=None
    ) -> bytes:
        if filters is None:
            filters = []
        job_id = self.trigger_xml_report_generation(
            tov_key, cycle_key, reportRootUID, filters
        )
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
            report_config["reportRootUID"] = reportRootUID
        report_config["filters"]: filters

        if cycle_key:
            response = self.session.post(
                self.server_url + "cycle/" + cycle_key + "/xmlReport",
                json=report_config,
            )
        else:
            response = self.session.post(
                self.server_url + "tovs/" + tov_key + "/xmlReport",
                json=report_config,
            )
        if response.status_code != requests.codes.accepted:
            raise AssertionError(f"{response.status_code} {response.text}")
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
            self.server_url + "xmlReport/" + report_tmp_name,
        )

        return report.content

    def get_all_testers_of_project(self, project_key: str) -> list[dict]:
        return [
            member
            for member in self.get_all_members_of_project(project_key)
            if "Tester" in member["value"]["membership"]["roles"]
        ]

    def get_all_members_of_project(self, project_key: str) -> list[dict]:
        all_project_members = self.session.get(
            self.server_url + "project/" + project_key + "/members",
        )

        return all_project_members.json()

    def upload_execution_results(self, results_file_base64: str) -> str:
        try:
            serverside_file_name = self.session.post(
                self.server_url + "executionResultsUpload",
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
        filters: list[dict[str, str]],
        import_config: Dict = ImportConfig["Typical"],
    ) -> str:

        import_config["fileName"] = serverside_file_name
        import_config["filters"] = filters
        if default_tester:
            import_config["defaultTester"] = default_tester
        if report_root_uid and report_root_uid != "ROOT":
            import_config["reportRootUID"] = report_root_uid

        try:
            job_id = self.session.post(
                self.server_url + "cycle/" + cycle_key + "/executionResultsImport",
                headers={
                    "Accept": "application/zip",
                },
                json=import_config,
            )
            return job_id.json()["jobID"]
        except requests.exceptions.RequestException as e:
            self.render_import_error(e)

    def wait_for_execution_results_import_to_finish(self, job_id: str) -> bool:
        try:
            while True:
                import_status = self.get_job_result(
                    "executionResultsImporterJob/", job_id
                )
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

    def render_import_error(self, e):
        pprint("!!!ERROR DURING IMPORT!!!", style="#ff0e0e italic")
        pprint(f"Report was NOT imported")
        pprint(f"Error Code {e.response.status_code}")
        pprint(f"Error Message {e.response.text}")
        pprint(f"URL: {e.response.url}")

    def get_imp_job_result(self, job_id):
        report_import_status = self.get_job_result(
            "executionResultsImporterJob/", job_id
        )
        if report_import_status is None:
            return None
        result = report_import_status["result"]
        if "Right" in result:
            return result["Right"]
        else:
            raise AssertionError(result)

    def get_test_cycle_structure(self, cycle_key: str) -> list[dict]:
        test_cycle_structure = self.session.get(
            self.server_url + "cycle/" + cycle_key + "/structure",
        )
        return test_cycle_structure.json()

    def get_tov_structure(self, tovKey: str) -> list[dict]:
        tov_structure = self.session.get(
            self.server_url + "tov/" + tovKey + "/structure",
        )
        return tov_structure.json()


def login() -> Connection:
    credentials = questions.ask_for_test_bench_credentials()

    while True:
        connection = Connection(**credentials)
        try:
            if connection.check_is_working():
                return connection

        except requests.HTTPError:
            print("Invalid login credentials.")
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
            print("Invalid server url.")
            action = questions.ask_for_action_after_failed_server_connection()
            if action == "retry_server":
                credentials["server_url"] = questions.ask_for_test_bench_server_url()
            elif action == "change_server":
                credentials = questions.ask_for_test_bench_credentials()
            else:
                close_program()

        except requests.exceptions.Timeout:
            print("No connection could be established due to timeout.")
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
        print("Generating JSON export")
        export_dict = {
            "configuration": [connection.export() for connection in self.connections]
        }

        with open(output_file_path, "w") as output_file:
            json.dump(export_dict, output_file, indent=2)
