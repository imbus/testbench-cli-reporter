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
from typing import Optional, Union
import requests
import urllib3
import time
from TestBenchCliReporter import actions
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
        ]


def delay():
    if os.name == "nt":
        return 0.1
    else:
        return 0.04


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
        verify: Union[bool, str],
        loginname: str,
        password: str,
        job_timeout_sec: int = 4 * 60 * 60,
        connection_timeout_sec: int = None,
        **kwargs,
    ):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.server_url = server_url
        self.loginname = loginname
        self.password = password
        self.job_timeout_sec = job_timeout_sec
        self.action_log: list[actions.Action] = []
        self.session = requests.Session()
        self.session.auth = (loginname, password)
        self.session.headers.update(
            {"Content-Type": "application/vnd.testbench+json; charset=utf-8"}
        )
        self.session.hooks = {
            "response": lambda r, *args, **kwargs: r.raise_for_status()
        }
        self.session.mount("http://", TimeoutHTTPAdapter(connection_timeout_sec))
        self.session.mount("https://", TimeoutHTTPAdapter(connection_timeout_sec))
        self.session.verify = verify
        # TODO: add id_ for selecting specific connections to actionlog?

    def close(self):
        self.session.close()

    def export(self) -> dict:
        return {
            "server_url": self.server_url,
            "verify": self.session.verify,
            "loginname": self.loginname,
            "password": self.password,
            "actions": [
                action_export
                for action_export in (action.export() for action in self.action_log)
                if action_export is not None
            ],
        }

    def add_action(self, action: actions.Action):
        self.action_log.append(action)

    def check_is_identical(self, other: Connection) -> bool:
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
        self, tov_key: str, cycle_key: str, reportRootUID: str, filters=None
    ) -> str:
        if filters is None:
            filters = []
        itep_options = {
            "exportAttachments": True,
            "exportDesignData": True,
            "characterEncoding": "utf-16",
            "suppressFilteredData": True,
            "exportExpandedData": True,
            "exportDescriptionFields": True,
            "outputFormattedText": False,
            "exportExecutionProtocols": False,
        }
        itorx_options = {
            "exportAttachments": True,
            "exportDesignData": True,
            "characterEncoding": "utf-8",
            "suppressFilteredData": True,
            "exportExpandedData": True,
            "exportDescriptionFields": True,
            "outputFormattedText": True,
            "exportExecutionProtocols": True,
        }
        xml_report_options = itorx_options  # TODO hier noch gut machen und Fragen
        if reportRootUID != "ROOT":
            xml_report_options["reportRootUID"] = reportRootUID
        xml_report_options["filters"]: filters

        if cycle_key:
            job_id = self.session.post(
                self.server_url + "cycle/" + cycle_key + "/xmlReport",
                json=xml_report_options,
            )
        else:
            job_id = self.session.post(
                self.server_url + "tovs/" + tov_key + "/xmlReport",
                json=xml_report_options,
            )

        return job_id.json()["jobID"]

    def wait_for_tmp_xml_report_name(self, job_id: str) -> str:
        end_time = time.time() + self.job_timeout_sec
        while True:
            report_generation_status = self.session.get(
                self.server_url + "job/" + job_id,
            )
            if report_generation_status.json()["completion"] is not None:
                break
            elif time.time() > end_time:
                raise JobTimeout(
                    f"Generation of XML report exceeded time limit of {self.job_timeout_sec} seconds."
                )
            for cursor in spinner():
                print(
                    f"Waiting until creation of XML report is complete {cursor}",
                    end="\r",
                )
                time.sleep(delay())

        report_tmp_name = report_generation_status.json()["completion"]["result"][
            "Right"
        ]
        return report_tmp_name

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

    def import_execution_results(
        self,
        results_file_base64: str,
        cycle_key: str,
        report_root_uid: str,
        default_tester: str,
        filters: list[dict[str, str]],
    ) -> bool:
        serverside_file_name = self.upload_execution_results(results_file_base64)
        job_id = self.trigger_execution_results_import(
            cycle_key, report_root_uid, serverside_file_name, default_tester, filters
        )
        success = self.wait_for_execution_results_import_to_finish(job_id)

        return success

    def upload_execution_results(self, results_file_base64: str) -> str:
        serverside_file_name = self.session.post(
            self.server_url + "executionResultsUpload",
            json={
                "data": results_file_base64,
            },
        )

        return serverside_file_name.json()["fileName"]

    def trigger_execution_results_import(
        self,
        cycle_key: str,
        report_root_uid: str,
        serverside_file_name: str,
        default_tester: str,
        filters: list[dict[str, str]],
    ) -> str:
        import_config = {
            "fileName": serverside_file_name,
            "ignoreNonExecutedTestCases": True,
            "defaultTester": default_tester,
            "checkPaths": True,
            "filters": filters,
            "discardTesterInformation": True,
            "useExistingDefect": True,
        }
        if report_root_uid != "ROOT":
            import_config["reportRootUID"] = report_root_uid
        job_id = self.session.post(
            self.server_url + "cycle/" + cycle_key + "/executionResultsImport",
            headers={
                "Accept": "application/zip",
            },
            json=import_config,
        )

        return job_id.json()["jobID"]

    def wait_for_execution_results_import_to_finish(self, job_id: str) -> bool:
        end_time = time.time() + self.job_timeout_sec
        while True:
            import_status = self.session.get(
                self.server_url + "executionResultsImporterJob/" + job_id,
            )
            if import_status.json()["completion"] is not None:
                break
            elif time.time() > end_time:
                raise JobTimeout(
                    f"Generation of XML report exceeded time limit of {self.job_timeout_sec} seconds."
                )
            for cursor in spinner():
                print(
                    f"Waiting until import of execution results is done {cursor}",
                    end="\r",
                )
                time.sleep(delay())

        return True

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


class TimeoutHTTPAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, timeout: Optional[int] = 60, *args, **kwargs):
        self.timeout = timeout
        super().__init__(*args, **kwargs)

    def send(self, *args, **kwargs):
        kwargs["timeout"] = self.timeout
        return super().send(*args, **kwargs)


class JobTimeout(requests.exceptions.Timeout):
    pass
