*** Settings ***
Resource    ../resources/Keywords.robot


*** Variables ***
${CONFIG_JSON_EXPORT_PATH}      ${CURDIR}/../data/config_json_export.json


*** Test Cases ***
Should Run Configured JSON Export If Valid Credentials
    [Setup]    Delete File If Exists    ${DEFAULT_REPORT_PATH}
    ${result}=    Run CLI Reporter With Valid Credentials    config=${CONFIG_JSON_EXPORT_PATH}
    Should Contain    ${result.stdout}    Authenticated with session token
    Should Contain    ${result.stdout}    Job ExportJSONReport
    Should Contain    ${result.stdout}    All jobs finished
    File Should Exist    ${DEFAULT_REPORT_PATH}
    Verify File Is Zip    ${DEFAULT_REPORT_PATH}
    Verify Zip File Contains    ${DEFAULT_REPORT_PATH}    project.json
    [Teardown]    Delete File If Exists    ${DEFAULT_REPORT_PATH}
