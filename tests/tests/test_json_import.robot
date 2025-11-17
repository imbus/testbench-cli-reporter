*** Settings ***
Resource    ../resources/Keywords.robot


*** Variables ***
${CONFIG_JSON_IMPORT_PATH}      ${CURDIR}/../data/config_json_import.json


*** Test Cases ***
Should Run Configured JSON Import If Valid Credentials
    ${result}=    Run CLI Reporter With Valid Credentials    config=${CONFIG_JSON_IMPORT_PATH}
    Should Contain    ${result.stdout}    Run Automatic Mode
    Should Contain    ${result.stdout}    Authenticated with session token
    Should Contain    ${result.stdout}    Job ImportJSONExecutionResults
    Should Contain    ${result.stdout}    All jobs finished
