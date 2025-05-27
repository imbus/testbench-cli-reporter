*** Settings ***
Resource    ../resources/Keywords.robot


*** Test Cases ***
Should Import XML Report If Cycle Key And Protocol Entry Exist
    VAR    ${input_path}=    ${CURDIR}/../data/xml_execution_results.zip
    ${result}=    Run CLI Reporter With Valid Credentials
    ...    cycle_key=6320
    ...    uid=iTB-TT-4090
    ...    type=i
    ...    path=${input_path}
    Should Contain    ${result.stdout}    Run Automatic Mode
    Should Contain    ${result.stdout}    Authenticated with session token
    Should Contain    ${result.stdout}    Job ImportXMLExecutionResults
    Should Contain    ${result.stdout}    All jobs finished

Should Display Error While Importing XML Report If Cycle Key Is Missing
    [Setup]    Delete File If Exists    ${DEFAULT_REPORT_PATH}
    Run CLI Reporter With Valid Credentials
    ...    project=Car Configurator
    ...    version=Version 2.0
    ...    path=${DEFAULT_REPORT_PATH}
    File Should Exist    ${DEFAULT_REPORT_PATH}
    ${result}=    Run CLI Reporter With Valid Credentials    type=i    path=${DEFAULT_REPORT_PATH}
    Should Contain    ${result.stdout}    Invalid Config! 'cycleKey' missing.
    [Teardown]    Delete File If Exists    ${DEFAULT_REPORT_PATH}

Should Display Error While Importing XML Report If Protocol Entry Is Missing
    [Setup]    Delete File If Exists    ${DEFAULT_REPORT_PATH}
    Run CLI Reporter With Valid Credentials    cycle_key=6320    path=${DEFAULT_REPORT_PATH}
    File Should Exist    ${DEFAULT_REPORT_PATH}
    ${result}=    Run CLI Reporter With Valid Credentials
    ...    cycle_key=6320
    ...    type=i
    ...    path=${DEFAULT_REPORT_PATH}
    Should Contain    ${result.stdout}    Report was NOT imported
    Should Contain    ${result.stdout}    The protocol entry is missing in this file content.
    [Teardown]    Delete File If Exists    ${DEFAULT_REPORT_PATH}
