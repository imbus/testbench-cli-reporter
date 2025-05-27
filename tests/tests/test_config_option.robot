*** Settings ***
Resource    ../resources/Keywords.robot


*** Variables ***
${CONFIG_XML_EXPORT_PATH}       ${CURDIR}/../data/config_xml_export.json


*** Test Cases ***
Should Run Automatic Mode If Config File Given
    VAR    ${config_path}=    ${CURDIR}/../data/config_empty_actions.json
    ${result}=    Run CLI Reporter With Valid Credentials    config=${config_path}
    Should Contain    ${result.stdout}    Run Automatic Mode

Should Run Configured XML Export If Valid Credentials
    [Setup]    Delete File If Exists    ${DEFAULT_REPORT_PATH}
    ${result}=    Run CLI Reporter With Valid Credentials    config=${CONFIG_XML_EXPORT_PATH}
    Should Contain    ${result.stdout}    Authenticated with session token
    Should Contain    ${result.stdout}    Job ExportXMLReport
    Should Contain    ${result.stdout}    All jobs finished
    File Should Exist    ${DEFAULT_REPORT_PATH}
    Verify File Is Zip    ${DEFAULT_REPORT_PATH}
    Verify Zip File Contains    ${DEFAULT_REPORT_PATH}    report.xml
    [Teardown]    Delete File If Exists    ${DEFAULT_REPORT_PATH}

Should Run Configured XML Export If Valid Session Token
    [Setup]    Delete File If Exists    ${DEFAULT_REPORT_PATH}
    ${session_token}=    Get Valid Session Token
    ${result}=    Run CLI Reporter    config=${CONFIG_XML_EXPORT_PATH}    session=${session_token}
    File Should Exist    ${DEFAULT_REPORT_PATH}
    Verify Zip File Contains    ${DEFAULT_REPORT_PATH}    report.xml
    [Teardown]    Delete File If Exists    ${DEFAULT_REPORT_PATH}

Should Run Configured XML Import If Valid Credentials
    VAR    ${config_path}=    ${CURDIR}/../data/config_xml_import.json
    ${result}=    Run CLI Reporter With Valid Credentials    config=${config_path}
    Should Contain    ${result.stdout}    Authenticated with session token
    Should Contain    ${result.stdout}    Job ImportXMLExecutionResults
    Should Contain    ${result.stdout}    All jobs finished

Should Run Configured Multiple XML Exports If Valid Credentials
    [Setup]    Create Temp Directory
    VAR    ${config_path}=    ${CURDIR}/../data/config_multiple_exports.json
    ${result}=    Run CLI Reporter With Valid Credentials    config=${config_path}
    VAR    @{file_paths}=
    ...    ${TEMP_DIR_PATH}/report_v1.0.zip
    ...    ${TEMP_DIR_PATH}/report_v2.0.zip
    ...    ${TEMP_DIR_PATH}/report_v2.0_Systemtest.zip
    FOR    ${file_path}    IN    @{file_paths}
        File Should Exist    ${file_path}
        Verify Zip File Contains    ${file_path}    report.xml
    END
    [Teardown]    Delete Temp Directory

Should Display Error If Invalid Config Path
    ${result}=    Run CLI Reporter With Valid Credentials    config=abc123.json
    Should Contain    ${result.stdout}    Could not open file

Should Display Error While Running Config File If Invalid Credentials
    VAR    ${config_path}=    ${CURDIR}/../data/config_invalid_credentials.json
    ${result}=    Run CLI Reporter With Valid Credentials    config=${config_path}
    Should Contain    ${result.stdout}    Run Automatic Mode
    Should Contain    ${result.stdout}    Action trigger failed
    Should Contain    ${result.stdout}    Missing or invalid authorization token

Should Display Error While Running Configured XML Export If Invalid Credentials
    ${result}=    Run CLI Reporter    config=${CONFIG_XML_EXPORT_PATH}    login=INVALID    password=INVALID
    Should Contain    ${result.stdout}    Action trigger failed
    Should Contain    ${result.stdout}    Authentication failed
    Should Contain    ${result.stdout}    Wrong login or password

Should Display Error While Running Configured XML Export If Invalid Session Token
    ${result}=    Run CLI Reporter    config=${CONFIG_XML_EXPORT_PATH}    session=INVALID
    Should Contain    ${result.stdout}    Action trigger failed
    Should Contain    ${result.stdout}    Missing or invalid authorization token

Should Display Error While Running Configured XML Export If Invalid ProjectPath
    VAR    ${config_path}=    ${CURDIR}/../data/config_xml_export_invalid_projectPath.json
    ${result}=    Run CLI Reporter With Valid Credentials    config=${config_path}
    Should Contain    ${result.stdout}    Project 'INVALID' not found.

Should Display Error While Running Configured XML Export If Invalid TovKey
    VAR    ${config_path}=    ${CURDIR}/../data/config_xml_export_invalid_tovKey.json
    ${result}=    Run CLI Reporter With Valid Credentials    config=${config_path}
    Should Contain    ${result.stdout}    The Test object version '-1' could not be found.

Should Display Error While Running Configured XML Export If Invalid CycleKey
    VAR    ${config_path}=    ${CURDIR}/../data/config_xml_export_invalid_cycleKey.json
    ${result}=    Run CLI Reporter With Valid Credentials    config=${config_path}
    Should Contain    ${result.stdout}    The test cycle '-1' could not be found.

Should Display Error While Running Configured XML Export If Invalid ReportRootUID
    VAR    ${config_path}=    ${CURDIR}/../data/config_xml_export_invalid_reportRootUID.json
    ${result}=    Run CLI Reporter With Valid Credentials    config=${config_path}
    Should Contain    ${result.stdout}    The test structure element with the unique id '-1' could not be found.
