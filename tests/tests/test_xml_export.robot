*** Settings ***
Resource    ../resources/Keywords.robot


*** Test Cases ***
Should Export XML Report On Default Location If Project And Test Object Version Exist
    [Setup]    Delete File If Exists    ${DEFAULT_REPORT_PATH}
    ${result}=    Run CLI Reporter With Valid Credentials    project=Car Configurator    version=Version 2.0
    Should Contain    ${result.stdout}    Run Automatic Mode
    Should Contain    ${result.stdout}    Authenticated with session token
    Should Contain    ${result.stdout}    Job ExportXMLReport
    Should Contain    ${result.stdout}    All jobs finished
    File Should Exist    ${DEFAULT_REPORT_PATH}
    Verify File Is Zip    ${DEFAULT_REPORT_PATH}
    Verify Zip File Contains    ${DEFAULT_REPORT_PATH}    report.xml
    [Teardown]    Delete File If Exists    ${DEFAULT_REPORT_PATH}

Should Export XML Report On Default Location If Test Object Version Key Exist
    [Setup]    Delete File If Exists    ${DEFAULT_REPORT_PATH}
    ${result}=    Run CLI Reporter With Valid Credentials    tov_key=6317
    File Should Exist    ${DEFAULT_REPORT_PATH}
    Verify File Is Zip    ${DEFAULT_REPORT_PATH}
    Verify Zip File Contains    ${DEFAULT_REPORT_PATH}    report.xml
    [Teardown]    Delete File If Exists    ${DEFAULT_REPORT_PATH}

Should Export XML Report On Default Location If Test Cycle Key Exist
    [Setup]    Delete File If Exists    ${DEFAULT_REPORT_PATH}
    ${result}=    Run CLI Reporter With Valid Credentials    cycle_key=6320
    File Should Exist    ${DEFAULT_REPORT_PATH}
    Verify File Is Zip    ${DEFAULT_REPORT_PATH}
    Verify Zip File Contains    ${DEFAULT_REPORT_PATH}    report.xml
    [Teardown]    Delete File If Exists    ${DEFAULT_REPORT_PATH}

Should Export XML Report On Default Location If Test Cycle Key And Root UID Exist
    [Setup]    Delete File If Exists    ${DEFAULT_REPORT_PATH}
    ${result}=    Run CLI Reporter With Valid Credentials    cycle_key=6320    uid=iTB-TT-4090
    File Should Exist    ${DEFAULT_REPORT_PATH}
    Verify File Is Zip    ${DEFAULT_REPORT_PATH}
    Verify Zip File Contains    ${DEFAULT_REPORT_PATH}    report.xml
    [Teardown]    Delete File If Exists    ${DEFAULT_REPORT_PATH}

Should Export XML Report On Given Output Path If Project And Test Object Version Exist
    [Setup]    Create Temp Directory
    VAR    ${output_path}=    ${TEMP_DIR_PATH}/report.zip
    Delete File If Exists    ${output_path}
    ${result}=    Run CLI Reporter With Valid Credentials
    ...    project=Car Configurator
    ...    version=Version 2.0
    ...    path=${output_path}
    File Should Exist    ${output_path}
    Verify File Is Zip    ${output_path}
    Verify Zip File Contains    ${output_path}    report.xml
    [Teardown]    Delete Temp Directory

Should Display Error While Exporting XML Report If Project Does Not Exist
    ${result}=    Run CLI Reporter With Valid Credentials    project=INVALID    version=Version 2.0
    Should Contain    ${result.stdout}    Run Automatic Mode
    Should Contain    ${result.stdout}    Authenticated with session token
    Should Contain    ${result.stdout}    ValueError: Project 'INVALID' not found.

Should Display Error While Exporting XML Report If Test Object Version Does Not Exist
    ${result}=    Run CLI Reporter With Valid Credentials    project=Car Configurator    version=Version -1
    Should Contain    ${result.stdout}    Run Automatic Mode
    Should Contain    ${result.stdout}    Authenticated with session token
    Should Contain    ${result.stdout}    ValueError: TOV 'Version -1' not found.

Should Display Error While Exporting XML Report If Test Cycle Does Not Exist
    ${result}=    Run CLI Reporter With Valid Credentials
    ...    project=Car Configurator
    ...    version=Version 2.0
    ...    cycle=INVALID
    Should Contain    ${result.stdout}    Run Automatic Mode
    Should Contain    ${result.stdout}    Authenticated with session token
    Should Contain    ${result.stdout}    ValueError: Cycle 'INVALID' not found.

Should Display Error While Exporting XML Report If Test Object Version Key Does Not Exist
    ${result}=    Run CLI Reporter With Valid Credentials    tov_key=-1
    Should Contain    ${result.stdout}    Run Automatic Mode
    Should Contain    ${result.stdout}    Authenticated with session token
    Should Contain    ${result.stdout}    The Test object version '-1' could not be found.

Should Display Error While Exporting XML Report If Test Cycle Key Does Not Exist
    ${result}=    Run CLI Reporter With Valid Credentials    cycle_key=-1
    Should Contain    ${result.stdout}    Run Automatic Mode
    Should Contain    ${result.stdout}    Authenticated with session token
    Should Contain    ${result.stdout}    The test cycle '-1' could not be found.

Should Display Error While Exporting XML Report If Root UID Does Not Exist
    ${result}=    Run CLI Reporter With Valid Credentials    cycle_key=6320    uid=-1
    Should Contain    ${result.stdout}    Run Automatic Mode
    Should Contain    ${result.stdout}    Authenticated with session token
    Should Contain    ${result.stdout}    The test structure element with the unique id '-1' could not be found.
