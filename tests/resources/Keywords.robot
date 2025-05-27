*** Settings ***
Library     Collections
Library     OperatingSystem
Library     Process
Library     String


*** Variables ***
${CLI_ENTRYPOINT}           testbench-cli-reporter
${LOG_FILE_PATH}            testbench-cli-reporter.log

${VALID_SERVER_URL}         localhost:443
${VALID_SERVER_HOST}        localhost
${VALID_SERVER_PORT}        443
${VALID_LOGIN}              tt-admin
${VALID_PASSWORD}           admin

${DEFAULT_REPORT_PATH}      report.zip
${TEMP_DIR_PATH}            temp


*** Keywords ***
Run CLI Reporter
    [Documentation]    Runs the TestBench CLI Reporter with the given arguments. Supports all common and extra options.
    [Arguments]
    ...    ${config}=${EMPTY}
    ...    ${server}=${EMPTY}
    ...    ${login}=${EMPTY}
    ...    ${password}=${EMPTY}
    ...    ${session}=${EMPTY}
    ...    ${project}=${EMPTY}
    ...    ${version}=${EMPTY}
    ...    ${cycle}=${EMPTY}
    ...    ${tov_key}=${EMPTY}
    ...    ${cycle_key}=${EMPTY}
    ...    ${uid}=${EMPTY}
    ...    ${type}=${EMPTY}
    ...    ${manual}=False
    ...    ${path}=${EMPTY}
    ...    ${stdout}=PIPE
    ...    ${stderr}=STDOUT
    ...    ${timeout}=5s
    VAR    @{args}=    ${CLI_ENTRYPOINT}
    IF    $config    Append To List    ${args}    --config    ${config}
    IF    $server    Append To List    ${args}    --server    ${server}
    IF    $login    Append To List    ${args}    --login    ${login}
    IF    $password    Append To List    ${args}    --password    ${password}
    IF    $session    Append To List    ${args}    --session    ${session}
    IF    $project    Append To List    ${args}    --project    ${project}
    IF    $version    Append To List    ${args}    --version    ${version}
    IF    $cycle    Append To List    ${args}    --cycle    ${cycle}
    IF    $tov_key    Append To List    ${args}    --tovKey    ${tov_key}
    IF    $cycle_key    Append To List    ${args}    --cycleKey    ${cycle_key}
    IF    $uid    Append To List    ${args}    --uid    ${uid}
    IF    $type    Append To List    ${args}    --type    ${type}
    IF    ${manual}    Append To List    ${args}    --manual
    IF    $path    Append To List    ${args}    ${path}
    ${result}=    Run Process    @{args}    stdout=${stdout}    stderr=${stderr}    timeout=${timeout}
    RETURN    ${result}

Run CLI Reporter With Valid Credentials
    [Documentation]    Runs the TestBench CLI Reporter with valid credentials. Supports all other options.
    [Arguments]
    ...    ${config}=${EMPTY}
    ...    ${project}=${EMPTY}
    ...    ${version}=${EMPTY}
    ...    ${cycle}=${EMPTY}
    ...    ${tov_key}=${EMPTY}
    ...    ${cycle_key}=${EMPTY}
    ...    ${uid}=${EMPTY}
    ...    ${type}=${EMPTY}
    ...    ${manual}=False
    ...    ${path}=${EMPTY}
    ...    ${stdout}=PIPE
    ...    ${stderr}=STDOUT
    ...    ${timeout}=5s
    ${result}=    Run CLI Reporter
    ...    config=${config}
    ...    server=${VALID_SERVER_URL}
    ...    login=${VALID_LOGIN}
    ...    password=${VALID_PASSWORD}
    ...    project=${project}
    ...    version=${version}
    ...    cycle=${cycle}
    ...    tov_key=${tov_key}
    ...    cycle_key=${cycle_key}
    ...    uid=${uid}
    ...    type=${type}
    ...    manual=${manual}
    ...    path=${path}
    ...    stdout=${stdout}
    ...    stderr=${stderr}
    ...    timeout=${timeout}
    RETURN    ${result}

Clear CLI Reporter Log
    [Arguments]    ${file_path}=${LOG_FILE_PATH}
    Remove File    ${file_path}

Get CLI Reporter Log
    ${log_content}=    Get File    ${LOG_FILE_PATH}
    RETURN    ${log_content}

Delete File If Exists
    [Arguments]    ${file_path}
    Run Keyword And Ignore Error    Remove File    ${file_path}

Create Temp Directory
    Remove Directory    ${TEMP_DIR_PATH}    recursive=True
    Create Directory    ${TEMP_DIR_PATH}

Delete Temp Directory
    Remove Directory    ${TEMP_DIR_PATH}    recursive=True

Get Valid Session Token
    ${result}=    Run CLI Reporter
    ...    server=${VALID_SERVER_URL}
    ...    login=${VALID_LOGIN}
    ...    password=${VALID_PASSWORD}
    ...    timeout=3s
    VAR    ${pattern}=    Authenticated with session token:\s*([^\s\r\n]+)
    ${matches}=    Get Regexp Matches    ${result.stdout}    ${pattern}    1
    ${session_token}=    Strip String    ${matches[0]}
    RETURN    ${session_token}

Verify File Is Zip
    [Arguments]    ${file_path}
    ${is_zip}=    Evaluate    zipfile.is_zipfile("${file_path}")    modules=zipfile
    Should Be True    ${is_zip}

Verify Zip File Contains
    [Arguments]    ${zip_path}    ${file_name}
    ${namelist}=    Evaluate    zipfile.ZipFile("${zip_path}").namelist()    modules=zipfile
    Should Contain    ${namelist}    ${file_name}
