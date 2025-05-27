*** Settings ***
Library     String
Resource    ../resources/Keywords.robot


*** Test Cases ***
Should Display Authenticated Message If Valid Credentials
    ${result}=    Run CLI Reporter    server=${VALID_SERVER_URL}    login=${VALID_LOGIN}    password=${VALID_PASSWORD}
    Should Contain    ${result.stdout}    Starting manual mode
    Should Contain    ${result.stdout}    Authenticated with session token

Should Not Display Invalid Login Message If Valid Session Token
    ${session_token}=    Get Valid Session Token
    ${result}=    Run CLI Reporter    server=${VALID_SERVER_URL}    session=${session_token}
    Should Contain    ${result.stdout}    Starting manual mode
    Should Not Contain    ${result.stdout}    Invalid login credentials

Should Display Invalid Server Message If Invalid Host
    ${result}=    Run CLI Reporter
    ...    server=invalid:${VALID_SERVER_PORT}
    ...    login=${VALID_LOGIN}
    ...    password=${VALID_PASSWORD}
    Should Contain    ${result.stdout}    Starting manual mode
    Should Not Contain    ${result.stdout}    Authenticated with session token
    Should Contain    ${result.stdout}    Invalid server url

Should Display ValueError If Server Host Is Missing
    ${result}=    Run CLI Reporter
    ...    server=${EMPTY}:${VALID_SERVER_PORT}
    ...    login=${VALID_LOGIN}
    ...    password=${VALID_PASSWORD}
    Should Not Contain    ${result.stdout}    Authenticated with session token
    Should Contain    ${result.stdout}    ValueError: Server name '${EMPTY}:${VALID_SERVER_PORT}' is not valid.

Should Display Invalid Server Message If Invalid Server Port
    ${result}=    Run CLI Reporter
    ...    server=${VALID_SERVER_HOST}:123
    ...    login=${VALID_LOGIN}
    ...    password=${VALID_PASSWORD}
    Should Contain    ${result.stdout}    Starting manual mode
    Should Not Contain    ${result.stdout}    Authenticated with session token
    Should Contain    ${result.stdout}    Invalid server url

Should Display ValueError If Server Port Is Missing
    ${result}=    Run CLI Reporter
    ...    server=${VALID_SERVER_HOST}:${EMPTY}
    ...    login=${VALID_LOGIN}
    ...    password=${VALID_PASSWORD}
    Should Not Contain    ${result.stdout}    Authenticated with session token
    Should Contain    ${result.stdout}    ValueError: Server name '${VALID_SERVER_HOST}:${EMPTY}' is not valid.

Should Display Invalid login Message If Invalid User Login
    ${result}=    Run CLI Reporter    server=${VALID_SERVER_URL}    login=invalid!$%&?    password=${VALID_PASSWORD}
    Should Contain    ${result.stdout}    Starting manual mode
    Should Not Contain    ${result.stdout}    Authenticated with session token
    Should Contain    ${result.stdout}    Invalid login credentials

Should Not Display Authenticated Message If User Login Is Missing
    ${result}=    Run CLI Reporter    server=${VALID_SERVER_URL}    login=${EMPTY}    password=${VALID_PASSWORD}
    Should Contain    ${result.stdout}    Starting manual mode
    Should Not Contain    ${result.stdout}    Authenticated with session token

Should Display Invalid Login Message If Invalid User Password
    ${result}=    Run CLI Reporter    server=${VALID_SERVER_URL}    login=${VALID_LOGIN}    password=123@$%&?
    Should Contain    ${result.stdout}    Starting manual mode
    Should Not Contain    ${result.stdout}    Authenticated with session token
    Should Contain    ${result.stdout}    Invalid login credentials

Should Not Display Authenticated Message If User Password Is Missing
    ${result}=    Run CLI Reporter    server=${VALID_SERVER_URL}    login=${VALID_LOGIN}    password=${EMPTY}
    Should Contain    ${result.stdout}    Starting manual mode
    Should Not Contain    ${result.stdout}    Authenticated with session token

Should Display Invalid Login Message If Invalid Session Token
    ${result}=    Run CLI Reporter    server=${VALID_SERVER_URL}    session=0123456789!
    Should Contain    ${result.stdout}    Starting manual mode
    Should Not Contain    ${result.stdout}    Authenticated with session token
    Should Contain    ${result.stdout}    Invalid login credentials
