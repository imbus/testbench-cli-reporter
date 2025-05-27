*** Settings ***
Library     OperatingSystem
Library     Process


*** Variables ***
@{CLI_ENTRYPOINTS}      testbench-cli-reporter    TestBenchCliReporter
@{CONFIG_OPTIONS}       -c    --config
@{HELP_OPTIONS}         -h    --help
${CONFIG_FILE_PATH}     ${CURDIR}/../data/config_empty_actions.json


*** Test Cases ***
All CLI Entrypoints Should Start Manual Mode With No Arguments
    FOR    ${cmd}    IN    @{CLI_ENTRYPOINTS}
        ${result}=    Run Process    ${cmd}    timeout=1s
        Should Contain    ${result.stdout}    Starting manual mode
    END

All CLI Entrypoints Should Run Automatic Mode If Config File Given
    FOR    ${cmd}    IN    @{CLI_ENTRYPOINTS}
        FOR    ${opt}    IN    @{CONFIG_OPTIONS}
            ${result}=    Run Process    ${cmd}    ${opt}    ${CONFIG_FILE_PATH}    stderr=STDOUT
            Should Contain    ${result.stdout}    Run Automatic Mode
        END
    END

Help Option Should Display Usage For All Entrypoints
    FOR    ${cmd}    IN    @{CLI_ENTRYPOINTS}
        FOR    ${opt}    IN    @{HELP_OPTIONS}
            ${result}=    Run Process    ${cmd}    ${opt}
            Should Be Equal As Integers    ${result.rc}    0
            Should Contain    ${result.stdout}    usage:
            Should Contain    ${result.stdout}    positional arguments:
            Should Contain    ${result.stdout}    options:
        END
    END

Invalid Option Should Display Error For All Entrypoints
    FOR    ${cmd}    IN    @{CLI_ENTRYPOINTS}
        ${result}=    Run Process    ${cmd}    --not-an-option
        Should Not Be Equal As Integers    ${result.rc}    0
        Should Contain    ${result.stderr}    error
        Should Contain    ${result.stderr}    unrecognized arguments
    END

Empty Option Should Display Error For All Entrypoints
    FOR    ${cmd}    IN    @{CLI_ENTRYPOINTS}
        ${result}=    Run Process    ${cmd}    -c
        Should Not Be Equal As Integers    ${result.rc}    0
        Should Contain    ${result.stderr}    error
        Should Contain    ${result.stderr}    expected one argument
    END
