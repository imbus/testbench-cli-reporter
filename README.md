# testbench-cli-reporter
## Supported Actions
- __Export XML Report__ from TestBench project
- __Import test execution results__ into TestBench project
- __Export actions__: Create a JSON file which can be used in automatic mode to repeat your previous actions automatically
- __Change connection__: Change TestBench server and/or user

## Installation

Python 3.6 is required!

`pip install --pre testbench-cli-reporter`

## Manual mode
Just execute in Command Line 
`testbench-cli-reporter` or `TestBenchCliReporter`

## Automatic mode
Run in automatic mode:
`
testbench-cli-reporter --configfile /path/to/config/file.json
`

## Config file structure

```json
{
    "configuration": [
        {
            "server_url": "https://testbench:1234/api/1/",
            "loginname": "User A",
            "password": "passwordA",
            "actions": [
                {
                    "type": "ExportXMLReport",
                    "parameters": {
                        "cycleKey": "12345678",
                        "reportRootUID": "ITBEXP-TT-1234",
                        "filters": [],
                        "outputPath": "C:\\Users\\testuser\\Dokumente\\test_report1.zip"
                    }
                },
                {
                    "type": "ExportXMLReport",
                    "parameters": {
                        "cycleKey": "98765432",
                        "reportRootUID": "ITBEXP-TT-4321",
                        "filters": [],
                        "outputPath": "C:\\Users\\testuser\\Dokumente\\test_report2.zip"
                    }
                }
            ]
        },
        {
            "server_url": "https://testbench:9999/api/1/",
            "loginname": "User B",
            "password": "passwordB",
            "actions": [
                {
                    "type": "ExportXMLReport",
                    "parameters": {
                        "cycleKey": "12344321",
                        "reportRootUID": "ITBEXP-TT-1221",
                        "filters": [],
                        "outputPath": "C:\\Users\\testuser\\Dokumente\\test_report3.zip"
                    }
                }
            ]
        }
    ]
}
```