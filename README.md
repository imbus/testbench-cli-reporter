# testbench-cli-reporter
## Supported Actions
- __Export XML Report__ from TestBench project
- __Import test execution results__ into TestBench project
- __Export actions__: Create a JSON file which can be used in automatic mode to repeat your previous actions automatically
- __Change connection__: Change TestBench server and/or user

## Installation

Python 3.6 is required!

`pip install testbench-cli-reporter`

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
      "server_url": "https://remus:9443/api/1/",
      "verify": false,
      "basicAuth": "dHQtYWRtaW46YWRtaW4=",
      "actions": [
        {
          "type": "ExportXMLReport",
          "parameters": {
            "tovKey": "8689447",
            "projectPath": [
              "TestBench Demo Agil",
              "Version 3.0",
              "3.0.1"
            ],
            "cycleKey": "8689450",
            "reportRootUID": "itb-TT-8161",
            "filters": [],
            "report_config": {
              "exportAttachments": true,
              "exportDesignData": true,
              "characterEncoding": "utf-16",
              "suppressFilteredData": true,
              "exportExpandedData": true,
              "exportDescriptionFields": true,
              "outputFormattedText": false,
              "exportExecutionProtocols": false,
              "reportRootUID": "itb-TT-8161"
            },
            "outputPath": "report.zip"
          }
        },
        {
          "type": "ImportExecutionResults",
          "parameters": {
            "inputPath": "report.zip",
            "cycleKey": "8689450",
            "reportRootUID": "ROOT",
            "defaultTester": false,
            "filters": [],
            "importConfig": {
              "ignoreNonExecutedTestCases": true,
              "checkPaths": true,
              "discardTesterInformation": true,
              "useExistingDefect": true,
              "filters": []
            }
          }
        }
      ]
    }
  ]
}
```