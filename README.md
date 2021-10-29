# testbench-cli-reporter
testbench-cli-reporter is a cli tool to export XML reports from an TestBench instance and import test results back into it.

This can be used for automated test execution with e.g. RobotFramework, triggered by a CI/CD pipeline.

## Supported Actions
- __Export XML Report__ from TestBench project
- __Import test execution results__ into TestBench project
- __Export actions__: Create a JSON file which can be used in automatic mode to repeat your previous actions automatically
- __Change connection__: Change TestBench server and/or user

## Installation

Python 3.6 is required!

`pip install testbench-cli-reporter`

## Manual mode
Just execute in command line 
`testbench-cli-reporter` or `TestBenchCliReporter`

### **Connect to TestBench instance**

1. Enter TestBench Server
```
PS C:\Users\falka> testbench-cli-reporter
No config file given
Starting manual mode
? Enter the TestBench server address and port <host:port>:
```

In here enter the testbench server you want to interact with. 
If you don't enter a port, the default TestBench port 9443 is used.

If you don't know the server adress of your testbench instance you can find it inside your iTBClient intallation folder: bin/application.conf

2. Enter Credential

Next Step is providing login data the testbench-cli-reporter should use to connect with the TestBench. 

Make sure the user has rights to access the test project you want to work with.

```
? Enter your login name: vadaj
? Enter your password: ****************
```

### **Select Action**

```
? What do you want to do? (Use arrow keys)
» Export XML Report
  Import execution results
  Write history to config file
  Change connection
  Quit
```

You can select the action you want to do using the arrow keys.

### **Export XML Report**
Export an XML Report for test execution from the TestBench.

1. Select a test project, test object version and test cycle you want.

```
? What do you want to do? Export XML Report
? Select a project. TestBench Demo Agil
? Select a test object version. Version 3.0
? Select a test cycle. 3.0.1
  Selection:
    TestBench Demo Agil                             projectKey:         7917307
      Version 3.0                                   tovKey:             8678256
        3.0.1                                       cycleKey:           8684351
```

**hint:** You can later use projectKey, tovKey and cycleKey in the config.json file to access the data without needing to know the name of the respective element. Elements names can change inside TestBench, Keys will remain the same. This approach can reduce maintenance effort and will increase robustness.

2. select test theme to be used as root of report
..you can also go back if you accidently selected a wrong test theme
```
? Please select an element to be used as the root of the report. TT: 1 TestBench
? Please select an element to be used as the root of the report. (Use arrow keys)
 » <SELECT> 1 TestBench [iTB-TT-299]
   TT: 1.1 Beispiele
   TT: 1.2 Regression
   TT: 1.3 Sprints V1.0
   TT: 1.4 Sprints V2.0
   <BACK>
```
3. activate filters
```
? Activate Filters: (Use arrow keys)
   No
 » Yes

 ? Provide a set of filters. (Use arrow keys to move, <space> to select, <a> to toggle, <i> to invert)
 » ○ automatisiert bdf
   ○ automatisiert keyword
   ○ Mir zugewiesen
```

4. Select report configuration
```
? Select Report Configuration: (Use arrow keys)
 » Itep Export
   iTorx Export (execution)
   iTorx Export (continue|view)
   <CUSTOM>
```
Itep Export, iTorx Export (execution) and iTorx Export(continue|view) are pre-configured exports.
With Custom you can configure the report by yourself.

In each case you must provide the path the export should be saved in.

TODO: add explanations of each option

Custom configuration possibilities

- exportAttachments (True | False)
: definition

- exportDesignData (True | False)
: definition

- characterEncoding (UTF-16 | UTF-8)
: definition

- suppressFilteredData (True | False)
: definition

- exportExpandedData (True | False)
: definition

- exportDescriptionFields (True | False)
: definition

- exportExecutionProtocols (True | False)
: definition



### **Import execution results**
Import test results into the TestBench.

```
? Provide the input path [report.zip]:
```

### **Write history to config file**
Writes a config.json file containing the inputs given in the current session using the testbench-cli-reporter.

This config file can later be used to execute the testbench-cli-reporter in automatic mode.

If you didn't export nor import anything in the current session yet, at least the connection properties are written.

```json
{
  "configuration": [
    {
      "server_url": "https://vadaj:9443/api/1/",
      "verify": false,
      "basicAuth": "dHQtYWRtaW46YWRtaW4=",
      "actions": []
    },
  ]
}
```

### Change connection
Connect to a different TestBench instance so you do not have to exit the testbench-cli-reporter completely.

```
? What do you want to do? Change connection
? Enter the TestBench server address and port <host:port>:
? Enter your login name: vadaj
? Enter your password: ****************
```

### Quit
Exits the testbench-cli-reporter

----------
## Automatic mode
Run in automatic mode:
`
testbench-cli-reporter --config /path/to/config/file.json
`

## Config file structure
The attribute `projectPath` is not mandatory though. Only using projectKey, tovKey, cycleKey is also more error prone, as they will not change within TestBench.
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
----------

## Optional arguments
TODO


You can access a list of optional arguments using `testbench-cli-reporter --help`

```
usage: testbench-cli-reporter [-h] [-c CONFIG] [-s SERVER] [--login LOGIN] [--password PASSWORD] [-p PROJECT]
                              [-v VERSION] [-y CYCLE] [-u UID] [-t {e,i}]
                              [path]

positional arguments:
  path                  Input- and Output-Path for xml reports <OPTIONAL, Default = report.zip>.

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Path to a config json file to execute pre-set actions based on the given configuration.
  -s SERVER, --server SERVER
                        TestBench Server address (hostname:port).
  --login LOGIN         Users Login.
  --password PASSWORD   Users Password.
  -p PROJECT, --project PROJECT
                        Project name to be exported <OPTIONAL if --type is 'i'>.
  -v VERSION, --version VERSION
                        Test Object Version name to be exported <OPTIONAL if --type is 'i'>.
  -y CYCLE, --cycle CYCLE
                        Test Cycle name to be exported <OPTIONAL>
  -u UID, --uid UID     Root UID to be exported <OPTIONAL, Default = ROOT>
  -t {e,i}, --type {e,i}
                        'e' for Export <default>, 'i' for Import
```
