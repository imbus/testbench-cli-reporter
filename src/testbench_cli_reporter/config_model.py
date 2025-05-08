from dataclasses import dataclass, field
from enum import Enum


class FilterInfoType(str, Enum):
    TestTheme = "TestTheme"
    TestCaseSet = "TestCaseSet"
    TestCase = "TestCase"


@dataclass
class FilterInfo:
    name: str
    type: FilterInfoType
    testThemeUID: str | None = None

    @classmethod
    def from_dict(cls, dictionary):
        return cls(
            name=dictionary["name"],
            type=FilterInfoType(dictionary["type"]),
            testThemeUID=dictionary.get("testThemeUID"),
        )


@dataclass
class TestCycleXMLReportOptions:
    exportAttachments: bool | None
    exportDesignData: bool | None
    reportRootUID: str | None
    suppressFilteredData: bool | None
    characterEncoding: str | None
    exportExpandedData: bool | None
    filters: list[FilterInfo] | None
    exportExecutionProtocols: bool | None
    exportDescriptionFields: bool | None
    outputFormattedText: bool | None

    @classmethod
    def from_dict(cls, dictionary):
        return cls(
            exportAttachments=dictionary.get("exportAttachments"),
            exportDesignData=dictionary.get("exportDesignData"),
            reportRootUID=dictionary.get("reportRootUID"),
            suppressFilteredData=dictionary.get("suppressFilteredData"),
            characterEncoding=dictionary.get("characterEncoding"),
            exportExpandedData=dictionary.get("exportExpandedData"),
            filters=[FilterInfo.from_dict(f) for f in dictionary.get("filters", [])],
            exportExecutionProtocols=dictionary.get("exportExecutionProtocols"),
            exportDescriptionFields=dictionary.get("exportDescriptionFields"),
            outputFormattedText=dictionary.get("outputFormattedText"),
        )


@dataclass
class ExportParameters:
    outputPath: str
    projectPath: list[str] | None = None
    tovKey: str | None = None
    cycleKey: str | None = None
    reportRootUID: str | None = None
    report_config: TestCycleXMLReportOptions | None = None
    filters: list[FilterInfo] | None = None

    @classmethod
    def from_dict(cls, dictionary):
        return cls(
            outputPath=dictionary["outputPath"],
            projectPath=dictionary.get("projectPath", []),
            tovKey=dictionary.get("tovKey"),
            cycleKey=dictionary.get("cycleKey"),
            reportRootUID=dictionary.get("reportRootUID"),
            report_config=TestCycleXMLReportOptions.from_dict(dictionary.get("report_config") or {})
            if dictionary.get("report_config")
            else None,
            filters=dictionary.get("filters", []),
        )


@dataclass
class ExportAction:
    parameters: ExportParameters
    type: str = "ExportXMLReport"

    @classmethod
    def from_dict(cls, dictionary):
        return cls(parameters=ExportParameters.from_dict(dictionary.get("parameters") or {}))


@dataclass
class ExecutionResultsImportOptions:
    fileName: str
    reportRootUID: str | None
    ignoreNonExecutedTestCases: bool | None
    defaultTester: str | None
    checkPaths: bool | None
    filters: list[FilterInfo] | None
    discardTesterInformation: bool | None
    useExistingDefect: bool | None

    @classmethod
    def from_dict(cls, dictionary) -> "ExecutionResultsImportOptions":
        return cls(
            fileName=dictionary.get("fileName", "result.zip"),
            reportRootUID=dictionary.get("reportRootUID"),
            ignoreNonExecutedTestCases=dictionary.get("ignoreNonExecutedTestCases"),
            defaultTester=dictionary.get("defaultTester"),
            checkPaths=dictionary.get("checkPaths"),
            filters=[FilterInfo.from_dict(f) for f in dictionary.get("filters", [])],
            discardTesterInformation=dictionary.get("discardTesterInformation"),
            useExistingDefect=dictionary.get("useExistingDefect"),
        )


@dataclass
class ImportParameters:
    inputPath: str
    cycleKey: str | None = None
    projectPath: list[str] | None = None
    reportRootUID: str | None = None
    defaultTester: str | None = None
    filters: list[FilterInfo] | None = None
    importConfig: ExecutionResultsImportOptions | None = None

    @classmethod
    def from_dict(cls, dictionary):
        return cls(
            inputPath=dictionary["inputPath"],
            reportRootUID=dictionary.get("reportRootUID"),
            defaultTester=dictionary.get("defaultTester"),
            filters=dictionary.get("filters", []),
            importConfig=ExecutionResultsImportOptions.from_dict(
                dictionary.get("importConfig") if dictionary.get("importConfig") else None
            ),
        )


@dataclass
class ImportAction:
    parameters: ImportParameters
    type: str = "ImportExecutionResults"

    @classmethod
    def from_dict(cls, dictionary):
        return cls(parameters=ImportParameters.from_dict(dictionary.get("parameters") or {}))


@dataclass
class Configuration:
    server_url: str | None = None
    verify: bool = True
    basicAuth: str | None = None
    loginname: str | None = None
    password: str | None = None
    actions: list[ExportAction | ImportAction] | None = None

    @classmethod
    def from_dict(cls, dictionary):
        return cls(
            server_url=dictionary["server_url"],
            verify=dictionary.get("verify", True),
            basicAuth=dictionary.get("basicAuth"),
            loginname=dictionary.get("loginname"),
            password=dictionary.get("password"),
            actions=[
                ExportAction.from_dict(a)
                if a["type"] == "ExportXMLReport"
                else ImportAction.from_dict(a)
                for a in dictionary["actions"]
            ],
        )


class LogLevel(str, Enum):
    CRITICAL = "CRITICAL"
    FATAL = CRITICAL
    ERROR = "ERROR"
    WARNING = "WARNING"
    WARN = WARNING
    INFO = "INFO"
    DEBUG = "DEBUG"
    NOTSET = "NOTSET"


@dataclass
class ConsoleLoggerConfig:
    logLevel: LogLevel
    logFormat: str

    @classmethod
    def from_dict(cls, dictionary):
        log_level = LogLevel[dictionary.get("logLevel", "INFO").upper()]
        if log_level.value not in LogLevel.__members__:
            print(
                f"ValueError: {log_level} is not a valid logLevel. "
                f"Available logLevel are: {list(LogLevel.__members__)}"
            )
            log_level = LogLevel.INFO
        return cls(
            logLevel=log_level,
            logFormat=dictionary.get("logFormat", "%(message)s"),
        )


@dataclass
class FileLoggerConfig(ConsoleLoggerConfig):
    fileName: str

    @classmethod
    def from_dict(cls, dictionary):
        log_level = LogLevel[dictionary.get("logLevel", "DEBUG").upper()]
        if log_level.value not in LogLevel.__members__:
            print(
                f"ValueError: {log_level} is not a valid logLevel. "
                f"Available logLevel are: {list(LogLevel.__members__)}"
            )
            log_level = LogLevel.DEBUG
        return cls(
            logLevel=log_level,
            logFormat=dictionary.get(
                "logFormat",
                "%(asctime)s - %(filename)s:%(lineno)d - %(levelname)8s - %(message)s",
            ),
            fileName=dictionary.get("fileName", "testbench-cli-reporter.log"),
        )


@dataclass
class loggingConfig:  # noqa: N801
    console: ConsoleLoggerConfig = field(default_factory=lambda: ConsoleLoggerConfig.from_dict({}))
    # file: FileLoggerConfig = field(default_factory=lambda: FileLoggerConfig.from_dict({}))
    file: FileLoggerConfig | None = None

    @classmethod
    def from_dict(cls, dictionary):
        return cls(
            console=ConsoleLoggerConfig.from_dict(dictionary.get("console") or {}),
            file=FileLoggerConfig.from_dict(dictionary.get("file") or {}),
        )


@dataclass
class CliReporterConfig:
    configuration: list[Configuration] = field(default_factory=list)
    loggingConfiguration: loggingConfig = field(default_factory=loggingConfig)

    @classmethod
    def from_dict(cls, dictionary):
        return cls(
            configuration=[Configuration.from_dict(c) for c in dictionary.get("configuration", [])],
            loggingConfiguration=loggingConfig.from_dict(
                dictionary.get("loggingConfiguration")
                or dictionary.get("logging_configuration")
                or {}
            ),
        )
