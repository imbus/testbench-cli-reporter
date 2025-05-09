from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum


class FilterInfoType(str, Enum):
    TestTheme = "TestTheme"
    TestCaseSet = "TestCaseSet"
    TestCase = "TestCase"


@dataclass
class FilterInfo:
    name: str
    filterType: FilterInfoType
    testThemeUID: str | None = None

    @classmethod
    def from_dict(cls, dictionary: dict):
        return cls(
            name=dictionary["name"],
            filterType=FilterInfoType(dictionary["type"]),
            testThemeUID=dictionary.get("testThemeUID"),
        )


@dataclass
class FilterJsonInfo:
    name: str
    filterType: FilterInfoType
    testThemeUID: str | None = None

    @classmethod
    def from_dict(cls, dictionary: dict):
        return cls(
            name=dictionary["name"],
            filterType=FilterInfoType(dictionary["filterType"]),
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
    def from_dict(cls, dictionary: dict):
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
class TestCycleJsonReportOptions:
    treeRootUID: str | None
    basedOnExecution: bool | None
    suppressFilteredData: bool | None
    suppressNotExecutable: bool | None
    suppressEmptyTestThemes: bool | None
    filters: list[FilterJsonInfo] | None

    @classmethod
    def from_dict(cls, dictionary: dict):
        return cls(
            treeRootUID=dictionary.get("treeRootUID"),
            basedOnExecution=dictionary.get("basedOnExecution"),
            suppressFilteredData=dictionary.get("suppressFilteredData"),
            suppressNotExecutable=dictionary.get("suppressNotExecutable"),
            suppressEmptyTestThemes=dictionary.get("suppressEmptyTestThemes"),
            filters=[FilterJsonInfo.from_dict(f) for f in dictionary.get("filters", [])],
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
    def from_dict(cls, dictionary: dict):
        return cls(
            outputPath=dictionary["outputPath"],
            projectPath=dictionary.get("projectPath", []),
            tovKey=dictionary.get("tovKey"),
            cycleKey=dictionary.get("cycleKey"),
            reportRootUID=dictionary.get("reportRootUID"),
            report_config=(
                TestCycleXMLReportOptions.from_dict(dictionary.get("report_config") or {})
                if dictionary.get("report_config")
                else None
            ),
            filters=[FilterInfo.from_dict(f) for f in dictionary.get("filters", [])],
        )


@dataclass
class ExportJsonParameters:
    outputPath: str
    projectPath: list[str] | None = None
    projectKey: str | None = None
    tovKey: str | None = None
    cycleKey: str | None = None
    reportRootUID: str | None = None
    report_config: TestCycleJsonReportOptions | None = None
    filters: list[FilterJsonInfo] | None = None

    @classmethod
    def from_dict(cls, dictionary: dict):
        return cls(
            outputPath=dictionary["outputPath"],
            projectPath=dictionary.get("projectPath", []),
            projectKey=dictionary.get("projectKey"),
            tovKey=dictionary.get("tovKey"),
            cycleKey=dictionary.get("cycleKey"),
            reportRootUID=dictionary.get("reportRootUID"),
            report_config=(
                TestCycleJsonReportOptions.from_dict(dictionary.get("report_config") or {})
                if dictionary.get("report_config")
                else None
            ),
            filters=[FilterJsonInfo.from_dict(f) for f in dictionary.get("filters", [])],
        )


@dataclass
class BaseAction(ABC):
    @classmethod
    @abstractmethod
    def from_dict(cls, dictionary: dict):
        pass


@dataclass
class ExportAction(BaseAction):
    parameters: ExportParameters
    type: str = "ExportXMLReport"

    @classmethod
    def from_dict(cls, dictionary: dict):
        return cls(parameters=ExportParameters.from_dict(dictionary.get("parameters") or {}))


@dataclass
class ExportJsonAction(BaseAction):
    parameters: ExportJsonParameters
    type: str = "ExportJSONReport"

    @classmethod
    def from_dict(cls, dictionary: dict):
        return cls(parameters=ExportJsonParameters.from_dict(dictionary.get("parameters") or {}))


@dataclass
class ExecutionXmlResultsImportOptions:
    fileName: str
    reportRootUID: str | None
    ignoreNonExecutedTestCases: bool | None
    defaultTester: str | None
    checkPaths: bool | None
    filters: list[FilterInfo] | None
    discardTesterInformation: bool | None
    useExistingDefect: bool | None

    @classmethod
    def from_dict(cls, dictionary: dict) -> "ExecutionXmlResultsImportOptions":
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
class ExecutionJsonResultsImportOptions:
    fileName: str
    reportRootUID: str | None
    ignoreNonExecutedTestCases: bool | None
    defaultTester: str | None
    checkPaths: bool | None
    filters: list[FilterInfo] | None
    discardTesterInformation: bool | None
    useExistingDefect: bool | None

    @classmethod
    def from_dict(cls, dictionary: dict) -> "ExecutionJsonResultsImportOptions":
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
    importConfig: ExecutionXmlResultsImportOptions | None = None

    @classmethod
    def from_dict(cls, dictionary: dict):
        import_config_dict = dictionary.get("importConfig")
        importConfig = (
            ExecutionXmlResultsImportOptions.from_dict(import_config_dict)
            if import_config_dict is not None
            else None
        )

        return cls(
            inputPath=dictionary["inputPath"],
            reportRootUID=dictionary.get("reportRootUID"),
            defaultTester=dictionary.get("defaultTester"),
            filters=dictionary.get("filters", []),
            importConfig=importConfig,
        )


@dataclass
class ImportJsonParameters:
    inputPath: str
    projectKey: str | None = None
    cycleKey: str | None = None
    projectPath: list[str] | None = None
    reportRootUID: str | None = None
    defaultTester: str | None = None
    filters: list[FilterInfo] | None = None
    importConfig: ExecutionJsonResultsImportOptions | None = None

    @classmethod
    def from_dict(cls, dictionary: dict):
        import_config_dict = dictionary.get("importConfig")
        importConfig = (
            ExecutionJsonResultsImportOptions.from_dict(import_config_dict)
            if import_config_dict is not None
            else None
        )

        return cls(
            inputPath=dictionary["inputPath"],
            reportRootUID=dictionary.get("reportRootUID"),
            defaultTester=dictionary.get("defaultTester"),
            filters=dictionary.get("filters", []),
            importConfig=importConfig,
        )


@dataclass
class ImportXMLAction(BaseAction):
    parameters: ImportParameters
    type: str = "ImportXMLExecutionResults"

    @classmethod
    def from_dict(cls, dictionary: dict):
        return cls(parameters=ImportParameters.from_dict(dictionary.get("parameters") or {}))


@dataclass
class ImportJSONAction(BaseAction):
    parameters: ImportJsonParameters
    type: str = "ImportJSONExecutionResults"

    @classmethod
    def from_dict(cls, dictionary: dict):
        return cls(parameters=ImportJsonParameters.from_dict(dictionary.get("parameters") or {}))


@dataclass
class Configuration:
    server_url: str | None = None
    verify: bool = True
    sessionToken: str | None = None
    basicAuth: str | None = None
    loginname: str | None = None
    password: str | None = None
    actions: list[BaseAction] | None = None

    @classmethod
    def from_dict(cls, dictionary: dict):
        action_classes: dict[str, type[BaseAction]] = {
            "ImportXMLExecutionResults": ImportXMLAction,
            "ExportXMLReport": ExportAction,
            "ExportJSONReport": ExportJsonAction,
            "ImportJSONExecutionResults": ImportJSONAction,
        }

        return cls(
            server_url=dictionary["server_url"],
            verify=dictionary.get("verify", True),
            sessionToken=dictionary.get("sessionToken"),
            basicAuth=dictionary.get("basicAuth"),
            loginname=dictionary.get("loginname"),
            password=dictionary.get("password"),
            actions=[
                action_classes[action["type"]].from_dict(action) for action in dictionary["actions"]
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
    def from_dict(cls, dictionary: dict):
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
    def from_dict(cls, dictionary: dict):
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
    file: FileLoggerConfig = field(default_factory=lambda: FileLoggerConfig.from_dict({}))

    @classmethod
    def from_dict(cls, dictionary: dict):
        return cls(
            console=ConsoleLoggerConfig.from_dict(dictionary.get("console") or {}),
            file=FileLoggerConfig.from_dict(dictionary.get("file") or {}),
        )


@dataclass
class CliReporterConfig:
    configuration: list[Configuration] = field(default_factory=list)
    loggingConfiguration: loggingConfig = field(default_factory=loggingConfig)

    @classmethod
    def from_dict(cls, dictionary: dict):
        return cls(
            configuration=[Configuration.from_dict(c) for c in dictionary.get("configuration", [])],
            loggingConfiguration=loggingConfig.from_dict(
                dictionary.get("loggingConfiguration")
                or dictionary.get("logging_configuration")
                or {}
            ),
        )
