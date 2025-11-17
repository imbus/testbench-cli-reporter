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
            filterType=FilterInfoType(dictionary["filterType"]),
            testThemeUID=dictionary.get("testThemeUID"),
        )


@dataclass
class FilteringOptions:
    appliedFilters: list[FilterInfo] | None = None
    excludedTestThemes: list[str] | None = None
    labelFilter: str | None = None

    def __post_init__(self):
        if self.appliedFilters is None:
            self.appliedFilters = []
        if self.excludedTestThemes is None:
            self.excludedTestThemes = []

    def get_applied_filters(self) -> list[FilterInfo]:
        return list(self.appliedFilters or [])

    @classmethod
    def from_dict(cls, dictionary: dict | None):
        if not dictionary:
            return cls()

        applied_filters = [FilterInfo.from_dict(item) for item in dictionary.get("appliedFilters", [])]
        excluded = [value for value in dictionary.get("excludedTestThemes", []) if isinstance(value, str)]
        label_filter = dictionary.get("labelFilter")

        return cls(
            appliedFilters=applied_filters,
            excludedTestThemes=excluded,
            labelFilter=label_filter,
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
class Key:
    serial: str

    @classmethod
    def from_dict(cls, dictionary: dict):
        return cls(serial=dictionary.get("serial", "0"))


@dataclass
class ProjectCSVReportScope:
    tovKey: Key
    reportRootUID: str | None = None
    cycleKeys: list[Key] | None = None

    def __post_init__(self):
        if self.cycleKeys is None:
            self.cycleKeys = []

    @classmethod
    def from_dict(cls, dictionary: dict):
        return cls(
            tovKey=Key.from_dict(dictionary.get("tovKey", {})),
            reportRootUID=dictionary.get("reportRootUID"),
            cycleKeys=[Key.from_dict(c) for c in dictionary.get("cycleKeys", [])],
        )


class SpecificationCSVField(str, Enum):
    Name = "spec.name"
    Status = "spec.status"
    Locker = "spec.locker"
    DueDate = "spec.duedate"
    Priority = "spec.priority"
    Responsible = "spec.responsible"
    Reviewer = "spec.reviewer"
    Description = "spec.description"
    Calls = "spec.calls"
    Parameters = "spec.parameters"
    Keywords = "spec.keywords"
    References = "spec.references"
    Version = "spec.version"
    VersionDate = "spec.versiondate"
    VersionLabel = "spec.versionlabel"
    VersionOwner = "spec.versionowner"
    UDFs = "spec.userdefinedfields"
    Requirements = "spec.requirements"
    RequirementIDs = "spec.requirements.identifier"
    Attachments = "spec.attachments"
    ReviewComment = "spec.reviewcomment"
    Comment = "spec.comment"
    VersionComment = "spec.versioncomment"
    TestCases = "spec.pcs"
    DetailedInteraction = "spec.testsequence"
    InteractionType = "ts.type"
    InteractionPhase = "ts.phase"
    InteractionDescription = "ts.description"
    InteractionName = "ts.name"

    def __str__(self):
        return self.value


class AutomationCSVField(str, Enum):
    Status = "aut.status"
    Locker = "aut.locker"
    DueDate = "aut.duedate"
    Priority = "aut.priority"
    Responsible = "aut.responsible"
    Reviewer = "aut.reviewer"
    ScriptTemplate = "aut.scripttemplate"
    ScriptEditor = "aut.scripteditor"
    References = "aut.references"
    Version = "aut.version"
    VersionDate = "aut.versiondate"
    VersionLabel = "aut.versionlabel"
    VersionOwner = "aut.versionowner"
    Attachments = "aut.attachments"
    VersionComment = "aut.versioncomment"

    def __str__(self):
        return self.value


class ExecutionCSVField(str, Enum):
    Status = "exec.status"
    Verdict = "exec.verdict"
    ExecStatus = "exec.execstatus"
    Locker = "exec.locker"
    DueDate = "exec.duedate"
    Priority = "exec.priority"
    Responsible = "exec.responsible"
    References = "exec.references"
    PlannedTime = "exec.plannedtime"
    ActualTime = "exec.actualtime"
    ScriptPath = "exec.scriptpath"
    ProtocolPath = "exec.protocolpath"
    ExecutionEngine = "exec.engine"
    Defects = "exec.error-details"
    Version = "exec.version"
    VersionDate = "exec.versiondate"
    VersionLabel = "exec.versionlabel"
    VersionOwner = "exec.versionowner"
    Keywords = "exec.keywords"
    UDFs = "exec.userdefinedfields"
    Attachments = "exec.attachments"
    TestCases = "exec.pcs"
    VersionComment = "exec.versioncomment"
    Tester = "exec.tester"
    Comment = "exec.comment"
    DefectIDs = "exec.errors"
    VerdictTimestamp = "exec.verdicttimestamp"

    def __str__(self):
        return self.value


class Permission(str, Enum):
    AccessSecuredData = "AccessSecuredData"
    DeleteUserAccount = "DeleteUserAccount"
    DeleteUserSession = "DeleteUserSession"
    DownloadReportFile = "DownloadReportFile"
    ImportExecutionResults = "ImportExecutionResults"
    ModifyGlobalTestLabels = "ModifyGlobalTestLabels"
    ModifyProjectDetails = "ModifyProjectDetails"
    ModifyProjectUDFs = "ModifyProjectUDFs"
    ModifySpecifications = "ModifySpecifications"
    ModifySpecManagementInfo = "ModifySpecManagementInfo"
    ModifySpecPriorityAndDueDate = "ModifySpecPriorityAndDueDate"
    ModifyTestElements = "ModifyTestElements"
    ModifyTestLabels = "ModifyTestLabels"
    ModifyUserData = "ModifyUserData"
    ModifyUserRolesInProject = "ModifyUserRolesInProject"
    PrivatizeGlobalTestLabels = "PrivatizeGlobalTestLabels"
    ReadActiveUsersList = "ReadActiveUsersList"
    ReadCompleteProjectsList = "ReadCompleteProjectsList"
    ReadCompleteUsersList = "ReadCompleteUsersList"
    ReadCycleReport = "ReadCycleReport"
    ReadCycleReportOverRMI = "ReadCycleReportOverRMI"
    ReadCycleRequirements = "ReadCycleRequirements"
    ReadDefectsMetricDistribution = "ReadDefectsMetricDistribution"
    ReadExecutionImportingJobDetails = "ReadExecutionImportingJobDetails"
    ReadInvisibleProjectContent = "ReadInvisibleProjectContent"
    ReadOwnProjectsList = "ReadOwnProjectsList"
    ReadOwnUserDetails = "ReadOwnUserDetails"
    ReadProjectDefectsAndTheirAssignments = "ReadProjectDefectsAndTheirAssignments"
    ReadProjectDetails = "ReadProjectDetails"
    ReadProjectExportOverRMI = "ReadProjectExportOverRMI"
    ReadProjectHierarchy = "ReadProjectHierarchy"
    ReadProjectMembers = "ReadProjectMembers"
    ReadProjectUDFs = "ReadProjectUDFs"
    ReadReportingJobDetails = "ReadReportingJobDetails"
    ReadTestCaseDetails = "ReadTestCaseDetails"
    ReadTestCaseSetDetails = "ReadTestCaseSetDetails"
    ReadTestElements = "ReadTestElements"
    ReadTestLabels = "ReadTestLabels"
    ReadTestThemeDetails = "ReadTestThemeDetails"
    ReadTestThemeStatusDistribution = "ReadTestThemeStatusDistribution"
    ReadTestThemeTree = "ReadTestThemeTree"
    ReadTovReport = "ReadTovReport"
    ReadTovReportOverRMI = "ReadTovReportOverRMI"
    ReadTovRequirements = "ReadTovRequirements"
    ReadUserDetails = "ReadUserDetails"
    ReadUserMemberships = "ReadUserMemberships"
    ReadUserSessions = "ReadUserSessions"
    RestrictProjectUDFs = "RestrictProjectUDFs"
    SynchronizeUsers = "SynchronizeUsers"
    UnlockForeignSpecs = "UnlockForeignSpecs"
    UnlockForeignTestElements = "UnlockForeignTestElements"

    def __str__(self):
        return self.value


CSVField = SpecificationCSVField | AutomationCSVField | ExecutionCSVField


# execute, continue, view, simulate
class ExecutionMode(str, Enum):
    EXECUTE = "execute"
    CONTINUE = "continue"
    VIEW = "view"
    SIMULATE = "simulate"

    def __str__(self):
        return self.value


def parse_csv_field(raw: str) -> CSVField | None:
    if raw.startswith(("spec.", "ts.")):
        return SpecificationCSVField(raw)
    if raw.startswith("aut."):
        return AutomationCSVField(raw)
    if raw.startswith("exec."):
        return ExecutionCSVField(raw)
    return None


def parse_csv_fields(values: list[str] | None) -> list[CSVField]:
    parsed_fields: list[CSVField] = []
    for value in values or []:
        if isinstance(value, str):
            parsed_field = parse_csv_field(value)
            if parsed_field is not None:
                parsed_fields.append(parsed_field)
    return parsed_fields


@dataclass
class ProjectCSVReportOptions:
    scopes: list[ProjectCSVReportScope]
    showUserFullName: bool | None = None
    fields: list[CSVField] | None = None
    characterEncoding: str | None = None

    def __post_init__(self):
        if self.fields is None:
            self.fields = []

    @classmethod
    def from_dict(cls, dictionary: dict):
        parsed_fields = parse_csv_fields(dictionary.get("fields"))

        return cls(
            scopes=[ProjectCSVReportScope.from_dict(s) for s in dictionary.get("scopes", [])],
            showUserFullName=dictionary.get("showUserFullName"),
            fields=parsed_fields,
            characterEncoding=dictionary.get("characterEncoding"),
        )


@dataclass
class TestCycleJsonReportOptions:
    treeRootUID: str | None
    basedOnExecution: bool | None
    suppressFilteredData: bool | None
    suppressNotExecutable: bool | None
    suppressEmptyTestThemes: bool | None
    executionMode: ExecutionMode | None
    filters: list[FilterInfo] | None

    @classmethod
    def from_dict(cls, dictionary: dict):
        return cls(
            treeRootUID=dictionary.get("treeRootUID"),
            basedOnExecution=dictionary.get("basedOnExecution"),
            suppressFilteredData=dictionary.get("suppressFilteredData"),
            suppressNotExecutable=dictionary.get("suppressNotExecutable"),
            suppressEmptyTestThemes=dictionary.get("suppressEmptyTestThemes"),
            executionMode=ExecutionMode(dictionary.get("executionMode", ExecutionMode.EXECUTE))
            if dictionary.get("executionMode")
            else None,
            filters=[FilterInfo.from_dict(f) for f in dictionary.get("filters", [])],
        )


@dataclass
class ExportCsvParameters:
    outputPath: str
    projectKey: str
    report_config: ProjectCSVReportOptions | None = None

    @classmethod
    def from_dict(cls, dictionary: dict):
        return cls(
            outputPath=dictionary.get("outputPath", "csv_report.zip"),
            projectKey=dictionary.get("projectKey", ""),
            report_config=(
                ProjectCSVReportOptions.from_dict(dictionary.get("report_config") or {})
                if dictionary.get("report_config")
                else None
            ),
        )


@dataclass
class ExportXmlParameters:
    outputPath: str
    projectPath: list[str] | None = None
    tovKey: str | None = None
    cycleKey: str | None = None
    report_config: TestCycleXMLReportOptions | None = None

    @classmethod
    def from_dict(cls, dictionary: dict):
        return cls(
            outputPath=dictionary["outputPath"],
            projectPath=dictionary.get("projectPath", []),
            tovKey=dictionary.get("tovKey"),
            cycleKey=dictionary.get("cycleKey"),
            report_config=(
                TestCycleXMLReportOptions.from_dict(dictionary.get("report_config") or {})
                if dictionary.get("report_config")
                else None
            ),
        )


@dataclass
class ExportJsonParameters:
    outputPath: str
    projectPath: list[str] | None = None
    projectKey: str | None = None
    tovKey: str | None = None
    cycleKey: str | None = None
    report_config: TestCycleJsonReportOptions | None = None

    @classmethod
    def from_dict(cls, dictionary: dict):
        return cls(
            outputPath=dictionary["outputPath"],
            projectPath=dictionary.get("projectPath", []),
            projectKey=dictionary.get("projectKey"),
            tovKey=dictionary.get("tovKey"),
            cycleKey=dictionary.get("cycleKey"),
            report_config=(
                TestCycleJsonReportOptions.from_dict(dictionary.get("report_config") or {})
                if dictionary.get("report_config")
                else None
            ),
        )


@dataclass
class ExportServerLogsParameters:
    outputPath: str

    @classmethod
    def from_dict(cls, dictionary: dict):
        return cls(
            outputPath=dictionary.get("outputPath", "server_logs.zip"),
        )


@dataclass
class BaseAction(ABC):
    @classmethod
    @abstractmethod
    def from_dict(cls, dictionary: dict) -> "BaseAction":
        pass


@dataclass
class ExportXmlAction(BaseAction):
    parameters: ExportXmlParameters
    type: str = "ExportXMLReport"

    @classmethod
    def from_dict(cls, dictionary: dict):
        return cls(parameters=ExportXmlParameters.from_dict(dictionary.get("parameters") or {}))


@dataclass
class ExportJsonAction(BaseAction):
    parameters: ExportJsonParameters
    type: str = "ExportJSONReport"

    @classmethod
    def from_dict(cls, dictionary: dict):
        return cls(parameters=ExportJsonParameters.from_dict(dictionary.get("parameters") or {}))


@dataclass
class ExportCsvAction(BaseAction):
    parameters: ExportCsvParameters
    type: str = "ExportCSVReport"

    @classmethod
    def from_dict(cls, dictionary: dict):
        return cls(parameters=ExportCsvParameters.from_dict(dictionary.get("parameters") or {}))


@dataclass
class ExportServerLogsAction(BaseAction):
    parameters: ExportServerLogsParameters
    type: str = "ExportServerLogs"

    @classmethod
    def from_dict(cls, dictionary: dict):
        return cls(parameters=ExportServerLogsParameters.from_dict(dictionary.get("parameters") or {}))


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
    treeRootUID: str | None
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
            treeRootUID=dictionary.get("treeRootUID"),
            ignoreNonExecutedTestCases=dictionary.get("ignoreNonExecutedTestCases"),
            defaultTester=dictionary.get("defaultTester"),
            checkPaths=dictionary.get("checkPaths"),
            filters=[FilterInfo.from_dict(f) for f in dictionary.get("filters", [])],
            discardTesterInformation=dictionary.get("discardTesterInformation"),
            useExistingDefect=dictionary.get("useExistingDefect"),
        )


@dataclass
class ImportXmlParameters:
    inputPath: str
    cycleKey: str | None = None
    projectPath: list[str] | None = None
    importConfig: ExecutionXmlResultsImportOptions | None = None

    @classmethod
    def from_dict(cls, dictionary: dict):
        import_config_dict = dictionary.get("importConfig")
        import_config = (
            ExecutionXmlResultsImportOptions.from_dict(import_config_dict)
            if import_config_dict is not None
            else None
        )

        return cls(
            inputPath=dictionary["inputPath"],
            importConfig=import_config,
        )


@dataclass
class ImportJsonParameters:
    inputPath: str
    projectKey: str | None = None
    cycleKey: str | None = None
    projectPath: list[str] | None = None
    importConfig: ExecutionJsonResultsImportOptions | None = None

    @classmethod
    def from_dict(cls, dictionary: dict):
        import_config_dict = dictionary.get("importConfig")
        import_config = (
            ExecutionJsonResultsImportOptions.from_dict(import_config_dict)
            if import_config_dict is not None
            else None
        )

        return cls(
            inputPath=dictionary["inputPath"],
            importConfig=import_config,
        )


@dataclass
class ImportXMLAction(BaseAction):
    parameters: ImportXmlParameters
    type: str = "ImportXMLExecutionResults"

    @classmethod
    def from_dict(cls, dictionary: dict):
        return cls(parameters=ImportXmlParameters.from_dict(dictionary.get("parameters") or {}))


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
    thread_limit: int | None = None

    def __post_init__(self):
        if self.actions is None:
            self.actions = []

    @classmethod
    def from_dict(cls, dictionary: dict):
        action_classes: dict[str, BaseAction] = ACTION_TYPES

        return cls(
            server_url=dictionary["server_url"],
            verify=dictionary.get("verify", True),
            sessionToken=dictionary.get("sessionToken"),
            basicAuth=dictionary.get("basicAuth"),
            loginname=dictionary.get("loginname"),
            password=dictionary.get("password"),
            actions=[action_classes[action["type"]].from_dict(action) for action in dictionary["actions"]],
            thread_limit=dictionary.get("thread_limit"),
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
                dictionary.get("loggingConfiguration") or dictionary.get("logging_configuration") or {}
            ),
        )


@dataclass
class JWTDataOptions:
    projectKey: str | None = None
    tovKey: str | None = None
    cycleKey: str | None = None
    permissions: list[Permission] = field(default_factory=list)  # Enum!
    subject: str | None = None
    expiresAfterSeconds: int | None = None

    @classmethod
    def from_dict(cls, dictionary: dict):
        raw_perms = dictionary.get("permissions") or []
        perms = [Permission(p) if not isinstance(p, Permission) else p for p in raw_perms]
        return cls(
            projectKey=dictionary.get("projectKey"),
            tovKey=dictionary.get("tovKey"),
            cycleKey=dictionary.get("cycleKey"),
            permissions=perms,
            subject=dictionary.get("subject"),
            expiresAfterSeconds=dictionary.get("expiresAfterSeconds"),
        )


@dataclass
class RequestJWTAction(BaseAction):
    parameters: JWTDataOptions
    type: str = "RequestJWT"

    @classmethod
    def from_dict(cls, dictionary: dict):
        return cls(parameters=JWTDataOptions.from_dict(dictionary.get("parameters") or {}))


ACTION_TYPES: dict[str, BaseAction] = {
    "ExportXMLReport": ExportXmlAction,  # type: ignore
    "ExportJSONReport": ExportJsonAction,  # type: ignore
    "ExportCSVReport": ExportCsvAction,  # type: ignore
    "ImportXMLExecutionResults": ImportXMLAction,  # type: ignore
    "ImportJSONExecutionResults": ImportJSONAction,  # type: ignore
    "ExportServerLogs": ExportServerLogsAction,  # type: ignore
    "RequestJWT": RequestJWTAction,  # type: ignore
}
