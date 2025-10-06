using System;

namespace ProcessParentDumper.Win32Enums
{
    [Flags]
    internal enum ACCESS_MASK : uint
    {
        // For Process
        PROCESS_ALL_ACCESS = 0x001F0FFF,
        PROCESS_TERMINATE = 0x00000001,
        PROCESS_CREATE_THREAD = 0x00000002,
        PROCESS_VM_OPERATION = 0x00000008,
        PROCESS_VM_READ = 0x00000010,
        PROCESS_VM_WRITE = 0x00000020,
        PROCESS_DUP_HANDLE = 0x00000040,
        PROCESS_CREATE_PROCESS = 0x000000080,
        PROCESS_SET_QUOTA = 0x00000100,
        PROCESS_SET_INFORMATION = 0x00000200,
        PROCESS_QUERY_INFORMATION = 0x00000400,
        PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000,
        // For Thread
        THREAD_ALL_ACCESS = 0x001FFFFF,
        THREAD_TERMINATE = 0x00000001,
        THREAD_SUSPEND_RESUME = 0x00000002,
        THREAD_ALERT = 0x00000004,
        THREAD_GET_CONTEXT = 0x00000008,
        THREAD_SET_CONTEXT = 0x00000010,
        THREAD_SET_INFORMATION = 0x00000020,
        THREAD_SET_LIMITED_INFORMATION = 0x00000400,
        THREAD_QUERY_LIMITED_INFORMATION = 0x00000800,
        // For Files
        FILE_ANY_ACCESS = 0x00000000,
        FILE_READ_ACCESS = 0x00000001,
        FILE_WRITE_ACCESS = 0x00000002,
        FILE_READ_DATA = 0x00000001,
        FILE_LIST_DIRECTORY = 0x00000001,
        FILE_WRITE_DATA = 0x00000002,
        FILE_ADD_FILE = 0x00000002,
        FILE_APPEND_DATA = 0x00000004,
        FILE_ADD_SUBDIRECTORY = 0x00000004,
        FILE_CREATE_PIPE_INSTANCE = 0x00000004,
        FILE_READ_EA = 0x00000008,
        FILE_WRITE_EA = 0x00000010,
        FILE_EXECUTE = 0x00000020,
        FILE_TRAVERSE = 0x00000020,
        FILE_DELETE_CHILD = 0x00000040,
        FILE_READ_ATTRIBUTES = 0x00000080,
        FILE_WRITE_ATTRIBUTES = 0x00000100,
        FILE_ALL_ACCESS = 0x001F01FF,
        FILE_GENERIC_READ = 0x00100089,
        FILE_GENERIC_WRITE = 0x00100116,
        FILE_GENERIC_EXECUTE = 0x001000A0,
        // Others
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_READ = 0x00020000,
        STANDARD_RIGHTS_WRITE = 0x00020000,
        STANDARD_RIGHTS_EXECUTE = 0x00020000,
        STANDARD_RIGHTS_ALL = 0x001F0000,
        SPECIFIC_RIGHTS_ALL = 0x0000FFFF,
        ACCESS_SYSTEM_SECURITY = 0x01000000,
        MAXIMUM_ALLOWED = 0x02000000,
        GENERIC_ALL = 0x10000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_READ = 0x80000000,
        DESKTOP_READOBJECTS = 0x00000001,
        DESKTOP_CREATEWINDOW = 0x00000002,
        DESKTOP_CREATEMENU = 0x00000004,
        DESKTOP_HOOKCONTROL = 0x00000008,
        DESKTOP_JOURNALRECORD = 0x00000010,
        DESKTOP_JOURNALPLAYBACK = 0x00000020,
        DESKTOP_ENUMERATE = 0x00000040,
        DESKTOP_WRITEOBJECTS = 0x00000080,
        DESKTOP_SWITCHDESKTOP = 0x00000100,
        WINSTA_ENUMDESKTOPS = 0x00000001,
        WINSTA_READATTRIBUTES = 0x00000002,
        WINSTA_ACCESSCLIPBOARD = 0x00000004,
        WINSTA_CREATEDESKTOP = 0x00000008,
        WINSTA_WRITEATTRIBUTES = 0x00000010,
        WINSTA_ACCESSGLOBALATOMS = 0x00000020,
        WINSTA_EXITWINDOWS = 0x00000040,
        WINSTA_ENUMERATE = 0x00000100,
        WINSTA_READSCREEN = 0x00000200,
        WINSTA_ALL_ACCESS = 0x0000037F,
        // For section
        SECTION_QUERY = 0x00000001,
        SECTION_MAP_WRITE = 0x00000002,
        SECTION_MAP_READ = 0x00000004,
        SECTION_MAP_EXECUTE = 0x00000008,
        SECTION_EXTEND_SIZE = 0x00000010,
        SECTION_MAP_EXECUTE_EXPLICIT = 0x00000020,
        SECTION_ALL_ACCESS = 0x000F001F
    }

    [Flags]
    internal enum ALLOCATION_TYPE
    {
        COMMIT = 0x1000,
        RESERVE = 0x2000,
        DECOMMIT = 0x4000,
        RELEASE = 0x8000,
        RESET = 0x80000,
        PHYSICAL = 0x400000,
        TOPDOWN = 0x100000,
        WRITEWATCH = 0x200000,
        LARGEPAGES = 0x20000000
    }

    internal enum BOOLEAN : byte
    {
        FALSE,
        TRUE
    }

    [Flags]
    internal enum FILE_DISPOSITION_FLAGS : uint
    {
        DO_NOT_DELETE = 0x00000000,
        DELETE = 0x00000001,
        POSIX_SEMANTICS = 0x00000002,
        FORCE_IMAGE_SECTION_CHECK = 0x00000004,
        ON_CLOSE = 0x00000008,
        IGNORE_READONLY_ATTRIBUTE = 0x00000010
    }

    internal enum FILE_INFORMATION_CLASS
    {
        FileDirectoryInformation = 1,
        FileFullDirectoryInformation,
        FileBothDirectoryInformation,
        FileBasicInformation,
        FileStandardInformation,
        FileInternalInformation,
        FileEaInformation,
        FileAccessInformation,
        FileNameInformation,
        FileRenameInformation,
        FileLinkInformation,
        FileNamesInformation,
        FileDispositionInformation,
        FilePositionInformation,
        FileFullEaInformation,
        FileModeInformation,
        FileAlignmentInformation,
        FileAllInformation,
        FileAllocationInformation,
        FileEndOfFileInformation,
        FileAlternateNameInformation,
        FileStreamInformation,
        FilePipeInformation,
        FilePipeLocalInformation,
        FilePipeRemoteInformation,
        FileMailslotQueryInformation,
        FileMailslotSetInformation,
        FileCompressionInformation,
        FileObjectIdInformation,
        FileCompletionInformation,
        FileMoveClusterInformation,
        FileQuotaInformation,
        FileReparsePointInformation,
        FileNetworkOpenInformation,
        FileAttributeTagInformation,
        FileTrackingInformation,
        FileIdBothDirectoryInformation,
        FileIdFullDirectoryInformation,
        FileValidDataLengthInformation,
        FileShortNameInformation,
        FileIoCompletionNotificationInformation,
        FileIoStatusBlockRangeInformation,
        FileIoPriorityHintInformation,
        FileSfioReserveInformation,
        FileSfioVolumeInformation,
        FileHardLinkInformation,
        FileProcessIdsUsingFileInformation,
        FileNormalizedNameInformation,
        FileNetworkPhysicalNameInformation,
        FileIdGlobalTxDirectoryInformation,
        FileMaximumInformation,
        FileIdInformation = 59,
        FileHardLinkFullIdInformation = 62,
        FileDispositionInformationEx = 64,
        FileRenameInformationEx = 65,
        FileStatInformation = 68,
        FileStatLxInformation = 70,
        FileCaseSensitiveInformation = 71,
        FileLinkInformationEx = 72,
        FileStorageReserveIdInformation = 74,
    }

    [Flags]
    internal enum FILE_OPEN_OPTIONS : uint
    {
        DIRECTORY_FILE = 0x00000001,
        WRITE_THROUGH = 0x00000002,
        SEQUENTIAL_ONLY = 0x00000004,
        NO_INTERMEDIATE_BUFFERING = 0x00000008,
        SYNCHRONOUS_IO_ALERT = 0x00000010,
        SYNCHRONOUS_IO_NONALERT = 0x00000020,
        NON_DIRECTORY_FILE = 0x00000040,
        CREATE_TREE_CONNECTION = 0x00000080,
        COMPLETE_IF_OPLOCKED = 0x00000100,
        NO_EA_KNOWLEDGE = 0x00000200,
        OPEN_REMOTE_INSTANCE = 0x00000400,
        RANDOM_ACCESS = 0x00000800,
        DELETE_ON_CLOSE = 0x00001000,
        OPEN_BY_FILE_ID = 0x00002000,
        OPEN_FOR_BACKUP_INTENT = 0x00004000,
        NO_COMPRESSION = 0x00008000,
        RESERVE_OPFILTER = 0x00100000,
        OPEN_REPARSE_POINT = 0x00200000,
        OPEN_NO_RECALL = 0x00400000,
        OPEN_FOR_FREE_SPACE_QUERY = 0x00800000,
        COPY_STRUCTURED_STORAGE = 0x00000041,
        STRUCTURED_STORAGE = 0x00000441,
        SUPERSEDE = 0x00000000,
        OPEN = 0x00000001,
        CREATE = 0x00000002,
        OPEN_IF = 0x00000003,
        OVERWRITE = 0x00000004,
        OVERWRITE_IF = 0x00000005,
        MAXIMUM_DISPOSITION = 0x00000005
    }

    [Flags]
    internal enum FILE_SHARE_ACCESS : uint
    {
        NONE = 0x00000000,
        READ = 0x00000001,
        WRITE = 0x00000002,
        DELETE = 0x00000004,
        VALID_FLAGS = 0x00000007
    }

    [Flags]
    internal enum FormatMessageFlags : uint
    {
        FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100,
        FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200,
        FORMAT_MESSAGE_FROM_STRING = 0x00000400,
        FORMAT_MESSAGE_FROM_HMODULE = 0x00000800,
        FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000,
        FORMAT_MESSAGE_ARGUMENT_ARRAY = 0x00002000
    }

    [Flags]
    internal enum MEMORY_PROTECTION : uint
    {
        NOACCESS = 0x01,
        READONLY = 0x02,
        READWRITE = 0x04,
        WRITECOPY = 0x08,
        EXECUTE = 0x10,
        EXECUTE_READ = 0x20,
        EXECUTE_READWRITE = 0x40,
        EXECUTE_WRITECOPY = 0x80,
        GUARD = 0x100,
        NOCACHE = 0x200,
        WRITECOMBINE = 0x400
    }

    [Flags]
    internal enum NT_PROCESS_CREATION_FLAGS : uint
    {
        NONE = 0,
        BREAKAWAY = 0x00000001,
        NO_DEBUG_INHERIT = 0x00000002,
        INHERIT_HANDLES = 0x00000004,
        OVERRIDE_ADDRESS_SPACE = 0x00000008,
        LARGE_PAGES = 0x00000010,
        LARGE_PAGE_SYSTEM_DLL = 0x00000020,
        PROTECTED_PROCESS = 0x00000040,
        CREATE_SESSION = 0x00000080,
        INHERIT_FROM_PARENT = 0x00000100,
        SUSPENDED = 0x00000200,
        EXTENDED_UNKNOWN = 0x00000400
    }

    [Flags]
    internal enum OBJECT_ATTRIBUTES_FLAGS : uint
    {
        None = 0x00000000,
        ProtectClose = 0x00000001,
        Inherit = 0x00000002,
        AuditObjectClose = 0x00000004,
        NoEightsUpgrade = 0x00000008,
        Permanent = 0x00000010,
        Exclusive = 0x00000020,
        CaseInsensitive = 0x00000040,
        OpenIf = 0x00000080,
        OpenLink = 0x00000100,
        KernelHandle = 0x00000200,
        ForceAccessCheck = 0x00000400,
        IgnoreImpersonatedDevicemap = 0x00000800,
        DontReparse = 0x00001000,
        ValieAttributes = 0x00001FF2
    }

    internal enum PROCESSINFOCLASS
    {
        ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
        ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
        ProcessIoCounters, // q: IO_COUNTERS
        ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
        ProcessTimes, // q: KERNEL_USER_TIMES
        ProcessBasePriority, // s: KPRIORITY
        ProcessRaisePriority, // s: ULONG
        ProcessDebugPort, // q: HANDLE
        ProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT (requires SeTcbPrivilege)
        ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
        ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
        ProcessLdtSize, // s: PROCESS_LDT_SIZE
        ProcessDefaultHardErrorMode, // qs: ULONG
        ProcessIoPortHandlers, // (kernel-mode only) // PROCESS_IO_PORT_HANDLER_INFORMATION
        ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
        ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
        ProcessUserModeIOPL, // qs: ULONG (requires SeTcbPrivilege)
        ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
        ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
        ProcessWx86Information, // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
        ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
        ProcessAffinityMask, // (q >WIN7)s: KAFFINITY, qs: GROUP_AFFINITY
        ProcessPriorityBoost, // qs: ULONG
        ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
        ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
        ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
        ProcessWow64Information, // q: ULONG_PTR
        ProcessImageFileName, // q: UNICODE_STRING
        ProcessLUIDDeviceMapsEnabled, // q: ULONG
        ProcessBreakOnTermination, // qs: ULONG
        ProcessDebugObjectHandle, // q: HANDLE // 30
        ProcessDebugFlags, // qs: ULONG
        ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
        ProcessIoPriority, // qs: IO_PRIORITY_HINT
        ProcessExecuteFlags, // qs: ULONG
        ProcessTlsInformation, // PROCESS_TLS_INFORMATION // ProcessResourceManagement
        ProcessCookie, // q: ULONG
        ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
        ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
        ProcessPagePriority, // qs: PAGE_PRIORITY_INFORMATION
        ProcessInstrumentationCallback, // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
        ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
        ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
        ProcessImageFileNameWin32, // q: UNICODE_STRING
        ProcessImageFileMapping, // q: HANDLE (input)
        ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
        ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
        ProcessGroupInformation, // q: USHORT[]
        ProcessTokenVirtualizationEnabled, // s: ULONG
        ProcessConsoleHostProcess, // qs: ULONG_PTR // ProcessOwnerInformation
        ProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
        ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
        ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
        ProcessDynamicFunctionTableInformation,
        ProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
        ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
        ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
        ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
        ProcessHandleTable, // q: ULONG[] // since WINBLUE
        ProcessCheckStackExtentsMode, // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
        ProcessCommandLineInformation, // q: UNICODE_STRING // 60
        ProcessProtectionInformation, // q: PS_PROTECTION
        ProcessMemoryExhaustion, // PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
        ProcessFaultInformation, // PROCESS_FAULT_INFORMATION
        ProcessTelemetryIdInformation, // q: PROCESS_TELEMETRY_ID_INFORMATION
        ProcessCommitReleaseInformation, // PROCESS_COMMIT_RELEASE_INFORMATION
        ProcessDefaultCpuSetsInformation, // SYSTEM_CPU_SET_INFORMATION[5]
        ProcessAllowedCpuSetsInformation, // SYSTEM_CPU_SET_INFORMATION[5]
        ProcessSubsystemProcess,
        ProcessJobMemoryInformation, // q: PROCESS_JOB_MEMORY_INFO
        ProcessInPrivate, // s: void // ETW // since THRESHOLD2 // 70
        ProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
        ProcessIumChallengeResponse,
        ProcessChildProcessInformation, // q: PROCESS_CHILD_PROCESS_INFORMATION
        ProcessHighGraphicsPriorityInformation, // qs: BOOLEAN (requires SeTcbPrivilege)
        ProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
        ProcessEnergyValues, // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
        ProcessPowerThrottlingState, // qs: POWER_THROTTLING_PROCESS_STATE
        ProcessReserved3Information, // ProcessActivityThrottlePolicy // PROCESS_ACTIVITY_THROTTLE_POLICY
        ProcessWin32kSyscallFilterInformation, // q: WIN32K_SYSCALL_FILTER
        ProcessDisableSystemAllowedCpuSets, // 80
        ProcessWakeInformation, // PROCESS_WAKE_INFORMATION
        ProcessEnergyTrackingState, // PROCESS_ENERGY_TRACKING_STATE
        ProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
        ProcessCaptureTrustletLiveDump,
        ProcessTelemetryCoverage,
        ProcessEnclaveInformation,
        ProcessEnableReadWriteVmLogging, // PROCESS_READWRITEVM_LOGGING_INFORMATION
        ProcessUptimeInformation, // q: PROCESS_UPTIME_INFORMATION
        ProcessImageSection, // q: HANDLE
        ProcessDebugAuthInformation, // since REDSTONE4 // 90
        ProcessSystemResourceManagement, // PROCESS_SYSTEM_RESOURCE_MANAGEMENT
        ProcessSequenceNumber, // q: ULONGLONG
        ProcessLoaderDetour, // since REDSTONE5
        ProcessSecurityDomainInformation, // PROCESS_SECURITY_DOMAIN_INFORMATION
        ProcessCombineSecurityDomainsInformation, // PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
        ProcessEnableLogging, // PROCESS_LOGGING_INFORMATION
        ProcessLeapSecondInformation, // PROCESS_LEAP_SECOND_INFORMATION
        ProcessFiberShadowStackAllocation, // PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
        ProcessFreeFiberShadowStackAllocation, // PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
        ProcessAltSystemCallInformation, // qs: BOOLEAN (kernel-mode only) // INT2E // since 20H1 // 100
        ProcessDynamicEHContinuationTargets, // PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
        ProcessDynamicEnforcedCetCompatibleRanges, // PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
        ProcessCreateStateChange, // since WIN11
        ProcessApplyStateChange,
        ProcessEnableOptionalXStateFeatures,
        ProcessAltPrefetchParam, // since 22H1
        ProcessAssignCpuPartitions,
        ProcessPriorityClassEx, // s: PROCESS_PRIORITY_CLASS_EX
        ProcessMembershipInformation,
        ProcessEffectiveIoPriority, // q: IO_PRIORITY_HINT
        ProcessEffectivePagePriority, // q: ULONG
        MaxProcessInfoClass
    }

    [Flags]
    internal enum RTL_USER_PROC_FLAGS : uint
    {
        PARAMS_NORMALIZED = 0x00000001,
        PROFILE_USER = 0x00000002,
        PROFILE_KERNEL = 0x00000004,
        PROFILE_SERVER = 0x00000008,
        RESERVE_1MB = 0x00000020,
        RESERVE_16MB = 0x00000040,
        CASE_SENSITIVE = 0x00000080,
        DISABLE_HEAP_DECOMMIT = 0x00000100,
        DLL_REDIRECTION_LOCAL = 0x00001000,
        APP_MANIFEST_PRESENT = 0x00002000,
        IMAGE_KEY_MISSING = 0x00004000,
        OPTIN_PROCESS = 0x00020000
    }

    [Flags]
    internal enum SECTION_ATTRIBUTES : uint
    {
        SEC_IMAGE = 0x01000000,
        SEC_RESERVE = 0x04000000,
        SEC_COMMIT = 0x08000000,
        SEC_IMAGE_NO_EXECUTE = 0x11000000,
        SEC_NOCACHE = 0x10000000,
        SEC_WRITECOMBINE = 0x40000000,
        SEC_LARGE_PAGES = 0x80000000
    }

    [Flags]
    internal enum SECTION_PROTECTIONS : uint
    {
        PAGE_READONLY = 0x02,
        PAGE_READWRITE = 0x04,
        PAGE_WRITECOPY = 0x08,
        PAGE_EXECUTE = 0x10
    }

    /*
     * Reference :
     * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f4296d69-1c0f-491f-9587-a960b292d070
     */
    [Flags]
    internal enum ACCESS_MASK_ACE : uint
    {
        NO_ACCESS = 0x00000000,
        CREATE_CHILD = 0x00000001,
        CREATE_DELETE = 0x00000002,
        LIST_CHILDREN = 0x00000004,
        SELF_WRITE = 0x00000008,
        READ_PROPERTY = 0x00000010,
        WRITE_PROPERTY = 0x00000020,
        DELETE_TREE = 0x00000040,
        LIST_OBJECT = 0x00000080,
        CONTROL_ACCESS = 0x00000100,
        KEY_WRITE = 0x00020006,
        KEY_EXECUTE_READ = 0x00020019,
        KEY_ALL_ACCESS = 0x000F003F,
        FILE_STANDARD_READ = 0x00120089,
        FILE_STANDARD_WRITE = 0x00120116,
        FILE_STANDARD_EXECUTE = 0x001200A0,
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        FILE_ALL_ACCESS = 0x001F01FF,
        GENERIC_ALL = 0x10000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_READ = 0x80000000
    }

    [Flags]
    internal enum ACCESS_MASK_DIRECTORY : uint
    {
        NO_ACCESS = 0x00000000,
        DIRECTORY_QUERY = 0x00000001,
        DIRECTORY_TRAVERSE = 0x00000002,
        DIRECTORY_CREATE_OBJECT = 0x00000004,
        DIRECTORY_CREATE_SUBDIRECTORY = 0x00000008,
        DIRECTORY_ALL_ACCESS = 0x000F000F,
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_EXECUTE_READWRITE = 0x00020000,
        STANDARD_RIGHTS_ALL = 0x001F0000,
        GENERIC_ALL = 0x10000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_READ = 0x80000000
    }

    [Flags]
    internal enum ACCESS_MASK_EVENT : uint
    {
        NO_ACCESS = 0x00000000,
        EVENT_QUERY_STATE = 0x00000001,
        EVENT_MODIFY_STATE = 0x00000002,
        EVENT_ALL_ACCESS = 0x001F0003,
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_EXECUTE_READWRITE = 0x00020000,
        STANDARD_RIGHTS_ALL = 0x001F0000,
        GENERIC_ALL = 0x10000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_READ = 0x80000000
    }

    [Flags]
    internal enum ACCESS_MASK_FILE : uint
    {
        NO_ACCESS = 0x00000000,
        FILE_READ_DATA = 0x00000001,
        FILE_WRITE_DATA = 0x00000002,
        FILE_APPEND_DATA = 0x00000004,
        FILE_READ_EA = 0x00000008,
        FILE_WRITE_EA = 0x00000010,
        FILE_EXECUTE = 0x00000020,
        FILE_READ_ATTRIBUTES = 0x00000080,
        FILE_WRITE_ATTRIBUTES = 0x00000100,
        FILE_STANDARD_READ = 0x00120089,
        FILE_STANDARD_WRITE = 0x00120116,
        FILE_STANDARD_EXECUTE = 0x001200A0,
        FILE_ALL_ACCESS = 0x001F01FF,
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        GENERIC_ALL = 0x10000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_READ = 0x80000000
    }

    [Flags]
    internal enum ACCESS_MASK_IO_COMPLETION : uint
    {
        NO_ACCESS = 0x00000000,
        IO_COMPLETION_QUERY_STATE = 0x00000001,
        IO_COMPLETION_MODIFY_STATE = 0x00000002,
        IO_COMPLETION_ALL_ACCESS = 0x001F0003,
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_EXECUTE_READWRITE = 0x00020000,
        STANDARD_RIGHTS_ALL = 0x001F0000,
        GENERIC_ALL = 0x10000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_READ = 0x80000000
    }

    [Flags]
    internal enum ACCESS_MASK_JOB : uint
    {
        NO_ACCESS = 0x00000000,
        JOB_ACCESS_ADMINISTER = 0x00000010,
        JOB_ACCESS_READ = 0x00000020,
        JOB_EXECUTE_WRITE = 0x00020010,
        JOB_READ = 0x00020020,
        JOB_ALL_ACCESS = 0x000F0030,
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_EXECUTE_READWRITE = 0x00020000,
        STANDARD_RIGHTS_ALL = 0x001F0000,
        GENERIC_ALL = 0x10000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_READ = 0x80000000
    }

    [Flags]
    internal enum ACCESS_MASK_KEY : uint
    {
        NO_ACCESS = 0x00000000,
        KEY_QUERY_VALUE = 0x00000001,
        KEY_SET_VALUE = 0x00000002,
        KEY_CREATE_SUB_KEY = 0x00000004,
        KEY_ENUMERATE_SUB_KEYS = 0x00000008,
        KEY_NOTIFY = 0x00000010,
        KEY_CREATE_LINK = 0x00000020,
        KEY_WRITE = 0x00020006,
        KEY_EXECUTE_READ = 0x00020019,
        KEY_ALL_ACCESS = 0x000F003F,
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_EXECUTE_READWRITE = 0x00020000,
        STANDARD_RIGHTS_ALL = 0x001F0000,
        GENERIC_ALL = 0x10000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_READ = 0x80000000
    }

    [Flags]
    internal enum ACCESS_MASK_MUTANT : uint
    {
        NO_ACCESS = 0x00000000,
        MUTANT_QUERY_STATE = 0x00000001,
        MUTANT_ALL_ACCESS = 0x001F0001,
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_EXECUTE_READWRITE = 0x00020000,
        STANDARD_RIGHTS_ALL = 0x001F0000,
        GENERIC_ALL = 0x10000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_READ = 0x80000000
    }

    [Flags]
    internal enum ACCESS_MASK_PARTITION : uint
    {
        NO_ACCESS = 0x00000000,
        MEMORY_PARTITION_QUERY_ACCESS = 0x00000001,
        MEMORY_PARTITION_MODIFY_ACCESS = 0x00000002,
        MEMORY_PARTITION_ALL_ACCESS = 0x001F0003,
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_EXECUTE_READWRITE = 0x00020000,
        STANDARD_RIGHTS_ALL = 0x001F0000,
        GENERIC_ALL = 0x10000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_READ = 0x80000000
    }

    [Flags]
    internal enum ACCESS_MASK_PIPE : uint
    {
        NO_ACCESS = 0x00000000,
        FILE_READ_DATA = 0x00000001,
        FILE_WRITE_DATA = 0x00000002,
        FILE_APPEND_DATA = 0x00000004,
        FILE_READ_EA = 0x00000008,
        FILE_WRITE_EA = 0x00000010,
        FILE_EXECUTE = 0x00000020,
        FILE_READ_ATTRIBUTES = 0x00000080,
        FILE_WRITE_ATTRIBUTES = 0x00000100,
        FILE_STANDARD_READ = 0x00120089,
        FILE_STANDARD_WRITE = 0x00120116,
        FILE_STANDARD_EXECUTE = 0x001200A0,
        FILE_ALL_ACCESS = 0x001F01FF,
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        GENERIC_ALL = 0x10000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_READ = 0x80000000
    }

    [Flags]
    internal enum ACCESS_MASK_PROCESS : uint
    {
        NO_ACCESS = 0x00000000,
        TERMINATE = 0x00000001,
        CREATE_THREAD = 0x00000002,
        SET_SESSIONID = 0x00000004,
        VM_OPERATION = 0x00000008,
        VM_READ = 0x00000010,
        VM_WRITE = 0x00000020,
        DUP_HANDLE = 0x00000040,
        CREATE_PROCESS = 0x000000080,
        SET_QUOTA = 0x00000100,
        SET_INFORMATION = 0x00000200,
        QUERY_INFORMATION = 0x00000400,
        SUSPEND_RESUME = 0x00000800,
        QUERY_LIMITED_INFORMATION = 0x00001000,
        SET_LIMITED_INFORMATION = 0x00002000,
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        PROCESS_ALL_ACCESS = 0x001FFFFF
    }

    [Flags]
    internal enum ACCESS_MASK_SECTION : uint
    {
        NO_ACCESS = 0x00000000,
        SECTION_QUERY = 0x00000001,
        SECTION_MAP_WRITE = 0x00000002,
        SECTION_MAP_READ = 0x00000004,
        SECTION_MAP_EXECUTE = 0x00000008,
        SECTION_EXTEND_SIZE = 0x00000010,
        SECTION_MAP_EXECUTE_EXPLICIT = 0x00000020,
        SECTION_ALL_ACCESS = 0x000F001F,
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_EXECUTE_READWRITE = 0x00020000,
        STANDARD_RIGHTS_ALL = 0x001F0000,
        GENERIC_ALL = 0x10000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_READ = 0x80000000
    }

    [Flags]
    internal enum ACCESS_MASK_SEMAPHORE : uint
    {
        NO_ACCESS = 0x00000000,
        SEMAPHORE_QUERY_STATE = 0x00000001,
        SEMAPHORE_MODIFY_STATE = 0x00000002,
        SEMAPHORE_ALL_ACCESS = 0x001F0003,
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_EXECUTE_READWRITE = 0x00020000,
        STANDARD_RIGHTS_ALL = 0x001F0000,
        GENERIC_ALL = 0x10000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_READ = 0x80000000
    }

    [Flags]
    internal enum ACCESS_MASK_SESSION : uint
    {
        NO_ACCESS = 0x00000000,
        SESSION_QUERY_ACCESS = 0x00000001,
        SESSION_MODIFY_ACCESS = 0x00000002,
        SESSION_ALL_ACCESS = 0x000F0003,
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_EXECUTE_READWRITE = 0x00020000,
        STANDARD_RIGHTS_ALL = 0x001F0000,
        GENERIC_ALL = 0x10000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_READ = 0x80000000
    }

    [Flags]
    internal enum ACCESS_MASK_STANDARD_DIRECTORY : uint
    {
        NO_ACCESS = 0x00000000,
        FILE_LIST_DIRECTORY = 0x00000001,
        FILE_ADD_FILE = 0x00000002,
        FILE_ADD_SUBDIRECTORY = 0x00000004,
        FILE_READ_EA = 0x00000008,
        FILE_WRITE_EA = 0x00000010,
        FILE_TRAVERSE = 0x00000020,
        FILE_DELETE_CHILD = 0x00000040,
        FILE_READ_ATTRIBUTES = 0x00000080,
        FILE_WRITE_ATTRIBUTES = 0x00000100,
        FILE_STANDARD_READ = 0x00120089,
        FILE_STANDARD_WRITE = 0x00120116,
        FILE_STANDARD_EXECUTE = 0x001200A0,
        FILE_ALL_ACCESS = 0x001F01FF,
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_READ = 0x80000000,
        GENERIC_ALL = 0x10000000,
    }

    [Flags]
    internal enum ACCESS_MASK_TIMER : uint
    {
        NO_ACCESS = 0x00000000,
        TIMER_QUERY_STATE = 0x00000001,
        TIMER_MODIFY_STATE = 0x00000002,
        TIMER_ALL_ACCESS = 0x001F0003,
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_EXECUTE_READWRITE = 0x00020000,
        STANDARD_RIGHTS_ALL = 0x001F0000,
        GENERIC_ALL = 0x10000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_READ = 0x80000000
    }

    [Flags]
    internal enum ACCESS_MASK_TOKEN : uint
    {
        NO_ACCESS = 0x00000000,
        TOKEN_ASSIGN_PRIMARY = 0x00000001,
        TOKEN_DUPLICATE = 0x00000002,
        TOKEN_IMPERSONATE = 0x00000004,
        TOKEN_QUERY = 0x00000008,
        TOKEN_QUERY_SOURCE = 0x00000010,
        TOKEN_ADJUST_PRIVILEGES = 0x00000020,
        TOKEN_ADJUST_GROUPS = 0x00000040,
        TOKEN_ADJUST_DEFAULT = 0x00000080,
        TOKEN_ADJUST_SESSIONID = 0x00000100,
        TOKEN_EXECUTE = 0x00020000,
        TOKEN_READ = 0x00020008,
        TOKEN_WRITE = 0x000200E0,
        TOKEN_ALL_ACCESS = 0x000F01FF,
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_EXECUTE_READWRITE = 0x00020000,
        STANDARD_RIGHTS_ALL = 0x001F0000,
        GENERIC_ALL = 0x10000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_READ = 0x80000000
    }

    [Flags]
    internal enum ACE_FLAGS : byte
    {
        NONE = 0x00,
        OBJECT_INHERIT_ACE = 0x01,
        CONTAINER_INHERIT_ACE = 0x02,
        NO_PROPAGATE_INHERIT_ACE = 0x04,
        INHERIT_ONLY_ACE = 0x08,
        INHERITED_ACE = 0x10,
        FAILED_ACCESS_ACE_FLAG = 0x40,
        SUCCESSFUL_ACCESS_ACE_FLAG = 0x80
    }

    [Flags]
    internal enum ACE_OBJECT_TYPE
    {
        NONE,
        ACE_OBJECT_TYPE_PRESENT,
        ACE_INHERITED_OBJECT_TYPE_PRESENT
    }

    internal enum ACE_TYPE : byte
    {
        ACCESS_ALLOWED,
        ACCESS_DENIED,
        SYSTEM_AUDIT,
        SYSTEM_ALARM,
        ACCESS_ALLOWED_COMPOUND,
        ACCESS_ALLOWED_OBJECT,
        ACCESS_DENIED_OBJECT,
        SYSTEM_AUDIT_OBJECT,
        SYSTEM_ALARM_OBJECT,
        ACCESS_ALLOWED_CALLBACK,
        ACCESS_DENIED_CALLBACK,
        ACCESS_ALLOWED_CALLBACK_OBJECT,
        ACCESS_DENIED_CALLBACK_OBJECT,
        SYSTEM_AUDIT_CALLBACK,
        SYSTEM_ALARM_CALLBACK,
        SYSTEM_AUDIT_CALLBACK_OBJECT,
        SYSTEM_ALARM_CALLBACK_OBJECT,
        SYSTEM_MANDATORY_LABEL,
        SYSTEM_RESOURCE_ATTRIBUTE,
        SYSTEM_SCOPED_POLICY_ID,
        SYSTEM_PROCESS_TRUST_LABEL,
        SYSTEM_ACCESS_FILTER,
        // ACCESS_MAX_MS_V5 = 0x15
    }

    internal enum ACL_REVISION : byte
    {
        ACL_REVISION = 2,
        ACL_REVISION_DS = 4,
    }

    internal enum CONDITIONAL_ACE_ATTRIBUTE_TOKEN : byte
    {
        LocalAttribute = 0xF8,
        UserAttribute = 0xF9,
        ResourceAttribute = 0xFA,
        DeviceAttribute = 0xFB
    }

    internal enum CONDITIONAL_ACE_BASE : byte
    {
        Octal = 1,
        Decimal,
        Hexadecimal
    }

    internal enum CONDITIONAL_ACE_SIGN : byte
    {
        Plus = 1,
        Minus,
        None
    }

    internal enum CONDITIONAL_ACE_TOKEN : byte
    {
        /*
         * Attribute Token
         */
        LocalAttribute = 0xF8,
        UserAttribute = 0xF9,
        ResourceAttribute = 0xFA,
        DeviceAttribute = 0xFB,
        /*
         * Literal
         */
        InvalidToken = 0x00,
        SignedInt8 = 0x01,
        SignedInt16 = 0x02,
        SignedInt32 = 0x03,
        SignedInt64 = 0x04,
        UnicodeString = 0x10,
        OctetString = 0x18,
        Composite = 0x50,
        Sid = 0x51,
        /*
         * Logical Operator
         */
        Exists = 0x87,
        NotExists = 0x8D,
        LogicalAnd = 0xA0,
        LogicalOr = 0xA1,
        LogicalNot = 0xA2,
        /*
         * Relational Operator
         */
        Equals = 0x80,
        NotEquals = 0x81,
        LessThan = 0x82,
        LessThanEquals = 0x83,
        GreaterThan = 0x84,
        GreaterThanEquals = 0x85,
        Contains = 0x86,
        AnyOf = 0x88,
        MemberOf = 0x89,
        DeviceMemberOf = 0x8A,
        MemberOfAny = 0x8B,
        DeviceMemberOfAny = 0x8C,
        NotContains = 0x8E,
        NotAnyOf = 0x8F,
        NotMemberOf = 0x90,
        NotDeviceMemberOf = 0x91,
        NotMemberOfAny = 0x92,
        NotDeviceMemberOfAny = 0x93
    }

    internal enum CREATE_DESPOSITION
    {
        NEW = 1,
        CREATE_ALWAYS = 2,
        OPEN_EXISTING = 3,
        OPEN_ALWAYS = 4,
        TRUNCATE_EXISTING = 5
    }

    [Flags]
    internal enum FILE_ATTRIBUTE : uint
    {
        NONE = 0x00000000,
        READONLY = 0x00000001,
        HIDDEN = 0x00000002,
        SYSTEM = 0x00000004,
        DIRECTORY = 0x00000010,
        ARCHIVE = 0x00000020,
        DEVICE = 0x00000040,
        NORMAL = 0x00000080,
        TEMPORARY = 0x00000100,
        SPARSE_FILE = 0x00000200,
        REPARSE_POINT = 0x00000400,
        COMPRESSED = 0x00000800,
        OFFLINE = 0x00001000,
        NOT_CONTENT_INDEXED = 0x00002000,
        ENCRYPTED = 0x00004000,
        VIRTUAL = 0x00010000,
        WRITE_THROUGH = 0x80000000,
        OVERLAPPED = 0x40000000,
        NO_BUFFERING = 0x20000000,
        RANDOM_ACCESS = 0x10000000,
        SEQUENTIAL_SCAN = 0x08000000,
        DELETE_ON_CLOSE = 0x04000000,
        BACKUP_SEMANTICS = 0x02000000,
        POSIX_SEMANTICS = 0x01000000,
        OPEN_REPARSE_POINT = 0x00200000,
        OPEN_NO_RECALL = 0x00100000,
        FIRST_PIPE_INSTANCE = 0x00080000,
        INVALID = 0xFFFFFFFF
    }

    internal enum FILE_CREATE_DISPOSITION : uint
    {
        SUPERSEDE = 0,
        OPEN = 1,
        CREATE = 2,
        OPEN_IF = 3,
        OVERWRITE = 4,
        OVERWRITE_IF = 5
    }

    [Flags]
    internal enum FILE_CREATE_OPTIONS : uint
    {
        NONE = 0x00000000,
        DIRECTORY_FILE = 0x00000001,
        WRITE_THROUGH = 0x00000002,
        SEQUENTIAL_ONLY = 0x00000004,
        NO_INTERMEDIATE_BUFFERING = 0x00000008,
        SYNCHRONOUS_IO_ALERT = 0x00000010,
        SYNCHRONOUS_IO_NONALERT = 0x00000020,
        NON_DIRECTORY_FILE = 0x00000040,
        CREATE_TREE_CONNECTION = 0x00000080,
        COMPLETE_IF_OPLOCKED = 0x00000100,
        NO_EA_KNOWLEDGE = 0x00000200,
        OPEN_FOR_RECOVERY = 0x00000400,
        RANDOM_ACCESS = 0x00000800,
        DELETE_ON_CLOSE = 0x00001000,
        OPEN_BY_FILE_ID = 0x00002000,
        OPEN_FOR_BACKUP_INTENT = 0x00004000,
        NO_COMPRESSION = 0x00008000,
        OPEN_REQUIRING_OPLOCK = 0x00010000,
        DISALLOW_EXCLUSIVE = 0x00020000,
        SESSION_AWARE = 0x00040000,
        RESERVE_OPFILTER = 0x00100000,
        OPEN_REPARSE_POINT = 0x00200000,
        OPEN_NO_RECALL = 0x00400000,
        OPEN_FOR_FREE_SPACE_QUERY = 0x00800000,
        COPY_STRUCTURED_STORAGE = 0x00000041,
        STRUCTURED_STORAGE = 0x00000441
    }

    [Flags]
    internal enum FILE_SHARE : uint
    {
        NONE = 0x00000000,
        READ = 0x00000001,
        WRITE = 0x00000002,
        DELETE = 0x00000004,
        VALID_FLAGS = 0x00000007
    }

    internal enum HKEY : uint
    {
        HKEY_CLASSES_ROOT = 0x80000000,
        HKEY_CURRENT_USER = 0x80000001,
        HKEY_LOCAL_MACHINE = 0x80000002,
        HKEY_USERS = 0x80000003,
        HKEY_PERFORMANCE_DATA = 0x80000004,
        HKEY_CURRENT_CONFIG = 0x80000005,
        HKEY_DYN_DATA = 0x80000006
    }

    [Flags]
    internal enum KEY_ACCESS : uint
    {
        KEY_QUERY_VALUE = 0x00000001,
        KEY_SET_VALUE = 0x00000002,
        KEY_CREATE_SUB_KEY = 0x00000004,
        KEY_ENUMERATE_SUB_KEYS = 0x00000008,
        KEY_NOTIFY = 0x00000010,
        KEY_CREATE_LINK = 0x00000020,
        KEY_WOW64_64KEY = 0x00000100,
        KEY_WOW64_32KEY = 0x00000200,
        KEY_WRITE = 0x00020006,
        KEY_READ = 0x00020019,
        KEY_EXECUTE = 0x00020019,
        KEY_ALL_ACCESS = 0x001F003F,
        // Generic / Standard
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_READ = 0x00020000,
        STANDARD_RIGHTS_WRITE = 0x00020000,
        STANDARD_RIGHTS_EXECUTE = 0x00020000,
        STANDARD_RIGHTS_ALL = 0x001F0000,
        SPECIFIC_RIGHTS_ALL = 0x0000FFFF,
        ACCESS_SYSTEM_SECURITY = 0x01000000,
        MAXIMUM_ALLOWED = 0x02000000,
        GENERIC_ALL = 0x10000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_READ = 0x80000000
    }

    internal enum OBJECT_INFORMATION_CLASS
    {
        ObjectBasicInformation, // PUBLIC_OBJECT_BASIC_INFORMATION
        ObjectTypeInformation // PUBLIC_OBJECT_TYPE_INFORMATION
    }

    internal enum REG_OPTION
    {
        RESERVED = 0x00000000,
        NON_VOLATILE = 0x00000000,
        VOLATILE = 0x00000001,
        CREATE_LINK = 0x00000002,
        BACKUP_RESTORE = 0x00000004,
        OPEN_LINK = 0x00000008
    }

    [Flags]
    internal enum SE_PRIVILEGE_ATTRIBUTES : uint
    {
        SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001,
        SE_PRIVILEGE_ENABLED = 0x00000002,
        SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000,
    }

    [Flags]
    internal enum SECURITY_DESCRIPTOR_CONTROL : ushort
    {
        NONE = 0x0000,
        SE_OWNER_DEFAULTED = 0x0001,
        SE_GROUP_DEFAULTED = 0x0002,
        SE_DACL_PRESENT = 0x0004,
        SE_DACL_DEFAULTED = 0x0008,
        SE_SACL_DEFAULTED = 0x0008,
        SE_SACL_PRESENT = 0x0010,
        SE_DACL_AUTO_INHERIT_REQ = 0x0100,
        SE_SACL_AUTO_INHERIT_REQ = 0x0200,
        SE_DACL_AUTO_INHERITED = 0x0400,
        SE_SACL_AUTO_INHERITED = 0x0800,
        SE_DACL_PROTECTED = 0x1000,
        SE_SACL_PROTECTED = 0x2000,
        SE_RM_CONTROL_VALID = 0x4000,
        SE_SELF_RELATIVE = 0x8000
    }

    internal enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }

    [Flags]
    internal enum SECURITY_INFORMATION : uint
    {
        OWNER_SECURITY_INFORMATION = 0x00000001,
        GROUP_SECURITY_INFORMATION = 0x00000002,
        DACL_SECURITY_INFORMATION = 0x00000004,
        SACL_SECURITY_INFORMATION = 0x00000008,
        LABEL_SECURITY_INFORMATION = 0x00000010,
        ATTRIBUTE_SECURITY_INFORMATION = 0x00000020,
        SCOPE_SECURITY_INFORMATION = 0x00000040,
        PROCESS_TRUST_LABEL_SECURITY_INFORMATION = 0x00000080,
        BACKUP_SECURITY_INFORMATION = 0x00010000,
        UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000,
        UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000,
        PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000,
        PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
    }

    internal enum SID_NAME_USE
    {
        SidTypeUser = 1,
        SidTypeGroup,
        SidTypeDomain,
        SidTypeAlias,
        SidTypeWellKnownGroup,
        SidTypeDeletedAccount,
        SidTypeInvalid,
        SidTypeUnknown,
        SidTypeComputer,
        SidTypeLabel,
        SidTypeLogonSession
    }

    internal enum TOKEN_TYPE
    {
        TokenPrimary = 1,
        TokenImpersonation
    }

    [Flags]
    internal enum TokenAccessFlags : uint
    {
        TOKEN_ADJUST_DEFAULT = 0x0080,
        TOKEN_ADJUST_GROUPS = 0x0040,
        TOKEN_ADJUST_PRIVILEGES = 0x0020,
        TOKEN_ADJUST_SESSIONID = 0x0100,
        TOKEN_ASSIGN_PRIMARY = 0x0001,
        TOKEN_DUPLICATE = 0x0002,
        TOKEN_EXECUTE = 0x00020000,
        TOKEN_IMPERSONATE = 0x0004,
        TOKEN_QUERY = 0x0008,
        TOKEN_QUERY_SOURCE = 0x0010,
        TOKEN_READ = 0x00020008,
        TOKEN_WRITE = 0x000200E0,
        TOKEN_ALL_ACCESS = 0x000F01FF,
        MAXIMUM_ALLOWED = 0x02000000
    }

    internal enum TOKEN_ELEVATION_TYPE
    {
        TokenElevationTypeDefault = 1,
        TokenElevationTypeFull,
        TokenElevationTypeLimited
    }

    /*
     * Reference:
     * https://github.com/processhacker/phnt/blob/master/ntseapi.h
     */
    internal enum TOKEN_INFORMATION_CLASS
    {
        TokenUser = 1, // q: TOKEN_USER
        TokenGroups, // q: TOKEN_GROUPS
        TokenPrivileges, // q: TOKEN_PRIVILEGES
        TokenOwner, // q; s: TOKEN_OWNER
        TokenPrimaryGroup, // q; s: TOKEN_PRIMARY_GROUP
        TokenDefaultDacl, // q; s: TOKEN_DEFAULT_DACL
        TokenSource, // q: TOKEN_SOURCE
        TokenType, // q: TOKEN_TYPE
        TokenImpersonationLevel, // q: SECURITY_IMPERSONATION_LEVEL
        TokenStatistics, // q: TOKEN_STATISTICS // 10
        TokenRestrictedSids, // q: TOKEN_GROUPS
        TokenSessionId, // q; s: ULONG (requires SeTcbPrivilege)
        TokenGroupsAndPrivileges, // q: TOKEN_GROUPS_AND_PRIVILEGES
        TokenSessionReference, // s: ULONG (requires SeTcbPrivilege)
        TokenSandBoxInert, // q: ULONG
        TokenAuditPolicy, // q; s: TOKEN_AUDIT_POLICY (requires SeSecurityPrivilege/SeTcbPrivilege)
        TokenOrigin, // q; s: TOKEN_ORIGIN (requires SeTcbPrivilege)
        TokenElevationType, // q: TOKEN_ELEVATION_TYPE
        TokenLinkedToken, // q; s: TOKEN_LINKED_TOKEN (requires SeCreateTokenPrivilege)
        TokenElevation, // q: TOKEN_ELEVATION // 20
        TokenHasRestrictions, // q: ULONG
        TokenAccessInformation, // q: TOKEN_ACCESS_INFORMATION
        TokenVirtualizationAllowed, // q; s: ULONG (requires SeCreateTokenPrivilege)
        TokenVirtualizationEnabled, // q; s: ULONG
        TokenIntegrityLevel, // q; s: TOKEN_MANDATORY_LABEL
        TokenUIAccess, // q; s: ULONG
        TokenMandatoryPolicy, // q; s: TOKEN_MANDATORY_POLICY (requires SeTcbPrivilege)
        TokenLogonSid, // q: TOKEN_GROUPS
        TokenIsAppContainer, // q: ULONG
        TokenCapabilities, // q: TOKEN_GROUPS // 30
        TokenAppContainerSid, // q: TOKEN_APPCONTAINER_INFORMATION
        TokenAppContainerNumber, // q: ULONG
        TokenUserClaimAttributes, // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
        TokenDeviceClaimAttributes, // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
        TokenRestrictedUserClaimAttributes, // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
        TokenRestrictedDeviceClaimAttributes, // q: CLAIM_SECURITY_ATTRIBUTES_INFORMATION
        TokenDeviceGroups, // q: TOKEN_GROUPS
        TokenRestrictedDeviceGroups, // q: TOKEN_GROUPS
        TokenSecurityAttributes, // q; s: TOKEN_SECURITY_ATTRIBUTES_[AND_OPERATION_]INFORMATION
        TokenIsRestricted, // q: ULONG // 40
        TokenProcessTrustLevel, // q: TOKEN_PROCESS_TRUST_LEVEL
        TokenPrivateNameSpace, // q; s: ULONG
        TokenSingletonAttributes, // q: TOKEN_SECURITY_ATTRIBUTES_INFORMATION
        TokenBnoIsolation, // q: TOKEN_BNO_ISOLATION_INFORMATION
        TokenChildProcessFlags, // s: ULONG
        TokenIsLessPrivilegedAppContainer, // q: ULONG
        TokenIsSandboxed, // q: ULONG
        TokenIsAppSilo, // TokenOriginatingProcessTrustLevel // q: TOKEN_PROCESS_TRUST_LEVEL
        MaxTokenInfoClass
    }

    /*
     * Reference:
     * https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools/blob/main/NtApiDotNet/NtSecurityNative.cs
     */
    [Flags]
    internal enum CachedSigningLevelFlags
    {
        None = 0,
        UntrustedSignature = 1,
        TrustedSignature = 2,
        Unknown4 = 4,
        DontUseUSNJournal = 8,
        HasPerAppRules = 0x10,
        SetInTestMode = 0x20,
        ProtectedLightVerification = 0x40
    }

    /*
     * Reference : 
     * http://publications.alex-ionescu.com/Recon/Recon%202018%20-%20Unknown%20Known%20DLLs%20and%20other%20code%20integrity%20trust%20violations.pdf
     */
    internal enum CI_DATA_BLOB_TYPE : byte
    {
        FileHash = 0,
        SignerHash,
        WIMGUID,
        Timestamp,
        DeviceGuardPolicyHash,
        AntiCheatPolicyHash
    }

    internal enum DAY_OF_WEEK : short
    {
        Sun,
        Mon,
        Tue,
        Wed,
        Thu,
        Fri,
        Sat
    }

    [Flags]
    internal enum EA_INFORMATION_FLAGS : byte
    {
        NONE = 0,
        FILE_NEED_EA = 0x80
    }

    internal enum HASH_ALGORITHM
    {
        NONE = 0,
        MAC = 32773,
        MD2 = 32769,
        MD4 = 32770,
        MD5 = 32771,
        SHA = 32772,
        SHA256 = 32780,
        SHA384 = 32781,
        SHA512 = 32782
    }

    internal enum SE_SIGNING_LEVEL : byte
    {
        UNCHECKED = 0,
        UNSIGNED,
        ENTERPRISE,
        DEVELOPER,
        AUTHENTICODE,
        CUSTOM_2,
        STORE,
        ANTIMALWARE,
        MICROSOFT,
        CUSTOM_4,
        CUSTOM_5,
        DYNAMIC_CODEGEN,
        WINDOWS,
        CUSTOM_7,
        WINDOWS_TCB,
        CUSTOM_6
    }

    [Flags]
    internal enum SIGNING_LEVEL_FILE_CACHE_FLAG : uint
    {
        NOT_VALIDATED = 0x00000001,
        VALIDATE_ONLY = 0x00000004
    }

    internal enum FILE_ATTRIBUTE_FLAGS
    {
        READONLY = 0x00000001,
        HIDDEN = 0x00000002,
        SYSTEM = 0x00000004,
        DIRECTORY = 0x00000010,
        ARCHIVE = 0x00000020,
        DEVICE = 0x00000040,
        NORMAL = 0x00000080,
        TEMPORARY = 0x00000100,
        SPARSE_FILE = 0x00000200,
        REPARSE_POINT = 0x00000400,
        COMPRESSED = 0x00000800,
        OFFLINE = 0x00001000,
        NOT_CONTENT_INDEXED = 0x00002000,
        ENCRYPTED = 0x00004000,
        VIRTUAL = 0x00010000,
        VALID_FLAGS = 0x00007FB7,
        VALID_SET_FLAGS = 0x000031A7
    }

    [Flags]
    internal enum MINIDUMP_TYPE : uint
    {
        MiniDumpNormal = 0x00000000,
        MiniDumpWithDataSegs = 0x00000001,
        MiniDumpWithFullMemory = 0x00000002,
        MiniDumpWithHandleData = 0x00000004,
        MiniDumpFilterMemory = 0x00000008,
        MiniDumpScanMemory = 0x00000010,
        MiniDumpWithUnloadedModules = 0x00000020,
        MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
        MiniDumpFilterModulePaths = 0x00000080,
        MiniDumpWithProcessThreadData = 0x00000100,
        MiniDumpWithPrivateReadWriteMemory = 0x00000200,
        MiniDumpWithoutOptionalData = 0x00000400,
        MiniDumpWithFullMemoryInfo = 0x00000800,
        MiniDumpWithThreadInfo = 0x00001000,
        MiniDumpWithCodeSegs = 0x00002000,
        MiniDumpWithoutAuxiliaryState = 0x00004000,
        MiniDumpWithFullAuxiliaryState = 0x00008000,
        MiniDumpWithPrivateWriteCopyMemory = 0x00010000,
        MiniDumpIgnoreInaccessibleMemory = 0x00020000,
        MiniDumpWithTokenInformation = 0x00040000,
        MiniDumpWithModuleHeaders = 0x00080000,
        MiniDumpFilterTriage = 0x00100000,
        MiniDumpWithAvxXStateContext = 0x00200000,
        MiniDumpWithIptTrace = 0x00400000,
        MiniDumpScanInaccessiblePartialPages = 0x00800000,
        MiniDumpFilterWriteCombinedMemory,
        MiniDumpValidTypeFlags = 0x01FFFFFF
    }

    internal enum PROCESS_INFORMATION_CLASS
    {
        ProcessBasicInformation = 0x00,
        ProcessQuotaLimits = 0x01,
        ProcessIoCounters = 0x02,
        ProcessVmCounters = 0x03,
        ProcessTimes = 0x04,
        ProcessBasePriority = 0x05,
        ProcessRaisePriority = 0x06,
        ProcessDebugPort = 0x07,
        ProcessExceptionPort = 0x08,
        ProcessAccessToken = 0x09,
        ProcessLdtInformation = 0x0A,
        ProcessLdtSize = 0x0B,
        ProcessDefaultHardErrorMode = 0x0C,
        ProcessIoPortHandlers = 0x0D,
        ProcessPooledUsageAndLimits = 0x0E,
        ProcessWorkingSetWatch = 0x0F,
        ProcessUserModeIOPL = 0x10,
        ProcessEnableAlignmentFaultFixup = 0x11,
        ProcessPriorityClass = 0x12,
        ProcessWx86Information = 0x13,
        ProcessHandleCount = 0x14,
        ProcessAffinityMask = 0x15,
        ProcessPriorityBoost = 0x16,
        ProcessDeviceMap = 0x17,
        ProcessSessionInformation = 0x18,
        ProcessForegroundInformation = 0x19,
        ProcessWow64Information = 0x1A,
        ProcessImageFileName = 0x1B,
        ProcessLUIDDeviceMapsEnabled = 0x1C,
        ProcessBreakOnTermination = 0x1D,
        ProcessDebugObjectHandle = 0x1E,
        ProcessDebugFlags = 0x1F,
        ProcessHandleTracing = 0x20,
        ProcessIoPriority = 0x21,
        ProcessExecuteFlags = 0x22,
        ProcessResourceManagement = 0x23,
        ProcessCookie = 0x24,
        ProcessImageInformation = 0x25,
        ProcessCycleTime = 0x26,
        ProcessPagePriority = 0x27,
        ProcessInstrumentationCallback = 0x28,
        ProcessThreadStackAllocation = 0x29,
        ProcessWorkingSetWatchEx = 0x2A,
        ProcessImageFileNameWin32 = 0x2B,
        ProcessImageFileMapping = 0x2C,
        ProcessAffinityUpdateMode = 0x2D,
        ProcessMemoryAllocationMode = 0x2E,
        ProcessGroupInformation = 0x2F,
        ProcessTokenVirtualizationEnabled = 0x30,
        ProcessConsoleHostProcess = 0x31,
        ProcessWindowInformation = 0x32,
        ProcessHandleInformation = 0x33,
        ProcessMitigationPolicy = 0x34,
        ProcessDynamicFunctionTableInformation = 0x35,
        ProcessHandleCheckingMode = 0x36,
        ProcessKeepAliveCount = 0x37,
        ProcessRevokeFileHandles = 0x38,
        ProcessWorkingSetControl = 0x39,
        ProcessHandleTable = 0x3A,
        ProcessCheckStackExtentsMode = 0x3B,
        ProcessCommandLineInformation = 0x3C,
        ProcessProtectionInformation = 0x3D,
        ProcessMemoryExhaustion = 0x3E,
        ProcessFaultInformation = 0x3F,
        ProcessTelemetryIdInformation = 0x40,
        ProcessCommitReleaseInformation = 0x41,
        ProcessDefaultCpuSetsInformation = 0x42,
        ProcessAllowedCpuSetsInformation = 0x43,
        ProcessSubsystemProcess = 0x44,
        ProcessJobMemoryInformation = 0x45,
        ProcessInPrivate = 0x46,
        ProcessRaiseUMExceptionOnInvalidHandleClose = 0x47,
        ProcessIumChallengeResponse = 0x48,
        ProcessChildProcessInformation = 0x49,
        ProcessHighGraphicsPriorityInformation = 0x4A,
        ProcessSubsystemInformation = 0x4B,
        ProcessEnergyValues = 0x4C,
        ProcessActivityThrottleState = 0x4D,
        ProcessActivityThrottlePolicy = 0x4E,
        ProcessWin32kSyscallFilterInformation = 0x4F,
        ProcessDisableSystemAllowedCpuSets = 0x50,
        ProcessWakeInformation = 0x51,
        ProcessEnergyTrackingState = 0x52,
        ProcessManageWritesToExecutableMemory = 0x53,
        ProcessCaptureTrustletLiveDump = 0x54,
        ProcessTelemetryCoverage = 0x55,
        ProcessEnclaveInformation = 0x56,
        ProcessEnableReadWriteVmLogging = 0x57,
        ProcessUptimeInformation = 0x58,
        ProcessImageSection = 0x59,
        ProcessDebugAuthInformation = 0x5A,
        ProcessSystemResourceManagement = 0x5B,
        ProcessSequenceNumber = 0x5C,
        ProcessLoaderDetour = 0x5D,
        ProcessSecurityDomainInformation = 0x5E,
        ProcessCombineSecurityDomainsInformation = 0x5F,
        ProcessEnableLogging = 0x60,
        ProcessLeapSecondInformation = 0x61,
        ProcessFiberShadowStackAllocation = 0x62,
        ProcessFreeFiberShadowStackAllocation = 0x63,
        MaxProcessInfoClass = 0x64
    }

    internal enum DLLMAIN_CALL_REASON
    {
        DLL_PROCESS_DETACH,
        DLL_PROCESS_ATTACH,
        DLL_THREAD_ATTACH,
        DLL_THREAD_DETACH
    }

    [Flags]
    internal enum FILE_ATTRIBUTES : uint
    {
        READONLY = 0x00000001,
        HIDDEN = 0x00000002,
        SYSTEM = 0x00000004,
        DIRECTORY = 0x00000010,
        ARCHIVE = 0x00000020,
        DEVICE = 0x00000040,
        NORMAL = 0x00000080,
        TEMPORARY = 0x00000100,
        SPARSE_FILE = 0x00000200,
        REPARSE_POINT = 0x00000400,
        COMPRESSED = 0x00000800,
        OFFLINE = 0x00001000,
        NOT_CONTENT_INDEXED = 0x00002000,
        ENCRYPTED = 0x00004000,
        INTEGRITY_STREAM = 0x00008000,
        VIRTUAL = 0x00010000,
        NO_SCRUB_DATA = 0x00020000,
        RECALL_ON_OPEN = 0x00040000,
        PINNED = 0x00080000,
        UNPINNED = 0x00100000,
        RECALL_ON_DATA_ACCESS = 0x00400000,
    }

    internal enum NT_FILE_CREATE_DISPOSITION : uint
    {
        SUPERSEDE = 0,
        OPEN = 1,
        CREATE = 2,
        OPEN_IF = 3,
        OVERWRITE = 4,
        OVERWRITE_IF = 5
    }

    internal enum SECTION_INHERIT
    {
        ViewShare = 1,
        ViewUnmap = 2
    }

    [Flags]
    internal enum RTL_PROCESS_REFLECTION_FLAGS : uint
    {
        INHERIT_HANDLES = 0x00000002,
        NO_SUSPEND = 0x00000004,
        NO_SYNCHRONIZE = 0x00000008,
        NO_CLOSE_EVENT = 0x00000010
    }

    [Flags]
    internal enum SHOW_WINDOW_FLAGS : uint
    {
        SW_HIDE = 0,
        SW_SHOWNORMAL = 1,
        SW_NORMAL = 1,
        SW_SHOWMINIMIZED = 2,
        SW_SHOWMAXIMIZED = 3,
        SW_MAXIMIZE = 3,
        SW_SHOWNOACTIVATE = 4,
        SW_SHOW = 5,
        SW_MINIMIZE = 6,
        SW_SHOWMINNOACTIVE = 7,
        SW_SHOWNA = 8,
        SW_RESTORE = 9,
        SW_SHOWDEFAULT = 10,
        SW_FORCEMINIMIZE = 11,
        SW_MAX = 11
    }

    /*
     * Reference :
     * + https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/create-method-in-class-win32-process
     */
    internal enum WMI_PROCESS_STATUS : uint
    {
        SUCCESS = 0,
        ACCESS_DENIED = 2,
        INSUFFICIENT_PRIVILEGE = 3,
        UNKNOWN_FAILURE = 8,
        PATH_NOT_FOUND = 9,
        INVALID_PARAMETERS = 21,
        OTHER_REASON = 22
    }

    [Flags]
    internal enum DUPLICATE_OPTION_FLAGS : uint
    {
        CLOSE_SOURCE = 0x00000001,
        SAME_ACCESS = 0x00000002,
        SAME_ATTRIBUTES = 0x00000004
    }

    internal enum EVENT_TYPE
    {
        NotificationEvent,
        SynchronizationEvent
    }

    internal enum SYSTEM_INFORMATION_CLASS
    {
        SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
        SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
        SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
        SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
        SystemPathInformation, // not implemented
        SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
        SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
        SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
        SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION (EX in: USHORT ProcessorGroup)
        SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
        SystemCallTimeInformation, // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
        SystemModuleInformation, // q: RTL_PROCESS_MODULES
        SystemLocksInformation, // q: RTL_PROCESS_LOCKS
        SystemStackTraceInformation, // q: RTL_PROCESS_BACKTRACES
        SystemPagedPoolInformation, // not implemented
        SystemNonPagedPoolInformation, // not implemented
        SystemHandleInformation, // q: SYSTEM_HANDLE_INFORMATION
        SystemObjectInformation, // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
        SystemPageFileInformation, // q: SYSTEM_PAGEFILE_INFORMATION
        SystemVdmInstemulInformation, // q: SYSTEM_VDM_INSTEMUL_INFO
        SystemVdmBopInformation, // not implemented // 20
        SystemFileCacheInformation, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
        SystemPoolTagInformation, // q: SYSTEM_POOLTAG_INFORMATION
        SystemInterruptInformation, // q: SYSTEM_INTERRUPT_INFORMATION (EX in: USHORT ProcessorGroup)
        SystemDpcBehaviorInformation, // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
        SystemFullMemoryInformation, // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
        SystemLoadGdiDriverInformation, // s (kernel-mode only)
        SystemUnloadGdiDriverInformation, // s (kernel-mode only)
        SystemTimeAdjustmentInformation, // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
        SystemSummaryMemoryInformation, // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
        SystemMirrorMemoryInformation, // s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
        SystemPerformanceTraceInformation, // q; s: (type depends on EVENT_TRACE_INFORMATION_CLASS)
        SystemObsolete0, // not implemented
        SystemExceptionInformation, // q: SYSTEM_EXCEPTION_INFORMATION
        SystemCrashDumpStateInformation, // s: SYSTEM_CRASH_DUMP_STATE_INFORMATION (requires SeDebugPrivilege)
        SystemKernelDebuggerInformation, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
        SystemContextSwitchInformation, // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
        SystemRegistryQuotaInformation, // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
        SystemExtendServiceTableInformation, // s (requires SeLoadDriverPrivilege) // loads win32k only
        SystemPrioritySeperation, // s (requires SeTcbPrivilege)
        SystemVerifierAddDriverInformation, // s (requires SeDebugPrivilege) // 40
        SystemVerifierRemoveDriverInformation, // s (requires SeDebugPrivilege)
        SystemProcessorIdleInformation, // q: SYSTEM_PROCESSOR_IDLE_INFORMATION (EX in: USHORT ProcessorGroup)
        SystemLegacyDriverInformation, // q: SYSTEM_LEGACY_DRIVER_INFORMATION
        SystemCurrentTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION
        SystemLookasideInformation, // q: SYSTEM_LOOKASIDE_INFORMATION
        SystemTimeSlipNotification, // s: HANDLE (NtCreateEvent) (requires SeSystemtimePrivilege)
        SystemSessionCreate, // not implemented
        SystemSessionDetach, // not implemented
        SystemSessionInformation, // not implemented (SYSTEM_SESSION_INFORMATION)
        SystemRangeStartInformation, // q: SYSTEM_RANGE_START_INFORMATION // 50
        SystemVerifierInformation, // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
        SystemVerifierThunkExtend, // s (kernel-mode only)
        SystemSessionProcessInformation, // q: SYSTEM_SESSION_PROCESS_INFORMATION
        SystemLoadGdiDriverInSystemSpace, // s: SYSTEM_GDI_DRIVER_INFORMATION (kernel-mode only) (same as SystemLoadGdiDriverInformation)
        SystemNumaProcessorMap, // q: SYSTEM_NUMA_INFORMATION
        SystemPrefetcherInformation, // q; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
        SystemExtendedProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
        SystemRecommendedSharedDataAlignment, // q: ULONG // KeGetRecommendedSharedDataAlignment
        SystemComPlusPackage, // q; s: ULONG
        SystemNumaAvailableMemory, // q: SYSTEM_NUMA_INFORMATION // 60
        SystemProcessorPowerInformation, // q: SYSTEM_PROCESSOR_POWER_INFORMATION (EX in: USHORT ProcessorGroup)
        SystemEmulationBasicInformation, // q: SYSTEM_BASIC_INFORMATION
        SystemEmulationProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
        SystemExtendedHandleInformation, // q: SYSTEM_HANDLE_INFORMATION_EX
        SystemLostDelayedWriteInformation, // q: ULONG
        SystemBigPoolInformation, // q: SYSTEM_BIGPOOL_INFORMATION
        SystemSessionPoolTagInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION
        SystemSessionMappedViewInformation, // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
        SystemHotpatchInformation, // q; s: SYSTEM_HOTPATCH_CODE_INFORMATION
        SystemObjectSecurityMode, // q: ULONG // 70
        SystemWatchdogTimerHandler, // s: SYSTEM_WATCHDOG_HANDLER_INFORMATION // (kernel-mode only)
        SystemWatchdogTimerInformation, // q: SYSTEM_WATCHDOG_TIMER_INFORMATION // (kernel-mode only)
        SystemLogicalProcessorInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION (EX in: USHORT ProcessorGroup)
        SystemWow64SharedInformationObsolete, // not implemented
        SystemRegisterFirmwareTableInformationHandler, // s: SYSTEM_FIRMWARE_TABLE_HANDLER // (kernel-mode only)
        SystemFirmwareTableInformation, // SYSTEM_FIRMWARE_TABLE_INFORMATION
        SystemModuleInformationEx, // q: RTL_PROCESS_MODULE_INFORMATION_EX
        SystemVerifierTriageInformation, // not implemented
        SystemSuperfetchInformation, // q; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
        SystemMemoryListInformation, // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
        SystemFileCacheInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
        SystemThreadPriorityClientIdInformation, // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
        SystemProcessorIdleCycleTimeInformation, // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup)
        SystemVerifierCancellationInformation, // SYSTEM_VERIFIER_CANCELLATION_INFORMATION // name:wow64:whNT32QuerySystemVerifierCancellationInformation
        SystemProcessorPowerInformationEx, // not implemented
        SystemRefTraceInformation, // q; s: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
        SystemSpecialPoolInformation, // q; s: SYSTEM_SPECIAL_POOL_INFORMATION (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
        SystemProcessIdInformation, // q: SYSTEM_PROCESS_ID_INFORMATION
        SystemErrorPortInformation, // s (requires SeTcbPrivilege)
        SystemBootEnvironmentInformation, // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
        SystemHypervisorInformation, // q: SYSTEM_HYPERVISOR_QUERY_INFORMATION
        SystemVerifierInformationEx, // q; s: SYSTEM_VERIFIER_INFORMATION_EX
        SystemTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
        SystemImageFileExecutionOptionsInformation, // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
        SystemCoverageInformation, // q: COVERAGE_MODULES s: COVERAGE_MODULE_REQUEST // ExpCovQueryInformation (requires SeDebugPrivilege)
        SystemPrefetchPatchInformation, // SYSTEM_PREFETCH_PATCH_INFORMATION
        SystemVerifierFaultsInformation, // s: SYSTEM_VERIFIER_FAULTS_INFORMATION (requires SeDebugPrivilege)
        SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
        SystemSystemDiskInformation, // q: SYSTEM_SYSTEM_DISK_INFORMATION
        SystemProcessorPerformanceDistribution, // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION (EX in: USHORT ProcessorGroup) // 100
        SystemNumaProximityNodeInformation, // q; s: SYSTEM_NUMA_PROXIMITY_MAP
        SystemDynamicTimeZoneInformation, // q; s: RTL_DYNAMIC_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
        SystemCodeIntegrityInformation, // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
        SystemProcessorMicrocodeUpdateInformation, // s: SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION
        SystemProcessorBrandString, // q: CHAR[] // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
        SystemVirtualAddressInformation, // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
        SystemLogicalProcessorAndGroupInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX (EX in: LOGICAL_PROCESSOR_RELATIONSHIP RelationshipType) // since WIN7 // KeQueryLogicalProcessorRelationship
        SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup)
        SystemStoreInformation, // q; s: SYSTEM_STORE_INFORMATION (requires SeProfileSingleProcessPrivilege) // SmQueryStoreInformation
        SystemRegistryAppendString, // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
        SystemAitSamplingValue, // s: ULONG (requires SeProfileSingleProcessPrivilege)
        SystemVhdBootInformation, // q: SYSTEM_VHD_BOOT_INFORMATION
        SystemCpuQuotaInformation, // q; s: PS_CPU_QUOTA_QUERY_INFORMATION
        SystemNativeBasicInformation, // q: SYSTEM_BASIC_INFORMATION
        SystemErrorPortTimeouts, // SYSTEM_ERROR_PORT_TIMEOUTS
        SystemLowPriorityIoInformation, // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
        SystemTpmBootEntropyInformation, // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
        SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
        SystemPagedPoolInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
        SystemSystemPtesInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
        SystemNodeDistanceInformation, // q: USHORT[4*NumaNodes] // (EX in: USHORT NodeNumber)
        SystemAcpiAuditInformation, // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
        SystemBasicPerformanceInformation, // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
        SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
        SystemSessionBigPoolInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
        SystemBootGraphicsInformation, // q; s: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
        SystemScrubPhysicalMemoryInformation, // q; s: MEMORY_SCRUB_INFORMATION
        SystemBadPageInformation,
        SystemProcessorProfileControlArea, // q; s: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
        SystemCombinePhysicalMemoryInformation, // s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 // 130
        SystemEntropyInterruptTimingInformation, // q; s: SYSTEM_ENTROPY_TIMING_INFORMATION
        SystemConsoleInformation, // q; s: SYSTEM_CONSOLE_INFORMATION
        SystemPlatformBinaryInformation, // q: SYSTEM_PLATFORM_BINARY_INFORMATION (requires SeTcbPrivilege)
        SystemPolicyInformation, // q: SYSTEM_POLICY_INFORMATION (Warbird/Encrypt/Decrypt/Execute)
        SystemHypervisorProcessorCountInformation, // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
        SystemDeviceDataInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
        SystemDeviceDataEnumerationInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
        SystemMemoryTopologyInformation, // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
        SystemMemoryChannelInformation, // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
        SystemBootLogoInformation, // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
        SystemProcessorPerformanceInformationEx, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // (EX in: USHORT ProcessorGroup) // since WINBLUE
        SystemCriticalProcessErrorLogInformation,
        SystemSecureBootPolicyInformation, // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
        SystemPageFileInformationEx, // q: SYSTEM_PAGEFILE_INFORMATION_EX
        SystemSecureBootInformation, // q: SYSTEM_SECUREBOOT_INFORMATION
        SystemEntropyInterruptTimingRawInformation,
        SystemPortableWorkspaceEfiLauncherInformation, // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
        SystemFullProcessInformation, // q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
        SystemKernelDebuggerInformationEx, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
        SystemBootMetadataInformation, // 150
        SystemSoftRebootInformation, // q: ULONG
        SystemElamCertificateInformation, // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
        SystemOfflineDumpConfigInformation, // q: OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2
        SystemProcessorFeaturesInformation, // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
        SystemRegistryReconciliationInformation, // s: NULL (requires admin) (flushes registry hives)
        SystemEdidInformation, // q: SYSTEM_EDID_INFORMATION
        SystemManufacturingInformation, // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
        SystemEnergyEstimationConfigInformation, // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
        SystemHypervisorDetailInformation, // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
        SystemProcessorCycleStatsInformation, // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION (EX in: USHORT ProcessorGroup) // 160
        SystemVmGenerationCountInformation,
        SystemTrustedPlatformModuleInformation, // q: SYSTEM_TPM_INFORMATION
        SystemKernelDebuggerFlags, // SYSTEM_KERNEL_DEBUGGER_FLAGS
        SystemCodeIntegrityPolicyInformation, // q; s: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
        SystemIsolatedUserModeInformation, // q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
        SystemHardwareSecurityTestInterfaceResultsInformation,
        SystemSingleModuleInformation, // q: SYSTEM_SINGLE_MODULE_INFORMATION
        SystemAllowedCpuSetsInformation, // s: SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION
        SystemVsmProtectionInformation, // q: SYSTEM_VSM_PROTECTION_INFORMATION (previously SystemDmaProtectionInformation)
        SystemInterruptCpuSetsInformation, // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
        SystemSecureBootPolicyFullInformation, // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
        SystemCodeIntegrityPolicyFullInformation,
        SystemAffinitizedInterruptProcessorInformation, // (requires SeIncreaseBasePriorityPrivilege)
        SystemRootSiloInformation, // q: SYSTEM_ROOT_SILO_INFORMATION
        SystemCpuSetInformation, // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
        SystemCpuSetTagInformation, // q: SYSTEM_CPU_SET_TAG_INFORMATION
        SystemWin32WerStartCallout,
        SystemSecureKernelProfileInformation, // q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
        SystemCodeIntegrityPlatformManifestInformation, // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // since REDSTONE
        SystemInterruptSteeringInformation, // q: in: SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT, out: SYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT // NtQuerySystemInformationEx // 180
        SystemSupportedProcessorArchitectures, // p: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx
        SystemMemoryUsageInformation, // q: SYSTEM_MEMORY_USAGE_INFORMATION
        SystemCodeIntegrityCertificateInformation, // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
        SystemPhysicalMemoryInformation, // q: SYSTEM_PHYSICAL_MEMORY_INFORMATION // since REDSTONE2
        SystemControlFlowTransition, // (Warbird/Encrypt/Decrypt/Execute)
        SystemKernelDebuggingAllowed, // s: ULONG
        SystemActivityModerationExeState, // SYSTEM_ACTIVITY_MODERATION_EXE_STATE
        SystemActivityModerationUserSettings, // SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
        SystemCodeIntegrityPoliciesFullInformation,
        SystemCodeIntegrityUnlockInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
        SystemIntegrityQuotaInformation,
        SystemFlushInformation, // q: SYSTEM_FLUSH_INFORMATION
        SystemProcessorIdleMaskInformation, // q: ULONG_PTR[ActiveGroupCount] // since REDSTONE3
        SystemSecureDumpEncryptionInformation,
        SystemWriteConstraintInformation, // SYSTEM_WRITE_CONSTRAINT_INFORMATION
        SystemKernelVaShadowInformation, // SYSTEM_KERNEL_VA_SHADOW_INFORMATION
        SystemHypervisorSharedPageInformation, // SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION // since REDSTONE4
        SystemFirmwareBootPerformanceInformation,
        SystemCodeIntegrityVerificationInformation, // SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION
        SystemFirmwarePartitionInformation, // SYSTEM_FIRMWARE_PARTITION_INFORMATION // 200
        SystemSpeculationControlInformation, // SYSTEM_SPECULATION_CONTROL_INFORMATION // (CVE-2017-5715) REDSTONE3 and above.
        SystemDmaGuardPolicyInformation, // SYSTEM_DMA_GUARD_POLICY_INFORMATION
        SystemEnclaveLaunchControlInformation, // SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION
        SystemWorkloadAllowedCpuSetsInformation, // SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION // since REDSTONE5
        SystemCodeIntegrityUnlockModeInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION
        SystemLeapSecondInformation, // SYSTEM_LEAP_SECOND_INFORMATION
        SystemFlags2Information, // q: SYSTEM_FLAGS_INFORMATION
        SystemSecurityModelInformation, // SYSTEM_SECURITY_MODEL_INFORMATION // since 19H1
        SystemCodeIntegritySyntheticCacheInformation,
        SystemFeatureConfigurationInformation, // SYSTEM_FEATURE_CONFIGURATION_INFORMATION // since 20H1 // 210
        SystemFeatureConfigurationSectionInformation, // SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION
        SystemFeatureUsageSubscriptionInformation, // SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS
        SystemSecureSpeculationControlInformation, // SECURE_SPECULATION_CONTROL_INFORMATION
        SystemSpacesBootInformation, // since 20H2
        SystemFwRamdiskInformation, // SYSTEM_FIRMWARE_RAMDISK_INFORMATION
        SystemWheaIpmiHardwareInformation,
        SystemDifSetRuleClassInformation, // SYSTEM_DIF_VOLATILE_INFORMATION
        SystemDifClearRuleClassInformation,
        SystemDifApplyPluginVerificationOnDriver, // SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION
        SystemDifRemovePluginVerificationOnDriver, // SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION // 220
        SystemShadowStackInformation, // SYSTEM_SHADOW_STACK_INFORMATION
        SystemBuildVersionInformation, // q: in: ULONG (LayerNumber), out: SYSTEM_BUILD_VERSION_INFORMATION // NtQuerySystemInformationEx // 222
        SystemPoolLimitInformation, // SYSTEM_POOL_LIMIT_INFORMATION (requires SeIncreaseQuotaPrivilege)
        SystemCodeIntegrityAddDynamicStore,
        SystemCodeIntegrityClearDynamicStores,
        SystemDifPoolTrackingInformation,
        SystemPoolZeroingInformation, // q: SYSTEM_POOL_ZEROING_INFORMATION
        SystemDpcWatchdogInformation, // q; s: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION
        SystemDpcWatchdogInformation2, // q; s: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION_V2
        SystemSupportedProcessorArchitectures2, // q: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx // 230
        SystemSingleProcessorRelationshipInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // (EX in: PROCESSOR_NUMBER Processor)
        SystemXfgCheckFailureInformation, // q: SYSTEM_XFG_FAILURE_INFORMATION
        SystemIommuStateInformation, // SYSTEM_IOMMU_STATE_INFORMATION // since 22H1
        SystemHypervisorMinrootInformation, // SYSTEM_HYPERVISOR_MINROOT_INFORMATION
        SystemHypervisorBootPagesInformation, // SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION
        SystemPointerAuthInformation, // SYSTEM_POINTER_AUTH_INFORMATION
        SystemSecureKernelDebuggerInformation,
        SystemOriginalImageFeatureInformation, // q: in: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_INPUT, out: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_OUTPUT // NtQuerySystemInformationEx
        MaxSystemInfoClass
    }

    internal enum THREADINFOCLASS
    {
        ThreadBasicInformation, // q: THREAD_BASIC_INFORMATION
        ThreadTimes, // q: KERNEL_USER_TIMES
        ThreadPriority, // s: KPRIORITY (requires SeIncreaseBasePriorityPrivilege)
        ThreadBasePriority, // s: KPRIORITY
        ThreadAffinityMask, // s: KAFFINITY
        ThreadImpersonationToken, // s: HANDLE
        ThreadDescriptorTableEntry, // q: DESCRIPTOR_TABLE_ENTRY (or WOW64_DESCRIPTOR_TABLE_ENTRY)
        ThreadEnableAlignmentFaultFixup, // s: BOOLEAN
        ThreadEventPair,
        ThreadQuerySetWin32StartAddress, // q: ULONG_PTR
        ThreadZeroTlsCell, // s: ULONG // TlsIndex // 10
        ThreadPerformanceCount, // q: LARGE_INTEGER
        ThreadAmILastThread, // q: ULONG
        ThreadIdealProcessor, // s: ULONG
        ThreadPriorityBoost, // qs: ULONG
        ThreadSetTlsArrayAddress, // s: ULONG_PTR
        ThreadIsIoPending, // q: ULONG
        ThreadHideFromDebugger, // q: BOOLEAN; s: void
        ThreadBreakOnTermination, // qs: ULONG
        ThreadSwitchLegacyState, // s: void // NtCurrentThread // NPX/FPU
        ThreadIsTerminated, // q: ULONG // 20
        ThreadLastSystemCall, // q: THREAD_LAST_SYSCALL_INFORMATION
        ThreadIoPriority, // qs: IO_PRIORITY_HINT (requires SeIncreaseBasePriorityPrivilege)
        ThreadCycleTime, // q: THREAD_CYCLE_TIME_INFORMATION
        ThreadPagePriority, // qs: PAGE_PRIORITY_INFORMATION
        ThreadActualBasePriority, // s: LONG (requires SeIncreaseBasePriorityPrivilege)
        ThreadTebInformation, // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_SET_CONTEXT)
        ThreadCSwitchMon,
        ThreadCSwitchPmu,
        ThreadWow64Context, // qs: WOW64_CONTEX, ARM_NT_CONTEXT since 20H1
        ThreadGroupInformation, // qs: GROUP_AFFINITY // 30
        ThreadUmsInformation, // q: THREAD_UMS_INFORMATION
        ThreadCounterProfiling, // q: BOOLEAN; s: THREAD_PROFILING_INFORMATION?
        ThreadIdealProcessorEx, // qs: PROCESSOR_NUMBER; s: previous PROCESSOR_NUMBER on return
        ThreadCpuAccountingInformation, // q: BOOLEAN; s: HANDLE (NtOpenSession) // NtCurrentThread // since WIN8
        ThreadSuspendCount, // q: ULONG // since WINBLUE
        ThreadHeterogeneousCpuPolicy, // q: KHETERO_CPU_POLICY // since THRESHOLD
        ThreadContainerId, // q: GUID
        ThreadNameInformation, // qs: THREAD_NAME_INFORMATION
        ThreadSelectedCpuSets,
        ThreadSystemThreadInformation, // q: SYSTEM_THREAD_INFORMATION // 40
        ThreadActualGroupAffinity, // q: GROUP_AFFINITY // since THRESHOLD2
        ThreadDynamicCodePolicyInfo, // q: ULONG; s: ULONG (NtCurrentThread)
        ThreadExplicitCaseSensitivity, // qs: ULONG; s: 0 disables, otherwise enables
        ThreadWorkOnBehalfTicket, // RTL_WORK_ON_BEHALF_TICKET_EX
        ThreadSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
        ThreadDbgkWerReportActive, // s: ULONG; s: 0 disables, otherwise enables
        ThreadAttachContainer, // s: HANDLE (job object) // NtCurrentThread
        ThreadManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
        ThreadPowerThrottlingState, // POWER_THROTTLING_THREAD_STATE
        ThreadWorkloadClass, // THREAD_WORKLOAD_CLASS // since REDSTONE5 // 50
        ThreadCreateStateChange, // since WIN11
        ThreadApplyStateChange,
        ThreadStrongerBadHandleChecks, // since 22H1
        ThreadEffectiveIoPriority, // q: IO_PRIORITY_HINT
        ThreadEffectivePagePriority, // q: ULONG
        MaxThreadInfoClass
    }

    [Flags]
    internal enum PROCESS_CREATION_FLAGS : uint
    {
        NONE = 0,
        BREAKAWAY = 0x00000001,
        NO_DEBUG_INHERIT = 0x00000002,
        INHERIT_HANDLES = 0x00000004,
        OVERRIDE_ADDRESS_SPACE = 0x00000008,
        LARGE_PAGES = 0x00000010,
        LARGE_PAGE_SYSTEM_DLL = 0x00000020,
        PROTECTED_PROCESS = 0x00000040,
        CREATE_SESSION = 0x00000080,
        INHERIT_FROM_PARENT = 0x00000100,
        SUSPENDED = 0x00000200,
        EXTENDED_UNKNOWN = 0x00000400
    }

    [Flags]
    internal enum PROCESS_CREATION_MITIGATION_POLICY : ulong
    {
        DEP_ENABLE = 0x00000001,
        DEP_ATL_THUNK_ENABLE = 0x00000002,
        SEHOP_ENABLE = 0x00000004,
        FORCE_RELOCATE_IMAGES_ALWAYS_ON = 0x00000100,
        FORCE_RELOCATE_IMAGES_ALWAYS_OFF = 0x00000200,
        FORCE_RELOCATE_IMAGES_ALWAYS_ON_REQ_RELOCS = 0x00000300,
        HEAP_TERMINATE_ALWAYS_ON = 0x00001000,
        HEAP_TERMINATE_ALWAYS_OFF = 0x00002000,
        BOTTOM_UP_ASLR_ALWAYS_ON = 0x00010000,
        BOTTOM_UP_ASLR_ALWAYS_OFF = 0x00020000,
        HIGH_ENTROPY_ASLR_ALWAYS_ON = 0x00100000,
        HIGH_ENTROPY_ASLR_ALWAYS_OFF = 0x00200000,
        STRICT_HANDLE_CHECKS_ALWAYS_ON = 0x01000000,
        STRICT_HANDLE_CHECKS_ALWAYS_OFF = 0x02000000,
        WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON = 0x10000000,
        WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_OFF = 0x20000000,
        EXTENSION_POINT_DISABLE_ALWAYS_ON = 0x0000000100000000,
        EXTENSION_POINT_DISABLE_ALWAYS_OFF = 0x0000000200000000,
        PROHIBIT_DYNAMIC_CODE_MASK = 0x0000003000000000,
        PROHIBIT_DYNAMIC_CODE_DEFER = 0x0000000000000000,
        PROHIBIT_DYNAMIC_CODE_ALWAYS_ON = 0x0000001000000000,
        PROHIBIT_DYNAMIC_CODE_ALWAYS_OFF = 0x0000002000000000,
        PROHIBIT_DYNAMIC_CODE_ALWAYS_ON_ALLOW_OPT_OUT = 0x0000003000000000,
        CONTROL_FLOW_GUARD_MASK = 0x0000030000000000,
        CONTROL_FLOW_GUARD_DEFER = 0x0000000000000000,
        CONTROL_FLOW_GUARD_ALWAYS_ON = 0x0000010000000000,
        CONTROL_FLOW_GUARD_ALWAYS_OFF = 0x0000010000000000,
        CONTROL_FLOW_GUARD_EXPORT_SUPPRESSION = 0x0000030000000000,
        BLOCK_NON_MICROSOFT_BINARIES_MASK = 0x0000300000000000,
        BLOCK_NON_MICROSOFT_BINARIES_DEFER = 0x0000000000000000,
        BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x0000100000000000,
        BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_OFF = 0x0000200000000000,
        BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE = 0x0000300000000000,
        FONT_DISABLE_MASK = 0x0003000000000000,
        FONT_DISABLE_DEFER = 0x0000000000000000,
        FONT_DISABLE_ALWAYS_ON = 0x0001000000000000,
        FONT_DISABLE_ALWAYS_OFF = 0x0002000000000000,
        AUDIT_NONSYSTEM_FONTS = 0x0003000000000000,
        IMAGE_LOAD_NO_REMOTE_MASK = 0x0030000000000000,
        IMAGE_LOAD_NO_REMOTE_DEFER = 0x0000000000000000,
        IMAGE_LOAD_NO_REMOTE_ALWAYS_ON = 0x0010000000000000,
        IMAGE_LOAD_NO_REMOTE_ALWAYS_OFF = 0x0020000000000000,
        IMAGE_LOAD_NO_REMOTE_RESERVED = 0x0030000000000000,
        IMAGE_LOAD_NO_LOW_LABEL_MASK = 0x0300000000000000,
        IMAGE_LOAD_NO_LOW_LABEL_DEFER = 0x0000000000000000,
        IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON = 0x0100000000000000,
        IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_OFF = 0x0200000000000000,
        IMAGE_LOAD_NO_LOW_LABEL_RESERVED = 0x0300000000000000,
        IMAGE_LOAD_PREFER_SYSTEM32_MASK = 0x3000000000000000,
        IMAGE_LOAD_PREFER_SYSTEM32_DEFER = 0x0000000000000000,
        IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON = 0x1000000000000000,
        IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_OFF = 0x2000000000000000,
        IMAGE_LOAD_PREFER_SYSTEM32_RESERVED = 0x3000000000000000,
    }

    internal enum PS_ATTRIBUTE_NUM
    {
        PsAttributeParentProcess, // in HANDLE
        PsAttributeDebugObject, // in HANDLE
        PsAttributeToken, // in HANDLE
        PsAttributeClientId, // out PCLIENT_ID
        PsAttributeTebAddress, // out PTEB *
        PsAttributeImageName, // in PWSTR
        PsAttributeImageInfo, // out PSECTION_IMAGE_INFORMATION
        PsAttributeMemoryReserve, // in PPS_MEMORY_RESERVE
        PsAttributePriorityClass, // in UCHAR
        PsAttributeErrorMode, // in ULONG
        PsAttributeStdHandleInfo, // 10, in PPS_STD_HANDLE_INFO
        PsAttributeHandleList, // in HANDLE[]
        PsAttributeGroupAffinity, // in PGROUP_AFFINITY
        PsAttributePreferredNode, // in PUSHORT
        PsAttributeIdealProcessor, // in PPROCESSOR_NUMBER
        PsAttributeUmsThread, // ? in PUMS_CREATE_THREAD_ATTRIBUTES
        PsAttributeMitigationOptions, // in PPS_MITIGATION_OPTIONS_MAP (PROCESS_CREATION_MITIGATION_POLICY_*) // since WIN8
        PsAttributeProtectionLevel, // in PS_PROTECTION // since WINBLUE
        PsAttributeSecureProcess, // in PPS_TRUSTLET_CREATE_ATTRIBUTES, since THRESHOLD
        PsAttributeJobList, // in HANDLE[]
        PsAttributeChildProcessPolicy, // 20, in PULONG (PROCESS_CREATION_CHILD_PROCESS_*) // since THRESHOLD2
        PsAttributeAllApplicationPackagesPolicy, // in PULONG (PROCESS_CREATION_ALL_APPLICATION_PACKAGES_*) // since REDSTONE
        PsAttributeWin32kFilter, // in PWIN32K_SYSCALL_FILTER
        PsAttributeSafeOpenPromptOriginClaim, // in
        PsAttributeBnoIsolation, // in PPS_BNO_ISOLATION_PARAMETERS // since REDSTONE2
        PsAttributeDesktopAppPolicy, // in PULONG (PROCESS_CREATION_DESKTOP_APP_*)
        PsAttributeChpe, // in BOOLEAN // since REDSTONE3
        PsAttributeMitigationAuditOptions, // in PPS_MITIGATION_AUDIT_OPTIONS_MAP (PROCESS_CREATION_MITIGATION_AUDIT_POLICY_*) // since 21H1
        PsAttributeMachineType, // in WORD // since 21H2
        PsAttributeComponentFilter,
        PsAttributeEnableOptionalXStateFeatures, // since WIN11
        PsAttributeMax
    }

    /*
     * Reference:
     * https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h
     */
    internal enum PS_ATTRIBUTES : ulong
    {
        PARENT_PROCESS = 0x00060000, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeParentProcess, false, true, true);
        DEBUG_OBJECT = 0x00060001, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeDebugObject, false, true, true);
        TOKEN = 0x00060002, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeToken, false, true, true);
        CLIENT_ID = 0x00010003, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeClientId, true, false, false);
        TEB_ADDRESS = 0x00010004, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeTebAddress, true, false, false);
        IMAGE_NAME = 0x00020005, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeImageName, false, true, false);
        IMAGE_INFO = 0x00000006, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeImageInfo, false, false, false);
        MEMORY_RESERVE = 0x00020007, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeMemoryReserve, false, true, false);
        PRIORITY_CLASS = 0x00020008, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributePriorityClass, false, true, false);
        ERROR_MODE = 0x00020009, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeErrorMode, false, true, false);
        STD_HANDLE_INFO = 0x0002000A, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeStdHandleInfo, false, true, false);
        HANDLE_LIST = 0x0002000B, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeHandleList, false, true, false);
        GROUP_AFFINITY = 0x0003000C, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeGroupAffinity, true, true, false);
        PREFERRED_NODE = 0x0002000D, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributePreferredNode, false, true, false);
        IDEAL_PROCESSOR = 0x0003000E, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeIdealProcessor, true, true, false);
        UMS_THREAD = 0x0003000F, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeUmsThread, true, true, false);
        MITIGATION_OPTIONS = 0x00020010, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeMitigationOptions, false, true, false);
        PROTECTION_LEVEL = 0x00060011, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeProtectionLevel, false, true, true);
        SECURE_PROCESS = 0x00020012, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeSecureProcess, false, true, false);
        JOB_LIST = 0x00020013, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeJobList, false, true, false);
        CHILD_PROCESS_POLICY = 0x00020014, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeChildProcessPolicy, false, true, false);
        ALL_APPLICATION_PACKAGES_POLICY = 0x00020015, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeAllApplicationPackagesPolicy, false, true, false);
        WIN32K_FILTER = 0x00020016, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeWin32kFilter, false, true, false);
        SAFE_OPEN_PROMPT_ORIGIN_CLAIM = 0x00020017, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeSafeOpenPromptOriginClaim, false, true, false);
        BNO_ISOLATION = 0x00020018, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeBnoIsolation, false, true, false);
        DESKTOP_APP_POLICY = 0x00020019, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeDesktopAppPolicy, false, true, false);
        CHPE = 0x0006001A, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeChpe, false, true, true);
        MITIGATION_AUDIT_OPTIONS = 0x0002001B, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeMitigationAuditOptions, false, true, false);
        MACHINE_TYPE = 0x0006001C, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeMachineType, false, true, true);
        COMPONENT_FILTER = 0x0002001D, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeComponentFilter, false, true, false);
        ENABLE_OPTIONAL_XSTATE_FEATURES = 0x0003001E, // PsAttributeValue(PS_ATTRIBUTE_NUM.PsAttributeEnableOptionalXStateFeatures, true, true, false);
    }

    [Flags]
    internal enum PS_CREATE_INIT_FLAGS : uint
    {
        WriteOutputOnExit = 0x00000001,
        DetectManifest = 0x00000002,
        IFEOSkipDebugger = 0x00000004,
        IFEODoNotPropagateKeyState = 0x00000008,
        ProhibitedImageCharacteristics = 0xFFFF0000
    }

    [Flags]
    internal enum PS_CREATE_OUTPUT_FLAGS : uint
    {
        ProtectedProcess = 0x00000001,
        AddressSpaceOverride = 0x00000002,
        DevOverrideEnabled = 0x00000004,
        ManifestDetected = 0x00000008,
        ProtectedProcessLight = 0x00000010
    }

    internal enum PS_CREATE_STATE
    {
        PsCreateInitialState,
        PsCreateFailOnFileOpen,
        PsCreateFailOnSectionCreate,
        PsCreateFailExeFormat,
        PsCreateFailMachineMismatch,
        PsCreateFailExeName, // Debugger specified
        PsCreateSuccess,
        PsCreateMaximumStates
    }

    [Flags]
    internal enum THREAD_CREATION_FLAGS : uint
    {
        NONE = 0,
        CREATE_SUSPENDED = 0x00000001,
        SKIP_THREAD_ATTACH = 0x00000002,
        HIDE_FROM_DEBUGGER = 0x00000004,
        HAS_SECURITY_DESCRIPTOR = 0x00000010,
        ACCESS_CHECK_IN_TARGET = 0x00000020,
        INITIAL_THREAD = 0x00000080
    }

    internal enum PROC_THREAD_ATTRIBUTE_NUM : uint
    {
        ProcThreadAttributeParentProcess = 0, // in HANDLE
        ProcThreadAttributeExtendedFlags = 1, // in ULONG (EXTENDED_PROCESS_CREATION_FLAG_*)
        ProcThreadAttributeHandleList = 2, // in HANDLE[]
        ProcThreadAttributeGroupAffinity = 3, // in GROUP_AFFINITY // since WIN7
        ProcThreadAttributePreferredNode = 4, // in USHORT
        ProcThreadAttributeIdealProcessor = 5, // in PROCESSOR_NUMBER
        ProcThreadAttributeUmsThread = 6, // in UMS_CREATE_THREAD_ATTRIBUTES
        ProcThreadAttributeMitigationPolicy = 7, // in ULONG, ULONG64, or ULONG64[2]
        ProcThreadAttributePackageFullName = 8, // in WCHAR[] // since WIN8
        ProcThreadAttributeSecurityCapabilities = 9, // in SECURITY_CAPABILITIES
        ProcThreadAttributeConsoleReference = 10, // BaseGetConsoleReference (kernelbase.dll)
        ProcThreadAttributeProtectionLevel = 11, // in ULONG (PROTECTION_LEVEL_*) // since WINBLUE
        ProcThreadAttributeOsMaxVersionTested = 12, // in MAXVERSIONTESTED_INFO // since THRESHOLD // (from exe.manifest)
        ProcThreadAttributeJobList = 13, // in HANDLE[]
        ProcThreadAttributeChildProcessPolicy = 14, // in ULONG (PROCESS_CREATION_CHILD_PROCESS_*) // since THRESHOLD2
        ProcThreadAttributeAllApplicationPackagesPolicy = 15, // in ULONG (PROCESS_CREATION_ALL_APPLICATION_PACKAGES_*) // since REDSTONE
        ProcThreadAttributeWin32kFilter = 16, // in WIN32K_SYSCALL_FILTER
        ProcThreadAttributeSafeOpenPromptOriginClaim = 17, // in SE_SAFE_OPEN_PROMPT_RESULTS
        ProcThreadAttributeDesktopAppPolicy = 18, // in ULONG (PROCESS_CREATION_DESKTOP_APP_*) // since RS2
        ProcThreadAttributeBnoIsolation = 19, // in PROC_THREAD_BNOISOLATION_ATTRIBUTE
        ProcThreadAttributePseudoConsole = 22, // in HANDLE (HPCON) // since RS5
        ProcThreadAttributeIsolationManifest = 23, // in ISOLATION_MANIFEST_PROPERTIES // rev (diversenok) // since 19H2+
        ProcThreadAttributeMitigationAuditPolicy = 24, // in ULONG, ULONG64, or ULONG64[2] // since 21H1
        ProcThreadAttributeMachineType = 25, // in USHORT // since 21H2
        ProcThreadAttributeComponentFilter = 26, // in ULONG
        ProcThreadAttributeEnableOptionalXStateFeatures = 27, // in ULONG64 // since WIN11
        ProcThreadAttributeCreateStore = 28, // ULONG // rev (diversenok)
        ProcThreadAttributeTrustedApp = 29
    }

    internal enum PROC_THREAD_ATTRIBUTES
    {
        GROUP_AFFINITY = 0x00030003,
        HANDLE_LIST = 0x00020002,
        IDEAL_PROCESSOR = 0x00030005,
        MITIGATION_POLICY = 0x00020007,
        PARENT_PROCESS = 0x00020000,
        PREFERRED_NODE = 0x00020004,
        UMS_THREAD = 0x00030006,
        SECURITY_CAPABILITIES = 0x00020009,
        PROTECTION_LEVEL = 0x0002000B,
        CHILD_PROCESS_POLICY = 0x0002000E,
        DESKTOP_APP_POLICY = 0x00020012,
        JOB_LIST = 0x0002000D,
        ENABLE_OPTIONAL_XSTATE_FEATURES = 0x0003001B,
        // Definitions for NtCreateThreadEx
        EXTENDED_FLAGS = 0x00060001, // ProcThreadAttributeValue(ProcThreadAttributeExtendedFlags, FALSE, TRUE, TRUE)
        PACKAGE_FULL_NAME = 0x00020008, // ProcThreadAttributeValue(ProcThreadAttributePackageFullName, FALSE, TRUE, FALSE)
        CONSOLE_REFERENCE = 0x0002000A, // ProcThreadAttributeValue(ProcThreadAttributeConsoleReference, FALSE, TRUE, FALSE)
        OSMAXVERSIONTESTED = 0x0002000C, // ProcThreadAttributeValue(ProcThreadAttributeOsMaxVersionTested, FALSE, TRUE, FALSE)
        SAFE_OPEN_PROMPT_ORIGIN_CLAIM = 0x00020011, // ProcThreadAttributeValue(ProcThreadAttributeSafeOpenPromptOriginClaim, FALSE, TRUE, FALSE)
        BNO_ISOLATION = 0x00020013, // ProcThreadAttributeValue(ProcThreadAttributeBnoIsolation, FALSE, TRUE, FALSE)
        ISOLATION_MANIFEST = 0x00020017, // ProcThreadAttributeValue(ProcThreadAttributeIsolationManifest, FALSE, TRUE, FALSE)
        CREATE_STORE = 0x0002001C // ProcThreadAttributeValue(ProcThreadAttributeCreateStore, FALSE, TRUE, FALSE)
    }

    [Flags]
    internal enum ProcessAccessFlags : uint
    {
        PROCESS_ALL_ACCESS = 0x001F0FFF,
        Terminate = 0x00000001,
        PROCESS_CREATE_THREAD = 0x00000002,
        PROCESS_VM_OPERATION = 0x00000008,
        PROCESS_VM_READ = 0x00000010,
        PROCESS_VM_WRITE = 0x00000020,
        PROCESS_DUP_HANDLE = 0x00000040,
        PROCESS_CREATE_PROCESS = 0x000000080,
        PROCESS_SET_QUOTA = 0x00000100,
        PROCESS_SET_INFORMATION = 0x00000200,
        PROCESS_QUERY_INFORMATION = 0x00000400,
        PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000,
        SYNCHRONIZE = 0x00100000,
        MAXIMUM_ALLOWED = 0x02000000
    }

    [Flags]
    internal enum ProcessCreationFlags : uint
    {
        DEBUG_PROCESS = 0x00000001,
        DEBUG_ONLY_THIS_PROCESS = 0x00000002,
        CREATE_SUSPENDED = 0x00000004,
        DETACHED_PROCESS = 0x00000008,
        CREATE_NEW_CONSOLE = 0x00000010,
        CREATE_NEW_PROCESS_GROUP = 0x00000200,
        CREATE_UNICODE_ENVIRONMENT = 0x00000400,
        CREATE_SEPARATE_WOW_VDM = 0x00000800,
        CREATE_SHARED_WOW_VDM = 0x00001000,
        INHERIT_PARENT_AFFINITY = 0x00010000,
        CREATE_PROTECTED_PROCESS = 0x00040000,
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
        CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
        CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
        CREATE_DEFAULT_ERROR_MODE = 0x04000000,
        CREATE_NO_WINDOW = 0x08000000,
    }

    internal enum FILE_POINTER_MOVE_METHOD
    {
        FILE_BEGIN,
        FILE_CURRENT,
        FILE_END
    }

    internal enum IMAGE_REL_BASED_TYPE
    {
        ABSOLUTE = 0,
        HIGH = 1,
        LOW = 2,
        HIGHLOW = 3,
        HIGHADJ = 4,
        MACHINE_SPECIFIC_5 = 5,
        RESERVED = 6,
        MACHINE_SPECIFIC_7 = 7,
        MACHINE_SPECIFIC_8 = 8,
        MACHINE_SPECIFIC_9 = 9,
        DIR64 = 10
    }

    [Flags]
    internal enum LDR_DATA_TABLE_ENTRY_FLAGS : uint
    {
        LDRP_PACKAGED_BINARY = 0x00000001,
        LDRP_MARKED_FOR_REMOVAL = 0x00000002,
        LDRP_IMAGE_DLL = 0x00000004,
        LDRP_LOAD_NOTIFICATIONS_SENT = 0x00000008,
        LDRP_TELEMETRY_ENTRY_PROCESSED = 0x00000010,
        LDRP_PROCESS_STATIC_IMPORT = 0x00000020,
        LDRP_IN_LEGACY_LISTS = 0x00000040,
        LDRP_IN_INDEXES = 0x00000080,
        LDRP_SHIM_DLL = 0x00000100,
        LDRP_IN_EXCEPTION_TABLE = 0x00000200,
        LDRP_LOAD_IN_PROGRESS = 0x00001000,
        LDRP_LOAD_CONFIG_PROCESSED = 0x00002000,
        LDRP_ENTRY_PROCESSED = 0x00004000,
        LDRP_PROTECT_DELAY_LOAD = 0x00008000,
        LDRP_DONT_CALL_FOR_THREADS = 0x00040000,
        LDRP_PROCESS_ATTACH_CALLED = 0x00080000,
        LDRP_PROCESS_ATTACH_FAILED = 0x00100000,
        LDRP_COR_DEFERRED_VALIDATE = 0x00200000,
        LDRP_COR_IMAGE = 0x00400000,
        LDRP_DONT_RELOCATE = 0x00800000,
        LDRP_COR_IL_ONLY = 0x01000000,
        LDRP_CHPE_IMAGE = 0x02000000,
        LDRP_CHPE_EMULATOR_IMAGE = 0x04000000,
        LDRP_REDIRECTED = 0x10000000,
        LDRP_COMPAT_DATABASE_PROCESSED = 0x80000000
    }

    [Flags]
    internal enum LDR_DATA_TABLE_ENTRY_FLAGS_INTERNAL : uint
    {
        PackagedBinary = 0x00000001,
        MarkedForRemoval = 0x00000002,
        ImageDll = 0x00000004,
        LoadNotificationsSent = 0x00000008,
        TelemetryEntryProcessed = 0x00000010,
        ProcessStaticImport = 0x00000020,
        InLegacyLists = 0x00000040,
        InIndexes = 0x00000080,
        ShimDll = 0x00000100,
        InExceptionTable = 0x00000200,
        ReservedFlags1 = 0x00000C00,
        LoadInProgress = 0x00001000,
        LoadConfigProcessed = 0x00002000,
        EntryProcessed = 0x00004000,
        ProtectDelayLoad = 0x00008000,
        ReservedFlags3 = 0x00030000,
        DontCallForThreads = 0x00040000,
        ProcessAttachCalled = 0x00080000,
        ProcessAttachFailed = 0x00100000,
        CorDeferredValidate = 0x00200000,
        CorImage = 0x00400000,
        DontRelocate = 0x00800000,
        CorILOnly = 0x01000000,
        ChpeImage = 0x02000000,
        ReservedFlags5 = 0x0C000000,
        Redirected = 0x10000000,
        ReservedFlags6 = 0x60000000,
        CompatDatabaseProcessed = 0x80000000
    }

    internal enum LDR_DDAG_STATE
    {
        LdrModulesMerged = -5,
        LdrModulesInitError = -4,
        LdrModulesSnapError = -3,
        LdrModulesUnloaded = -2,
        LdrModulesUnloading = -1,
        LdrModulesPlaceHolder = 0,
        LdrModulesMapping = 1,
        LdrModulesMapped = 2,
        LdrModulesWaitingForDependencies = 3,
        LdrModulesSnapping = 4,
        LdrModulesSnapped = 5,
        LdrModulesCondensed = 6,
        LdrModulesReadyToInit = 7,
        LdrModulesInitializing = 8,
        LdrModulesReadyToRun = 9
    }

    internal enum LDR_DLL_LOAD_REASON
    {
        StaticDependency = 0,
        StaticForwarderDependency = 1,
        DynamicForwarderDependency = 2,
        DelayloadDependency = 3,
        DynamicLoad = 4,
        AsImageLoad = 5,
        AsDataLoad = 6,
        EnclavePrimary = 7,
        EnclaveDependency = 8,
        PatchImage = 9,
        Unknown = -1
    }

    internal enum LDR_HOT_PATCH_STATE
    {
        LdrHotPatchBaseImage = 0,
        LdrHotPatchNotApplied = 1,
        LdrHotPatchAppliedReverse = 2,
        LdrHotPatchAppliedForward = 3,
        LdrHotPatchFailedToPatch = 4,
        LdrHotPatchStateMax = 5
    }

    [Flags]
    internal enum SectionFlags : uint
    {
        TYPE_NO_PAD = 0x00000008,
        CNT_CODE = 0x00000020,
        CNT_INITIALIZED_DATA = 0x00000040,
        CNT_UNINITIALIZED_DATA = 0x00000080,
        LNK_INFO = 0x00000200,
        LNK_REMOVE = 0x00000800,
        LNK_COMDAT = 0x00001000,
        NO_DEFER_SPEC_EXC = 0x00004000,
        GPREL = 0x00008000,
        MEM_FARDATA = 0x00008000,
        MEM_PURGEABLE = 0x00020000,
        MEM_16BIT = 0x00020000,
        MEM_LOCKED = 0x00040000,
        MEM_PRELOAD = 0x00080000,
        ALIGN_1BYTES = 0x00100000,
        ALIGN_2BYTES = 0x00200000,
        ALIGN_4BYTES = 0x00300000,
        ALIGN_8BYTES = 0x00400000,
        ALIGN_16BYTES = 0x00500000,
        ALIGN_32BYTES = 0x00600000,
        ALIGN_64BYTES = 0x00700000,
        ALIGN_128BYTES = 0x00800000,
        ALIGN_256BYTES = 0x00900000,
        ALIGN_512BYTES = 0x00A00000,
        ALIGN_1024BYTES = 0x00B00000,
        ALIGN_2048BYTES = 0x00C00000,
        ALIGN_4096BYTES = 0x00D00000,
        ALIGN_8192BYTES = 0x00E00000,
        ALIGN_MASK = 0x00F00000,
        LNK_NRELOC_OVFL = 0x01000000,
        MEM_DISCARDABLE = 0x02000000,
        MEM_NOT_CACHED = 0x04000000,
        MEM_NOT_PAGED = 0x08000000,
        MEM_SHARED = 0x10000000,
        MEM_EXECUTE = 0x20000000,
        MEM_READ = 0x40000000,
        MEM_WRITE = 0x80000000
    }

    internal enum BINARY_TYPE
    {
        SCS_32BIT_BINARY,
        SCS_DOS_BINARY,
        SCS_WOW_BINARY,
        SCS_PIF_BINARY,
        SCS_POSIX_BINARY,
        SCS_OS216_BINARY,
        SCS_64BIT_BINARY,
    }

    [Flags]
    internal enum IMAGE_FILE_MACHINE : ushort
    {
        UNKNOWN = 0,
        TARGET_HOST = 0x0001,
        I386 = 0x014c,
        R3000 = 0x0162,
        R4000 = 0x0166,
        R10000 = 0x0168,
        WCEMIPSV2 = 0x0169,
        ALPHA = 0x0184,
        SH3 = 0x01a2,
        SH3DSP = 0x01a3,
        SH3E = 0x01a4,
        SH4 = 0x01a6,
        SH5 = 0x01a8,
        ARM = 0x01c0,
        THUMB = 0x01c2,
        ARMNT = 0x01c4,
        AM33 = 0x01d3,
        POWERPC = 0x01F0,
        POWERPCFP = 0x01f1,
        IA64 = 0x0200,
        MIPS16 = 0x0266,
        ALPHA64 = 0x0284,
        MIPSFPU = 0x0366,
        MIPSFPU16 = 0x0466,
        AXP64 = 0x0284,
        TRICORE = 0x0520,
        CEF = 0x0CEF,
        EBC = 0x0EBC,
        AMD64 = 0x8664,
        M32R = 0x9041,
        ARM64 = 0xAA64
    }

    [Flags]
    internal enum STARTF : uint
    {
        STARTF_USESHOWWINDOW = 0x00000001,
        STARTF_USESIZE = 0x00000002,
        STARTF_USEPOSITION = 0x00000004,
        STARTF_USECOUNTCHARS = 0x00000008,
        STARTF_USEFILLATTRIBUTE = 0x00000010,
        STARTF_RUNFULLSCREEN = 0x00000020, // ignored for non-x86 platforms
        STARTF_FORCEONFEEDBACK = 0x00000040,
        STARTF_FORCEOFFFEEDBACK = 0x00000080,
        STARTF_USESTDHANDLES = 0x00000100,
        STARTF_USEHOTKEY = 0x00000200,
        STARTF_TITLEISLINKNAME = 0x00000800,
        STARTF_TITLEISAPPID = 0x00001000,
        STARTF_PREVENTPINNING = 0x00002000,
        STARTF_UNTRUSTEDSOURCE = 0x00008000,
    }

    internal enum DllCharacteristicsType : ushort
    {
        RES_0 = 0x0001,
        RES_1 = 0x0002,
        RES_2 = 0x0004,
        RES_3 = 0x0008,
        IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
        IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
        IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
        IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
        IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
        IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
        RES_4 = 0x1000,
        IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
        IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
    }

    internal enum KTHREAD_STATE
    {
        Initialized,
        Ready,
        Running,
        Standby,
        Terminated,
        Waiting,
        Transition,
        DeferredReady,
        GateWaitObsolete,
        WaitingForProcessInSwap,
        MaximumThreadState
    }

    internal enum KWAIT_REASON
    {
        Executive,
        FreePage,
        PageIn,
        PoolAllocation,
        DelayExecution,
        Suspended,
        UserRequest,
        WrExecutive,
        WrFreePage,
        WrPageIn,
        WrPoolAllocation,
        WrDelayExecution,
        WrSuspended,
        WrUserRequest,
        WrEventPair,
        WrQueue,
        WrLpcReceive,
        WrLpcReply,
        WrVirtualMemory,
        WrPageOut,
        WrRendezvous,
        WrKeyedEvent,
        WrTerminated,
        WrProcessInSwap,
        WrCpuRateControl,
        WrCalloutStack,
        WrKernel,
        WrResource,
        WrPushLock,
        WrMutex,
        WrQuantumEnd,
        WrDispatchInt,
        WrPreempted,
        WrYieldExecution,
        WrFastMutex,
        WrGuardedMutex,
        WrRundown,
        WrAlertByThreadId,
        WrDeferredPreempt,
        WrPhysicalFault,
        WrIoRing,
        WrMdlCache,
        WrRcu,
        MaximumWaitReason
    }

    internal enum MagicType : ushort
    {
        IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
        IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
    }

    [Flags]
    internal enum MEMORY_ALLOCATION_TYPE : uint
    {
        NONE = 0x00000000,
        MEM_COMMIT = 0x00001000,
        MEM_RESERVE = 0x00002000,
        MEM_DECOMMIT = 0x00004000,
        MEM_RELEASE = 0x00008000,
        MEM_FREE = 0x00010000,
        MEM_PRIVATE = 0x00020000,
        MEM_MAPPED = 0x00040000,
        MEM_RESET = 0x00080000,
        MEM_TOP_DOWN = 0x00100000,
        MEM_WRITE_WATCH = 0x00200000,
        MEM_PHYSICAL = 0x00400000,
        MEM_ROTATE = 0x00800000,
        MEM_DIFFERENT_IMAGE_BASE_OK = 0x00800000,
        MEM_IMAGE = 0x01000000,
        // MEM_RESET_UNDO = 0x01000000,
        MEM_LARGE_PAGES = 0x20000000,
        MEM_DOS_LIM = 0x40000000,
        MEM_4MB_PAGES = 0x80000000,
        MEM_64K_PAGES = (MEM_LARGE_PAGES | MEM_PHYSICAL)
    }

    internal enum MEMORY_INFORMATION_CLASS
    {
        MemoryBasicInformation, // MEMORY_BASIC_INFORMATION
        MemoryWorkingSetInformation, // MEMORY_WORKING_SET_INFORMATION
        MemoryMappedFilenameInformation, // UNICODE_STRING
        MemoryRegionInformation, // MEMORY_REGION_INFORMATION
        MemoryWorkingSetExInformation, // MEMORY_WORKING_SET_EX_INFORMATION // since VISTA
        MemorySharedCommitInformation, // MEMORY_SHARED_COMMIT_INFORMATION // since WIN8
        MemoryImageInformation, // MEMORY_IMAGE_INFORMATION
        MemoryRegionInformationEx, // MEMORY_REGION_INFORMATION
        MemoryPrivilegedBasicInformation,
        MemoryEnclaveImageInformation, // MEMORY_ENCLAVE_IMAGE_INFORMATION // since REDSTONE3
        MemoryBasicInformationCapped, // 10
        MemoryPhysicalContiguityInformation, // MEMORY_PHYSICAL_CONTIGUITY_INFORMATION // since 20H1
        MemoryBadInformation, // since WIN11
        MemoryBadInformationAllProcesses, // since 22H1
        MaxMemoryInfoClass
    }

    internal enum SE_PRIVILEGE_ID
    {
        SeCreateTokenPrivilege = 2,
        SeAssignPrimaryTokenPrivilege,
        SeLockMemoryPrivilege,
        SeIncreaseQuotaPrivilege,
        SeMachineAccountPrivilege,
        SeTcbPrivilege,
        SeSecurityPrivilege,
        SeTakeOwnershipPrivilege,
        SeLoadDriverPrivilege,
        SeSystemProfilePrivilege,
        SeSystemtimePrivilege,
        SeProfileSingleProcessPrivilege,
        SeIncreaseBasePriorityPrivilege,
        SeCreatePagefilePrivilege,
        SeCreatePermanentPrivilege,
        SeBackupPrivilege,
        SeRestorePrivilege,
        SeShutdownPrivilege,
        SeDebugPrivilege,
        SeAuditPrivilege,
        SeSystemEnvironmentPrivilege,
        SeChangeNotifyPrivilege,
        SeRemoteShutdownPrivilege,
        SeUndockPrivilege,
        SeSyncAgentPrivilege,
        SeEnableDelegationPrivilege,
        SeManageVolumePrivilege,
        SeImpersonatePrivilege,
        SeCreateGlobalPrivilege,
        SeTrustedCredManAccessPrivilege,
        SeRelabelPrivilege,
        SeIncreaseWorkingSetPrivilege,
        SeTimeZonePrivilege,
        SeCreateSymbolicLinkPrivilege,
        SeDelegateSessionUserImpersonatePrivilege,
        MaximumCount
    }

    internal enum SECURITY_CONTEXT_TRACKING_MODE : byte
    {
        StaticTracking = 0,
        DynamicTracking
    }

    internal enum SubSystemType : ushort
    {
        IMAGE_SUBSYSTEM_UNKNOWN = 0,
        IMAGE_SUBSYSTEM_NATIVE = 1,
        IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
        IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
        IMAGE_SUBSYSTEM_POSIX_CUI = 7,
        IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
        IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
        IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
        IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
        IMAGE_SUBSYSTEM_EFI_ROM = 13,
        IMAGE_SUBSYSTEM_XBOX = 14
    }

    [Flags]
    internal enum SYM_OPTIONS : uint
    {
        CASE_INSENSITIVE = 0x00000001,
        UNDNAME = 0x00000002,
        DEFERRED_LOADS = 0x00000004,
        NO_CPP = 0x00000008,
        LOAD_LINES = 0x00000010,
        OMAP_FIND_NEAREST = 0x00000020,
        LOAD_ANYTHING = 0x00000040,
        IGNORE_CVREC = 0x00000080,
        NO_UNQUALIFIED_LOADS = 0x00000100,
        FAIL_CRITICAL_ERRORS = 0x00000200,
        EXACT_SYMBOLS = 0x00000400,
        ALLOW_ABSOLUTE_SYMBOLS = 0x00000800,
        IGNORE_NT_SYMPATH = 0x00001000,
        INCLUDE_32BIT_MODULES = 0x00002000,
        PUBLICS_ONLY = 0x00004000,
        NO_PUBLICS = 0x00008000,
        AUTO_PUBLICS = 0x00010000,
        NO_IMAGE_SEARCH = 0x00020000,
        SECURE = 0x00040000,
        NO_PROMPTS = 0x00080000,
        OVERWRITE = 0x00100000,
        IGNORE_IMAGEDIR = 0x00200000,
        FLAT_DIRECTORY = 0x00400000,
        FAVOR_COMPRESSED = 0x00800000,
        ALLOW_ZERO_ADDRESS = 0x01000000,
        DISABLE_SYMSRV_AUTODETECT = 0x02000000,
        DEBUG = 0x80000000
    }

    [Flags]
    internal enum ThreadCreationFlags : uint
    {
        IMMEDIATE = 0x00000000,
        CREATE_SUSPENDED = 0x00000004,
        STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000,
    }

    [Flags]
    internal enum ASLR_POLICY_FLAGS : uint
    {
        None = 0x00000000,
        EnableBottomUpRandomization = 0x00000001,
        EnableForceRelocateImages = 0x00000002,
        EnableHighEntropy = 0x00000004,
        DisallowStrippedImages = 0x00000008
    }

    [Flags]
    internal enum BINARY_SIGNATURE_POLICY_FLAGS : uint
    {
        None = 0x00000000,
        MicrosoftSignedOnly = 0x00000001,
        StoreSignedOnly = 0x00000002,
        MitigationOptIn = 0x00000004,
        AuditMicrosoftSignedOnly = 0x00000008,
        AuditStoreSignedOnly = 0x00000010
    }

    [Flags]
    internal enum CONTROL_FLOW_GUARD_POLICY_FLAGS : uint
    {
        None = 0x00000000,
        EnableControlFlowGuard = 0x00000001,
        EnableExportSuppression = 0x00000002,
        StrictMode = 0x00000004,
        EnableXfgy = 0x00000008,
        EnableXfgAuditMode = 0x00000010
    }

    [Flags]
    internal enum DEP_POLICY_FLAGS : uint
    {
        None = 0x00000000,
        Enable = 0x00000001,
        DisableAtlThunkEmulation = 0x00000002
    }

    [Flags]
    internal enum DYNAMIC_CODE_POLICY_FLAGS : uint
    {
        None = 0x00000000,
        ProhibitDynamicCode = 0x00000001,
        AllowThreadOptOut = 0x00000002,
        AllowRemoteDowngrade = 0x00000004,
        AuditProhibitDynamicCode = 0x00000008
    }

    [Flags]
    internal enum EXTENSION_POINT_DISABLE_POLICY_FLAGS : uint
    {
        None = 0x00000000,
        DisableExtensionPoints = 0x00000001
    }

    [Flags]
    internal enum FONT_DISABLE_POLICY_FLAGS : uint
    {
        None = 0x00000000,
        DisableNonSystemFonts = 0x00000001,
        AuditNonSystemFontLoading = 0x00000002
    }

    [Flags]
    internal enum IMAGE_LOAD_POLICY_FLAGS : uint
    {
        None = 0x00000000,
        NoRemoteImages = 0x00000001,
        NoLowMandatoryLabelImages = 0x00000002,
        PreferSystem32Images = 0x00000004,
        AuditNoRemoteImages = 0x00000008,
        AuditNoLowMandatoryLabelImages = 0x00000010
    }

    internal enum PROCESS_MITIGATION_POLICY : uint
    {
        ProcessDEPPolicy,
        ProcessASLRPolicy,
        ProcessDynamicCodePolicy,
        ProcessStrictHandleCheckPolicy,
        ProcessSystemCallDisablePolicy,
        ProcessMitigationOptionsMask,
        ProcessExtensionPointDisablePolicy,
        ProcessControlFlowGuardPolicy,
        ProcessSignaturePolicy,
        ProcessFontDisablePolicy,
        ProcessImageLoadPolicy,
        ProcessSystemCallFilterPolicy,
        ProcessPayloadRestrictionPolicy,
        ProcessChildProcessPolicy,
        ProcessSideChannelIsolationPolicy,
        ProcessUserShadowStackPolicy,
        ProcessRedirectionTrustPolicy,
        ProcessUserPointerAuthPolicy,
        ProcessSEHOPPolicy,
        MaxProcessMitigationPolicy
    }

    [Flags]
    internal enum REDIRECTION_TRUST_POLICY_FLAGS : uint
    {
        None = 0x00000000,
        EnforceRedirectionTrust = 0x00000001,
        AuditRedirectionTrust = 0x00000002
    }

    [Flags]
    internal enum SIDE_CHANNEL_ISOLATION_POLICY_FLAGS : uint
    {
        None = 0x00000000,
        SmtBranchTargetIsolation = 0x00000001,
        IsolateSecurityDomain = 0x00000002,
        DisablePageCombine = 0x00000004,
        SpeculativeStoreBypassDisable = 0x00000008,
        RestrictCoreSharing = 0x00000010
    }

    [Flags]
    internal enum STRICT_HANDLE_CHECK_POLICY_FLAGS : uint
    {
        None = 0x00000000,
        RaiseExceptionOnInvalidHandleReference = 0x00000001,
        HandleExceptionsPermanentlyEnabled = 0x00000002
    }

    [Flags]
    internal enum SYSTEM_CALL_DISABLE_POLICY_FLAGS : uint
    {
        None = 0x00000000,
        DisallowWin32kSystemCalls = 0x00000001,
        AuditDisallowWin32kSystemCalls = 0x00000002
    }

    [Flags]
    internal enum USER_SHADOW_STACK_POLICY_FLAGS : uint
    {
        None = 0x00000000,
        EnableUserShadowStack = 0x00000001,
        AuditUserShadowStack = 0x00000002,
        SetContextIpValidation = 0x00000004,
        AuditSetContextIpValidation = 0x00000008,
        EnableUserShadowStackStrictMode = 0x00000010,
        BlockNonCetBinaries = 0x00000020,
        BlockNonCetBinariesNonEhcont = 0x00000040,
        AuditBlockNonCetBinaries = 0x00000080,
        CetDynamicApisOutOfProcOnly = 0x00000100,
        SetContextIpValidationRelaxedMode = 0x00000200
    }
}