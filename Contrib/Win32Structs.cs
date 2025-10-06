using System;
using System.Runtime.InteropServices;
using System.Text;
using ProcessParentDumper.Win32Enums;

namespace ProcessParentDumper.NativeStructs
{
    using NTSTATUS = Int32;
    using SIZE_T = UIntPtr;

    [StructLayout(LayoutKind.Sequential)]
    internal struct CLIENT_ID
    {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CURDIR
    {
        public UNICODE_STRING DosPath;
        public IntPtr Handle;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FILE_DISPOSITION_INFORMATION
    {
        public BOOLEAN DeleteFile;
        public FILE_DISPOSITION_INFORMATION(bool flag)
        {
            if (flag)
                DeleteFile = BOOLEAN.TRUE;
            else
                DeleteFile = BOOLEAN.FALSE;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FILE_DISPOSITION_INFORMATION_EX
    {
        public FILE_DISPOSITION_FLAGS Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IO_STATUS_BLOCK
    {
        public NTSTATUS status;
        public IntPtr information;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct LARGE_INTEGER
    {
        [FieldOffset(0)]
        public int Low;
        [FieldOffset(4)]
        public int High;
        [FieldOffset(0)]
        public long QuadPart;
        public long ToInt64()
        {
            return ((long)High << 32) | (uint)Low;
        }

        public static LARGE_INTEGER FromInt64(long value)
        {
            return new LARGE_INTEGER
            {
                Low = (int)(value),
                High = (int)((value >> 32))
            };
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct OBJECT_ATTRIBUTES : IDisposable
    {
        public int Length;
        public IntPtr RootDirectory;
        private IntPtr objectName;
        public OBJECT_ATTRIBUTES_FLAGS Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
        public OBJECT_ATTRIBUTES(string name, OBJECT_ATTRIBUTES_FLAGS attrs)
        {
            Length = 0;
            RootDirectory = IntPtr.Zero;
            objectName = IntPtr.Zero;
            Attributes = attrs;
            SecurityDescriptor = IntPtr.Zero;
            SecurityQualityOfService = IntPtr.Zero;
            Length = Marshal.SizeOf(this);
            ObjectName = new UNICODE_STRING(name);
        }

        public UNICODE_STRING ObjectName
        {
            get
            {
                return (UNICODE_STRING)Marshal.PtrToStructure(objectName, typeof(UNICODE_STRING));
            }

            set
            {
                bool fDeleteOld = objectName != IntPtr.Zero;
                if (!fDeleteOld)
                    objectName = Marshal.AllocHGlobal(Marshal.SizeOf(value));
                Marshal.StructureToPtr(value, objectName, fDeleteOld);
            }
        }

        public void Dispose()
        {
            if (objectName != IntPtr.Zero)
            {
                Marshal.DestroyStructure(objectName, typeof(UNICODE_STRING));
                Marshal.FreeHGlobal(objectName);
                objectName = IntPtr.Zero;
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PEB32_PARTIAL
    {
        public byte InheritedAddressSpace;
        public byte ReadImageFileExecOptions;
        public byte BeingDebugged;
        public byte BitField;
        public uint Mutant;
        public uint ImageBaseAddress;
        public uint Ldr;
        public uint ProcessParameters;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PEB64_PARTIAL
    {
        public byte InheritedAddressSpace;
        public byte ReadImageFileExecOptions;
        public byte BeingDebugged;
        public byte BitField;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Padding0;
        public ulong Mutant;
        public ulong ImageBaseAddress;
        public ulong Ldr; // _PEB_LDR_DATA*
        public ulong ProcessParameters; // _RTL_USER_PROCESS_PARAMETERS*
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_BASIC_INFORMATION
    {
        public NTSTATUS ExitStatus;
        public IntPtr PebBaseAddress;
        public UIntPtr AffinityMask;
        public int BasePriority;
        public UIntPtr UniqueProcessId;
        public UIntPtr InheritedFromUniqueProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RTL_DRIVE_LETTER_CURDIR
    {
        public ushort Flags;
        public ushort Length;
        public uint TimeStamp;
        public STRING DosPath;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RTL_USER_PROCESS_PARAMETERS
    {
        public uint MaximumLength;
        public uint Length;
        public uint Flags;
        public uint DebugFlags;
        public IntPtr ConsoleHandle;
        public uint ConsoleFlags;
        public IntPtr StandardInput;
        public IntPtr StandardOutput;
        public IntPtr StandardError;
        public CURDIR CurrentDirectory;
        public UNICODE_STRING DllPath;
        public UNICODE_STRING ImagePathName;
        public UNICODE_STRING CommandLine;
        public IntPtr Environment;
        public uint StartingX;
        public uint StartingY;
        public uint CountX;
        public uint CountY;
        public uint CountCharsX;
        public uint CountCharsY;
        public uint FillAttribute;
        public uint WindowFlags;
        public uint ShowWindowFlags;
        public UNICODE_STRING WindowTitle;
        public UNICODE_STRING DesktopInfo;
        public UNICODE_STRING ShellInfo;
        public UNICODE_STRING RuntimeData;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public RTL_DRIVE_LETTER_CURDIR[] CurrentDirectores;
        public ulong EnvironmentSize;
        public ulong EnvironmentVersion;
        public IntPtr PackageDependencyData;
        public uint ProcessGroupId;
        public uint LoaderThreads;
        public UNICODE_STRING RedirectionDllName;
        public UNICODE_STRING HeapPartitionName;
        public IntPtr DefaultThreadpoolCpuSetMasks;
        public uint DefaultThreadpoolCpuSetMaskCount;
        public uint DefaultThreadpoolThreadMaximum;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct STRING : IDisposable
    {
        public ushort Length;
        public ushort MaximumLength;
        private IntPtr buffer;
        public STRING(string s)
        {
            byte[] bytes;
            if (string.IsNullOrEmpty(s))
            {
                Length = 0;
                bytes = new byte[1];
            }
            else
            {
                Length = (ushort)s.Length;
                bytes = Encoding.ASCII.GetBytes(s);
            }

            MaximumLength = (ushort)(Length + 1);
            buffer = Marshal.AllocHGlobal(MaximumLength);
            Marshal.Copy(new byte[MaximumLength], 0, buffer, MaximumLength);
            Marshal.Copy(bytes, 0, buffer, bytes.Length);
        }

        public void Dispose()
        {
            Marshal.FreeHGlobal(buffer);
            buffer = IntPtr.Zero;
        }

        public override string ToString()
        {
            return Marshal.PtrToStringAnsi(buffer);
        }

        public IntPtr GetBuffer()
        {
            return buffer;
        }

        public void SetBuffer(IntPtr _buffer)
        {
            buffer = _buffer;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct UNICODE_STRING : IDisposable
    {
        public ushort Length;
        public ushort MaximumLength;
        private IntPtr buffer;
        public UNICODE_STRING(string s)
        {
            byte[] bytes;
            if (string.IsNullOrEmpty(s))
            {
                Length = 0;
                bytes = new byte[2];
            }
            else
            {
                Length = (ushort)(s.Length * 2);
                bytes = Encoding.Unicode.GetBytes(s);
            }

            MaximumLength = (ushort)(Length + 2);
            buffer = Marshal.AllocHGlobal(MaximumLength);
            Marshal.Copy(new byte[MaximumLength], 0, buffer, MaximumLength);
            Marshal.Copy(bytes, 0, buffer, bytes.Length);
        }

        public void Dispose()
        {
            Marshal.FreeHGlobal(buffer);
            buffer = IntPtr.Zero;
        }

        public override string ToString()
        {
            return Marshal.PtrToStringUni(buffer, Length / 2);
        }

        public IntPtr GetBuffer()
        {
            return buffer;
        }

        public void SetBuffer(IntPtr _buffer)
        {
            buffer = _buffer;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_ALLOWED_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_ALLOWED_CALLBACK_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_ALLOWED_CALLBACK_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public ACE_OBJECT_TYPE Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_ALLOWED_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public ACE_OBJECT_TYPE Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_DENIED_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_DENIED_CALLBACK_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_DENIED_CALLBACK_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public ACE_OBJECT_TYPE Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_DENIED_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public ACE_OBJECT_TYPE Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACE_HEADER
    {
        public ACE_TYPE AceType;
        public ACE_FLAGS AceFlags;
        public short AceSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACL
    {
        public ACL_REVISION AclRevision;
        public byte Sbz1;
        public short AclSize;
        public short AceCount;
        public short Sbz2;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct BY_HANDLE_FILE_INFORMATION
    {
        public FILE_ATTRIBUTE dwFileAttributes;
        public LARGE_INTEGER /* FILETIME */ ftCreationTime;
        public LARGE_INTEGER /* FILETIME */ ftLastAccessTime;
        public LARGE_INTEGER /* FILETIME */ ftLastWriteTime;
        public int dwVolumeSerialNumber;
        public int nFileSizeHigh;
        public int nFileSizeLow;
        public int nNumberOfLinks;
        public int nFileIndexHigh;
        public int nFileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LUID
    {
        public uint LowPart;
        public uint HighPart;
        public LUID(uint _lowPart, uint _highPart)
        {
            LowPart = _lowPart;
            HighPart = _highPart;
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    internal struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PUBLIC_OBJECT_BASIC_INFORMATION
    {
        public int Attributes;
        public ACCESS_MASK GrantedAccess;
        public int HandleCount;
        public int PointerCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
        public int[] Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PUBLIC_OBJECT_TYPE_INFORMATION
    {
        public UNICODE_STRING TypeName;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 22)]
        public int[] Reserved;
    }

    /*
     * PACL and PSID are relative in this tool, so type as int (not IntPtr)
     */
    [StructLayout(LayoutKind.Sequential)]
    internal struct SECURITY_DESCRIPTOR
    {
        public byte Revision;
        public byte Sbz1;
        public SECURITY_DESCRIPTOR_CONTROL Control;
        public int /* PSID */ Owner;
        public int /* PSID */ Group;
        public int /* PACL */ Sacl;
        public int /* PACL */ Dacl;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SID
    {
        public byte Revision;
        public byte SubAuthorityCount;
        public SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public uint[] SubAuthority;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SID_AND_ATTRIBUTES
    {
        public IntPtr /* PSID */ Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SID_IDENTIFIER_AUTHORITY
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] Value;
        public SID_IDENTIFIER_AUTHORITY(byte[] value)
        {
            Value = value;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_ACCESS_FILTER_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_ALARM_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_ALARM_CALLBACK_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_ALARM_CALLBACK_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public uint Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_ALARM_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public uint Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_AUDIT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_AUDIT_CALLBACK_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_AUDIT_CALLBACK_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public uint Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_AUDIT_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public uint Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_MANDATORY_LABEL_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_PROCESS_TRUST_LABEL_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_RESOURCE_ATTRIBUTE_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_SCOPED_POLICY_ID_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_DEFAULT_DACL
    {
        public IntPtr /* PACL */ DefaultDacl;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_OWNER
    {
        public IntPtr /* PSID */ Owner;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_PRIMARY_GROUP
    {
        public IntPtr /* PSID */ PrimaryGroup;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_PROCESS_TRUST_LEVEL
    {
        public IntPtr /* PSID */ TrustLevelSid;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CI_ESB_EA_V3
    {
        public int Size;
        public ushort MajorVersion;
        public byte MinorVersion;
        public SE_SIGNING_LEVEL SignerLevel;
        public LARGE_INTEGER UsnJournalId;
        public LARGE_INTEGER LastBlackListTime;
        public uint Flags;
        public short ExtraDataSize;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public byte[] ExtraData; // CI_DATA_BLOB
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CI_DATA_BLOB
    {
        public byte Size;
        public CI_DATA_BLOB_TYPE Type;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public byte[] BlobData; // CI_HASH_DATA_BLOB or others
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CI_HASH_DATA_BLOB
    {
        public HASH_ALGORITHM HashAlgorithm;
        public byte HashLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public byte[] HashData;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FILE_FULL_EA_INFORMATION
    {
        public uint NextEntryOffset;
        public EA_INFORMATION_FLAGS Flags;
        public byte EaNameLength;
        public ushort EaValueLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public byte[] EaName;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FILE_GET_EA_INFORMATION
    {
        public uint NextEntryOffset;
        public byte EaNameLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public byte[] EaName;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEMTIME
    {
        public short wYear;
        public short wMonth;
        public DAY_OF_WEEK wDayOfWeek;
        public short wDay;
        public short wHour;
        public short wMinute;
        public short wSecond;
        public short wMilliseconds;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TIME_ZONE_INFORMATION
    {
        public int Bias;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public short[] StandardName;
        public SYSTEMTIME StandardDate;
        public int StandardBias;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public short[] DaylightName;
        public SYSTEMTIME DaylightDate;
        public int DaylightBias;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MINIDUMP_CALLBACK_INFORMATION
    {
        public IntPtr /* MINIDUMP_CALLBACK_ROUTINE */ CallbackRoutine;
        public IntPtr CallbackParam;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MINIDUMP_EXCEPTION_INFORMATION
    {
        public int ThreadId;
        public IntPtr /* PEXCEPTION_POINTERS */ ExceptionPointers;
        public bool ClientPointers;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MINIDUMP_USER_STREAM_INFORMATION
    {
        public uint UserStreamCount;
        public IntPtr /* PMINIDUMP_USER_STREAM */ UserStreamArray;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MINIDUMP_USER_STREAM
    {
        public uint Type;
        public uint BufferSize;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION
    {
        public IntPtr ReflectionProcessHandle;
        public IntPtr ReflectionThreadHandle;
        public CLIENT_ID ReflectionClientId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct GENERIC_MAPPING
    {
        public ACCESS_MASK GenericRead;
        public ACCESS_MASK GenericWrite;
        public ACCESS_MASK GenericExecute;
        public ACCESS_MASK GenericAll;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct OBJECT_NAME_INFORMATION
    {
        public UNICODE_STRING Name;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct OBJECT_TYPE_INFORMATION
    {
        public UNICODE_STRING TypeName;
        public uint TotalNumberOfObjects;
        public uint TotalNumberOfHandles;
        public uint TotalPagedPoolUsage;
        public uint TotalNonPagedPoolUsage;
        public uint TotalNamePoolUsage;
        public uint TotalHandleTableUsage;
        public uint HighWaterNumberOfObjects;
        public uint HighWaterNumberOfHandles;
        public uint HighWaterPagedPoolUsage;
        public uint HighWaterNonPagedPoolUsage;
        public uint HighWaterNamePoolUsage;
        public uint HighWaterHandleTableUsage;
        public uint InvalidAttributes;
        public GENERIC_MAPPING GenericMapping;
        public uint ValidAccessMask;
        public BOOLEAN SecurityRequired;
        public BOOLEAN MaintainHandleCount;
        public byte TypeIndex; // since WINBLUE
        public byte ReservedByte;
        public uint PoolType;
        public uint DefaultPagedPoolCharge;
        public uint DefaultNonPagedPoolCharge;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct OBJECT_TYPES_INFORMATION
    {
        public uint NumberOfTypes;
        // OBJECT_TYPE_INFORMATION data entries are here.
        // Offset for OBJECT_TYPE_INFORMATION entries is IntPtr.Size
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_HANDLE_INFORMATION
    {
        public uint NumberOfHandles;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public SYSTEM_HANDLE_TABLE_ENTRY_INFO[] Handles;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_HANDLE_TABLE_ENTRY_INFO
    {
        public ushort UniqueProcessId;
        public ushort CreatorBackTraceIndex;
        public byte ObjectTypeIndex;
        public byte HandleAttributes;
        public ushort HandleValue;
        public IntPtr Object;
        public uint GrantedAccess;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct THREAD_BASIC_INFORMATION
    {
        public NTSTATUS ExitStatus;
        public IntPtr TebBaseAddress;
        public CLIENT_ID ClientId;
        public IntPtr /* KAFFINITY */ AffinityMask;
        public int /* KPRIORITY */ Priority;
        public int /* KPRIORITY */ BasePriority;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_USER
    {
        public SID_AND_ATTRIBUTES User;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal class TOKEN_PRIVILEGES
    {
        public int PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privileges;
        public TOKEN_PRIVILEGES()
        {
            PrivilegeCount = 0;
            Privileges = new LUID_AND_ATTRIBUTES[1];
        }

        public TOKEN_PRIVILEGES(int nPrivilegeCount)
        {
            PrivilegeCount = nPrivilegeCount;
            Privileges = new LUID_AND_ATTRIBUTES[1];
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_STATISTICS
    {
        public LUID TokenId;
        public LUID AuthenticationId;
        public LARGE_INTEGER ExpirationTime;
        public TOKEN_TYPE TokenType;
        public SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
        public int DynamicCharged;
        public int DynamicAvailable;
        public int GroupCount;
        public int PrivilegeCount;
        public LUID ModifiedId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PS_ATTRIBUTE
    {
        public UIntPtr Attribute; // PS_ATTRIBUTES
        public SIZE_T Size;
        public IntPtr Value;
        public IntPtr /* PSIZE_T */ ReturnLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PS_ATTRIBUTE_LIST
    {
        public SIZE_T TotalLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public PS_ATTRIBUTE[] Attributes;
        public PS_ATTRIBUTE_LIST(int nAttributes)
        {
            int length;
            if (nAttributes < 8)
                length = 8;
            else
                length = nAttributes;
            Attributes = new PS_ATTRIBUTE[length];
            TotalLength = new SIZE_T((uint)(Marshal.SizeOf(typeof(SIZE_T)) + (Marshal.SizeOf(typeof(PS_ATTRIBUTE)) * nAttributes)));
        }

        public PS_ATTRIBUTE_LIST(PS_ATTRIBUTE[] attributes)
        {
            int length;
            if (attributes.Length < 8)
                length = 8;
            else
                length = attributes.Length;
            Attributes = new PS_ATTRIBUTE[length];
            for (var idx = 0; idx < attributes.Length; idx++)
            {
                Attributes[idx].Attribute = attributes[idx].Attribute;
                Attributes[idx].Size = attributes[idx].Size;
                Attributes[idx].Value = attributes[idx].Value;
            }

            TotalLength = new SIZE_T((uint)(Marshal.SizeOf(typeof(SIZE_T)) + (Marshal.SizeOf(typeof(PS_ATTRIBUTE)) * length)));
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PS_CREATE_INFO
    {
        public SIZE_T Size;
        public PS_CREATE_STATE State;
        public PS_CREATE_INFO_UNION Information;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PS_CREATE_EXE_FORMAT
    {
        public ushort DllCharacteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PS_CREATE_EXE_NAME
    {
        public IntPtr IFEOKey;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PS_CREATE_FAIL_SECTION
    {
        public IntPtr FileHandle;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct PS_CREATE_INFO_UNION
    {
        [FieldOffset(0)]
        public PS_CREATE_INITIAL_STATE InitState; // PsCreateInitialState
        [FieldOffset(0)]
        public PS_CREATE_FAIL_SECTION FailSection; // PsCreateFailOnSectionCreate
        [FieldOffset(0)]
        public PS_CREATE_EXE_FORMAT ExeFormat; // PsCreateFailExeFormat
        [FieldOffset(0)]
        public PS_CREATE_EXE_NAME ExeName; // PsCreateFailExeName
        [FieldOffset(0)]
        public PS_CREATE_SUCCESS_STATE SuccessState; // PsCreateSuccess
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PS_CREATE_INITIAL_STATE
    {
        public PS_CREATE_INIT_FLAGS InitFlags;
        public ACCESS_MASK AdditionalFileAccess;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PS_CREATE_SUCCESS_STATE
    {
        public PS_CREATE_OUTPUT_FLAGS OutputFlags;
        public IntPtr FileHandle;
        public IntPtr SectionHandle;
        public ulong UserProcessParametersNative;
        public uint UserProcessParametersWow64;
        public uint CurrentParameterFlags;
        public ulong PebAddressNative;
        public uint PebAddressWow64;
        public ulong ManifestAddress;
        public uint ManifestSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IMAGE_BASE_RELOCATION
    {
        public int VirtualAddress;
        public int SizeOfBlock;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IMAGE_DATA_DIRECTORY
    {
        public uint VirtualAddress;
        public uint Size;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IMAGE_DELAYLOAD_DESCRIPTOR
    {
        public int Attributes;
        public int DllNameRVA; // RVA to the name of the target library (NULL-terminate ASCII string)
        public int ModuleHandleRVA; // RVA to the HMODULE caching location (PHMODULE)
        public int ImportAddressTableRVA; // RVA to the start of the IAT (PIMAGE_THUNK_DATA)
        public int ImportNameTableRVA; // RVA to the start of the name table (PIMAGE_THUNK_DATA::AddressOfData)
        public int BoundImportAddressTableRVA; // RVA to an optional bound IAT
        public int UnloadInformationTableRVA; // RVA to an optional unload info table
        public int TimeDateStamp; // 0 if not bound, Otherwise, date/time of the target DLL
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IMAGE_EXPORT_DIRECTORY
    {
        public int Characteristics;
        public int TimeDateStamp;
        public short MajorVersion;
        public short MinorVersion;
        public int Name;
        public int Base;
        public int NumberOfFunctions;
        public int NumberOfNames;
        public int AddressOfFunctions; // RVA from base of image
        public int AddressOfNames; // RVA from base of image
        public int AddressOfNameOrdinals; // RVA from base of image
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IMAGE_IMPORT_BY_NAME
    {
        public short Hint;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public byte[] Name;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct IMAGE_IMPORT_DESCRIPTOR
    {
        [FieldOffset(0)]
        public uint Characteristics;
        [FieldOffset(0)]
        public uint OriginalFirstThunk;
        [FieldOffset(4)]
        public uint TimeDateStamp;
        [FieldOffset(8)]
        public uint ForwarderChain;
        [FieldOffset(12)]
        public uint Name;
        [FieldOffset(16)]
        public uint FirstThunk;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct IMAGE_SECTION_HEADER
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
        public string Name;
        public uint VirtualSize;
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        public uint PointerToRelocations;
        public uint PointerToLinenumbers;
        public ushort NumberOfRelocations;
        public ushort NumberOfLinenumbers;
        public SectionFlags Characteristics;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct IMAGE_THUNK_DATA
    {
        [FieldOffset(0)]
        public IntPtr ForwarderString;
        [FieldOffset(0)]
        public IntPtr Function;
        [FieldOffset(0)]
        public IntPtr Ordinal;
        [FieldOffset(0)]
        public IntPtr AddressOfData;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IMAGE_TLS_DIRECTORY
    {
        public IntPtr StartAddressOfRawData;
        public IntPtr EndAddressOfRawData;
        public IntPtr AddressOfIndex; // PDWORD
        public IntPtr AddressOfCallBacks; // PIMAGE_TLS_CALLBACK *;
        public int SizeOfZeroFill;
        public int Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LDR_DATA_TABLE_ENTRY
    {
        public LIST_ENTRY InLoadOrderLinks;
        public LIST_ENTRY InMemoryOrderLinks;
        public LIST_ENTRY InInitializationOrderLinks;
        public IntPtr DllBase;
        public IntPtr EntryPoint;
        public uint SizeOfImage;
        public UNICODE_STRING FullDllName;
        public UNICODE_STRING BaseDllName;
        public LDR_DATA_TABLE_ENTRY_FLAGS Flags;
        public ushort ObsoleteLoadCount;
        public ushort TlsIndex;
        public LIST_ENTRY HashLinks;
        public uint TimeDateStamp;
        public IntPtr /* _ACTIVATION_CONTEXT* */ EntryPointActivationContext;
        public IntPtr Lock;
        public IntPtr /* _LDR_DDAG_NODE* */ DdagNode;
        public LIST_ENTRY NodeModuleLink;
        public IntPtr /* _LDRP_LOAD_CONTEXT* */ LoadContext;
        public IntPtr ParentDllBase;
        public IntPtr SwitchBackContext;
        public RTL_BALANCED_NODE BaseAddressIndexNode;
        public RTL_BALANCED_NODE MappingInfoIndexNode;
        public IntPtr OriginalBase;
        public LARGE_INTEGER LoadTime;
        public uint BaseNameHashValue;
        public LDR_DLL_LOAD_REASON LoadReason;
        public uint ImplicitPathOptions;
        public uint ReferenceCount;
        public uint DependentLoadFlags;
        public byte SigningLevel;
        /* Following members only in 64bit mode (Size = 0x10)*/
        // public uint CheckSum;
        // public IntPtr ActivePatchImageBase;
        // public LDR_HOT_PATCH_STATE HotPatchState;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LDR_DDAG_NODE
    {
        public LIST_ENTRY Modules;
        public IntPtr /* LDR_SERVICE_TAG_RECORD* */ ServiceTagList;
        public uint LoadCount;
        public uint LoadWhileUnloadingCount;
        public uint LowestLink;
        public LDRP_CSLIST Dependencies;
        public LDRP_CSLIST IncomingDependencies;
        public LDR_DDAG_STATE State;
        public SINGLE_LIST_ENTRY CondenseLink;
        public uint PreorderNumber;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LDR_SERVICE_TAG_RECORD
    {
        public IntPtr /* LDR_SERVICE_TAG_RECORD* */ Next;
        public uint ServiceTag;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LDRP_CSLIST
    {
        public IntPtr /* SINGLE_LIST_ENTRY* */ Tail;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LIST_ENTRY
    {
        public IntPtr /* LIST_ENTRY* */ Flink;
        public IntPtr /* LIST_ENTRY* */ Blink;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PEB_LDR_DATA
    {
        public uint Length;
        public byte Initialized;
        public IntPtr SsHandle;
        public LIST_ENTRY InLoadOrderModuleList;
        public LIST_ENTRY InMemoryOrderModuleList;
        public LIST_ENTRY InInitializationOrderModuleList;
        public IntPtr EntryInProgress;
        public byte ShutdownInProgress;
        public IntPtr ShutdownThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PEB_PARTIAL
    {
        public BOOLEAN InheritedAddressSpace;
        public BOOLEAN ReadImageFileExecOptions;
        public BOOLEAN BeingDebugged;
        public byte BitField;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] Padding0;
        public IntPtr Mutant;
        public IntPtr ImageBaseAddress;
        public IntPtr /* PEB_LDR_DATA */ Ldr;
        public IntPtr /* RTL_USER_PROCESS_PARAMETERS* */ ProcessParameters;
        public IntPtr SubSystemData;
        public IntPtr ProcessHeap;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RTL_BALANCED_NODE
    {
        public IntPtr /* RTL_BALANCED_NODE* */ Left;
        public IntPtr /* RTL_BALANCED_NODE* */ Right;
        public IntPtr ParentValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RTL_RB_TREE
    {
        public IntPtr /* RTL_BALANCED_NODE* */ Root;
        public IntPtr /* RTL_BALANCED_NODE* */ Min;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SINGLE_LIST_ENTRY
    {
        public IntPtr /* SINGLE_LIST_ENTRY* */ Next;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct OBJECT_BASIC_INFORMATION
    {
        public uint Attributes;
        public ACCESS_MASK GrantedAccess;
        public uint HandleCount;
        public uint PointerCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
        public uint[] Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
    {
        public IntPtr Object;
        public UIntPtr UniqueProcessId;
        public UIntPtr HandleValue;
        public uint GrantedAccess;
        public ushort CreatorBackTraceIndex;
        public ushort ObjectTypeIndex;
        public uint HandleAttributes;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CURDIR32
    {
        public UNICODE_STRING32 DosPath;
        public uint Handle;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CURDIR64
    {
        public UNICODE_STRING64 DosPath;
        public ulong Handle;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RTL_DRIVE_LETTER_CURDIR32
    {
        public ushort Flags;
        public ushort Length;
        public uint TimeStamp;
        public STRING32 DosPath;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RTL_DRIVE_LETTER_CURDIR64
    {
        public ushort Flags;
        public ushort Length;
        public uint TimeStamp;
        public STRING64 DosPath;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RTL_USER_PROCESS_PARAMETERS32
    {
        public uint MaximumLength;
        public uint Length;
        public uint Flags;
        public uint DebugFlags;
        public uint ConsoleHandle;
        public uint ConsoleFlags;
        public uint StandardInput;
        public uint StandardOutput;
        public uint StandardError;
        public CURDIR32 CurrentDirectory;
        public UNICODE_STRING32 DllPath;
        public UNICODE_STRING32 ImagePathName;
        public UNICODE_STRING32 CommandLine;
        public uint Environment;
        public uint StartingX;
        public uint StartingY;
        public uint CountX;
        public uint CountY;
        public uint CountCharsX;
        public uint CountCharsY;
        public uint FillAttribute;
        public uint WindowFlags;
        public uint ShowWindowFlags;
        public UNICODE_STRING32 WindowTitle;
        public UNICODE_STRING32 DesktopInfo;
        public UNICODE_STRING32 ShellInfo;
        public UNICODE_STRING32 RuntimeData;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public RTL_DRIVE_LETTER_CURDIR32[] CurrentDirectores;
        public ulong EnvironmentSize;
        public ulong EnvironmentVersion;
        public uint PackageDependencyData;
        public uint ProcessGroupId;
        public uint LoaderThreads;
        public UNICODE_STRING32 RedirectionDllName;
        public UNICODE_STRING32 HeapPartitionName;
        public uint DefaultThreadpoolCpuSetMasks;
        public uint DefaultThreadpoolCpuSetMaskCount;
        public uint DefaultThreadpoolThreadMaximum;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RTL_USER_PROCESS_PARAMETERS64
    {
        public uint MaximumLength;
        public uint Length;
        public uint Flags;
        public uint DebugFlags;
        public ulong ConsoleHandle;
        public uint ConsoleFlags;
        public ulong StandardInput;
        public ulong StandardOutput;
        public ulong StandardError;
        public CURDIR64 CurrentDirectory;
        public UNICODE_STRING64 DllPath;
        public UNICODE_STRING64 ImagePathName;
        public UNICODE_STRING64 CommandLine;
        public IntPtr Environment;
        public uint StartingX;
        public uint StartingY;
        public uint CountX;
        public uint CountY;
        public uint CountCharsX;
        public uint CountCharsY;
        public uint FillAttribute;
        public uint WindowFlags;
        public uint ShowWindowFlags;
        public UNICODE_STRING64 WindowTitle;
        public UNICODE_STRING64 DesktopInfo;
        public UNICODE_STRING64 ShellInfo;
        public UNICODE_STRING64 RuntimeData;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public RTL_DRIVE_LETTER_CURDIR64[] CurrentDirectores;
        public ulong EnvironmentSize;
        public ulong EnvironmentVersion;
        public ulong PackageDependencyData;
        public uint ProcessGroupId;
        public uint LoaderThreads;
        public UNICODE_STRING64 RedirectionDllName;
        public UNICODE_STRING64 HeapPartitionName;
        public ulong DefaultThreadpoolCpuSetMasks;
        public uint DefaultThreadpoolCpuSetMaskCount;
        public uint DefaultThreadpoolThreadMaximum;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct STRING32
    {
        public ushort Length;
        public ushort MaximumLength;
        public uint Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct STRING64
    {
        public ushort Length;
        public ushort MaximumLength;
        public ulong Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct UNICODE_STRING32
    {
        public ushort Length;
        public ushort MaximumLength;
        public uint Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct UNICODE_STRING64
    {
        public ushort Length;
        public ushort MaximumLength;
        public ulong Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IMAGE_DOS_HEADER
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public char[] e_magic; // Magic number
        public ushort e_cblp; // Bytes on last page of file
        public ushort e_cp; // Pages in file
        public ushort e_crlc; // Relocations
        public ushort e_cparhdr; // Size of header in paragraphs
        public ushort e_minalloc; // Minimum extra paragraphs needed
        public ushort e_maxalloc; // Maximum extra paragraphs needed
        public ushort e_ss; // Initial (relative) SS value
        public ushort e_sp; // Initial SP value
        public ushort e_csum; // Checksum
        public ushort e_ip; // Initial IP value
        public ushort e_cs; // Initial (relative) CS value
        public ushort e_lfarlc; // File address of relocation table
        public ushort e_ovno; // Overlay number
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public ushort[] e_res1; // Reserved words
        public ushort e_oemid; // OEM identifier (for e_oeminfo)
        public ushort e_oeminfo; // OEM information; e_oemid specific
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
        public ushort[] e_res2; // Reserved words
        public int e_lfanew; // File address of new exe header
        private string GetMagic
        {
            get
            {
                return new string(e_magic);
            }
        }

        public bool IsValid
        {
            get
            {
                return GetMagic == "MZ";
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IMAGE_FILE_HEADER
    {
        public IMAGE_FILE_MACHINE Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LDR_DATA_TABLE_ENTRY32
    {
        public LIST_ENTRY32 InLoadOrderLinks;
        public LIST_ENTRY32 InMemoryOrderLinks;
        public LIST_ENTRY32 InInitializationOrderLinks;
        public int /* IntPtr */ DllBase;
        public int /* IntPtr */ EntryPoint;
        public uint SizeOfImage;
        public UNICODE_STRING32 FullDllName;
        public UNICODE_STRING32 BaseDllName;
        public uint Flags;
        public ushort ObsoleteLoadCount;
        public ushort TlsIndex;
        public LIST_ENTRY32 HashLinks;
        public uint TimeDateStamp;
        public int /* _ACTIVATION_CONTEXT* */ EntryPointActivationContext;
        public int /* IntPtr */ Lock;
        public int /* _LDR_DDAG_NODE* */ DdagNode;
        public LIST_ENTRY32 NodeModuleLink;
        public int /* _LDRP_LOAD_CONTEXT* */ LoadContext;
        public int /* IntPtr */ ParentDllBase;
        public int /* IntPtr */ SwitchBackContext;
        public RTL_BALANCED_NODE32 BaseAddressIndexNode;
        public RTL_BALANCED_NODE32 MappingInfoIndexNode;
        public uint OriginalBase;
        public LARGE_INTEGER LoadTime;
        public uint BaseNameHashValue;
        public LDR_DLL_LOAD_REASON LoadReason;
        public uint ImplicitPathOptions;
        public uint ReferenceCount;
        public uint DependentLoadFlags;
        public byte SigningLevel;
        public uint CheckSum;
        public int /* IntPtr */ ActivePatchImageBase;
        public LDR_HOT_PATCH_STATE HotPatchState;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LIST_ENTRY32
    {
        public int Flink;
        public int Blink;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public MEMORY_PROTECTION AllocationProtect;
        public SIZE_T RegionSize;
        public MEMORY_ALLOCATION_TYPE State;
        public MEMORY_PROTECTION Protect;
        public MEMORY_ALLOCATION_TYPE Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MEMORY_IMAGE_INFORMATION
    {
        public IntPtr ImageBase;
        public SIZE_T SizeOfImage;
        public uint ImageFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PEB_LDR_DATA32
    {
        public uint Length;
        public BOOLEAN Initialized;
        public int SsHandle;
        public LIST_ENTRY32 InLoadOrderModuleList;
        public LIST_ENTRY32 InMemoryOrderModuleList;
        public LIST_ENTRY32 InInitializationOrderModuleList;
        public int EntryInProgress;
        public BOOLEAN ShutdownInProgress;
        public int ShutdownThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_DEVICEMAP_INFORMATION
    {
        public uint DriveMap;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] DriveType;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RTL_BALANCED_NODE32
    {
        public int /* RTL_BALANCED_NODE32* */ Left;
        public int /* RTL_BALANCED_NODE32* */ Right;
        public uint ParentValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SECURITY_QUALITY_OF_SERVICE
    {
        public int Length;
        public SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
        public SECURITY_CONTEXT_TRACKING_MODE ContextTrackingMode;
        public BOOLEAN EffectiveOnly;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYMBOL_INFO
    {
        public uint SizeOfStruct;
        public uint TypeIndex;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public ulong[] Reserved;
        public uint Index;
        public uint Size;
        public ulong ModBase;
        public uint Flags;
        public ulong Value;
        public ulong Address;
        public uint Register;
        public uint Scope;
        public uint Tag;
        public uint NameLen;
        public uint MaxNameLen;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2000 /* MAX_SYM_NAME */)]
        public byte[] Name;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_THREAD_INFORMATION
    {
        public LARGE_INTEGER KernelTime;
        public LARGE_INTEGER UserTime;
        public LARGE_INTEGER CreateTime;
        public uint WaitTime;
        public IntPtr StartAddress;
        public CLIENT_ID ClientId;
        public int Priority;
        public int BasePriority;
        public uint ContextSwitches;
        public KTHREAD_STATE ThreadState;
        public KWAIT_REASON WaitReason;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct IMAGE_RUNTIME_FUNCTION_ENTRY
    {
        [FieldOffset(0)]
        public int BeginAddress;
        [FieldOffset(4)]
        public int EndAddress;
        [FieldOffset(8)]
        public int UnwindInfoAddress;
        [FieldOffset(8)]
        public int UnwindData;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_MITIGATION_ASLR_POLICY
    {
        public ASLR_POLICY_FLAGS Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY
    {
        public BINARY_SIGNATURE_POLICY_FLAGS Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY
    {
        public CONTROL_FLOW_GUARD_POLICY_FLAGS Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_MITIGATION_DEP_POLICY
    {
        public DEP_POLICY_FLAGS Flags;
        public BOOLEAN Permanent;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_MITIGATION_DYNAMIC_CODE_POLICY
    {
        public DYNAMIC_CODE_POLICY_FLAGS Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY
    {
        public EXTENSION_POINT_DISABLE_POLICY_FLAGS Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_MITIGATION_FONT_DISABLE_POLICY
    {
        public FONT_DISABLE_POLICY_FLAGS Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_MITIGATION_IMAGE_LOAD_POLICY
    {
        public IMAGE_LOAD_POLICY_FLAGS Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_MITIGATION_POLICY_INFORMATION
    {
        public PROCESS_MITIGATION_POLICY Policy;
        public PROCESS_MITIGATION_POLICY_INFORMATION_UNION Information;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct PROCESS_MITIGATION_POLICY_INFORMATION_UNION
    {
        [FieldOffset(0)]
        public PROCESS_MITIGATION_ASLR_POLICY ASLRPolicy;
        [FieldOffset(0)]
        public PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY StrictHandleCheckPolicy;
        [FieldOffset(0)]
        public PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY SystemCallDisablePolicy;
        [FieldOffset(0)]
        public PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ExtensionPointDisablePolicy;
        [FieldOffset(0)]
        public PROCESS_MITIGATION_DYNAMIC_CODE_POLICY DynamicCodePolicy;
        [FieldOffset(0)]
        public PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY ControlFlowGuardPolicy;
        [FieldOffset(0)]
        public PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY SignaturePolicy;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY
    {
        public REDIRECTION_TRUST_POLICY_FLAGS Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY
    {
        public SIDE_CHANNEL_ISOLATION_POLICY_FLAGS Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY
    {
        public STRICT_HANDLE_CHECK_POLICY_FLAGS Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY
    {
        public SYSTEM_CALL_DISABLE_POLICY_FLAGS Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY
    {
        public USER_SHADOW_STACK_POLICY_FLAGS Flags;
    }
}