function Get-SystemInfo {
<#
.SYNOPSIS

A wrapper for kernel32!GetSystemInfo

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: PSReflect module
Optional Dependencies: None
#>

    $Mod = New-InMemoryModule -ModuleName SysInfo

    $ProcessorType = psenum $Mod SYSINFO.PROCESSOR_ARCH UInt16 @{
        PROCESSOR_ARCHITECTURE_INTEL =   0
        PROCESSOR_ARCHITECTURE_MIPS =    1
        PROCESSOR_ARCHITECTURE_ALPHA =   2
        PROCESSOR_ARCHITECTURE_PPC =     3
        PROCESSOR_ARCHITECTURE_SHX =     4
        PROCESSOR_ARCHITECTURE_ARM =     5
        PROCESSOR_ARCHITECTURE_IA64 =    6
        PROCESSOR_ARCHITECTURE_ALPHA64 = 7
        PROCESSOR_ARCHITECTURE_AMD64 =   9
        PROCESSOR_ARCHITECTURE_UNKNOWN = 0xFFFF
    }

    $SYSTEM_INFO = struct $Mod SYSINFO.SYSTEM_INFO @{
        ProcessorArchitecture = field 0 $ProcessorType
        Reserved = field 1 Int16
        PageSize = field 2 Int32
        MinimumApplicationAddress = field 3 IntPtr
        MaximumApplicationAddress = field 4 IntPtr
        ActiveProcessorMask = field 5 IntPtr
        NumberOfProcessors = field 6 Int32
        ProcessorType = field 7 Int32
        AllocationGranularity = field 8 Int32
        ProcessorLevel = field 9 Int16
        ProcessorRevision = field 10 Int16
    }

    $FunctionDefinitions = @(
        (func kernel32 GetSystemInfo ([Void]) @($SYSTEM_INFO.MakeByRefType()))
    )

    $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32SysInfo'
    $Kernel32 = $Types['kernel32']

    $SysInfo = [Activator]::CreateInstance($SYSTEM_INFO)
    $Kernel32::GetSystemInfo([Ref] $SysInfo)

    $SysInfo
}