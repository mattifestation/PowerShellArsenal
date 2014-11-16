function Get-VirtualMemoryInfo {
<#
.SYNOPSIS

A wrapper for kernel32!VirtualQueryEx

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: PSReflect module
Optional Dependencies: None

.PARAMETER ProcessID

Specifies the process ID.

.PARAMETER ModuleBaseAddress

Specifies the address of the memory to be queried.

.PARAMETER PageSize

Specifies the system page size. Defaults to 0x1000 if one is not
specified.

.EXAMPLE

Get-VirtualMemoryInfo -ProcessID $PID -ModuleBaseAddress 0
#>

    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateScript({Get-Process -Id $_})]
        [Int]
        $ProcessID,

        [Parameter(Position = 1, Mandatory = $True)]
        [IntPtr]
        $ModuleBaseAddress,

        [Int]
        $PageSize = 0x1000
    )

    $Mod = New-InMemoryModule -ModuleName MemUtils

    $MemProtection = psenum $Mod MEMUTIL.MEM_PROTECT Int32 @{
        PAGE_EXECUTE =           0x00000010
        PAGE_EXECUTE_READ =      0x00000020
        PAGE_EXECUTE_READWRITE = 0x00000040
        PAGE_EXECUTE_WRITECOPY = 0x00000080
        PAGE_NOACCESS =          0x00000001
        PAGE_READONLY =          0x00000002
        PAGE_READWRITE =         0x00000004
        PAGE_WRITECOPY =         0x00000008
        PAGE_GUARD =             0x00000100
        PAGE_NOCACHE =           0x00000200
        PAGE_WRITECOMBINE =      0x00000400
    } -Bitfield

    $MemState = psenum $Mod MEMUTIL.MEM_STATE Int32 @{
        MEM_COMMIT =  0x00001000
        MEM_FREE =    0x00010000
        MEM_RESERVE = 0x00002000
    } -Bitfield

    $MemType = psenum $Mod MEMUTIL.MEM_TYPE Int32 @{
        MEM_IMAGE =   0x01000000
        MEM_MAPPED =  0x00040000
        MEM_PRIVATE = 0x00020000
    } -Bitfield

    if ([IntPtr]::Size -eq 4) {
        $MEMORY_BASIC_INFORMATION = struct $Mod MEMUTIL.MEMORY_BASIC_INFORMATION @{
            BaseAddress = field 0 Int32
            AllocationBase = field 1 Int32
            AllocationProtect = field 2 $MemProtection
            RegionSize = field 3 Int32
            State = field 4 $MemState
            Protect = field 5 $MemProtection
            Type = field 6 $MemType
        }
    } else {
        $MEMORY_BASIC_INFORMATION = struct $Mod MEMUTIL.MEMORY_BASIC_INFORMATION @{
            BaseAddress = field 0 Int64
            AllocationBase = field 1 Int64
            AllocationProtect = field 2 $MemProtection
            Alignment1 = field 3 Int32
            RegionSize = field 4 Int64
            State = field 5 $MemState
            Protect = field 6 $MemProtection
            Type = field 7 $MemType
            Alignment2 = field 8 Int32
        }
    }

    $FunctionDefinitions = @(
        (func kernel32 VirtualQueryEx ([Int32]) @([IntPtr], [IntPtr], $MEMORY_BASIC_INFORMATION.MakeByRefType(), [Int]) -SetLastError),
        (func kernel32 OpenProcess ([IntPtr]) @([UInt32], [Bool], [UInt32]) -SetLastError),
        (func kernel32 CloseHandle ([Bool]) @([IntPtr]) -SetLastError)
    )

    $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32MemUtils'
    $Kernel32 = $Types['kernel32']

    # Get handle to the process
    $hProcess = $Kernel32::OpenProcess(0x400, $False, $ProcessID) # PROCESS_QUERY_INFORMATION (0x00000400)

    if (-not $hProcess) {
        throw "Unable to get a process handle for process ID: $ProcessID"
    }

    $MemoryInfo = New-Object $MEMORY_BASIC_INFORMATION
    $BytesRead = $Kernel32::VirtualQueryEx($hProcess, $ModuleBaseAddress, [Ref] $MemoryInfo, $PageSize)

    $null = $Kernel32::CloseHandle($hProcess)

    $Fields = @{
        BaseAddress = $MemoryInfo.BaseAddress
        AllocationBase = $MemoryInfo.AllocationBase
        AllocationProtect = $MemoryInfo.AllocationProtect
        RegionSize = $MemoryInfo.RegionSize
        State = $MemoryInfo.State
        Protect = $MemoryInfo.Protect
        Type = $MemoryInfo.Type
    }

    $Result = New-Object PSObject -Property $Fields
    $Result.PSObject.TypeNames.Insert(0, 'MEM.INFO')

    $Result
}

function Get-StructFromMemory {
<#
.SYNOPSIS

Marshals data from an unmanaged block of memory in an arbitrary process to a newly allocated managed object of the specified type.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Get-StructFromMemory is similar to the Marshal.PtrToStructure method but will parse and return a structure from any process.

.PARAMETER Id

Process ID of the process whose virtual memory space you want to access.

.PARAMETER MemoryAddress

The address containing the structure to be parsed.

.PARAMETER StructType

The type (System.Type) of the desired structure to be parsed.

.EXAMPLE

C:\PS> Get-Process | ForEach-Object { Get-StructFromMemory -Id $_.Id -MemoryAddress $_.MainModule.BaseAddress -StructType ([PE+_IMAGE_DOS_HEADER]) }

Description
-----------
Parses the DOS headers of every loaded process. Note: In this example, this assumes that [PE+_IMAGE_DOS_HEADER] is defined. You can get the code to define [PE+_IMAGE_DOS_HEADER] here: http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html

.NOTES

Be sure to enclose the StructType parameter with parenthesis in order to force PowerShell to cast it as a Type object.

Get-StructFromMemory does a good job with error handling however it will crash if the structure contains fields that attempt to marshal pointers. For example, if a field has a custom attribute of UnmanagedType.LPStr, when the structure is parsed, it will attempt to dererence a string pointer for virtual memory in another process and access violate.
#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('ProcessId')]
        [Alias('PID')]
        [UInt16]
        $Id,

        [Parameter(Position = 1, Mandatory = $True)]
        [IntPtr]
        $MemoryAddress,

        [Parameter(Position = 2, Mandatory = $True)]
        [Alias('Type')]
        [Type]
        $StructType
    )

    Set-StrictMode -Version 2

    $PROCESS_VM_READ = 0x0010 # The process permissions we'l ask for when getting a handle to the process

    # Get a reference to the private GetProcessHandle method is System.Diagnostics.Process
    $GetProcessHandle = [Diagnostics.Process].GetMethod('GetProcessHandle', [Reflection.BindingFlags] 'NonPublic, Instance', $null, @([Int]), $null)

    try
    {
        # Make sure user didn't pass in a non-existent PID
        $Process = Get-Process -Id $Id -ErrorVariable GetProcessError
        # Get the default process handle
        $Handle = $Process.Handle
    }
    catch [Exception]
    {
        throw $GetProcessError
    }

    if ($Handle -eq $null)
    {
        throw "Unable to obtain a handle for PID $Id. You will likely need to run this script elevated."
    }

    # Get a reference to MEMORY_BASIC_INFORMATION. I don't feel like making the structure myself
    $mscorlib = [AppDomain]::CurrentDomain.GetAssemblies() | ? { $_.FullName.Split(',')[0].ToLower() -eq 'mscorlib' }
    $Win32Native = $mscorlib.GetTypes() | ? { $_.FullName -eq 'Microsoft.Win32.Win32Native' }
    $MEMORY_BASIC_INFORMATION = $Win32Native.GetNestedType('MEMORY_BASIC_INFORMATION', [Reflection.BindingFlags] 'NonPublic')

    if ($MEMORY_BASIC_INFORMATION -eq $null)
    {
        throw 'Unable to get a reference to the MEMORY_BASIC_INFORMATION structure.'
    }

    # Get references to private fields in MEMORY_BASIC_INFORMATION
    $ProtectField = $MEMORY_BASIC_INFORMATION.GetField('Protect', [Reflection.BindingFlags] 'NonPublic, Instance')
    $AllocationBaseField = $MEMORY_BASIC_INFORMATION.GetField('BaseAddress', [Reflection.BindingFlags] 'NonPublic, Instance')
    $RegionSizeField = $MEMORY_BASIC_INFORMATION.GetField('RegionSize', [Reflection.BindingFlags] 'NonPublic, Instance')

    try { $NativeUtils = [NativeUtils] } catch [Management.Automation.RuntimeException] # Only build the assembly if it hasn't already been defined
    {
        # Build dynamic assembly in order to use P/Invoke for interacting with the following Win32 functions: ReadProcessMemory, VirtualQueryEx
        $DynAssembly = New-Object Reflection.AssemblyName('MemHacker')
        $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('MemHacker', $False)
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('NativeUtils', $Attributes, [ValueType])
        $TypeBuilder.DefinePInvokeMethod('ReadProcessMemory', 'kernel32.dll', [Reflection.MethodAttributes] 'Public, Static', [Reflection.CallingConventions]::Standard, [Bool], @([IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()), [Runtime.InteropServices.CallingConvention]::Winapi, 'Auto') | Out-Null
        $TypeBuilder.DefinePInvokeMethod('VirtualQueryEx', 'kernel32.dll', [Reflection.MethodAttributes] 'Public, Static', [Reflection.CallingConventions]::Standard, [UInt32], @([IntPtr], [IntPtr], $MEMORY_BASIC_INFORMATION.MakeByRefType(), [UInt32]), [Runtime.InteropServices.CallingConvention]::Winapi, 'Auto') | Out-Null

        $NativeUtils = $TypeBuilder.CreateType()
    }

    # Request a handle to the process in interest
    try
    {
        $SafeHandle = $GetProcessHandle.Invoke($Process, @($PROCESS_VM_READ))
        $Handle = $SafeHandle.DangerousGetHandle()
    }
    catch
    {
        throw $Error[0]
    }

    # Create an instance of MEMORY_BASIC_INFORMATION
    $MemoryBasicInformation = [Activator]::CreateInstance($MEMORY_BASIC_INFORMATION)

    # Confirm you can actually read the address you're interested in
    $NativeUtils::VirtualQueryEx($Handle, $MemoryAddress, [Ref] $MemoryBasicInformation, [Runtime.InteropServices.Marshal]::SizeOf([Type] $MEMORY_BASIC_INFORMATION)) | Out-Null

    $PAGE_EXECUTE_READ = 0x20
    $PAGE_EXECUTE_READWRITE = 0x40
    $PAGE_READONLY = 2
    $PAGE_READWRITE = 4

    $Protection = $ProtectField.GetValue($MemoryBasicInformation)
    $AllocationBaseOriginal = $AllocationBaseField.GetValue($MemoryBasicInformation)
    $GetPointerValue = $AllocationBaseOriginal.GetType().GetMethod('GetPointerValue', [Reflection.BindingFlags] 'NonPublic, Instance')
    $AllocationBase = $GetPointerValue.Invoke($AllocationBaseOriginal, $null).ToInt64()
    $RegionSize = $RegionSizeField.GetValue($MemoryBasicInformation).ToUInt64()

    Write-Verbose "Protection: $Protection"
    Write-Verbose "AllocationBase: $AllocationBase"
    Write-Verbose "RegionSize: $RegionSize"

    if (($Protection -ne $PAGE_READONLY) -and ($Protection -ne $PAGE_READWRITE) -and ($Protection -ne $PAGE_EXECUTE_READ) -and ($Protection -ne $PAGE_EXECUTE_READWRITE))
    {
        $SafeHandle.Close()
        throw 'The address specified does not have read access.'
    }

    $StructSize = [Runtime.InteropServices.Marshal]::SizeOf([Type] $StructType)
    $EndOfAllocation = $AllocationBase + $RegionSize
    $EndOfStruct = $MemoryAddress.ToInt64() + $StructSize

    if ($EndOfStruct -gt $EndOfAllocation)
    {
        $SafeHandle.Close()
        throw 'You are attempting to read beyond what was allocated.'
    }

    try
    {
        # Allocate unmanaged memory. This will be used to store the memory read from ReadProcessMemory
        $LocalStructPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($StructSize)
    }
    catch [OutOfMemoryException]
    {
        throw Error[0]
    }

    Write-Verbose "Memory allocated at 0x$($LocalStructPtr.ToString("X$([IntPtr]::Size * 2)"))"

    # Zero out the memory that was just allocated. According to MSDN documentation:
    # "When AllocHGlobal calls LocalAlloc, it passes a LMEM_FIXED flag, which causes the allocated memory to be locked in place. Also, the allocated memory is not zero-filled."
    # http://msdn.microsoft.com/en-us/library/s69bkh17.aspx
    $ZeroBytes = New-Object Byte[]($StructSize)
    [Runtime.InteropServices.Marshal]::Copy($ZeroBytes, 0, $LocalStructPtr, $StructSize)

    $BytesRead = [UInt32] 0

    if ($NativeUtils::ReadProcessMemory($Handle, $MemoryAddress, $LocalStructPtr, $StructSize, [Ref] $BytesRead))
    {
        $SafeHandle.Close()
        [Runtime.InteropServices.Marshal]::FreeHGlobal($LocalStructPtr)
        throw ([ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }

    Write-Verbose "Struct Size: $StructSize"
    Write-Verbose "Bytes read: $BytesRead"

    $ParsedStruct = [Runtime.InteropServices.Marshal]::PtrToStructure($LocalStructPtr, [Type] $StructType)

    [Runtime.InteropServices.Marshal]::FreeHGlobal($LocalStructPtr)
    $SafeHandle.Close()

    Write-Output $ParsedStruct
}

filter Get-ProcessMemoryInfo {
<#
.SYNOPSIS

Retrieve virtual memory information for every unique set of pages in
user memory. This function is similar to the !vadump WinDbg command.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: PSReflect module
                       Get-SystemInfo
                       Get-VirtualMemoryInfo
Optional Dependencies: None

.PARAMETER ProcessID

Specifies the process ID.

.EXAMPLE

Get-ProcessMemoryInfo -ProcessID $PID
#>

    Param (
        [Parameter(ParameterSetName = 'InMemory', Position = 0, Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Id')]
        [ValidateScript({Get-Process -Id $_})]
        [Int]
        $ProcessID
    )

    $SysInfo = Get-SystemInfo

    $MemoryInfo = Get-VirtualMemoryInfo -ProcessID $ProcessID -ModuleBaseAddress ([IntPtr]::Zero) -PageSize $SysInfo.PageSize

    $MemoryInfo

    while (($MemoryInfo.BaseAddress + $MemoryInfo.RegionSize) -lt $SysInfo.MaximumApplicationAddress) {
        $BaseAllocation = [IntPtr] ($MemoryInfo.BaseAddress + $MemoryInfo.RegionSize)
        $MemoryInfo = Get-VirtualMemoryInfo -ProcessID $ProcessID -ModuleBaseAddress $BaseAllocation -PageSize $SysInfo.PageSize
        
        if ($MemoryInfo.State -eq 0) { break }
        $MemoryInfo
    }
}

function Get-ProcessStrings
{
<#
.SYNOPSIS

Outputs all printable strings from the user-mode memory of a process.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: PSReflect module
                       Get-ProcessMemoryInfo
Optional Dependencies: MemoryTools.format.ps1xml

.DESCRIPTION

Get-ProcessStrings reads every committed memory allocation that is
not a guard page and returns all printable strings. By default,
Get-ProcessStrings ignores MEM_IMAGE allocations (most commonly
allocated when modules are loaded) but they can be included with the
-IncludeImages switch.

.PARAMETER ProcessID

Specifies the process ID.

.PARAMETER MinimumLength

Specifies the minimum length string to return. The default length is 3.

.PARAMETER Encoding

Specifies the string encoding to use. The default option is 'Default'
which will return both Ascii and Unicode strings.

.PARAMETER IncludeImages

Specifies that memory allocations marked MEM_IMAGE should be
included. These allocations typically consist of loaded PE images.

.EXAMPLE

Get-Process cmd | Get-ProcessStrings

.EXAMPLE

Get-Process cmd | Get-ProcessStrings -MinimumLength 40 -Encoding Ascii
#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Id')]
        [ValidateScript({Get-Process -Id $_})]
        [Int32]
        $ProcessID,

        [UInt16]
        $MinimumLength = 3,

        [ValidateSet('Default','Ascii','Unicode')]
        [String]
        $Encoding = 'Default',

        [Switch]
        $IncludeImages
    )

    BEGIN {
        $Mod = New-InMemoryModule -ModuleName ProcessStrings

        $FunctionDefinitions = @(
            (func kernel32 OpenProcess ([IntPtr]) @([UInt32], [Bool], [UInt32]) -SetLastError),
            (func kernel32 ReadProcessMemory ([Bool]) @([IntPtr], [IntPtr], [Byte[]], [Int], [Int].MakeByRefType()) -SetLastError),
            (func kernel32 CloseHandle ([Bool]) @([IntPtr]) -SetLastError)
        )

        $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32ProcessStrings'
        $Kernel32 = $Types['kernel32']
    }
    
    PROCESS {
        $hProcess = $Kernel32::OpenProcess(0x10, $False, $ProcessID) # PROCESS_VM_READ (0x00000010)

        Get-ProcessMemoryInfo -ProcessID $ProcessID | ? { $_.State -eq 'MEM_COMMIT' } | % {
            $Allocation = $_
            $ReadAllocation = $True
            if (($Allocation.Type -eq 'MEM_IMAGE') -and (-not $IncludeImages)) { $ReadAllocation = $False }
            # Do not attempt to read guard pages
            if ($Allocation.Protect.ToString().Contains('PAGE_GUARD')) { $ReadAllocation = $False }

            if ($ReadAllocation) {
                $Bytes = New-Object Byte[]($Allocation.RegionSize)

                $BytesRead = 0
                $Result = $Kernel32::ReadProcessMemory($hProcess, $Allocation.BaseAddress, $Bytes, $Allocation.RegionSize, [Ref] $BytesRead)

                if ((-not $Result) -or ($BytesRead -ne $Allocation.RegionSize)) {
                    Write-Warning "Unable to read 0x$($Allocation.BaseAddress.ToString('X16')) from PID $ProcessID. Size: 0x$($Allocation.RegionSize.ToString('X8'))"
                } else {
                    if (($Encoding -eq 'Ascii') -or ($Encoding -eq 'Default')) {
                        # This hack will get the raw ascii chars. The System.Text.UnicodeEncoding object will replace some unprintable chars with question marks.
                        $ArrayPtr = [Runtime.InteropServices.Marshal]::UnsafeAddrOfPinnedArrayElement($Bytes, 0)
                        $RawString = [Runtime.InteropServices.Marshal]::PtrToStringAnsi($ArrayPtr, $Bytes.Length)
                        $Regex = [Regex] "[\x20-\x7E]{$MinimumLength,}"
                        $Regex.Matches($RawString) | % {
                            $Properties = @{
                                Address = [IntPtr] ($Allocation.BaseAddress + $_.Index)
                                Encoding = 'Ascii'
                                String = $_.Value
                            }

                            $String = New-Object PSObject -Property $Properties
                            $String.PSObject.TypeNames.Insert(0, 'MEM.STRING')

                            Write-Output $String
                        }

                        
                    }

                    if (($Encoding -eq 'Unicode') -or ($Encoding -eq 'Default')) {
                        $Encoder = New-Object System.Text.UnicodeEncoding
                        $RawString = $Encoder.GetString($Bytes, 0, $Bytes.Length)
                        $Regex = [Regex] "[\u0020-\u007E]{$MinimumLength,}"
                        $Regex.Matches($RawString) | % {
                            $Properties = @{
                                Address = [IntPtr] ($Allocation.BaseAddress + ($_.Index * 2))
                                Encoding = 'Unicode'
                                String = $_.Value
                            }

                            $String = New-Object PSObject -Property $Properties
                            $String.PSObject.TypeNames.Insert(0, 'MEM.STRING')

                            Write-Output $String
                        }
                    }
                }

                $Bytes = $null
            }
        }
        
        $null = $Kernel32::CloseHandle($hProcess)
    }

    END {}
}