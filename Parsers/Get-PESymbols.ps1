function Get-PESymbols
{
<#
.SYNOPSIS

Displays symbolic information for PE files.

Author: Sebastian Solnica (@lowleveldesign)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Get-PESymbols parses and returns symbols for Windows PE files. It uses the dbghelp.dll
library found in C:\Windows\System32, unless you set the _DBGHELP_PATH environment variable
to another path (it requires Powershell restart before the cmdlet will use the new path).

.PARAMETER Path

Specifies a path to one or more PE file locations.

.PARAMETER SearchMask

Specifies a search mask to filter the symbol names (wildcards allowed).

.PARAMETER PdbSearchPath

Specifies a search path for PDB files (may contain a symbols server url
and a cache folder, eg.: SRV*C:\symbols\dbg*https://msdl.microsoft.com/download/symbols)

.EXAMPLE

Get-PESymbols -Path c:\windows\system32\kernel32.dll

.EXAMPLE

PS temp> Get-PESymbols -Path c:\windows\system32\kernel32.dll -SearchMask Load* -PdbSearchPath "SRV*C:\symbols\dbg*https://msdl.microsoft.com/download/symbols"

.EXAMPLE

ls *.dll | Get-PESymbols

.INPUTS

System.String[]

You can pipe a file system path (in quotation marks) to Get-PESymbols.

.OUTPUTS

COFF.SymbolInfo
#>
    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateScript({ Test-Path $_ })]
        [Alias('FullName')]
        [String[]]
        $Path,

        [Parameter(Position = 1, Mandatory = $False, ValueFromPipelineByPropertyName = $False)]
        [String]
        $SearchMask = $null,

        [Parameter(Position = 3, Mandatory = $False, ValueFromPipelineByPropertyName = $False)]
        [String]
        $PdbSearchPath = $env:_NT_SYMBOL_PATH
    )

    BEGIN
    {
        if (-not [String]::IsNullOrWhiteSpace($env:_DBGHELP_PATH) -and 
            $(Test-Path $env:_DBGHELP_PATH)) {
            $DbgHelpPath = $env:_DBGHELP_PATH
        } else {
            $DbgHelpPath = 'dbghelp.dll'
        }

        $Mod = New-InMemoryModule -ModuleName PDBParser

        $SymbolInfoType = struct $Mod PDB.SYMBOL_INFO @{
            SizeOfStruct = field 0 UInt32
            TypeIndex = field 1 UInt32
            Reserved1 = field 2 UInt64
            Reserved2 = field 3 UInt64
            Index = field 4 UInt32
            Size = field 5 UInt32
            ModBase = field 6 UInt64
            Flags = field 7 UInt32
            Value = field 8 UInt64
            Address = field 9 UInt64
            Register = field 10 UInt32
            Scope = field 11 UInt32
            Tag = field 12 UInt32
            NameLen = field 13 UInt32
            MaxNameLen = field 14 UInt32
            Name = field 15 String -MarshalAs @('ByValTStr', 1024)
        } -Charset ([Runtime.InteropServices.CharSet]::Unicode)

        $ShortSymbolInfoType = struct $Mod PDB.SHORT_SYMBOL_INFO @{
            Index = field 0 UInt32
            RVA = field 1 UInt64
            Name = field 2 String
        }

        $script:Symbols = @()
        $CallbackScript = {
            Param (
                [PDB.SYMBOL_INFO]$SymbolInfo,
                [UInt32]$SymbolSize,
                [IntPtr]$UserContext
            )
            $script:Symbols += New-Object -TypeName PDB.SHORT_SYMBOL_INFO -Property @{
                Name = $SymbolInfo.Name
                Index = $SymbolInfo.Index
                RVA = $SymbolInfo.Address - $SymbolInfo.ModBase
            }
            return $True
        }

        $Delegate = ([System.Management.Automation.PSTypeName]'PDB.SymEnumProcDelegateType').Type
        if (-not $Delegate) {
            function Local:Get-DelegateType
            {
                [OutputType([Type])]
                Param (    
                    [Parameter( Position = 0)]
                    [Type[]]
                    $Parameters = (New-Object Type[](0)),
            
                    [Parameter( Position = 1 )]
                    [Type]
                    $ReturnType = [Void]
                )

                $Domain = [AppDomain]::CurrentDomain
                $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
                $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
                $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $False)
                $TypeBuilder = $ModuleBuilder.DefineType('PDB.SymEnumProcDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
                $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
                $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
                $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
                $MethodBuilder.SetImplementationFlags('Runtime, Managed')
        
                return $TypeBuilder.CreateType()
            }

            $Delegate = Get-DelegateType @([PDB.SYMBOL_INFO], [UInt32], [IntPtr]) ([Boolean])
        }
        $Callback = $CallbackScript -as $Delegate

        $FunctionDefinitions = @(
            (func $DbgHelpPath SymInitialize ([Boolean]) @([IntPtr], [String], [Boolean]) -Charset ([Runtime.InteropServices.CharSet]::Unicode) -SetLastError),
            (func $DbgHelpPath SymLoadModuleEx ([Int64]) @([IntPtr], [IntPtr], [String], [String], [Int64], [Int32], [IntPtr], [Int32]) -Charset ([Runtime.InteropServices.CharSet]::Unicode) -SetLastError),
            (func $DbgHelpPath SymEnumSymbols ([Boolean]) @([IntPtr], [Int64], [String], $Delegate, [IntPtr]) -Charset ([Runtime.InteropServices.CharSet]::Unicode) -SetLastError),
            (func $DbgHelpPath SymCleanup ([Boolean]) @([IntPtr]) -Charset ([Runtime.InteropServices.CharSet]::Unicode) -SetLastError)
        )

        $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'PDB'
        $DbgHelp = $Types["dbghelp"]
    }

    PROCESS
    {
        foreach ($File in $Path)
        {
            # Resolve the absolute path of the DLL file.
            $DllFilePath = Resolve-Path $File
            
            $hProcess = [IntPtr]123
            $BaseAddress = 0x01000000

            $null = $DbgHelp::SymInitialize($hProcess, $PdbSearchPath, $False)

            $null = $DbgHelp::SymLoadModuleEx($hProcess, [IntPtr]-1, $DllFilePath, $null, $BaseAddress, 0x0, [IntPtr]::Zero, 0)

            $Symbols.Clear()
            $null = $DbgHelp::SymEnumSymbols($hProcess, $BaseAddress, $SearchMask, $Callback, [IntPtr]::Zero)
            $Symbols

            $null = $DbgHelp::SymCleanup($hProcess)
        }
    }

    END {}
}
