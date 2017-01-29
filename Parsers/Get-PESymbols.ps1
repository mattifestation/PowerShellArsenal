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

Specifies a path to one or more lib file locations.

.PARAMETER SearchMask

Specifies a search mask to filter the symbol names (wildcards allowed).

.PARAMETER PdbSearchPath

Specifies a search path for PDB files (may contain a symbols server url
and a cache folder, eg.: SRV*C:\symbols\dbg*https://msdl.microsoft.com/download/symbols)

.EXAMPLE

Get-PESymbols -Path kernel32.dll

.EXAMPLE

ls *.lib | Get-PESymbols

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
        if (-not ([System.Management.Automation.PSTypeName]'PDB.DbgHelpWrapper').Type)
        {
            if (-not [String]::IsNullOrWhiteSpace($env:_DBGHELP_PATH) -and 
                $(Test-Path $env:_DBGHELP_PATH)) {
                $DbgHelpPath = $env:_DBGHELP_PATH
            } else {
                $DbgHelpPath = "dbghelp.dll"
            }
            $Code = @'
            using System;
            using System.Runtime.InteropServices;
            using System.ComponentModel;
            using Microsoft.Win32;
            using System.Collections.Generic;

            namespace PDB 
            {
                public class SymbolInfo {
                    public String Name { get; set; }
    
                    public UInt64 RVA { get; set; }
    
                    public UInt32 Index { get; set; }
                }

                public class DbgHelpWrapper 
                {
'@
            $Code += "`r`nconst string DbgHelpPath = @`"$DbgHelpPath`";`r`n";
            $Code += @'
                    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
                    internal struct SYMBOL_INFO
                    {
                        public UInt32 SizeOfStruct;  
                        public UInt32 TypeIndex;  
                        public UInt64 Reserved1;  
                        public UInt64 Reserved2;  
                        public UInt32 Index;  
                        public UInt32 Size;  
                        public UInt64 ModBase; 
                        public UInt32 Flags;  
                        public UInt64 Value;  
                        public UInt64 Address;  
                        public UInt32 Register;  
                        public UInt32 Scope;  
                        public UInt32 Tag;  
                        public UInt32 NameLen;  
                        public UInt32 MaxNameLen;  

                        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=1024)]
                        public string Name;
                    }
    
                    delegate bool SymEnumSymbolsProc(
                            [MarshalAs(UnmanagedType.Struct)]
                            SYMBOL_INFO pSymInfo,
                            UInt32 SymbolSize,
                            IntPtr UserContext);
    
                    [DllImport(DbgHelpPath, CharSet = CharSet.Unicode, SetLastError = true)]
	                extern static Boolean SymInitialize(IntPtr hProcess, 
                                                        [MarshalAs(UnmanagedType.LPTStr)]
                                                        String UserSearchPath, 
                                                        Boolean fInvadeProcess);
	
                    [DllImport(DbgHelpPath, CharSet = CharSet.Unicode, SetLastError = true)]
	                extern static Int64 SymLoadModuleEx(IntPtr hProcess, 
                                                        IntPtr hFile, 
                                                        [MarshalAs(UnmanagedType.LPTStr)]
                                                        String ImageName,
                                                        [MarshalAs(UnmanagedType.LPTStr)]
                                                        String ModuleName, 
                                                        Int64 BaseOfDll, 
                                                        Int32 DllSize,
                                                        IntPtr Data, 
                                                        Int32 Flags);
                                            
                    [DllImport(DbgHelpPath, CharSet = CharSet.Unicode, SetLastError = true)]
                    extern static bool SymEnumSymbols(IntPtr hProcess, 
                                                      Int64 BaseOfDll, 
                                                      [MarshalAs(UnmanagedType.LPTStr)]
                                                      String Mask,
                                                      SymEnumSymbolsProc EnumSymbolsCallback, 
                                                      IntPtr UserContext);
                                      
                    [DllImport(DbgHelpPath, CharSet = CharSet.Unicode, SetLastError = true)]
                    extern static bool SymCleanup(IntPtr process);
    
                    public static SymbolInfo[] GetSymbolsForDll(String dllPath, String mask, String searchPath = null) {
                        var regKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
		                var handle = regKey.Handle.DangerousGetHandle();
                        var hFile = new IntPtr(-1);
                        Int64 baseAddress = 0x01000000;
        
                        if (!SymInitialize(handle, searchPath, false)) {
                            throw new Win32Exception();
                        }
                        try {
                            var res = SymLoadModuleEx(handle, hFile, dllPath, null, baseAddress, 0x0 /* FIXME */, IntPtr.Zero, 0);
                            if (res == 0) {
                                throw new Win32Exception();
                            }
    
                            var result = new List<SymbolInfo>();
                            if (!SymEnumSymbols(handle, baseAddress, mask, (symInfo, symSize, userCtx) => {
                                result.Add(new SymbolInfo { 
                                    Name = symInfo.Name,
                                    RVA = symInfo.Address - symInfo.ModBase,
                                    Index = symInfo.Index
                                });
                                return true; 
                            }, IntPtr.Zero)) {
                                throw new Win32Exception();
                            }
                            return result.ToArray();
                        } finally {
                            SymCleanup(handle);
                            regKey.Dispose();
                        }
                    }
                }

            }
'@
            Add-Type -TypeDefinition $Code
        }
    }

    PROCESS
    {
        foreach ($File in $Path)
        {
            # Resolve the absolute path of the DLL file.
            $DllFilePath = Resolve-Path $File
            
            [PDB.DbgHelpWrapper]::GetSymbolsForDll($DllFilePath, $SearchMask, $PdbSearchPath)
        }
    }

    END {}
}
