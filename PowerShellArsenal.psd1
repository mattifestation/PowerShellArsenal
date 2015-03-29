@{
# Script module or binary module file associated with this manifest.
ModuleToProcess = 'PowerShellArsenal.psm1'

# Version number of this module.
ModuleVersion = '1.0.0.0'

# ID used to uniquely identify this module
GUID = '55edc9c7-e790-4e78-88d6-0492cdcc4b3c'

# Author of this module
Author = 'Matthew Graeber'

# Company or vendor of this module
CompanyName = ''

# Copyright statement for this module
Copyright = 'BSD 3-Clause unless explicitly noted otherwise'

# Description of the functionality provided by this module
Description = 'Reverse Eningeering Module'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '2.0'

# Assemblies that must be loaded prior to importing this module
RequiredAssemblies = @('Lib\De4dot\dnlib.dll',
                       'Lib\De4dot\de4dot.blocks.dll',
                       'Lib\De4dot\de4dot.code.dll',
                       'Lib\De4dot\de4dot.mdecrypt.dll',
                       'Lib\De4dot\AssemblyData.dll')

# Format files (.ps1xml) to be loaded when importing this module
FormatsToProcess = @('Lib\Formatters\Get-CSDisassembly.format.ps1xml',
                     'Lib\Formatters\Get-ILDisassembly.format.ps1xml',
                     'Lib\Formatters\Get-LibSymbols.format.ps1xml',
                     'Lib\Formatters\Get-NtSystemInformation.format.ps1xml',
                     'Lib\Formatters\Get-ObjDump.format.ps1xml',
                     'Lib\Formatters\Get-PEB.format.ps1xml',
                     'Lib\Formatters\Get-PE.format.ps1xml',
                     'Lib\Formatters\ProcessModuleTrace.format.ps1xml',
                     'Lib\Formatters\MemoryTools.format.ps1xml')

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
NestedModules = @('Lib\Capstone\Capstone.psd1',
                  'Lib\PSReflect\PSReflect.psd1')

# Functions to export from this module
# I've chosen to explicitly the functions I want to expose rather than exporting everything or calling Export-ModuleMember
FunctionsToExport = @('Get-CSDisassembly',
                      'Get-ILDisassembly',
                      'Get-StructFromMemory',
                      'ConvertTo-String',
                      'Get-Strings',
                      'Get-Entropy',
                      'Get-Member',
                      'Get-PE',
                      'Find-ProcessPEs',
                      'Get-LibSymbols',
                      'Get-ObjDump',
                      'Get-SystemInfo',
                      'Get-VirtualMemoryInfo',
                      'Get-ProcessMemoryInfo',
                      'Get-ProcessStrings',
                      'Get-AssemblyResources',
                      'Get-AssemblyStrings',
                      'Get-AssemblyImplementedMethods',
                      'Get-HostsFile',
                      'New-HostsFileEntry',
                      'Remove-HostsFileEntry',
                      'Remove-AssemblySuppressIldasmAttribute',
                      'New-FunctionDelegate',
                      'Get-NtSystemInformation')

# Cmdlets to export from this module
CmdletsToExport = ''

# Variables to export from this module
VariablesToExport = ''

# Aliases to export from this module
AliasesToExport = ''

# List of all modules packaged with this module.
ModuleList = @(@{ModuleName = 'Capstone';  ModuleVersion = '1.0.0.0'; GUID = 'bc335667-02fd-46c4-a3d9-0a5113c9c03b'},
               @{ModuleName = 'PSReflect'; ModuleVersion = '1.1.1.0'; GUID = '32c3f36a-519f-4032-9090-053956ae85e1'})
}
