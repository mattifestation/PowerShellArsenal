### PowerShellArsenal is a PowerShell module used to aid a reverse engineer. The module can be used to disassemble managed and unmanaged code, perform .NET malware analysis, analyze/scrape memory, parse file formats and memory structures, obtain internal system information, etc. PowerShellArsenal is comprised of the following tools:

## Disassembly

**Disassemble native and managed code.**

#### `Get-CSDisassembly`

Disassembles a byte array using the Capstone Engine disassembly framework.

#### `Get-ILDisassembly`

Disassembles a raw MSIL byte array passed in from a MethodInfo object in a manner similar to that of Ildasm.

## MalwareAnalysis

**Useful tools when performing malware analysis.**

#### `New-FunctionDelegate`

Provides an executable wrapper for an X86 or X86_64 function.

#### `Get-HostsFile`

Parses a HOSTS file.

#### `New-HostsFileEntry`

Replace or append an entry to a HOSTS file.

#### `Remove-HostsFileEntry`

Remove an entry or series of entries from a HOSTS file.

#### `Get-AssemblyStrings`

Output all strings from a .NET executable.

#### `Get-AssemblyResources`

Extract managed resources from a .NET assembly

#### `Remove-AssemblySuppressIldasmAttribute`

Strips a SuppressIldasmAttribute attribute from a .NET assembly.

#### `Get-AssemblyImplementedMethods`

Returns all methods in an assembly that are implemented in MSIL.

## MemoryTools

**Inspect and analyze process memory**

#### `Get-ProcessStrings`

Outputs all printable strings from the user-mode memory of a process.

#### `Get-VirtualMemoryInfo`

A wrapper for kernel32!VirtualQueryEx

#### `Get-ProcessMemoryInfo`

Retrieve virtual memory information for every unique set of pages in user memory. This function is similar to the !vadump WinDbg command.

#### `Get-StructFromMemory`

Marshals data from an unmanaged block of memory in an arbitrary process to a newly allocated managed object of the specified type.

## Parsers

**Parse file formats and in-memory structures.**

#### `Get-PE`

An on-disk and in-memory PE parser and process dumper.

#### `Find-ProcessPEs`

Finds portable executables in memory regardless of whether or not they were loaded in a legitimate fashion.

#### `Get-LibSymbols`

Displays symbolic information from Windows LIB files.

#### `Get-ObjDump`

Displays information about Windows object (OBJ) files.

## WindowsInternals

**Obtain and analyze low-level Windows OS information.**

#### `Get-NtSystemInformation`

A utility that calls and parses the output of the ntdll!NtQuerySystemInformation function. This utility can be used to query internal OS information that is typically not made visible to a user.

#### `Get-PEB`

Returns the process environment block (PEB) of a process.

#### `Register-ProcessModuleTrace`

Starts a trace of loaded process modules

#### `Get-ProcessModuleTrace`

Displays the process modules that have been loaded since the call to Register-ProcessModuleTrace

#### `Unregister-ProcessModuleTrace`

Stops the running process module trace

#### `Get-SystemInfo`

A wrapper for kernel32!GetSystemInfo

## Misc

**Miscellaneous helper functions**

#### `Get-Member`

A proxy function used to extend the built-in Get-Member cmdlet. It adds the '-Private' parameter allowing you to display non-public .NET members

#### `Get-Strings`

Dumps strings from files in both Unicode and Ascii. This cmdlet replicates the functionality of strings.exe from Sysinternals.

#### `ConvertTo-String`

Converts the bytes of a file to a string that has a 1-to-1 mapping back to the file's original bytes. ConvertTo-String is useful for performing binary regular expressions.

#### `Get-Entropy`

Calculates the entropy of a file or byte array.

## Lib

**Libraries required by some of the RE functions.**

#### `Capstone`

The Capstone disassembly engine C# binding.

#### `De4dot`

A powerful .NET deobfuscation and .NET PE parsing library.

#### `PSReflect`

A module used to easily define in-memory enums, structs, and Win32 functions.

#### `Formatters`

ps1xml files used to format the output of various PowerShellArsenal functions.

## License

The PowerShellArsenal module and all individual scripts are under the [BSD 3-Clause license](https://raw.github.com/mattifestation/PowerSploit/master/LICENSE) unless explicitly noted otherwise.

## Usage

Refer to the comment-based help in each individual script for detailed usage information.

To install this module, drop the entire PowerShellArsenal folder into one of your module directories. The default PowerShell module paths are listed in the $Env:PSModulePath environment variable.

The default per-user module path is: "$Env:HomeDrive$Env:HOMEPATH\Documents\WindowsPowerShell\Modules"
The default computer-level module path is: "$Env:windir\System32\WindowsPowerShell\v1.0\Modules"

To use the module, type `Import-Module PowerShellArsenal`

To see the commands imported, type `Get-Command -Module PowerShellArsenal`

If you're running PowerShell v3 and you want to remove the annoying 'Do you really want to run scripts downloaded from the Internet' warning, once you've placed PowerShellArsenal into your module path, run the following one-liner:
`$Env:PSModulePath.Split(';') |
 % { if ( Test-Path (Join-Path $_ PowerShellArsenal) )
 {Get-ChildItem $_ -Recurse | Unblock-File} }`

For help on each individual command, Get-Help is your friend.

Note: The tools contained within this module were all designed such that they can be run individually. Including them in a module simply lends itself to increased portability.

## Script Style Guide

**For all contributors and future contributors to PowerShellArsenal, I ask that you follow this style guide when writing your scripts/modules.**

* Avoid Write-Host **at all costs**. PowerShell functions/cmdlets are not command-line utilities! Pull requests containing code that uses Write-Host will not be considered. You should output custom objects instead. For more information on creating custom objects, read these articles:
   * <http://blogs.technet.com/b/heyscriptingguy/archive/2011/05/19/create-custom-objects-in-your-powershell-script.aspx>
   * <http://technet.microsoft.com/en-us/library/ff730946.aspx>

* If you want to display relevant debugging information to the screen, use Write-Verbose. The user can always just tack on '-Verbose'.

* Always provide descriptive, comment-based help for every script. Also, be sure to include your name and a BSD 3-Clause license (unless there are extenuating circumstances that prevent the application of the BSD license).

* Make sure all functions follow the proper PowerShell verb-noun agreement. Use Get-Verb to list the default verbs used by PowerShell. Exceptions to supported verbs will be considered on a case-by-case basis.

* I prefer that variable names be capitalized and be as descriptive as possible.

* Provide logical spacing in between your code. Indent your code to make it more readable.

* If you find yourself repeating code, write a function.

* Catch all anticipated errors and provide meaningful output. If you have an error that should stop execution of the script, use 'Throw'. If you have an error that doesn't need to stop execution, use Write-Error.

* If you are writing a script that interfaces with the Win32 API, try to avoid compiling C# inline with Add-Type. Try to use the PSReflect module, if possible.

* Do not use hardcoded paths. A script should be useable right out of the box. No one should have to modify the code unless they want to.

* PowerShell v2 compatibility is highly desired.

* Use positional parameters and make parameters mandatory when it makes sense to do so. For example, I'm looking for something like the following:
   * `[Parameter(Position = 0, Mandatory = $True)]`

* Don't use any aliases unless it makes sense for receiving pipeline input. They make code more difficult to read for people who are unfamiliar with a particular alias.

* Try not to let commands run on for too long. For example, a pipeline is a natural place for a line break.

* Don't go overboard with inline comments. Only use them when certain aspects of the code might be confusing to a reader.

* Rather than using Out-Null to suppress unwanted/irrelevant output, save the unwanted output to $null. Doing so provides a slight performance enhancement.

* Use default values for your parameters when it makes sense. Ideally, you want a script that will work without requiring any parameters.

* Explicitly state all required and optional dependencies in the comment-based help for your function. All library dependencies should reside in the 'Lib' folder.

* If a script creates complex custom objects, include a ps1xml file that will properly format the object's output. ps1xml files are stored in Lib\Formatters.