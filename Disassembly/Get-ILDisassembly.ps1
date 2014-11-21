filter Get-ILDisassembly {
<#
.SYNOPSIS

A MSIL (Microsoft Intermediate Language) disassembler.

Author: Matthew Graeber (@mattifestation)
License: GPLv3
Required Dependencies: de4dot library dlls
Optional Dependencies: Get-ILDisassembly.format.ps1xml

.PARAMETER MethodInfo

A MethodInfo object that describes the implementation of the method and contains the IL for the method.

.EXAMPLE

[Int].GetMethod('Parse', [String]) | Get-ILDisassembly

.EXAMPLE

[Array].GetMethod('BinarySearch', [Type[]]([Array], [Object])) | Get-ILDisassembly

.EXAMPLE

Get-ILDisassembly -AssemblyPath evil.exe -MetadataToken 0x06000001

.OUTPUTS

System.Object

Returns a custom object consisting of the method name, metadata token, method signature, and instructions.
#>

    Param (
        [Parameter(Mandatory = $True, ParameterSetName = 'AssemblyPath')]
        [ValidateScript({Test-Path $_})]
        [Alias('Path')]
        [String]
        $AssemblyPath,

        [Parameter(Mandatory = $True, ParameterSetName = 'AssemblyPath')]
        [ValidateScript({($_ -band 0x06000000) -eq 0x06000000})]
        [Int32]
        $MetadataToken,

        [Parameter(Mandatory = $True, ParameterSetName = 'MethodInfo', ValueFromPipeline = $True)]
        [Reflection.MethodBase]
        $MethodInfo,

        [Parameter(Mandatory = $True, ParameterSetName = 'MethodDef', ValueFromPipeline = $True)]
        [dnlib.DotNet.MethodDef]
        $MethodDef
    )

    switch ($PsCmdlet.ParameterSetName)
    {
        'AssemblyPath' {
            $FullPath = Resolve-Path $AssemblyPath
            $Module = [dnlib.DotNet.ModuleDefMD]::Load($FullPath.Path)
            $Method = $Module.ResolveMethod(($MetadataToken -band 0xFFFFFF))
        }

        'MethodInfo' {
            $Module = [dnlib.DotNet.ModuleDefMD]::Load($MethodInfo.Module)
            $Method = $Module.ResolveMethod(($MethodInfo.MetadataToken -band 0xFFFFFF))
        }

        'MethodDef' {
            $Method = $MethodDef
        }
    }

    if ($Method.HasBody) {
        $Result = @{
            Name = $Method.Name.String
            MetadataToken = "0x$($Method.MDToken.Raw.ToString('X8'))"
            Signature = $Method.ToString()
            Instructions = $Method.MethodBody.Instructions
        }

        $Disasm = New-Object PSObject -Property $Result
        $Disasm.PSObject.TypeNames.Insert(0, 'IL_METAINFO')

        return $Disasm
    } else {
        Write-Warning "Method is not implemented. Name: $($Method.Name.String), MetadataToken: 0x$($Method.MDToken.Raw.ToString('X8'))"
    }
}