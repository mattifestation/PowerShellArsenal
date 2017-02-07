function Get-MethodGraph {
<#
.SYNOPSIS

    Draws an assembly graph using GraphViz. 

    PowerSploit Function: Get-MethodGraph
    Author: Sebastian Solnica (@lowleveldesign)
    License: See LICENSE.TXT
    Required Dependencies: GraphViz
    Optional Dependencies: None

.DESCRIPTION

    Get-MethodGraph generates an assembly graph for a given list of assembly instructions.

.PARAMETER Instructions

    A list of instructions to visualize on graph - may be the output of the Get-CSDisassembly or
    the Get-MethodAssembly command.

.PARAMETER OutputFile

    A path to the PNG file containing the method graph. If the path is not specified, a temporary file
    will be created and an image viewer will be called on the destination file.

.EXAMPLE

    Get-MethodAssembly c:\Windows\System32\taskbarcpl.dll DllGetClassObject | Get-MethodGraph

    Get-MethodAssembly c:\Windows\System32\taskbarcpl.dll DllGetClassObject | Get-MethodGraph -OutputFile DllGetClassObject.png

.INPUTS

    Accepts an array of assembly instructions (of type Capstone.Instruction).

.OUTPUTS

    Capstone.Instruction[]

    Get-MethodGraph returns an array of Instruction objects.
#>

    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateCount(1,1000)]
        [Capstone.Instruction[]]
        $Instructions,
        [String]
        $OutputFile
    )

    BEGIN {
        function Local:Get-GraphNodes {
            Param(
                [Capstone.Instruction[]]
                $Instructions)

            $BranchAddresses = @()
            foreach ($Instruction in $Instructions) {
                if ($Instruction.Mnemonic -like 'j*') {
                    $BranchAddresses += $Instruction.Operands
                }
            }

            $Nodes = @()
            $LastNode = $null
            $CurrentNode = $null

            foreach ($Instruction in $Instructions) {
                if (!$CurrentNode) {
                    $CurrentNode = New-Object -TypeName PSObject -Property @{
                        Name = "L0x{0:x}" -f $Instruction.Address
                        Labels = @()
                        ConnectedNodeNames = @()
                    }
                    if ($LastNode) {
                        $LastNode.ConnectedNodeNames += $CurrentNode.Name
                    }
                } elseif (("0x{0:x}" -f $Instruction.Address) -in $BranchAddresses) {
                    $Nodes += $CurrentNode
                    $LastNode = $CurrentNode
                    $CurrentNode = New-Object -TypeName PSObject -Property @{
                        Name = "L0x{0:x}" -f $Instruction.Address
                        Labels = @()
                        ConnectedNodeNames = @()
                    }
                    if ($LastNode) {
                        $LastNode.ConnectedNodeNames += $CurrentNode.Name
                    }
                }
        
                $CurrentNode.Labels += '{0:x8} {1,-10} {2}' -f $Instruction.Address,$Instruction.Mnemonic,$Instruction.Operands

                if ($Instruction.Mnemonic -like 'j*') {
                    $CurrentNode.ConnectedNodeNames += "L$($Instruction.Operands)"
                    $Nodes += $CurrentNode
                    $LastNode = $CurrentNode
                    $CurrentNode = $null
                }
            }

            if ($CurrentNode) {
                $Nodes += $CurrentNode
            }

            $Nodes
        }

        function Local:New-DotFile {
            Param(
                [PSObject[]]
                $Nodes,
                [String]
                $OutputFilePath
            )

            $File = New-Object IO.StreamWriter($OutputFilePath)

            $File.WriteLine('digraph {')
            $File.WriteLine('node [fontname="Lucida Console",shape="box"];')
            $File.WriteLine('graph [fontname="Lucida Console",fontsize=10.0,labeljust=l,nojustify=true,splines=polyline];')

            foreach ($Node in $Nodes) {
                $Label = $Node.Labels -join '\l'
                $File.Write("$($Node.Name)[label=`"$Label\l`"]")
            }
            $File.WriteLine()
            $File.WriteLine()

            foreach ($Node in $Nodes) {
                foreach ($ConnectedNodeName in $Node.ConnectedNodeNames) {
                    $File.WriteLine("$($Node.Name) -> $ConnectedNodeName")
                }
            }

            $File.WriteLine()
            $File.WriteLine('}')

            $File.Close()
        }

        $AllInstructions = @()
    }

    PROCESS {
        $AllInstructions += $Instructions
    }

    END {
        $Nodes = Get-GraphNodes $AllInstructions
        $DotFilePath = [IO.Path]::GetTempFileName()
        New-DotFile $Nodes $DotFilePath

        $InvokeImageViewer = $false
        if (!$OutputFile) {
            $OutputFile = "$DotFilePath.png"
            $InvokeImageViewer = $true
        }

        try {
            & "dot.exe" -T png -o $OutputFile $DotFilePath
            
            if ($InvokeImageViewer) {
                Invoke-Item $OutputFile
            }
        } catch [System.Management.Automation.CommandNotFoundException] {
            throw [InvalidOperationException]"GraphViz bin folder is not in the PATH - please add it first"
        }

        Remove-Item $DotFilePath
    }
}