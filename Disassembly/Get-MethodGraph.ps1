Set-StrictMode -Version Latest

function Get-MethodGraph {
    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateCount(1,1000)]
        [Capstone.Instruction[]]
        $Instructions)

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

    $Nodes = Get-GraphNodes $Instructions
    $DotFilePath = [IO.Path]::GetTempFileName()
    New-DotFile $Nodes $DotFilePath

    $DotFilePath

    #Remove-Item $DotFilePath
}