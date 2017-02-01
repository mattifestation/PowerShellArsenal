
function Get-MethodAssembly {

    [CmdletBinding(DefaultParameterSetName = 'ByAddress')] Param (
        [Parameter(Mandatory = $True,
                   Position = 0,
                   ValueFromPipelineByPropertyName = $True)]
        [ValidateScript({Test-Path $_ -PathType 'Leaf'})]
        [String]
        $Module,

        [Parameter(Mandatory = $True,
                   Position = 1,
                   ParameterSetName = 'ByName',
                   ValueFromPipelineByPropertyName = $True)]
        [String]
        $Method,

        [Parameter(Mandatory = $True,
                   Position = 1,
                   ParameterSetName = 'ByAddress',
                   ValueFromPipelineByPropertyName = $True)]
        [Alias("RVA")]
        [UInt64]
        $Address
    )

    BEGIN { }

    PROCESS {
        $pe = Get-PE $Module
        if ($PSCmdlet.ParameterSetName -eq "ByName") {
            $Symbols = @(Get-PESymbols -Path $Module -SearchMask $Method)
            if ($Symbols.Length -ne 1) {
                throw [ArgumentException]"The method was not found or more than 1 method with this name exists"
            }
            $Rva = $Symbols[0].RVA
        } else {
            $Rva = $Address
        }

        # we need to transform the relative address against the section base address
        $TextSection = $pe.SectionHeaders | Where-Object Name -EQ ".text"

        $OffsetInFile = $Rva - ($TextSection.VirtualAddress - $TextSection.PointerToRawData)
        $NumberOfBytesToRead = $TextSection.SizeOfRawData - ($Rva - $TextSection.VirtualAddress)
        $NumberOfBytesToRead = [Math]::Min(2048, $NumberOfBytesToRead)

        $FileStream = [IO.File]::OpenRead($Module)
        try {
            $null = $FileStream.Seek($OffsetInFile, [IO.SeekOrigin]::Begin)
            $TextSectionBytes = New-Object Byte[] $NumberOfBytesToRead

            if ($NumberOfBytesToRead -ne $FileStream.Read($TextSectionBytes, 0, $NumberOfBytesToRead)) {
                throw [InvalidOperationException]"Something is wrong with the PE file or I don't know what I'm doing..."
            }

            $Mode = [Capstone.Mode]::Mode32
            if ($pe.Bits -eq 64) {
                $Mode = [Capstone.Mode]::Mode64
            }

            $Code = @(Get-CSDisassembly -Code $TextSectionBytes -Architecture X86 -Mode Mode64 -Count $StepCount)
            if (-not $Code) {
                throw [InvalidOperationException]"Code not understandable"
            }

            # find the return instruction
            $ReturnIndex = $Code.Length - 1
            for ($i = 0; $i -lt $Code.Length; $i++) {
                if ($Code[$i].Mnemonic -eq "ret") {
                    $ReturnIndex = $i
                    break
                }
            }
            $Code[0..$ReturnIndex]
        } finally {
            $FileStream.Close()
        }
    }

    END {
    }
}