# Read in all ps1 files expect those in the Lib folder
Get-ChildItem $PSScriptRoot |
    ? {$_.PSIsContainer -and ($_.Name -ne 'Lib')} |
    % {Get-ChildItem "$($_.FullName)\*" -Include '*.ps1'} |
    % {. $_.FullName}