$functionRoot = Join-Path $PSScriptRoot "Functions"

Get-ChildItem -Path $functionRoot -Filter *.ps1 | ForEach-Object {
    . $_.FullName
}

Export-ModuleMember -Function PGEncrypt,PGDecrypt 

