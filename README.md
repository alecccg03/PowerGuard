# PowerGuard

A cross-platform PowerShell module for encrypting and decrypting files using AES-256 with PBKDF2 key derivation.

## Features

- 🔐 Dual layer encryption: AES-256 key derived from password and key-file
- 🔓 Decrypt files securely 
- Supports Windows and Linux OS
- Cross-platform SecureString handling

⚠️ Security Note: Always keep your key-file and password safe. If either is lost, encrypted files cannot be recovered.

## Installation 

Copy the module folder into one of the following PowerShell module paths: 

```powershell
$env:PSModulePath -split [IO.Path]::PathSeparator

Import the module to run
'Import-Module PowerGuard'

Verify it loaded
'Get-Module PowerGuard'
```
## Prerequisites

### Windows 🪟

You need to create a key-file before you can encrypt any files. Run the following commands:

```powershell
# create a file to hold the key in %localappdata%\Keys\PowerGuard.key
$keyFile = "$env:LOCALAPPDATA\Keys\PowerGuard.key"
$keyBytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Fill($keyBytes)
[System.IO.File]::WriteAllBytes($keyFile, $keyBytes)
```

### Linux 🐧

On Linux, save your key-file in $env:HOME/.local/share/Keys/PowerGuard.key
```powershell
$keyFile = "$env:HOME/.local/share/Keys/PowerGuard.key"
$keyBytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Fill($keyBytes)
[System.IO.File]::WriteAllBytes($keyFile, $keyBytes)
```
In Linux, you also need to create a vault to store your AES key using SecretManagement. Run the following commands:
```powershell
Install-Module Microsoft.PowerShell.SecretManagement -Scope CurrentUser -Force
Install-Module Microsoft.PowerShell.SecretStore -Scope CurrentUser -Force 
Register-SecretVault -Name PowerGuard -ModuleName Microsoft.PowerShell.SecretStore 

# Store your SecretVault password in a text file in a hidden folder
# this will be used to unlock the vault on encryption/decryption, removing user input at the command line
$vaultPath = Join-Path $env:HOME ".local/share/Keys/PGVaultPass.txt"
"your password here" | Out-File -FilePath $vaultPath -Encoding ASCII -NoNewLine 
```

## Usage 

```powershell 
Get-Help pgencrypt
Get-Help pgdecrypt

PGEncrypt -inputPath "absolute path to file to encrypt" -outputPath "absolute destination path for encrypted file"

PGDecrypt -inputPath "absolute path to file to decrypt" -outputPath "absolute destination path for decrypted file"
``` 


