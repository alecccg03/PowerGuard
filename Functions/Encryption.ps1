function PGEncrypt {
    <#
    .SYNOPSIS
    This function encrypts a file

    .DESCRIPTION
    This function encrypts the file passed to parameter -inputPath with dual-layer encryption using AES-256. The password must be at least 8 characters long, contain an uppercase and lowercase letter, a number, and a special character: !@#$%^&*<>?:{}

    .NOTES
    Losing the key-file or password means the encrypted data is unrecoverable. Keep both safe and secure.

    .PARAMETER inputPath
    This is the absolute path of the file you want to encrypt

    .PARAMETER outputPath
    This is the absolute path of where you want the encrypted file to be
    #>

    # This is the function used to encrypt the file specified
    # validate parameters, check if syntax is correct per OS and the file exists
    param(
        [Parameter (Mandatory = $true)] 
        [ValidateScript({
                if ($IsWindows -and $_ -notmatch '^(?:[a-zA-Z]:\\|\\\\)(?:[^<>:"/\\|?*\r\n]+\\)*[^<>:"/\\|?*\r\n]+$') { throw "Invalid path for Windows: $_" }
                elseif ($IsLinux -and $_ -notmatch '^(/[^/`0]+)+/?$') { throw "Invalid path for Linux: $_" }
                elseif (-not (Test-Path -LiteralPath $_ -PathType Leaf)) { throw "Path does not exist or is a directory" }
                else { $true }
            })] 
        [string] $inputPath,
        [Parameter (Mandatory = $true)]
        [ValidateScript({
                if ($IsWindows -and $_ -notmatch '^(?:[a-zA-Z]:\\|\\\\)(?:[^<>:"/\\|?*\r\n]+\\)*[^<>:"/\\|?*\r\n]+$') { throw "Invalid path for Windows: $_" }
                elseif ($IsLinux -and $_ -notmatch '^(/[^/`0]+)+/?$') { throw "Invalid path for Linux: $_" }
            
                $fileName = [System.IO.Path]::GetFileName($_)

                if ([System.IO.Path]::GetExtension($_) -eq "") {
                    throw "Output path cannot be a directory"
                }
                $invalid = [System.IO.Path]::GetInvalidFileNameChars()
                if ($fileName.IndexOfAny($invalid) -ge 0) {
                    throw "Output path contains invalid characters"
                }

                $true 
            })]
        [string] $outputPath
    )

    [securestring] $password = (Read-Host "Enter your password for encryption: " -AsSecureString)
    # check for minimum password requirements
    $BSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR)

        if ($plain.Length -lt 8) { throw "Password must be at least 8 characters" }
        if ($plain -notmatch '[A-Z]') { throw "Password must contain an uppercase letter" }
        if ($plain -notmatch '[a-z]') { throw "Password must contain a lowercase letter" }
        if ($plain -notmatch '[0-9]') { throw "Password must contain a number" }
        if ($plain -notmatch '[!@#$%^&*(),.?":{}|<>]') { throw "Password must contain a special character: !@#$%^&*?<>:{}" }
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR) # clear plain text password after complexity check
    }
    $aesKey = Get-FinalKey -password $password 


    # Create aes object using GCM for better security
    $aesCBC = [System.Security.Cryptography.Aes]::Create()
    $aesCBC.Mode = 'CBC'
    $aesCBC.Padding = 'PKCS7'
    $aesCBC.KeySize = 256
    $aesCBC.Key = $aesKey[0]
    $aesCBC.GenerateIV()

    # create hmac key for integrity checking
    $hmacKey = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($hmacKey)
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($hmacKey)
    
    # use FileStream so it doesn't default to 4KB chunks
    $fsIn = [System.IO.FileStream]::new(
        $inputPath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read,
        1MB,
        [System.IO.FileOptions]::SequentialScan
    )
    $fsOut = [System.IO.FileStream]::new(
        $outputPath,
        [System.IO.FileMode]::Create,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None,
        1MB,
        [System.IO.FileOptions]::SequentialScan
    )

    try {
        # get the IV for the encryption
        $fsOut.Write($aesCBC.IV, 0, $aesCBC.IV.Length)
        $hmac.TransformBlock($aesCBC.IV, 0, $aesCBC.IV.Length, $null, 0) | Out-Null 

        # use streaming to better handle larger files
        $encryptor = $aesCBC.CreateEncryptor()
        $plainBuffer = New-Object byte[] 1MB
        $cipherBuffer = New-Object byte[] ($plainBuffer.Length + 16)

        # create variable to handle small/empty files
        $anyDataRead = $false 

        while (($read = $fsIn.Read($plainBuffer, 0, $plainBuffer.Length)) -gt 0) {
            $anyDataRead = $true 
            $isLast = ($fsIn.Position -eq $fsIn.Length)
            
            if (-not $isLast) {
                # streaming block
                # using TransformBlock instead of CryptoStream to update hmac more easily 
                $outCount = $encryptor.TransformBlock($plainBuffer, 0, $read, $cipherBuffer, 0)
                if ($outCount -gt 0) {
                    $fsOut.Write($cipherBuffer, 0, $outCount)
                    # update hmac
                    $hmac.TransformBlock($cipherBuffer, 0, $outCount, $null, 0) | Out-Null 
                }
            }
            else {
                # final block
                # final block adds padding if needed to meet block size 
                $final = $encryptor.TransformFinalBlock($plainBuffer, 0, $read)
                if ($final.Length -gt 0) {
                    $fsOut.Write($final, 0, $final.Length)
                    $hmac.TransformBlock($final, 0, $final.Length, $null, 0) | Out-Null 
                }
            }
        }
        # handle empty file, add padding to meet block size 
        if (-not $anyDataRead) {
            $final = $encryptor.TransformFinalBlock([byte[]]::new(0), 0, 0)
            $fsOut.Write($final, 0, $final.Length)
            $hmac.TransformBlock($final, 0, $final.Length, $null, 0) | Out-Null 
        }

        # finalize hmac
        $hmac.TransformFinalBlock([byte[]]::new(0), 0, 0) | Out-Null 
        $tag = $hmac.Hash
        $fsOut.Write($tag, 0, $tag.Length)
    }
    finally {
        $fsIn.Close()
        $fsOut.Close()
        Write-Host "File encrypted"
    }


    # Save the AES key with DPAPI 
    # saving to key store based on encryption path allows for multiple files to be encrypted with separate keys
    if ($IsWindows) {
        $keyStore = "$ENV:appdata\PowerGuard\Keys"
        if (!(Test-Path $keyStore)) { New-Item -ItemType Directory -Path $keyStore | Out-Null }
        $protectedFile = Join-Path $keyStore ("$(Split-Path $outputPath -Leaf).key")
        

        $protected = [System.Security.Cryptography.ProtectedData]::Protect($aesKey[0], $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        [System.IO.File]::WriteAllBytes($protectedFile, $protected)

        # save salt so you can use for decryption
        $protectedSaltPath = Join-Path $keyStore ("$(Split-Path $outputPath -Leaf)-salt.key")
        $protectedSalt = [System.Security.Cryptography.ProtectedData]::Protect($aesKey[1], $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        [System.IO.File]::WriteAllBytes($protectedSaltPath, $protectedSalt)

        # save hmac key
        $protectedHmacPath = Join-Path $keyStore ("$(Split-Path $outputPath -Leaf)-hmac.key") 
        $protectedHmac = [System.Security.Cryptography.ProtectedData]::Protect($hmacKey, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
        [System.IO.File]::WriteAllBytes($protectedHmacPath, $protectedHmac)
        
    }

    # Linux does not use DPAPI
    # Save in secret vault using SecretStore
    if ($IsLinux) {
        if (-not (Get-Module -ListAvailable -Name Microsoft.PowerShell.SecretStore)) {
            throw "SecretStore module is required on this OS. Please run: Install-Module Microsoft.PowerShell.SecretStore -Scope CurrentUser"
        }

        # convert salt to use later 
        $base64Salt = [System.Convert]::ToBase64String($aesKey[1])
        # unlock secret vault
        $vaultPath = Join-Path $env:HOME ".local/share/Keys/PGVaultPass.txt"
        $vaultPassword = Get-Content -Path $vaultPath -Raw 
        $secure = ConvertTo-SecureString $vaultPassword -AsPlainText -Force
        Unlock-SecretVault -Name PowerGuard -Password $secure 

        Set-Secret -Name ("$(Split-Path $outputPath -Leaf)") -Secret $aesKey[0] -Vault "PowerGuard"
        Set-Secret -Name ("$(Split-Path $outputPath -Leaf)-salt") -Secret $base64Salt -Vault "PowerGuard"
        Set-Secret -Name ("$(Split-Path $outputPath -Leaf)-hmac") -Secret $hmacKey -Vault "PowerGuard" 
    }
    

    # Clean up sensitive data 
    [Array]::Clear($aesKey[0], 0, $aesKey[0].Length)

}
