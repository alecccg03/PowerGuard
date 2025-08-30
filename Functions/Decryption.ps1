function PGDecrypt {
  <#
    .SYNOPSIS
    This function decrypts a file

    .DESCRIPTION
    This function decrypts the file passed to parameter -inputPath and stores it in -outputPath

    .NOTES
    Losing the key-file or password means the encrypted data is unrecoverable. Keep both safe and secure.

    .PARAMETER inputPath
    This is the absolute path of the file you want to decrypt

    .PARAMETER outputPath
    This is the absolute path of where you want the decrypted file to be
    #>

  param (
    [Parameter (Mandatory = $true)]
    [ValidateScript({
        if ($IsWindows -and $_ -notmatch '^(?:[a-zA-Z]:\\|\\\\)(?:[^<>:"/\\|?*\r\n]+\\)*[^<>:"/\\|?*\r\n]+$') { throw "Invalid path for Windows: $_" }
        elseif ($IsLinux -and $_ -notmatch '^(/[^/`0]+)+/?$') { throw "Invalid path for Linux: $_" }
        elseif (-not (Test-Path -LiteralPath $_ -PathType Leaf)) { throw "Path does not exist" }
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

  [securestring] $password = (Read-Host "Enter your password: " -AsSecureString)

  # recreate final aes key from password and file
  $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
  try {
    $convertPswd = [System.Text.Encoding]::UTF8.GetBytes(
      [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    )
  }
  finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
  }
  

  # get saved aes key and compare
  if ($IsWindows) {
    # get saved aes key
    $keyStore = "$ENV:appdata\PowerGuard\Keys"
    $protectedPath = Join-Path $keyStore ("$(Split-Path $inputPath -Leaf).key")
    $protected = [System.IO.File]::ReadAllBytes($protectedPath)
    $unprotected = [System.Security.Cryptography.ProtectedData]::Unprotect($protected, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)

    #get saved salt
    $protectedSaltPath = Join-Path $keyStore ("$(Split-Path $inputPath -Leaf)-salt.key")
    $protectedSalt = [System.IO.File]::ReadAllBytes($protectedSaltPath)
    $unprotectedSalt = [System.Security.Cryptography.ProtectedData]::Unprotect($protectedSalt, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)

    # get saved hmac key
    $protectedHmacPath = Join-Path $keyStore ("$(Split-Path $inputPath -Leaf)-hmac.key")
    $protectedHmac = [System.IO.File]::ReadAllBytes($protectedHmacPath)
    $unprotectedHmacKey = [System.Security.Cryptography.ProtectedData]::Unprotect($protectedHmac, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)


    $iterations = 200000
    $hash = [System.Security.Cryptography.HashAlgorithmName]::SHA256
    $size = 32
    $passwordKey = [Security.Cryptography.Rfc2898DeriveBytes]::Pbkdf2($convertPswd, $unprotectedSalt, $iterations, $hash, $size)

    $keyPath = Join-Path $env:LOCALAPPDATA "Keys\PowerGuard.key"
    $keyFile = [System.IO.File]::ReadAllBytes($keyPath)
    $combinedKey = $passwordKey + $keyFile 
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $recreateKey = $sha.ComputeHash($combinedKey)

    if (! [System.Linq.Enumerable]::SequenceEqual($unprotected, $recreateKey)) {
      throw "Invalid Password!"
    }
  }

 

  if ($IsLinux) {
    # unlock secret vault
    $vaultPath = Join-Path $env:HOME ".local/share/Keys/PGVaultPass.txt"
    $vaultPassword = Get-Content -Path $vaultPath -Raw 
    $secure = ConvertTo-SecureString $vaultPassword -AsPlainText -Force
    Unlock-SecretVault -Name PowerGuard -Password $secure   
    # get saved salt
    $salt = Get-Secret -Name ("$(Split-Path $inputPath -Leaf)-salt") -Vault "PowerGuard" -AsPlainText
    $saltBytes = [System.Convert]::FromBase64String($salt)
    $iterations = 200000
    $hash = [System.Security.Cryptography.HashAlgorithmName]::SHA256
    $size = 32
    $passwordKey = [Security.Cryptography.Rfc2898DeriveBytes]::Pbkdf2($convertPswd, $saltBytes, $iterations, $hash, $size)

    $keyPath = Join-Path $env:HOME ".local/share/Keys/PowerGuard.key"
    $keyFile = [System.IO.File]::ReadAllBytes($keyPath)
    $combinedKey = $passwordKey + $keyFile
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $recreateKey = $sha.ComputeHash($combinedKey)

    $unprotected = Get-Secret -Name ("$(Split-Path $inputPath -Leaf)") -Vault "PowerGuard" -AsPlainText 

    if (-not [System.Linq.Enumerable]::SequenceEqual($unprotected, $recreateKey)) {
      throw "Invalid Password!"
    }

    # get stored hmac key
    $unprotectedHmacKey = Get-Secret -Name ("$(Split-Path $inputPath -Leaf)-hmac") -Vault "PowerGuard" -AsPlainText
  }
 

  # prepare hmac for verification
  $hmac = [System.Security.Cryptography.HMACSHA256]::new($unprotectedHmacKey)


  # create decryption object
  $aesCBC = [System.Security.Cryptography.Aes]::Create()
  $aesCBC.Mode = 'CBC'
  $aesCBC.Padding = 'PKCS7'
  $aesCBC.KeySize = 256
  $aesCBC.Key = $recreateKey

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
    $iv = New-Object byte[] 16
    $bytesRead = $fsIn.Read($iv, 0, $iv.Length)
    if ($bytesRead -ne $iv.Length) { throw "Failed to read IV" }
    $aesCBC.IV = $iv 

    $hmac.TransformBlock($iv, 0, $iv.Length, $null, 0) | Out-Null 

    # get ciphertext length 
    $cipherLength = $fsIn.Length - $iv.Length - 32
    if ($cipherLength -lt 0) { throw "Invalid file format: no ciphertext" }

    $decryptor = $aesCBC.CreateDecryptor()
    $plainBuffer = New-Object byte[] 1MB 
    $cipherBuffer = New-Object byte[] 1MB 

    $remaining = $cipherLength
    while ($remaining -gt 0) {
      $toRead = [Math]::Min($remaining, $cipherBuffer.Length)
      $read = $fsIn.Read($cipherBuffer, 0, $toRead)
      if ($read -le 0) { throw "Decryption failed: Unexpected end of ciphertext" }

      $remaining -= $read

      if ($remaining -gt 0) {
        # stream decryption
        $outCount = $decryptor.TransformBlock($cipherBuffer, 0, $read, $plainBuffer, 0)
        if ($outCount -gt 0) {
          $fsOut.Write($plainBuffer, 0, $outCount)
        }

        # update hmac 
        $hmac.TransformBlock($cipherBuffer, 0, $read, $null, 0) | Out-Null 
      }
      else {
        $finalPlain = $decryptor.TransformFinalBlock($cipherBuffer, 0, $read)
        if ($finalPlain.Length -gt 0) {
          $fsOut.Write($finalPlain, 0, $finalPlain.Length)
        }

        $hmac.TransformBlock($cipherBuffer, 0, $read, $null, 0) | Out-Null 
      }
    }
    $storedTag = New-Object byte[] 32
    $bytesRead = $fsIn.Read($storedTag, 0, $storedTag.Length)
    if ($bytesRead -ne $storedTag.Length) { throw "Decryption Faild: Could not read stored HMAC tag" }

    $hmac.TransformFinalBlock([byte[]]::new(0), 0, 0) | Out-Null 
    $computedTag = $hmac.Hash 

    if (-not [System.Linq.Enumerable]::SequenceEqual($storedTag, $computedTag)) {
      throw "HMAC verification failed: File corrupted or tampered"
    }
  }
  finally {
    $fsIn.Close()
    $fsOut.Close()
    Write-Host "File decrypted"
  }


  if ($IsWindows) {
    # remove used keys after
    Remove-Item -Path $protectedPath -Force
    Write-Verbose "Removed Key File: $protectedPath"

    Remove-Item -Path $protectedSaltPath -Force
    Write-Verbose "Removed Salt File: $protectedSaltPath"

    Remove-Item -Path $protectedHmacPath -Force
    Write-Verbose "Removed HMAC File: $protectedHmacPath" 
  }
  elseif ($IsLinux) {
    # remove secrets after decryption
    Remove-Secret -Name ("$(Split-Path $inputPath -Leaf)") -Vault "PowerGuard"
    Remove-Secret -Name ("$(Split-Path $inputPath -Leaf)-salt") -Vault "PowerGuard"
    Remove-Secret -Name ("$(Split-Path $inputPath -Leaf)-hmac") -Vault "PowerGuard" 
  }


}
