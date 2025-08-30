function Get-FinalKey {
    # This function combines the key file and password based key for extra security
    param(
      [securestring] $password 
    )

    $firstKey = Get-KeyDerivation -password $password 

    # This is the key-file key (32 bytes)
    if ($IsWindows) {
      $keyPath = Join-Path $env:LOCALAPPDATA "Keys\PowerGuard.key"
      $keyBytes = [System.IO.File]::ReadAllBytes($keyPath)
      $combinedKey = $firstKey[0] + $keyBytes
      $sha = [System.Security.Cryptography.SHA256]::Create()
      $finalKey = $sha.ComputeHash($combinedKey)
    }

    if ($IsLinux) {
        $keyPath = Join-Path $env:HOME ".local/share/Keys/PowerGuard.key"
        $keyBytes = [System.IO.File]::ReadAllBytes($keyPath)
        $combinedKey = $firstKey[0] + $keyBytes
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $finalKey = $sha.ComputeHash($combinedKey)
    }

    [Array]::Clear($firstKey[0], 0, $firstKey[0].Length)

    # This is the final AES-256 bit key (key-file combined with password based hash)
    return $finalKey,$firstKey[1]
}