function Get-KeyDerivation {
    param(
        [securestring] $password
    )

    # convert password from securestring to string for Pbkdf2
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
    try {
        $convertPswd = [System.Text.Encoding]::UTF8.GetBytes(
            [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
        )
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }

    # This function returns the password based key
    $salt = New-Object byte[] 16
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($salt)
    $iterations = 200000
    $hash = [System.Security.Cryptography.HashAlgorithmName]::SHA256
    $size = 32

    $keyder = [Security.Cryptography.Rfc2898DeriveBytes]::Pbkdf2($convertPswd,$salt,$iterations,$hash,$size)

    return $keyder,$salt
}