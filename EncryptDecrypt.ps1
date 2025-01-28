############################################################
# EncryptDecrypt.ps1
#   - �t�@�C���̐擪�ɏ�������Modulus�ƁA���t�@�C��(XML)��Modulus��
#     �ƍ����Ȃ���Í�/�������s��PowerShell�X�N���v�g
#
#  1) �g���q�� .pubkey �Ȃ�Í��� (EncryptFile)
#  2) �g���q�� .pvtkey �Ȃ畜���� (DecryptFile)
#  3) Modulus�s��v�Ȃ�G���[�\��
#
# �\��:
#   - #2) �p�X���K�����֐� (Normalize-Paths)
#   - ���J��/�閧���ǂݍ��݂�Modulus���o�����ʉ� (Get-ModulusFromXmlString)
#   - �e��Í��E���������֐� (EncryptFile, DecryptFile �Ȃ�)
#   - #3�`#5) �g���q����`�t�@�C���������֐� (Process-Files)
#   - ���C�����W�b�N (���������K�����g���q���聨�Í� or ����)
############################################################

# --- ��XML���� <Modulus> �𒊏o����֐� ---
function Get-ModulusFromXmlString {
    Param(
        [Parameter(Mandatory)]
        [string]$XmlString
    )
    # XML�v�f <Modulus> �` </Modulus> ���ȈՓI�Ɏ��o�� (���^�p�ł�XML�p�[�T����)
    $modulusBase64 = ($XmlString -split "<Modulus>|</Modulus>")[1].Trim()
    if (-not $modulusBase64) {
        return $null
    }
    return $modulusBase64
}

# --- �֐�: �p�X���K�� (#2 �̕���) ---
function Normalize-Paths {
    Param(
        [Parameter(Mandatory)]
        [string[]]$InputArgs
    )

    $resolved = $InputArgs | ForEach-Object {
        (Resolve-Path $_).Path
    }
    return $resolved
}

# --- 1) �֐���`: EncryptFile ---
function EncryptFile {
    Param(
        [Parameter(Mandatory)]
        [string]$PublicKeyPath,
        [Parameter(Mandatory)]
        [string]$InputFilePath
    )

    # 1) AES���̏���
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.BlockSize = 128
    $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.GenerateKey()
    $aes.GenerateIV()

    # 2) ���J���̓ǂݍ��� + RSA�Í���
    $publicKeyXml = Get-Content -Path $PublicKeyPath -Raw
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $rsa.FromXmlString($publicKeyXml)

    # ��XML����Modulus���擾
    $modulusBase64 = Get-ModulusFromXmlString -XmlString $publicKeyXml
    if (-not $modulusBase64) {
        Write-Host "�G���[: ���J��XML���� <Modulus> ���擾�ł��܂���ł����B"
        return
    }

    # RSA��AES�����Í��� (PKCS#1 v1.5)
    $encryptedAesKey = $rsa.Encrypt($aes.Key, $false)

    # Modulus�o�C�g��ȂǏ���
    $modulusBytes    = [System.Text.Encoding]::UTF8.GetBytes($modulusBase64)
    $modulusLenBytes = [BitConverter]::GetBytes($modulusBytes.Length)

    # 3) �o�̓t�@�C���� (���t�@�C���� + .enc)
    $baseFileName = [System.IO.Path]::GetFileName($InputFilePath)
    $folder       = [System.IO.Path]::GetDirectoryName($InputFilePath)
    $outEncPath   = Join-Path $folder ($baseFileName + ".enc")

    # 4) �o�̓t�@�C������������
    $fsOut = [System.IO.File]::OpenWrite($outEncPath)
    try {
        # (a) [Modulus��(4byte)] + [Modulus������(UTF8)]
        $fsOut.Write($modulusLenBytes, 0, $modulusLenBytes.Length)
        $fsOut.Write($modulusBytes,    0, $modulusBytes.Length)

        # (b) IV(16�o�C�g)
        $fsOut.Write($aes.IV, 0, $aes.IV.Length)

        # (c) RSA�Í������ꂽAES���̃T�C�Y(4�o�C�g)
        $encKeyLen = $encryptedAesKey.Length
        $lenBytes  = [BitConverter]::GetBytes($encKeyLen)
        $fsOut.Write($lenBytes, 0, $lenBytes.Length)

        # (d) RSA�Í������ꂽAES��
        $fsOut.Write($encryptedAesKey, 0, $encKeyLen)

        # (e) AES�Í��X�g���[�� (�t�@�C���� + �{��)
        $encryptor    = $aes.CreateEncryptor()
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($fsOut, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)

        #   - �t�@�C���� (�t�@�C������ + �t�@�C����)
        $fileNameBytes    = [System.Text.Encoding]::UTF8.GetBytes($baseFileName)
        $fileNameLenBytes = [BitConverter]::GetBytes($fileNameBytes.Length)
        $cryptoStream.Write($fileNameLenBytes, 0, $fileNameLenBytes.Length)
        $cryptoStream.Write($fileNameBytes,    0, $fileNameBytes.Length)

        #   - �{�̃f�[�^ (�o�b�t�@�ǂݍ��� + ��������)
        $fsIn = [System.IO.File]::OpenRead($InputFilePath)
        try {
            $bufSize = 4096
            $buf = New-Object byte[] $bufSize
            while ($true) {
                $bytesRead = $fsIn.Read($buf, 0, $bufSize)
                if ($bytesRead -le 0) { break }
                $cryptoStream.Write($buf, 0, $bytesRead)
            }
            $cryptoStream.FlushFinalBlock()
        }
        finally {
            $fsIn.Close()
        }
    }
    finally {
        $fsOut.Close()
        $aes.Dispose()
        $rsa.Dispose()
    }

    Write-Host "�Í�������: $outEncPath"
}

# --- Modulus�擾�֐� (�Í��t�@�C���擪����) ---
function GetModulusFromEncryptedFile {
    Param(
        [Parameter(Mandatory)]
        [string]$InputFilePath
    )

    $fsIn = [System.IO.File]::OpenRead($InputFilePath)
    if (-not $fsIn) {
        Write-Host "�G���[: $InputFilePath ���J���܂���ł����B"
        return $null
    }

    try {
        # [4byte: Modulus������] + [Modulus������(UTF8)]
        $modLenBuf = New-Object byte[] 4
        $bytesRead = $fsIn.Read($modLenBuf, 0, 4)
        if ($bytesRead -ne 4) {
            Write-Host "�G���[: ���ߍ���Modulus�����ǂݍ��߂܂���B�t�@�C���j��?"
            return $null
        }
        $modLen = [BitConverter]::ToInt32($modLenBuf, 0)

        # 1) Modulus���`�F�b�N (0�ȉ��E1024���͕s��)
        if ($modLen -le 0 -or $modLen -gt 1024) {
            Write-Host "�G���[: Modulus�����s�� ($modLen)"
            return $null
        }

        $modulusBytesFromFile = New-Object byte[] $modLen
        $bytesRead = $fsIn.Read($modulusBytesFromFile, 0, $modLen)
        if ($bytesRead -ne $modLen) {
            Write-Host "�G���[: Modulus��������Ō�܂œǂݍ��߂܂���"
            return $null
        }
        $modulusFromFile = [System.Text.Encoding]::UTF8.GetString($modulusBytesFromFile)

        return @{
            Modulus  = $modulusFromFile
            Position = $fsIn.Position
        }
    }
    finally {
        $fsIn.Close()
    }
}

# --- (�V�K) �Í��t�@�C���擪����Modulus���擾���ĕԂ��֐� ---
function Get-ModulusInfoOrFail {
    Param(
        [Parameter(Mandatory)]
        [string]$EncryptedFilePath
    )

    # GetModulusFromEncryptedFile ���Ăяo���A���s������G���[�\�����đ����^�[��
    $modulusInfo = GetModulusFromEncryptedFile -InputFilePath $EncryptedFilePath
    if (-not $modulusInfo) {
        Write-Host "�G���[: Modulus�擾�Ɏ��s���܂����B"
        return $null
    }
    return $modulusInfo
}

# --- 2) �֐���`: DecryptFile ---
function DecryptFile {
    Param(
        [Parameter(Mandatory)]
        [string]$PrivateKeyPath,
        [Parameter(Mandatory)]
        [string]$InputFilePath
    )

    # 1) �Í��t�@�C���擪����Modulus�擾 (�؂�o�����֐��𗘗p)
    $modulusInfo = Get-ModulusInfoOrFail -EncryptedFilePath $InputFilePath
    if (-not $modulusInfo) {
        return  # ��L�ŃG���[�ς݂Ȃ̂ł����ŏI��
    }
    $modulusFromFile = $modulusInfo.Modulus
    $currentPosition = $modulusInfo.Position

    # 2) �閧����ǂݍ��� + Modulus��r
    $privateKeyXml = Get-Content -Path $PrivateKeyPath -Raw
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $rsa.FromXmlString($privateKeyXml)

    # ��XML����Modulus���擾
    $modulusFromPriv = Get-ModulusFromXmlString -XmlString $privateKeyXml
    if (-not $modulusFromPriv) {
        Write-Host "�G���[: �閧��XML���� <Modulus> ���擾�ł��܂���B"
        return
    }

    # �s��v�Ȃ�G���[
    if ($modulusFromFile -ne $modulusFromPriv) {
        Write-Host "�G���[: ���̈Í��t�@�C���͕ʂ̌��J���ō���Ă��܂��B(Modulus�s��v)"
        return
    }
    Write-Host "Modulus��v: ���������𑱍s���܂��B"

    # 3) �Í��t�@�C�����ēx�J���A�����̈ʒu����ǂݍ���
    $fsIn = [System.IO.File]::OpenRead($InputFilePath)
    $fsIn.Seek($currentPosition, [System.IO.SeekOrigin]::Begin) > $null

    try {
        # 4) IV(16�o�C�g)
        $iv = New-Object byte[] 16
        $bytesRead = $fsIn.Read($iv, 0, 16)
        if ($bytesRead -ne 16) {
            Write-Host "�G���[: IV�̓ǂݍ��݂Ɏ��s"
            return
        }

        # 5) AES���T�C�Y(4�o�C�g)���擾
        $keyLenBuf = New-Object byte[] 4
        $bytesRead = $fsIn.Read($keyLenBuf, 0, 4)
        if ($bytesRead -ne 4) {
            Write-Host "�G���[: AES���T�C�Y(4byte)���ǂݍ��߂܂���"
            return
        }
        $encAesKeyLen = [BitConverter]::ToInt32($keyLenBuf, 0)

        # (a) AES���T�C�Y�̑Ó����`�F�b�N (��: 0�ȉ� or 4096���͕s��)
        if ($encAesKeyLen -le 0 -or $encAesKeyLen -gt 4096) {
            Write-Host "�G���[: AES���T�C�Y���s�� ($encAesKeyLen)"
            return
        }

        # 6) RSA�Í������ꂽAES����ǂݍ���
        $encryptedAesKey = New-Object byte[] $encAesKeyLen
        $bytesRead = $fsIn.Read($encryptedAesKey, 0, $encAesKeyLen)
        if ($bytesRead -ne $encAesKeyLen) {
            Write-Host "�G���[: RSA�Í�AES���̓ǂݍ��ݎ��s"
            return
        }

        # 7) AES����RSA����
        $aesKey = $rsa.Decrypt($encryptedAesKey, $false)

        # 8) AES�����X�g���[��
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.KeySize = 256
        $aes.BlockSize = 128
        $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $aesKey
        $aes.IV  = $iv

        $decryptor    = $aes.CreateDecryptor()
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($fsIn, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)

        # 9) �t�@�C������(4byte) + �t�@�C����
        $fnameLenBuf = New-Object byte[] 4
        $count = $cryptoStream.Read($fnameLenBuf, 0, 4)
        if ($count -lt 4) {
            Write-Host "�G���[: �����f�[�^����t�@�C���������ǂݎ��܂���"
            return
        }
        $fnameLen = [BitConverter]::ToInt32($fnameLenBuf, 0)

        # (b) �t�@�C�������̃`�F�b�N
        if ($fnameLen -le 0 -or $fnameLen -gt 512) {
            Write-Host "�G���[: �t�@�C���������s���ł� ($fnameLen)"
            return
        }

        $fnameBuf = New-Object byte[] $fnameLen
        $count = $cryptoStream.Read($fnameBuf, 0, $fnameLen)
        if ($count -lt $fnameLen) {
            Write-Host "�G���[: �����f�[�^����t�@�C������ǂݎ��܂���"
            return
        }
        $originalFileName = [System.Text.Encoding]::UTF8.GetString($fnameBuf)

        # (c) �t�@�C�����̈��S�΍�
        $invalidChars = [System.IO.Path]::GetInvalidFileNameChars()
        foreach ($c in $invalidChars) {
            $originalFileName = $originalFileName -replace [Regex]::Escape($c), '_'
        }

        # �f�B���N�g���g���o�[�T�������֎~
        $folder = [System.IO.Path]::GetDirectoryName($InputFilePath)
        $outFilePath = Join-Path $folder $originalFileName

        $fullOutFilePath = [System.IO.Path]::GetFullPath($outFilePath)
        $fullFolderPath  = [System.IO.Path]::GetFullPath($folder)
        if (-not $fullOutFilePath.StartsWith($fullFolderPath)) {
            Write-Host "�G���[: �f�B���N�g���O�ւ̏������݂����s����܂����B"
            return
        }

        Write-Host "���t�@�C����: $originalFileName"

        # 10) �c����t�@�C���o��
        $fsOut = [System.IO.File]::OpenWrite($fullOutFilePath)
        try {
            $bufSize = 4096
            $buf = New-Object byte[] $bufSize
            while ($true) {
                $rd = $cryptoStream.Read($buf, 0, $bufSize)
                if ($rd -le 0) { break }
                $fsOut.Write($buf, 0, $rd)
            }
        }
        finally {
            $fsOut.Close()
        }

        Write-Host "��������: $fullOutFilePath"

        $cryptoStream.Close()
        $cryptoStream.Dispose()
        $decryptor.Dispose()
        $aes.Dispose()
        $rsa.Dispose()
    }
    finally {
        $fsIn.Close()
    }
}

# --- �֐�: ���C������ (#3 ~ #5 �̕���) ---
function Process-Files {
    Param(
        [Parameter(Mandatory)]
        [string[]]$AllPaths
    )

    # 3) �g���q�� .pubkey / .pvtkey �̃t�@�C�����o
    $pubkeys = @()
    $pvtkeys = @()

    foreach ($path in $AllPaths) {
        $lowerPath = $path.ToLower()
        if ($lowerPath.EndsWith(".pubkey")) {
            $pubkeys += $path
        }
        elseif ($lowerPath.EndsWith(".pvtkey")) {
            $pvtkeys += $path
        }
    }

    # ���t�@�C����������������A�������݁A0�̏ꍇ�G���[
    if (($pubkeys.Count -gt 0) -and ($pvtkeys.Count -gt 0)) {
        Write-Host "�y�G���[�z.pubkey �� .pvtkey �������Ɋ܂܂�Ă��܂��B1�����ɂ��Ă��������B"
        Pause
        exit 1
    }
    if (($pubkeys.Count + $pvtkeys.Count) -eq 0) {
        Write-Host "�y�G���[�z���t�@�C��(.pubkey �܂��� .pvtkey)��1��������܂���B"
        Pause
        exit 1
    }
    if (($pubkeys.Count + $pvtkeys.Count) -gt 1) {
        Write-Host "�y�G���[�z���t�@�C��������������܂����B1�����ɂ��Ă��������B"
        Pause
        exit 1
    }

    # 4) ���[�h���� (�Í��� or ������)
    $keyFile   = $null
    $dataFiles = @()

    if ($pubkeys.Count -eq 1) {
        $keyFile   = $pubkeys[0]
        $dataFiles = $AllPaths | Where-Object { $_ -ne $keyFile }
        Write-Host "`n--- �Í������[�h(.pubkey) ---"
        Write-Host "���J��: $keyFile"
    }
    elseif ($pvtkeys.Count -eq 1) {
        $keyFile   = $pvtkeys[0]
        $dataFiles = $AllPaths | Where-Object { $_ -ne $keyFile }
        Write-Host "`n--- ���������[�h(.pvtkey) ---"
        Write-Host "�閧��: $keyFile"
    }

    if ($dataFiles.Count -eq 0) {
        Write-Host "�y�G���[�z�Í���/����������t�@�C��������܂���B"
        Pause
        exit 1
    }

    # 5) ���s (�Í� or ����)
    foreach ($f in $dataFiles) {
        if (-not (Test-Path $f)) {
            Write-Host "�y�G���[�z�t�@�C�������݂��܂���: $f"
            continue
        }
        else {
            Write-Host "�����Ώۃt�@�C��: $f"
        }
        if ($pubkeys.Count -eq 1) {
            EncryptFile -PublicKeyPath $keyFile -InputFilePath $f
        }
        else {
            DecryptFile -PrivateKeyPath $keyFile -InputFilePath $f
        }
    }
    Pause
    exit 0
}

###############################################################
# --- ���C�����W�b�N: �����`�F�b�N -> Normalize-Paths -> Process-Files
###############################################################

# 1) ����������Ȃ��ꍇ
if ($args.Count -lt 2) {
    Write-Host "�y�G���[�z.pubkey(�܂��� .pvtkey) �� �Í���/�����������t�@�C�� �𓯎��Ƀh���b�v���Ă��������B"
    Pause
    exit 1
}

# 2) �p�X���K��
$allPaths = Normalize-Paths -InputArgs $args

# 3) ~ 5) ���ꊇ���� (�g���q���� �� ���[�h���� �� ���s)
Process-Files -AllPaths $allPaths
