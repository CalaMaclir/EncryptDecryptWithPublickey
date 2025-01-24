############################################################
# EncryptDecrypt.ps1
#   - Modulus���t�@�C���擪�ɕ����ŏ������݁A�������Ƀ`�F�b�N�����
#
#  1) �g���q�� .pubkey �Ȃ�Í��� (EncryptFile)
#  2) �g���q�� .pvtkey �Ȃ畜���� (DecryptFile)
#  3) Modulus�s��v�Ȃ�G���[�\��
# ----------------------------------------------------------
# �����v�]:
#   - #2) �p�X���K�����֐���
#   - #3) �g���q����`#5) ���s��1�̊֐���
############################################################

# --- �֐�: �p�X���K�� (#2 �̕���) ---
function Normalize-Paths {
    Param(
        [Parameter(Mandatory)]
        [string[]]$InputArgs
    )

    # ������ PowerShell �� (Resolve-Path) �Ő�΃p�X�ɐ��K������
    $resolved = $InputArgs | ForEach-Object { (Resolve-Path $_).Path }
    return $resolved
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

    # 4) ���[�h����
    $keyFile   = $null
    $dataFiles = @()

    if ($pubkeys.Count -eq 1) {
        $keyFile = $pubkeys[0]
        # ���̑����Í����Ώ�
        $dataFiles = $AllPaths | Where-Object { $_ -ne $keyFile }
        Write-Host "`n--- �Í������[�h(.pubkey) ---"
        Write-Host "���J��: $keyFile"
    }
    elseif ($pvtkeys.Count -eq 1) {
        $keyFile = $pvtkeys[0]
        # ���̑��𕜍��Ώ�
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
            # �����t�@�C���̕\��
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


# --- 1) �֐���`: EncryptFile ---
function EncryptFile {
Param(
    [Parameter(Mandatory)]
    [string]$PublicKeyPath,
    [Parameter(Mandatory)]
    [string]$InputFilePath
)


    # --- 1) AES���̏��� ---
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.BlockSize = 128
    $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.GenerateKey()
    $aes.GenerateIV()

    # --- 2) ���J���̓ǂݍ��� + RSA�Í��� ---
    $publicKeyXml = Get-Content -Path $PublicKeyPath -Raw
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $rsa.FromXmlString($publicKeyXml)

    # RSA��AES�����Í���
    $encryptedAesKey = $rsa.Encrypt($aes.Key, $false)  # $false=PKCS#1 v1.5

    # --- 2-1) ���J��XML���� <Modulus> �𔲂��o���ABase64����������o�� (�Ȉ�split��) ---
    #    �����^�p�ł�XML�p�[�T�␳�K�\�����g���̂��]�܂����ꍇ����
    $modulusBase64 = ($publicKeyXml -split "<Modulus>|</Modulus>")[1].Trim()
    if (-not $modulusBase64) {
        Write-Host "�G���[: ���J��XML���� <Modulus> ���擾�ł��܂���ł����B"
        return
    }
    $modulusBytes    = [System.Text.Encoding]::UTF8.GetBytes($modulusBase64)
    $modulusLenBytes = [BitConverter]::GetBytes($modulusBytes.Length)

    # --- 3) �o�̓t�@�C���� (���t�@�C���� + .enc) ---
    $baseFileName = [System.IO.Path]::GetFileName($InputFilePath)
    $folder       = [System.IO.Path]::GetDirectoryName($InputFilePath)
    $outEncPath   = Join-Path $folder ($baseFileName + ".enc")

    # --- 4) �o�̓t�@�C������������ ---
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

        #     - �t�@�C���� (�t�@�C������ + �t�@�C����)
        $fileNameBytes    = [System.Text.Encoding]::UTF8.GetBytes($baseFileName)
        $fileNameLenBytes = [BitConverter]::GetBytes($fileNameBytes.Length)
        $cryptoStream.Write($fileNameLenBytes, 0, $fileNameLenBytes.Length)
        $cryptoStream.Write($fileNameBytes,    0, $fileNameBytes.Length)

        #     - �{�̃f�[�^ (�o�b�t�@�ǂݍ��� + ��������)
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


# --- 2) �֐���`: DecryptFile ---
function DecryptFile {
Param(
    [Parameter(Mandatory)]
    [string]$PrivateKeyPath,
    [Parameter(Mandatory)]
    [string]$InputFilePath
)


    # �Í��t�@�C�����J��
    $fsIn = [System.IO.File]::OpenRead($InputFilePath)
    if (-not $fsIn) {
        Write-Host "�G���[: $InputFilePath ���J���܂���ł����B"
        return
    }

    try {
        # 0) �擪: [4byte: Modulus������] + [Modulus������(UTF8)]
        $modLenBuf = New-Object byte[] 4
        $bytesRead = $fsIn.Read($modLenBuf, 0, 4)
        if ($bytesRead -ne 4) {
            Write-Host "�G���[: ���ߍ���Modulus�����ǂݍ��߂܂���B�t�@�C���j��?"
            return
        }
        $modLen = [BitConverter]::ToInt32($modLenBuf, 0)
        if ($modLen -le 0) {
            Write-Host "�G���[: Modulus�����s�� (0�ȉ�)"
            return
        }

        $modulusBytesFromFile = New-Object byte[] $modLen
        $bytesRead = $fsIn.Read($modulusBytesFromFile, 0, $modLen)
        if ($bytesRead -ne $modLen) {
            Write-Host "�G���[: Modulus��������Ō�܂œǂݍ��߂܂���"
            return
        }
        $modulusFromFile = [System.Text.Encoding]::UTF8.GetString($modulusBytesFromFile)

        # 1) IV(16�o�C�g)
        $iv = New-Object byte[] 16
        $bytesRead = $fsIn.Read($iv, 0, 16)
        if ($bytesRead -ne 16) {
            Write-Host "�G���[: IV�̓ǂݍ��݂Ɏ��s"
            return
        }

        # 2) AES���T�C�Y(4�o�C�g)
        $keyLenBuf = New-Object byte[] 4
        $bytesRead = $fsIn.Read($keyLenBuf, 0, 4)
        if ($bytesRead -ne 4) {
            Write-Host "�G���[: AES���T�C�Y(4byte)���ǂݍ��߂܂���"
            return
        }
        $encAesKeyLen = [BitConverter]::ToInt32($keyLenBuf, 0)

        # 3) RSA�Í������ꂽAES��
        $encryptedAesKey = New-Object byte[] $encAesKeyLen
        $bytesRead = $fsIn.Read($encryptedAesKey, 0, $encAesKeyLen)
        if ($bytesRead -ne $encAesKeyLen) {
            Write-Host "�G���[: RSA�Í�AES���̓ǂݍ��ݎ��s"
            return
        }

        # 4) �閧����ǂݍ��� + Modulus��r
        $privateKeyXml = Get-Content -Path $PrivateKeyPath -Raw
        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        $rsa.FromXmlString($privateKeyXml)

        $modulusFromPriv = ($privateKeyXml -split "<Modulus>|</Modulus>")[1].Trim()
        if (-not $modulusFromPriv) {
            Write-Host "�G���[: �閧��XML���� <Modulus> ���擾�ł��܂���B"
            return
        }

        # �s��v�Ȃ�G���[
        if ($modulusFromFile -ne $modulusFromPriv) {
            Write-Host "�G���[: ���̈Í��t�@�C���͕ʂ̌��J���ō���Ă��܂��B(Modulus�s��v)"
            return
        }

        # 5) AES����RSA����
        $aesKey = $rsa.Decrypt($encryptedAesKey, $false)

        # 6) AES�����X�g���[��
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.KeySize = 256
        $aes.BlockSize = 128
        $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $aesKey
        $aes.IV  = $iv

        $decryptor = $aes.CreateDecryptor()
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($fsIn, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)

        # (a) �t�@�C������(4byte) + �t�@�C����
        $fnameLenBuf = New-Object byte[] 4
        $count = $cryptoStream.Read($fnameLenBuf, 0, 4)
        if ($count -lt 4) {
            Write-Host "�G���[: �����f�[�^����t�@�C���������ǂݎ��܂���"
            return
        }
        $fnameLen = [BitConverter]::ToInt32($fnameLenBuf, 0)

        $fnameBuf = New-Object byte[] $fnameLen
        $count = $cryptoStream.Read($fnameBuf, 0, $fnameLen)
        if ($count -lt $fnameLen) {
            Write-Host "�G���[: �����f�[�^����t�@�C������ǂݎ��܂���"
            return
        }
        $originalFileName = [System.Text.Encoding]::UTF8.GetString($fnameBuf)
        Write-Host "���t�@�C����: $originalFileName"

        # (b) �c����t�@�C���o��
        $folder = [System.IO.Path]::GetDirectoryName($InputFilePath)
        $outFilePath = Join-Path $folder $originalFileName
        $fsOut = [System.IO.File]::OpenWrite($outFilePath)
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

        Write-Host "��������: $outFilePath"

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


###############################################################
# --- ���C�����W�b�N: �����`�F�b�N -> Normalize-Paths -> Process-Files
###############################################################

# 1) ����������Ȃ��ꍇ
if ($args.Count -lt 2) {
    Write-Host "�y�G���[�z.pubkey(�܂��� .pvtkey) �� �Í���/�����������t�@�C�� �𓯎��Ƀh���b�v���Ă��������B"
    Pause
    exit 1
}

# 2) �p�X���K�� (�֐��ɐ؂�o��)
$allPaths = Normalize-Paths -InputArgs $args

# 3) ~ 5) ���ꊇ���� (�g���q���� �� ���[�h���� �� ���s)
Process-Files -AllPaths $allPaths
