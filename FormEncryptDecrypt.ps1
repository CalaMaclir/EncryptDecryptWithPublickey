########################################################################
# EncryptDecryptGUI_Standalone.ps1
#
# 1�̃X�N���v�g���ɈÍ�/�������W�b�N + GUI ���܂Ƃ߂��T���v��
#   - keys �t�H���_�F���J��(.pubkey)/�閧��(.pvtkey)���Ǘ�
#   - RSA���J���ɂ��AES���Í��� + AES�Ńt�@�C���Í�
#   - �������͈Í��t�@�C���擪����Modulus���擾���Akeys�ɂ���閧���������}�b�`���O
#   - GUI��Ńt�@�C���h���b�v,������,�Í���,�����𑀍�
########################################################################

# --- �K�v�ȃA�Z���u�� ---
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.IO

#=== 1) �X�N���v�g���O�ݒ� ============================================

# �{�X�N���v�g�̃t�H���_
$scriptFolder = Split-Path -Parent $MyInvocation.MyCommand.Path

# ���t�H���_ (keys) �����݂��Ȃ���΍쐬
$keysFolder = Join-Path $scriptFolder "keys"
if (-not (Test-Path $keysFolder)) {
    New-Item -ItemType Directory -Path $keysFolder | Out-Null
}

#=== 2) ���ʊ֐�: RSA���y�A���� =======================================

function Generate-KeyPair {
    # ��ӂ�ID������Ő��� (�K�v�ɉ����ĕύX)
    $id = (Get-Date).ToString("yyyyMMddHHmmss")

    # 2048bit RSA�����쐬
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider(2048)
    $privateXml = $rsa.ToXmlString($true)
    $publicXml  = $rsa.ToXmlString($false)
    $rsa.Dispose()

    # .pvtkey / .pubkey ��ۑ�
    $pvtPath = Join-Path $keysFolder "$id.pvtkey"
    $pubPath = Join-Path $keysFolder "$id.pubkey"

    $privateXml | Out-File -FilePath $pvtPath -Encoding UTF8 -Force
    $publicXml  | Out-File -FilePath $pubPath -Encoding UTF8 -Force

    Write-Host "���y�A����: $pvtPath, $pubPath"
    return $id
}

#=== 3) �Í��E�������W�b�N�ɕK�v�Ȋ֐� ================================

# (A) ���J��/�閧��XML���� <Modulus> �����o���ȈՊ֐�
function Get-ModulusFromXmlString {
    Param([string]$XmlString)
    if (-not $XmlString) { return $null }
    $spl = $XmlString -split "<Modulus>|</Modulus>"
    if ($spl.Count -lt 2) { return $null }
    return $spl[1].Trim()
}

# (B) �Í��t�@�C���擪���� Modulus �����o��
function GetModulusFromEncryptedFile {
    Param([string]$InputFilePath)
    if (-not (Test-Path $InputFilePath)) {
        Write-Host "�t�@�C�������݂��܂���: $InputFilePath"
        return $null
    }

    try {
        $fsIn = [System.IO.File]::OpenRead($InputFilePath)
        $br   = New-Object System.IO.BinaryReader($fsIn)
        
        # 4byte: Modulus��
        $modLenBytes = $br.ReadBytes(4)
        if ($modLenBytes.Count -lt 4) {
            Write-Host "�G���[: Modulus��(4byte)��ǂݍ��߂܂���B"
            $br.Close(); $fsIn.Close()
            return $null
        }
        $modLen = [BitConverter]::ToInt32($modLenBytes, 0)
        if ($modLen -le 0 -or $modLen -gt 1024) {
            Write-Host "�G���[: Modulus�����s�� ($modLen)"
            $br.Close(); $fsIn.Close()
            return $null
        }

        # Modulus������(UTF8)
        $modBytes = $br.ReadBytes($modLen)
        if ($modBytes.Count -ne $modLen) {
            Write-Host "�G���[: Modulus�������ǂݎ�肫��܂���B"
            $br.Close(); $fsIn.Close()
            return $null
        }
        $modulusFromFile = [System.Text.Encoding]::UTF8.GetString($modBytes)

        $br.Close(); $fsIn.Close()
        return $modulusFromFile
    }
    catch {
        Write-Host "�G���[: $($_.Exception.Message)"
        return $null
    }
}

#=== 4) �Í����֐� (EncryptFile) ======================================
function EncryptFile {
    Param(
        [Parameter(Mandatory)][string]$PublicKeyPath,
        [Parameter(Mandatory)][string]$InputFilePath
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

    # ���J��XML����Modulus�擾
    $modulusBase64 = Get-ModulusFromXmlString -XmlString $publicKeyXml
    if (-not $modulusBase64) {
        Write-Host "�G���[: ���J��XML���� <Modulus> ���擾�ł��܂���B -> $PublicKeyPath"
        return
    }

    # AES����RSA�ňÍ��� (PKCS#1 v1.5)
    $encryptedAesKey = $rsa.Encrypt($aes.Key, $false)

    # 3) �o�̓t�@�C���� (���t�@�C�� + .enc)
    $baseFileName = [System.IO.Path]::GetFileName($InputFilePath)
    $folder       = [System.IO.Path]::GetDirectoryName($InputFilePath)
    $outEncPath   = Join-Path $folder ($baseFileName + ".enc")

    # 4) �o�̓t�@�C����������
    $fsOut = [System.IO.File]::OpenWrite($outEncPath)
    try {
        # (a) [Modulus��(4byte)] + [Modulus������(UTF8)]
        $modulusBytes = [System.Text.Encoding]::UTF8.GetBytes($modulusBase64)
        $modulusLenBytes = [BitConverter]::GetBytes($modulusBytes.Length)
        $fsOut.Write($modulusLenBytes, 0, $modulusLenBytes.Length)
        $fsOut.Write($modulusBytes,    0, $modulusBytes.Length)

        # (b) IV(16�o�C�g)
        $fsOut.Write($aes.IV, 0, $aes.IV.Length)

        # (c) RSA�Í������ꂽAES���T�C�Y(4�o�C�g) + �{��
        $encKeyLen = $encryptedAesKey.Length
        $lenBytes  = [BitConverter]::GetBytes($encKeyLen)
        $fsOut.Write($lenBytes, 0, $lenBytes.Length)
        $fsOut.Write($encryptedAesKey, 0, $encKeyLen)

        # (d) AES�Í��X�g���[��
        $encryptor    = $aes.CreateEncryptor()
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($fsOut, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)

        #   - �t�@�C���� (�t�@�C������ + �t�@�C����)
        $fileNameBytes    = [System.Text.Encoding]::UTF8.GetBytes($baseFileName)
        $fileNameLenBytes = [BitConverter]::GetBytes($fileNameBytes.Length)
        $cryptoStream.Write($fileNameLenBytes, 0, $fileNameLenBytes.Length)
        $cryptoStream.Write($fileNameBytes,    0, $fileNameBytes.Length)

        #   - ���f�[�^
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

#=== 5) �����֐� (DecryptFile) =========================================
function DecryptFile {
    Param(
        [Parameter(Mandatory)][string]$PrivateKeyPath,
        [Parameter(Mandatory)][string]$InputFilePath
    )

    if (-not (Test-Path $InputFilePath)) {
        Write-Host "�G���[: �����Ώۃt�@�C����������܂��� -> $InputFilePath"
        return
    }

    # 1) �Í��t�@�C���擪����Modulus�擾
    $modulusFromFile = GetModulusFromEncryptedFile -InputFilePath $InputFilePath
    if (-not $modulusFromFile) {
        Write-Host "�G���[: �Í��t�@�C������Modulus���擾�ł��܂���B"
        return
    }

    # 2) �閧��XML���擾���AModulus�ƍ�
    $privateXml = Get-Content -Path $PrivateKeyPath -Raw
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $rsa.FromXmlString($privateXml)

    $modulusFromPriv = Get-ModulusFromXmlString -XmlString $privateXml
    if (-not $modulusFromPriv) {
        Write-Host "�G���[: �閧��XML���� <Modulus> ���擾�ł��܂���B -> $PrivateKeyPath"
        return
    }

    if ($modulusFromFile -ne $modulusFromPriv) {
        Write-Host "�G���[: �Í��t�@�C����Modulus�Ɣ閧������v���܂���B"
        return
    }

    Write-Host "Modulus��v: �����𑱍s���܂��B"

    # 3) �t�@�C���ăI�[�v��
    $fsIn = [System.IO.File]::OpenRead($InputFilePath)
    try {
        $br = New-Object System.IO.BinaryReader($fsIn)

        # (a) �擪4byte + Modulus(���łɎ擾�ς�) �Ȃ̂� skip
        #     => skip: 4 + $modulusFromFile.Length
        #     �������o�C�g����Seek���邽�߁A������̃o�C�g�������߂Čv�Z
        $modLen = [System.Text.Encoding]::UTF8.GetByteCount($modulusFromFile)
        $fsIn.Seek(4 + $modLen, [System.IO.SeekOrigin]::Begin) > $null

        # (b) IV(16�o�C�g)
        $iv = $br.ReadBytes(16)
        if ($iv.Count -ne 16) {
            Write-Host "�G���[: IV�̓ǂݍ��݂Ɏ��s"
            return
        }

        # (c) AES���T�C�Y(4�o�C�g)
        $keyLenBytes = $br.ReadBytes(4)
        if ($keyLenBytes.Count -lt 4) {
            Write-Host "�G���[: AES���T�C�Y(4byte)���ǂݍ��߂܂���"
            return
        }
        $encAesKeyLen = [BitConverter]::ToInt32($keyLenBytes, 0)

        # (d) RSA�Í������ꂽAES���{��
        if ($encAesKeyLen -le 0 -or $encAesKeyLen -gt 4096) {
            Write-Host "�G���[: AES���T�C�Y���s�� ($encAesKeyLen)"
            return
        }
        $encryptedAesKey = $br.ReadBytes($encAesKeyLen)
        if ($encryptedAesKey.Count -ne $encAesKeyLen) {
            Write-Host "�G���[: RSA�Í�AES���̓ǂݍ��ݎ��s"
            return
        }

        # 4) AES����RSA����
        $aesKey = $rsa.Decrypt($encryptedAesKey, $false)

        # 5) AES�����X�g���[��
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.KeySize = 256
        $aes.BlockSize = 128
        $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $aesKey
        $aes.IV  = $iv

        $decryptor    = $aes.CreateDecryptor()
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($fsIn, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)

        # 6) �t�@�C������(4byte) + �t�@�C����
        $fnameLenBuf = New-Object byte[] 4
        $count = $cryptoStream.Read($fnameLenBuf, 0, 4)
        if ($count -lt 4) {
            Write-Host "�G���[: �����f�[�^����t�@�C���������擾�ł��܂���"
            return
        }
        $fnameLen = [BitConverter]::ToInt32($fnameLenBuf, 0)
        if ($fnameLen -le 0 -or $fnameLen -gt 512) {
            Write-Host "�G���[: �t�@�C���������s�� ($fnameLen)"
            return
        }

        $fnameBuf = New-Object byte[] $fnameLen
        $count = $cryptoStream.Read($fnameBuf, 0, $fnameLen)
        if ($count -lt $fnameLen) {
            Write-Host "�G���[: �����f�[�^����t�@�C������ǂݎ��܂���"
            return
        }

        $originalFileName = [System.Text.Encoding]::UTF8.GetString($fnameBuf)
        # �t�@�C�����̈��S�΍�
        $invalidChars = [System.IO.Path]::GetInvalidFileNameChars()
        foreach ($c in $invalidChars) {
            $originalFileName = $originalFileName -replace [Regex]::Escape($c), '_'
        }

        # �o�̓p�X (�f�B���N�g���g���o�[�T���΍�)
        $folder = [System.IO.Path]::GetDirectoryName($InputFilePath)
        $outFilePath = Join-Path $folder $originalFileName

        $fullOutFilePath = [System.IO.Path]::GetFullPath($outFilePath)
        $fullFolderPath  = [System.IO.Path]::GetFullPath($folder)
        if (-not $fullOutFilePath.StartsWith($fullFolderPath)) {
            Write-Host "�G���[: �f�B���N�g���O�ւ̏������݂����s����܂����B"
            return
        }

        Write-Host "���t�@�C����: $originalFileName"

        # 7) �c����t�@�C���o��
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

#=== 6) GUI�p���[�e�B���e�B: ���J���ꗗ/�閧���Ƃ�Modulus�ƍ� ==========

function Load-PubKeyList {
    # keys���� *.pubkey �������擾���A�g���q���������t�@�C�����Ń��X�g��
    $pubkeyFiles = Get-ChildItem -Path $keysFolder -Filter '*.pubkey' -File -ErrorAction SilentlyContinue
    $list = @()
    foreach ($f in $pubkeyFiles) {
        $nameWithoutExt = [System.IO.Path]::GetFileNameWithoutExtension($f.Name)
        $list += $nameWithoutExt
    }
    $list = $list | Sort-Object -Unique
    return $list
}

function GetModulusFromPvtKey {
    Param([string]$pvtFilePath)
    if (-not (Test-Path $pvtFilePath)) {
        return $null
    }
    try {
        $xml = Get-Content -Path $pvtFilePath -Raw
        $spl = $xml -split "<Modulus>|</Modulus>"
        if ($spl.Count -lt 2) { return $null }
        return $spl[1].Trim()
    }
    catch {
        return $null
    }
}

#=== 7) GUI�t�H�[���̍\�z =============================================

# --- ���C���t�H�[�� ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "EncryptDecrypt GUI (All-in-One)"
$form.Size = New-Object System.Drawing.Size(600, 500)
$form.StartPosition = "CenterScreen"

# --- �h���b�v�G���A(Label) ---
$dropLabelInit = "�����Ƀt�@�C�����h���b�O���h���b�v���Ă�������"
$dropLabel = New-Object System.Windows.Forms.Label
$dropLabel.Text = $dropLabelInit
$dropLabel.AutoSize = $false
$dropLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$dropLabel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$dropLabel.Size = New-Object System.Drawing.Size(550, 150)
$dropLabel.Location = New-Object System.Drawing.Point(20, 20)
$dropLabel.AllowDrop = $true
$form.Controls.Add($dropLabel)

$fileListBox = New-Object System.Windows.Forms.ListBox
$fileListBox.Location = New-Object System.Drawing.Point(20, 180)
$fileListBox.Size = New-Object System.Drawing.Size(550, 100)
$form.Controls.Add($fileListBox)

# �h���b�O�C�x���g�ݒ�
$dropLabel.Add_DragEnter({
    param($sender, $e)
    if ($e.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) {
        $e.Effect = [System.Windows.Forms.DragDropEffects]::Copy
    }
    else {
        $e.Effect = [System.Windows.Forms.DragDropEffects]::None
    }
})
$dropLabel.Add_DragDrop({
    param($sender, $e)
    $files = $e.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop)
    foreach ($file in $files) {
        if (-not $fileListBox.Items.Contains($file)) {
            $fileListBox.Items.Add($file)
        }
    }
    $dropLabel.Text = "�t�@�C�����ǉ�����܂����B"
})

# --- ���J�����X�g (�Í����p) ---
$keyLabel = New-Object System.Windows.Forms.Label
$keyLabel.Text = "�����X�g"
$keyLabel.Location = New-Object System.Drawing.Point(20, 300)
$keyLabel.Size = New-Object System.Drawing.Size(120, 20)
$form.Controls.Add($keyLabel)

$keyComboBox = New-Object System.Windows.Forms.ComboBox
$keyComboBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
$keyComboBox.Location = New-Object System.Drawing.Point(150, 295)
$keyComboBox.Size = New-Object System.Drawing.Size(150, 20)
$form.Controls.Add($keyComboBox)

# --- Generate Key �{�^�� ---
$genKeyButton = New-Object System.Windows.Forms.Button
$genKeyButton.Text = "������"
$genKeyButton.Location = New-Object System.Drawing.Point(420, 290)
$genKeyButton.Size = New-Object System.Drawing.Size(150, 30)
$genKeyButton.Add_Click({
    $newId = Generate-KeyPair
    [System.Windows.Forms.MessageBox]::Show("�V�������𐶐����܂���: $newId", "������")
    Refresh-PubKeyList
})
$form.Controls.Add($genKeyButton)

#=== Encrypt �{�^�� ==================================================
$encryptButton = New-Object System.Windows.Forms.Button
$encryptButton.Text = "Encrypt (�Í���)"
$encryptButton.Location = New-Object System.Drawing.Point(20, 330)
$encryptButton.Size = New-Object System.Drawing.Size(120, 30)
$encryptButton.Add_Click({
    if ($fileListBox.Items.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("�t�@�C��������܂���B", "�G���[")
        return
    }
    $selectedKey = $keyComboBox.SelectedItem
    if (-not $selectedKey) {
        [System.Windows.Forms.MessageBox]::Show("�Í����Ɏg�����J����I�����Ă��������B", "�G���[")
        return
    }

    # ���J���̃t���p�X
    $pubPath = Join-Path $keysFolder ($selectedKey + ".pubkey")
    if (-not (Test-Path $pubPath)) {
        [System.Windows.Forms.MessageBox]::Show("���J���t�@�C����������܂���: `n$pubPath", "�G���[")
        return
    }

    # �I�����ꂽ�t�@�C�������ɈÍ���
    foreach ($f in $fileListBox.Items) {
        Write-Host "�Í����Ώ�: $f (��: $pubPath)"
        EncryptFile -PublicKeyPath $pubPath -InputFilePath $f
    }
    [System.Windows.Forms.MessageBox]::Show("�Í������������܂����B", "����")
})
$form.Controls.Add($encryptButton)

#=== Decrypt �{�^�� ==================================================
$decryptButton = New-Object System.Windows.Forms.Button
$decryptButton.Text = "Decrypt (����)"
$decryptButton.Location = New-Object System.Drawing.Point(170, 330)
$decryptButton.Size = New-Object System.Drawing.Size(120, 30)
$decryptButton.Add_Click({
    if ($fileListBox.Items.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("�t�@�C��������܂���B", "�G���[")
        return
    }

    # 1) keys���̂��ׂĂ� .pvtkey ���� <Modulus> ��ǂݎ��A�����ɂ܂Ƃ߂�
    $pvtkeyDict = @{}  # key=Modulus, value=�t���p�X
    $pvtList = Get-ChildItem -Path $keysFolder -Filter '*.pvtkey' -File
    foreach ($pf in $pvtList) {
        $m = GetModulusFromPvtKey $pf.FullName
        if ($m) {
            $pvtkeyDict[$m] = $pf.FullName
        }
    }
    if ($pvtkeyDict.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("�閧���t�@�C����������܂���B", "�G���[")
        return
    }

    # 2) �h���b�v�t�@�C���ɑ΂��ĕ���
    foreach ($f in $fileListBox.Items) {
        Write-Host "�����Ώ�: $f"
        $modEnc = GetModulusFromEncryptedFile $f
        if (-not $modEnc) {
            [System.Windows.Forms.MessageBox]::Show("Modulus���擾�ł��܂���: `n$($f)", "�G���[")
            continue
        }

        if (-not $pvtkeyDict.ContainsKey($modEnc)) {
            [System.Windows.Forms.MessageBox]::Show("���v����閧��������܂���: `n$($f)", "�G���[")
            continue
        }

        $matchedPvtKey = $pvtkeyDict[$modEnc]
        Write-Host "�� �g�p�閧��: $matchedPvtKey"
        DecryptFile -PrivateKeyPath $matchedPvtKey -InputFilePath $f
    }
    [System.Windows.Forms.MessageBox]::Show("�����������������܂����B", "����")
})
$form.Controls.Add($decryptButton)

#=== ���X�g�N���A�{�^�� ===============================================
$clearButton = New-Object System.Windows.Forms.Button
$clearButton.Text = "���X�g�N���A"
$clearButton.Location = New-Object System.Drawing.Point(320, 330)
$clearButton.Size = New-Object System.Drawing.Size(120, 30)
$clearButton.Add_Click({
    $fileListBox.Items.Clear()
    $dropLabel.Text = $dropLabelInit
})
$form.Controls.Add($clearButton)

#=== ���J�����X�g�ēǂݍ��݃{�^�� =====================================
$reloadKeyButton = New-Object System.Windows.Forms.Button
$reloadKeyButton.Text = "�ēǍ�"
$reloadKeyButton.Location = New-Object System.Drawing.Point(320, 290)
$reloadKeyButton.Size = New-Object System.Drawing.Size(80, 30)
$reloadKeyButton.Add_Click({
    Refresh-PubKeyList
})
$form.Controls.Add($reloadKeyButton)

#=== ComboBox �X�V�p�֐� ==============================================
function Refresh-PubKeyList {
    $keyComboBox.Items.Clear()
    $names = Load-PubKeyList
    foreach ($n in $names) {
        [void]$keyComboBox.Items.Add($n)
    }
    if ($keyComboBox.Items.Count -gt 0) {
        $keyComboBox.SelectedIndex = 0
    }
}

#=== �N���������� & �t�H�[���\�� ======================================

Refresh-PubKeyList
$form.Topmost = $true
$form.Add_Shown({ $form.Activate() })
[void]$form.ShowDialog()
