########################################################################
# EncryptDecryptGUI_Standalone.ps1
#
# 1つのスクリプト内に暗号/復号ロジック + GUI をまとめたサンプル
#   - keys フォルダ：公開鍵(.pubkey)/秘密鍵(.pvtkey)を管理
#   - RSA公開鍵によるAES鍵暗号化 + AESでファイル暗号
#   - 復号時は暗号ファイル先頭からModulusを取得し、keysにある秘密鍵を自動マッチング
#   - GUI上でファイルドロップ,鍵生成,暗号化,復号を操作
########################################################################

# --- 必要なアセンブリ ---
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.IO

#=== 1) スクリプト事前設定 ============================================

# 本スクリプトのフォルダ
$scriptFolder = Split-Path -Parent $MyInvocation.MyCommand.Path

# 鍵フォルダ (keys) が存在しなければ作成
$keysFolder = Join-Path $scriptFolder "keys"
if (-not (Test-Path $keysFolder)) {
    New-Item -ItemType Directory -Path $keysFolder | Out-Null
}

#=== 2) 共通関数: RSA鍵ペア生成 =======================================

function Generate-KeyPair {
    # 一意なIDを日時で生成 (必要に応じて変更)
    $id = (Get-Date).ToString("yyyyMMddHHmmss")

    # 2048bit RSA鍵を作成
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider(2048)
    $privateXml = $rsa.ToXmlString($true)
    $publicXml  = $rsa.ToXmlString($false)
    $rsa.Dispose()

    # .pvtkey / .pubkey を保存
    $pvtPath = Join-Path $keysFolder "$id.pvtkey"
    $pubPath = Join-Path $keysFolder "$id.pubkey"

    $privateXml | Out-File -FilePath $pvtPath -Encoding UTF8 -Force
    $publicXml  | Out-File -FilePath $pubPath -Encoding UTF8 -Force

    Write-Host "鍵ペア生成: $pvtPath, $pubPath"
    return $id
}

#=== 3) 暗号・復号ロジックに必要な関数 ================================

# (A) 公開鍵/秘密鍵XMLから <Modulus> を取り出す簡易関数
function Get-ModulusFromXmlString {
    Param([string]$XmlString)
    if (-not $XmlString) { return $null }
    $spl = $XmlString -split "<Modulus>|</Modulus>"
    if ($spl.Count -lt 2) { return $null }
    return $spl[1].Trim()
}

# (B) 暗号ファイル先頭から Modulus を取り出す
function GetModulusFromEncryptedFile {
    Param([string]$InputFilePath)
    if (-not (Test-Path $InputFilePath)) {
        Write-Host "ファイルが存在しません: $InputFilePath"
        return $null
    }

    try {
        $fsIn = [System.IO.File]::OpenRead($InputFilePath)
        $br   = New-Object System.IO.BinaryReader($fsIn)
        
        # 4byte: Modulus長
        $modLenBytes = $br.ReadBytes(4)
        if ($modLenBytes.Count -lt 4) {
            Write-Host "エラー: Modulus長(4byte)を読み込めません。"
            $br.Close(); $fsIn.Close()
            return $null
        }
        $modLen = [BitConverter]::ToInt32($modLenBytes, 0)
        if ($modLen -le 0 -or $modLen -gt 1024) {
            Write-Host "エラー: Modulus長が不正 ($modLen)"
            $br.Close(); $fsIn.Close()
            return $null
        }

        # Modulus文字列(UTF8)
        $modBytes = $br.ReadBytes($modLen)
        if ($modBytes.Count -ne $modLen) {
            Write-Host "エラー: Modulus文字列を読み取りきれません。"
            $br.Close(); $fsIn.Close()
            return $null
        }
        $modulusFromFile = [System.Text.Encoding]::UTF8.GetString($modBytes)

        $br.Close(); $fsIn.Close()
        return $modulusFromFile
    }
    catch {
        Write-Host "エラー: $($_.Exception.Message)"
        return $null
    }
}

#=== 4) 暗号化関数 (EncryptFile) ======================================
function EncryptFile {
    Param(
        [Parameter(Mandatory)][string]$PublicKeyPath,
        [Parameter(Mandatory)][string]$InputFilePath
    )

    # 1) AES鍵の準備
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.BlockSize = 128
    $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.GenerateKey()
    $aes.GenerateIV()

    # 2) 公開鍵の読み込み + RSA暗号化
    $publicKeyXml = Get-Content -Path $PublicKeyPath -Raw
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $rsa.FromXmlString($publicKeyXml)

    # 公開鍵XMLからModulus取得
    $modulusBase64 = Get-ModulusFromXmlString -XmlString $publicKeyXml
    if (-not $modulusBase64) {
        Write-Host "エラー: 公開鍵XMLから <Modulus> を取得できません。 -> $PublicKeyPath"
        return
    }

    # AES鍵をRSAで暗号化 (PKCS#1 v1.5)
    $encryptedAesKey = $rsa.Encrypt($aes.Key, $false)

    # 3) 出力ファイル名 (元ファイル + .enc)
    $baseFileName = [System.IO.Path]::GetFileName($InputFilePath)
    $folder       = [System.IO.Path]::GetDirectoryName($InputFilePath)
    $outEncPath   = Join-Path $folder ($baseFileName + ".enc")

    # 4) 出力ファイル書き込み
    $fsOut = [System.IO.File]::OpenWrite($outEncPath)
    try {
        # (a) [Modulus長(4byte)] + [Modulus文字列(UTF8)]
        $modulusBytes = [System.Text.Encoding]::UTF8.GetBytes($modulusBase64)
        $modulusLenBytes = [BitConverter]::GetBytes($modulusBytes.Length)
        $fsOut.Write($modulusLenBytes, 0, $modulusLenBytes.Length)
        $fsOut.Write($modulusBytes,    0, $modulusBytes.Length)

        # (b) IV(16バイト)
        $fsOut.Write($aes.IV, 0, $aes.IV.Length)

        # (c) RSA暗号化されたAES鍵サイズ(4バイト) + 本体
        $encKeyLen = $encryptedAesKey.Length
        $lenBytes  = [BitConverter]::GetBytes($encKeyLen)
        $fsOut.Write($lenBytes, 0, $lenBytes.Length)
        $fsOut.Write($encryptedAesKey, 0, $encKeyLen)

        # (d) AES暗号ストリーム
        $encryptor    = $aes.CreateEncryptor()
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($fsOut, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)

        #   - ファイル名 (ファイル名長 + ファイル名)
        $fileNameBytes    = [System.Text.Encoding]::UTF8.GetBytes($baseFileName)
        $fileNameLenBytes = [BitConverter]::GetBytes($fileNameBytes.Length)
        $cryptoStream.Write($fileNameLenBytes, 0, $fileNameLenBytes.Length)
        $cryptoStream.Write($fileNameBytes,    0, $fileNameBytes.Length)

        #   - 実データ
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

    Write-Host "暗号化完了: $outEncPath"
}

#=== 5) 復号関数 (DecryptFile) =========================================
function DecryptFile {
    Param(
        [Parameter(Mandatory)][string]$PrivateKeyPath,
        [Parameter(Mandatory)][string]$InputFilePath
    )

    if (-not (Test-Path $InputFilePath)) {
        Write-Host "エラー: 復号対象ファイルが見つかりません -> $InputFilePath"
        return
    }

    # 1) 暗号ファイル先頭からModulus取得
    $modulusFromFile = GetModulusFromEncryptedFile -InputFilePath $InputFilePath
    if (-not $modulusFromFile) {
        Write-Host "エラー: 暗号ファイルからModulusを取得できません。"
        return
    }

    # 2) 秘密鍵XMLを取得し、Modulus照合
    $privateXml = Get-Content -Path $PrivateKeyPath -Raw
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $rsa.FromXmlString($privateXml)

    $modulusFromPriv = Get-ModulusFromXmlString -XmlString $privateXml
    if (-not $modulusFromPriv) {
        Write-Host "エラー: 秘密鍵XMLから <Modulus> を取得できません。 -> $PrivateKeyPath"
        return
    }

    if ($modulusFromFile -ne $modulusFromPriv) {
        Write-Host "エラー: 暗号ファイルのModulusと秘密鍵が一致しません。"
        return
    }

    Write-Host "Modulus一致: 復号を続行します。"

    # 3) ファイル再オープン
    $fsIn = [System.IO.File]::OpenRead($InputFilePath)
    try {
        $br = New-Object System.IO.BinaryReader($fsIn)

        # (a) 先頭4byte + Modulus(すでに取得済み) なので skip
        #     => skip: 4 + $modulusFromFile.Length
        #     ただしバイト数でSeekするため、文字列のバイト長を改めて計算
        $modLen = [System.Text.Encoding]::UTF8.GetByteCount($modulusFromFile)
        $fsIn.Seek(4 + $modLen, [System.IO.SeekOrigin]::Begin) > $null

        # (b) IV(16バイト)
        $iv = $br.ReadBytes(16)
        if ($iv.Count -ne 16) {
            Write-Host "エラー: IVの読み込みに失敗"
            return
        }

        # (c) AES鍵サイズ(4バイト)
        $keyLenBytes = $br.ReadBytes(4)
        if ($keyLenBytes.Count -lt 4) {
            Write-Host "エラー: AES鍵サイズ(4byte)が読み込めません"
            return
        }
        $encAesKeyLen = [BitConverter]::ToInt32($keyLenBytes, 0)

        # (d) RSA暗号化されたAES鍵本体
        if ($encAesKeyLen -le 0 -or $encAesKeyLen -gt 4096) {
            Write-Host "エラー: AES鍵サイズが不正 ($encAesKeyLen)"
            return
        }
        $encryptedAesKey = $br.ReadBytes($encAesKeyLen)
        if ($encryptedAesKey.Count -ne $encAesKeyLen) {
            Write-Host "エラー: RSA暗号AES鍵の読み込み失敗"
            return
        }

        # 4) AES鍵をRSA復号
        $aesKey = $rsa.Decrypt($encryptedAesKey, $false)

        # 5) AES復号ストリーム
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.KeySize = 256
        $aes.BlockSize = 128
        $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $aesKey
        $aes.IV  = $iv

        $decryptor    = $aes.CreateDecryptor()
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($fsIn, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)

        # 6) ファイル名長(4byte) + ファイル名
        $fnameLenBuf = New-Object byte[] 4
        $count = $cryptoStream.Read($fnameLenBuf, 0, 4)
        if ($count -lt 4) {
            Write-Host "エラー: 復号データからファイル名長を取得できません"
            return
        }
        $fnameLen = [BitConverter]::ToInt32($fnameLenBuf, 0)
        if ($fnameLen -le 0 -or $fnameLen -gt 512) {
            Write-Host "エラー: ファイル名長が不正 ($fnameLen)"
            return
        }

        $fnameBuf = New-Object byte[] $fnameLen
        $count = $cryptoStream.Read($fnameBuf, 0, $fnameLen)
        if ($count -lt $fnameLen) {
            Write-Host "エラー: 復号データからファイル名を読み取れません"
            return
        }

        $originalFileName = [System.Text.Encoding]::UTF8.GetString($fnameBuf)
        # ファイル名の安全対策
        $invalidChars = [System.IO.Path]::GetInvalidFileNameChars()
        foreach ($c in $invalidChars) {
            $originalFileName = $originalFileName -replace [Regex]::Escape($c), '_'
        }

        # 出力パス (ディレクトリトラバーサル対策)
        $folder = [System.IO.Path]::GetDirectoryName($InputFilePath)
        $outFilePath = Join-Path $folder $originalFileName

        $fullOutFilePath = [System.IO.Path]::GetFullPath($outFilePath)
        $fullFolderPath  = [System.IO.Path]::GetFullPath($folder)
        if (-not $fullOutFilePath.StartsWith($fullFolderPath)) {
            Write-Host "エラー: ディレクトリ外への書き込みが試行されました。"
            return
        }

        Write-Host "元ファイル名: $originalFileName"

        # 7) 残りをファイル出力
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

        Write-Host "復号完了: $fullOutFilePath"

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

#=== 6) GUI用ユーティリティ: 公開鍵一覧/秘密鍵とのModulus照合 ==========

function Load-PubKeyList {
    # keys内の *.pubkey だけを取得し、拡張子を除いたファイル名でリスト化
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

#=== 7) GUIフォームの構築 =============================================

# --- メインフォーム ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "EncryptDecrypt GUI (All-in-One)"
$form.Size = New-Object System.Drawing.Size(600, 500)
$form.StartPosition = "CenterScreen"

# --- ドロップエリア(Label) ---
$dropLabelInit = "ここにファイルをドラッグ＆ドロップしてください"
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

# ドラッグイベント設定
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
    $dropLabel.Text = "ファイルが追加されました。"
})

# --- 公開鍵リスト (暗号化用) ---
$keyLabel = New-Object System.Windows.Forms.Label
$keyLabel.Text = "鍵リスト"
$keyLabel.Location = New-Object System.Drawing.Point(20, 300)
$keyLabel.Size = New-Object System.Drawing.Size(120, 20)
$form.Controls.Add($keyLabel)

$keyComboBox = New-Object System.Windows.Forms.ComboBox
$keyComboBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
$keyComboBox.Location = New-Object System.Drawing.Point(150, 295)
$keyComboBox.Size = New-Object System.Drawing.Size(150, 20)
$form.Controls.Add($keyComboBox)

# --- Generate Key ボタン ---
$genKeyButton = New-Object System.Windows.Forms.Button
$genKeyButton.Text = "鍵生成"
$genKeyButton.Location = New-Object System.Drawing.Point(420, 290)
$genKeyButton.Size = New-Object System.Drawing.Size(150, 30)
$genKeyButton.Add_Click({
    $newId = Generate-KeyPair
    [System.Windows.Forms.MessageBox]::Show("新しい鍵を生成しました: $newId", "鍵生成")
    Refresh-PubKeyList
})
$form.Controls.Add($genKeyButton)

#=== Encrypt ボタン ==================================================
$encryptButton = New-Object System.Windows.Forms.Button
$encryptButton.Text = "Encrypt (暗号化)"
$encryptButton.Location = New-Object System.Drawing.Point(20, 330)
$encryptButton.Size = New-Object System.Drawing.Size(120, 30)
$encryptButton.Add_Click({
    if ($fileListBox.Items.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("ファイルがありません。", "エラー")
        return
    }
    $selectedKey = $keyComboBox.SelectedItem
    if (-not $selectedKey) {
        [System.Windows.Forms.MessageBox]::Show("暗号化に使う公開鍵を選択してください。", "エラー")
        return
    }

    # 公開鍵のフルパス
    $pubPath = Join-Path $keysFolder ($selectedKey + ".pubkey")
    if (-not (Test-Path $pubPath)) {
        [System.Windows.Forms.MessageBox]::Show("公開鍵ファイルが見つかりません: `n$pubPath", "エラー")
        return
    }

    # 選択されたファイルを順に暗号化
    foreach ($f in $fileListBox.Items) {
        Write-Host "暗号化対象: $f (鍵: $pubPath)"
        EncryptFile -PublicKeyPath $pubPath -InputFilePath $f
    }
    [System.Windows.Forms.MessageBox]::Show("暗号化が完了しました。", "完了")
})
$form.Controls.Add($encryptButton)

#=== Decrypt ボタン ==================================================
$decryptButton = New-Object System.Windows.Forms.Button
$decryptButton.Text = "Decrypt (復号)"
$decryptButton.Location = New-Object System.Drawing.Point(170, 330)
$decryptButton.Size = New-Object System.Drawing.Size(120, 30)
$decryptButton.Add_Click({
    if ($fileListBox.Items.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("ファイルがありません。", "エラー")
        return
    }

    # 1) keys内のすべての .pvtkey から <Modulus> を読み取り、辞書にまとめる
    $pvtkeyDict = @{}  # key=Modulus, value=フルパス
    $pvtList = Get-ChildItem -Path $keysFolder -Filter '*.pvtkey' -File
    foreach ($pf in $pvtList) {
        $m = GetModulusFromPvtKey $pf.FullName
        if ($m) {
            $pvtkeyDict[$m] = $pf.FullName
        }
    }
    if ($pvtkeyDict.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("秘密鍵ファイルが見つかりません。", "エラー")
        return
    }

    # 2) ドロップファイルに対して復号
    foreach ($f in $fileListBox.Items) {
        Write-Host "復号対象: $f"
        $modEnc = GetModulusFromEncryptedFile $f
        if (-not $modEnc) {
            [System.Windows.Forms.MessageBox]::Show("Modulusを取得できません: `n$($f)", "エラー")
            continue
        }

        if (-not $pvtkeyDict.ContainsKey($modEnc)) {
            [System.Windows.Forms.MessageBox]::Show("合致する秘密鍵がありません: `n$($f)", "エラー")
            continue
        }

        $matchedPvtKey = $pvtkeyDict[$modEnc]
        Write-Host "→ 使用秘密鍵: $matchedPvtKey"
        DecryptFile -PrivateKeyPath $matchedPvtKey -InputFilePath $f
    }
    [System.Windows.Forms.MessageBox]::Show("復号処理が完了しました。", "完了")
})
$form.Controls.Add($decryptButton)

#=== リストクリアボタン ===============================================
$clearButton = New-Object System.Windows.Forms.Button
$clearButton.Text = "リストクリア"
$clearButton.Location = New-Object System.Drawing.Point(320, 330)
$clearButton.Size = New-Object System.Drawing.Size(120, 30)
$clearButton.Add_Click({
    $fileListBox.Items.Clear()
    $dropLabel.Text = $dropLabelInit
})
$form.Controls.Add($clearButton)

#=== 公開鍵リスト再読み込みボタン =====================================
$reloadKeyButton = New-Object System.Windows.Forms.Button
$reloadKeyButton.Text = "再読込"
$reloadKeyButton.Location = New-Object System.Drawing.Point(320, 290)
$reloadKeyButton.Size = New-Object System.Drawing.Size(80, 30)
$reloadKeyButton.Add_Click({
    Refresh-PubKeyList
})
$form.Controls.Add($reloadKeyButton)

#=== ComboBox 更新用関数 ==============================================
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

#=== 起動時初期化 & フォーム表示 ======================================

Refresh-PubKeyList
$form.Topmost = $true
$form.Add_Shown({ $form.Activate() })
[void]$form.ShowDialog()
