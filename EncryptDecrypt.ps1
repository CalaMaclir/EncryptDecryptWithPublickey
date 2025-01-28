############################################################
# EncryptDecrypt.ps1
#   - ファイルの先頭に書き込んだModulusと、鍵ファイル(XML)のModulusを
#     照合しながら暗号/復号を行うPowerShellスクリプト
#
#  1) 拡張子が .pubkey なら暗号化 (EncryptFile)
#  2) 拡張子が .pvtkey なら復号化 (DecryptFile)
#  3) Modulus不一致ならエラー表示
#
# 構成:
#   - #2) パス正規化を関数 (Normalize-Paths)
#   - 公開鍵/秘密鍵読み込みやModulus抽出を共通化 (Get-ModulusFromXmlString)
#   - 各種暗号・復号処理関数 (EncryptFile, DecryptFile など)
#   - #3～#5) 拡張子判定～ファイル処理を関数 (Process-Files)
#   - メインロジック (引数→正規化→拡張子判定→暗号 or 復号)
############################################################

# --- 鍵XMLから <Modulus> を抽出する関数 ---
function Get-ModulusFromXmlString {
    Param(
        [Parameter(Mandatory)]
        [string]$XmlString
    )
    # XML要素 <Modulus> ～ </Modulus> を簡易的に取り出す (実運用ではXMLパーサ推奨)
    $modulusBase64 = ($XmlString -split "<Modulus>|</Modulus>")[1].Trim()
    if (-not $modulusBase64) {
        return $null
    }
    return $modulusBase64
}

# --- 関数: パス正規化 (#2 の部分) ---
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

# --- 1) 関数定義: EncryptFile ---
function EncryptFile {
    Param(
        [Parameter(Mandatory)]
        [string]$PublicKeyPath,
        [Parameter(Mandatory)]
        [string]$InputFilePath
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

    # 鍵XMLからModulusを取得
    $modulusBase64 = Get-ModulusFromXmlString -XmlString $publicKeyXml
    if (-not $modulusBase64) {
        Write-Host "エラー: 公開鍵XMLから <Modulus> を取得できませんでした。"
        return
    }

    # RSAでAES鍵を暗号化 (PKCS#1 v1.5)
    $encryptedAesKey = $rsa.Encrypt($aes.Key, $false)

    # Modulusバイト列など準備
    $modulusBytes    = [System.Text.Encoding]::UTF8.GetBytes($modulusBase64)
    $modulusLenBytes = [BitConverter]::GetBytes($modulusBytes.Length)

    # 3) 出力ファイル名 (元ファイル名 + .enc)
    $baseFileName = [System.IO.Path]::GetFileName($InputFilePath)
    $folder       = [System.IO.Path]::GetDirectoryName($InputFilePath)
    $outEncPath   = Join-Path $folder ($baseFileName + ".enc")

    # 4) 出力ファイルを書き込み
    $fsOut = [System.IO.File]::OpenWrite($outEncPath)
    try {
        # (a) [Modulus長(4byte)] + [Modulus文字列(UTF8)]
        $fsOut.Write($modulusLenBytes, 0, $modulusLenBytes.Length)
        $fsOut.Write($modulusBytes,    0, $modulusBytes.Length)

        # (b) IV(16バイト)
        $fsOut.Write($aes.IV, 0, $aes.IV.Length)

        # (c) RSA暗号化されたAES鍵のサイズ(4バイト)
        $encKeyLen = $encryptedAesKey.Length
        $lenBytes  = [BitConverter]::GetBytes($encKeyLen)
        $fsOut.Write($lenBytes, 0, $lenBytes.Length)

        # (d) RSA暗号化されたAES鍵
        $fsOut.Write($encryptedAesKey, 0, $encKeyLen)

        # (e) AES暗号ストリーム (ファイル名 + 本文)
        $encryptor    = $aes.CreateEncryptor()
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($fsOut, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)

        #   - ファイル名 (ファイル名長 + ファイル名)
        $fileNameBytes    = [System.Text.Encoding]::UTF8.GetBytes($baseFileName)
        $fileNameLenBytes = [BitConverter]::GetBytes($fileNameBytes.Length)
        $cryptoStream.Write($fileNameLenBytes, 0, $fileNameLenBytes.Length)
        $cryptoStream.Write($fileNameBytes,    0, $fileNameBytes.Length)

        #   - 本体データ (バッファ読み込み + 書き込み)
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

# --- Modulus取得関数 (暗号ファイル先頭から) ---
function GetModulusFromEncryptedFile {
    Param(
        [Parameter(Mandatory)]
        [string]$InputFilePath
    )

    $fsIn = [System.IO.File]::OpenRead($InputFilePath)
    if (-not $fsIn) {
        Write-Host "エラー: $InputFilePath を開けませんでした。"
        return $null
    }

    try {
        # [4byte: Modulus文字列長] + [Modulus文字列(UTF8)]
        $modLenBuf = New-Object byte[] 4
        $bytesRead = $fsIn.Read($modLenBuf, 0, 4)
        if ($bytesRead -ne 4) {
            Write-Host "エラー: 埋め込みModulus長が読み込めません。ファイル破損?"
            return $null
        }
        $modLen = [BitConverter]::ToInt32($modLenBuf, 0)

        # 1) Modulus長チェック (0以下・1024超は不正)
        if ($modLen -le 0 -or $modLen -gt 1024) {
            Write-Host "エラー: Modulus長が不正 ($modLen)"
            return $null
        }

        $modulusBytesFromFile = New-Object byte[] $modLen
        $bytesRead = $fsIn.Read($modulusBytesFromFile, 0, $modLen)
        if ($bytesRead -ne $modLen) {
            Write-Host "エラー: Modulus文字列を最後まで読み込めません"
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

# --- (新規) 暗号ファイル先頭からModulusを取得して返す関数 ---
function Get-ModulusInfoOrFail {
    Param(
        [Parameter(Mandatory)]
        [string]$EncryptedFilePath
    )

    # GetModulusFromEncryptedFile を呼び出し、失敗したらエラー表示して即リターン
    $modulusInfo = GetModulusFromEncryptedFile -InputFilePath $EncryptedFilePath
    if (-not $modulusInfo) {
        Write-Host "エラー: Modulus取得に失敗しました。"
        return $null
    }
    return $modulusInfo
}

# --- 2) 関数定義: DecryptFile ---
function DecryptFile {
    Param(
        [Parameter(Mandatory)]
        [string]$PrivateKeyPath,
        [Parameter(Mandatory)]
        [string]$InputFilePath
    )

    # 1) 暗号ファイル先頭からModulus取得 (切り出した関数を利用)
    $modulusInfo = Get-ModulusInfoOrFail -EncryptedFilePath $InputFilePath
    if (-not $modulusInfo) {
        return  # 上記でエラー済みなのでここで終了
    }
    $modulusFromFile = $modulusInfo.Modulus
    $currentPosition = $modulusInfo.Position

    # 2) 秘密鍵を読み込み + Modulus比較
    $privateKeyXml = Get-Content -Path $PrivateKeyPath -Raw
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $rsa.FromXmlString($privateKeyXml)

    # 鍵XMLからModulusを取得
    $modulusFromPriv = Get-ModulusFromXmlString -XmlString $privateKeyXml
    if (-not $modulusFromPriv) {
        Write-Host "エラー: 秘密鍵XMLから <Modulus> が取得できません。"
        return
    }

    # 不一致ならエラー
    if ($modulusFromFile -ne $modulusFromPriv) {
        Write-Host "エラー: この暗号ファイルは別の公開鍵で作られています。(Modulus不一致)"
        return
    }
    Write-Host "Modulus一致: 復号処理を続行します。"

    # 3) 暗号ファイルを再度開き、続きの位置から読み込む
    $fsIn = [System.IO.File]::OpenRead($InputFilePath)
    $fsIn.Seek($currentPosition, [System.IO.SeekOrigin]::Begin) > $null

    try {
        # 4) IV(16バイト)
        $iv = New-Object byte[] 16
        $bytesRead = $fsIn.Read($iv, 0, 16)
        if ($bytesRead -ne 16) {
            Write-Host "エラー: IVの読み込みに失敗"
            return
        }

        # 5) AES鍵サイズ(4バイト)を取得
        $keyLenBuf = New-Object byte[] 4
        $bytesRead = $fsIn.Read($keyLenBuf, 0, 4)
        if ($bytesRead -ne 4) {
            Write-Host "エラー: AES鍵サイズ(4byte)が読み込めません"
            return
        }
        $encAesKeyLen = [BitConverter]::ToInt32($keyLenBuf, 0)

        # (a) AES鍵サイズの妥当性チェック (例: 0以下 or 4096超は不正)
        if ($encAesKeyLen -le 0 -or $encAesKeyLen -gt 4096) {
            Write-Host "エラー: AES鍵サイズが不正 ($encAesKeyLen)"
            return
        }

        # 6) RSA暗号化されたAES鍵を読み込む
        $encryptedAesKey = New-Object byte[] $encAesKeyLen
        $bytesRead = $fsIn.Read($encryptedAesKey, 0, $encAesKeyLen)
        if ($bytesRead -ne $encAesKeyLen) {
            Write-Host "エラー: RSA暗号AES鍵の読み込み失敗"
            return
        }

        # 7) AES鍵をRSA復号
        $aesKey = $rsa.Decrypt($encryptedAesKey, $false)

        # 8) AES復号ストリーム
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.KeySize = 256
        $aes.BlockSize = 128
        $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $aesKey
        $aes.IV  = $iv

        $decryptor    = $aes.CreateDecryptor()
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($fsIn, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)

        # 9) ファイル名長(4byte) + ファイル名
        $fnameLenBuf = New-Object byte[] 4
        $count = $cryptoStream.Read($fnameLenBuf, 0, 4)
        if ($count -lt 4) {
            Write-Host "エラー: 復号データからファイル名長が読み取れません"
            return
        }
        $fnameLen = [BitConverter]::ToInt32($fnameLenBuf, 0)

        # (b) ファイル名長のチェック
        if ($fnameLen -le 0 -or $fnameLen -gt 512) {
            Write-Host "エラー: ファイル名長が不正です ($fnameLen)"
            return
        }

        $fnameBuf = New-Object byte[] $fnameLen
        $count = $cryptoStream.Read($fnameBuf, 0, $fnameLen)
        if ($count -lt $fnameLen) {
            Write-Host "エラー: 復号データからファイル名を読み取れません"
            return
        }
        $originalFileName = [System.Text.Encoding]::UTF8.GetString($fnameBuf)

        # (c) ファイル名の安全対策
        $invalidChars = [System.IO.Path]::GetInvalidFileNameChars()
        foreach ($c in $invalidChars) {
            $originalFileName = $originalFileName -replace [Regex]::Escape($c), '_'
        }

        # ディレクトリトラバーサル等を禁止
        $folder = [System.IO.Path]::GetDirectoryName($InputFilePath)
        $outFilePath = Join-Path $folder $originalFileName

        $fullOutFilePath = [System.IO.Path]::GetFullPath($outFilePath)
        $fullFolderPath  = [System.IO.Path]::GetFullPath($folder)
        if (-not $fullOutFilePath.StartsWith($fullFolderPath)) {
            Write-Host "エラー: ディレクトリ外への書き込みが試行されました。"
            return
        }

        Write-Host "元ファイル名: $originalFileName"

        # 10) 残りをファイル出力
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

# --- 関数: メイン処理 (#3 ~ #5 の部分) ---
function Process-Files {
    Param(
        [Parameter(Mandatory)]
        [string[]]$AllPaths
    )

    # 3) 拡張子が .pubkey / .pvtkey のファイル抽出
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

    # 鍵ファイルが複数あったり、両方混在、0個の場合エラー
    if (($pubkeys.Count -gt 0) -and ($pvtkeys.Count -gt 0)) {
        Write-Host "【エラー】.pubkey と .pvtkey が同時に含まれています。1つだけにしてください。"
        Pause
        exit 1
    }
    if (($pubkeys.Count + $pvtkeys.Count) -eq 0) {
        Write-Host "【エラー】鍵ファイル(.pubkey または .pvtkey)が1つも見つかりません。"
        Pause
        exit 1
    }
    if (($pubkeys.Count + $pvtkeys.Count) -gt 1) {
        Write-Host "【エラー】鍵ファイルが複数見つかりました。1つだけにしてください。"
        Pause
        exit 1
    }

    # 4) モード判定 (暗号化 or 復号化)
    $keyFile   = $null
    $dataFiles = @()

    if ($pubkeys.Count -eq 1) {
        $keyFile   = $pubkeys[0]
        $dataFiles = $AllPaths | Where-Object { $_ -ne $keyFile }
        Write-Host "`n--- 暗号化モード(.pubkey) ---"
        Write-Host "公開鍵: $keyFile"
    }
    elseif ($pvtkeys.Count -eq 1) {
        $keyFile   = $pvtkeys[0]
        $dataFiles = $AllPaths | Where-Object { $_ -ne $keyFile }
        Write-Host "`n--- 復号化モード(.pvtkey) ---"
        Write-Host "秘密鍵: $keyFile"
    }

    if ($dataFiles.Count -eq 0) {
        Write-Host "【エラー】暗号化/復号化するファイルがありません。"
        Pause
        exit 1
    }

    # 5) 実行 (暗号 or 復号)
    foreach ($f in $dataFiles) {
        if (-not (Test-Path $f)) {
            Write-Host "【エラー】ファイルが存在しません: $f"
            continue
        }
        else {
            Write-Host "処理対象ファイル: $f"
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
# --- メインロジック: 引数チェック -> Normalize-Paths -> Process-Files
###############################################################

# 1) 引数が足りない場合
if ($args.Count -lt 2) {
    Write-Host "【エラー】.pubkey(または .pvtkey) と 暗号化/復号したいファイル を同時にドロップしてください。"
    Pause
    exit 1
}

# 2) パス正規化
$allPaths = Normalize-Paths -InputArgs $args

# 3) ~ 5) を一括処理 (拡張子判定 → モード判定 → 実行)
Process-Files -AllPaths $allPaths
