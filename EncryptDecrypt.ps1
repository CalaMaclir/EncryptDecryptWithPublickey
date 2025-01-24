############################################################
# EncryptDecrypt.ps1
#   - Modulusをファイル先頭に平文で書き込み、復号時にチェックする版
#
#  1) 拡張子が .pubkey なら暗号化 (EncryptFile)
#  2) 拡張子が .pvtkey なら復号化 (DecryptFile)
#  3) Modulus不一致ならエラー表示
# ----------------------------------------------------------
# 分割要望:
#   - #2) パス正規化を関数化
#   - #3) 拡張子判定～#5) 実行を1つの関数に
############################################################

# --- 関数: パス正規化 (#2 の部分) ---
function Normalize-Paths {
    Param(
        [Parameter(Mandatory)]
        [string[]]$InputArgs
    )

    # 引数を PowerShell の (Resolve-Path) で絶対パスに正規化する
    $resolved = $InputArgs | ForEach-Object { (Resolve-Path $_).Path }
    return $resolved
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

    # 4) モード判定
    $keyFile   = $null
    $dataFiles = @()

    if ($pubkeys.Count -eq 1) {
        $keyFile = $pubkeys[0]
        # その他を暗号化対象
        $dataFiles = $AllPaths | Where-Object { $_ -ne $keyFile }
        Write-Host "`n--- 暗号化モード(.pubkey) ---"
        Write-Host "公開鍵: $keyFile"
    }
    elseif ($pvtkeys.Count -eq 1) {
        $keyFile = $pvtkeys[0]
        # その他を復号対象
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
            # 処理ファイルの表示
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


# --- 1) 関数定義: EncryptFile ---
function EncryptFile {
Param(
    [Parameter(Mandatory)]
    [string]$PublicKeyPath,
    [Parameter(Mandatory)]
    [string]$InputFilePath
)


    # --- 1) AES鍵の準備 ---
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.BlockSize = 128
    $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.GenerateKey()
    $aes.GenerateIV()

    # --- 2) 公開鍵の読み込み + RSA暗号化 ---
    $publicKeyXml = Get-Content -Path $PublicKeyPath -Raw
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $rsa.FromXmlString($publicKeyXml)

    # RSAでAES鍵を暗号化
    $encryptedAesKey = $rsa.Encrypt($aes.Key, $false)  # $false=PKCS#1 v1.5

    # --- 2-1) 公開鍵XMLから <Modulus> を抜き出し、Base64文字列を取り出す (簡易split版) ---
    #    ※実運用ではXMLパーサや正規表現を使うのが望ましい場合あり
    $modulusBase64 = ($publicKeyXml -split "<Modulus>|</Modulus>")[1].Trim()
    if (-not $modulusBase64) {
        Write-Host "エラー: 公開鍵XMLから <Modulus> を取得できませんでした。"
        return
    }
    $modulusBytes    = [System.Text.Encoding]::UTF8.GetBytes($modulusBase64)
    $modulusLenBytes = [BitConverter]::GetBytes($modulusBytes.Length)

    # --- 3) 出力ファイル名 (元ファイル名 + .enc) ---
    $baseFileName = [System.IO.Path]::GetFileName($InputFilePath)
    $folder       = [System.IO.Path]::GetDirectoryName($InputFilePath)
    $outEncPath   = Join-Path $folder ($baseFileName + ".enc")

    # --- 4) 出力ファイルを書き込み ---
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

        #     - ファイル名 (ファイル名長 + ファイル名)
        $fileNameBytes    = [System.Text.Encoding]::UTF8.GetBytes($baseFileName)
        $fileNameLenBytes = [BitConverter]::GetBytes($fileNameBytes.Length)
        $cryptoStream.Write($fileNameLenBytes, 0, $fileNameLenBytes.Length)
        $cryptoStream.Write($fileNameBytes,    0, $fileNameBytes.Length)

        #     - 本体データ (バッファ読み込み + 書き込み)
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


# --- 2) 関数定義: DecryptFile ---
function DecryptFile {
Param(
    [Parameter(Mandatory)]
    [string]$PrivateKeyPath,
    [Parameter(Mandatory)]
    [string]$InputFilePath
)


    # 暗号ファイルを開く
    $fsIn = [System.IO.File]::OpenRead($InputFilePath)
    if (-not $fsIn) {
        Write-Host "エラー: $InputFilePath を開けませんでした。"
        return
    }

    try {
        # 0) 先頭: [4byte: Modulus文字列長] + [Modulus文字列(UTF8)]
        $modLenBuf = New-Object byte[] 4
        $bytesRead = $fsIn.Read($modLenBuf, 0, 4)
        if ($bytesRead -ne 4) {
            Write-Host "エラー: 埋め込みModulus長が読み込めません。ファイル破損?"
            return
        }
        $modLen = [BitConverter]::ToInt32($modLenBuf, 0)
        if ($modLen -le 0) {
            Write-Host "エラー: Modulus長が不正 (0以下)"
            return
        }

        $modulusBytesFromFile = New-Object byte[] $modLen
        $bytesRead = $fsIn.Read($modulusBytesFromFile, 0, $modLen)
        if ($bytesRead -ne $modLen) {
            Write-Host "エラー: Modulus文字列を最後まで読み込めません"
            return
        }
        $modulusFromFile = [System.Text.Encoding]::UTF8.GetString($modulusBytesFromFile)

        # 1) IV(16バイト)
        $iv = New-Object byte[] 16
        $bytesRead = $fsIn.Read($iv, 0, 16)
        if ($bytesRead -ne 16) {
            Write-Host "エラー: IVの読み込みに失敗"
            return
        }

        # 2) AES鍵サイズ(4バイト)
        $keyLenBuf = New-Object byte[] 4
        $bytesRead = $fsIn.Read($keyLenBuf, 0, 4)
        if ($bytesRead -ne 4) {
            Write-Host "エラー: AES鍵サイズ(4byte)が読み込めません"
            return
        }
        $encAesKeyLen = [BitConverter]::ToInt32($keyLenBuf, 0)

        # 3) RSA暗号化されたAES鍵
        $encryptedAesKey = New-Object byte[] $encAesKeyLen
        $bytesRead = $fsIn.Read($encryptedAesKey, 0, $encAesKeyLen)
        if ($bytesRead -ne $encAesKeyLen) {
            Write-Host "エラー: RSA暗号AES鍵の読み込み失敗"
            return
        }

        # 4) 秘密鍵を読み込み + Modulus比較
        $privateKeyXml = Get-Content -Path $PrivateKeyPath -Raw
        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        $rsa.FromXmlString($privateKeyXml)

        $modulusFromPriv = ($privateKeyXml -split "<Modulus>|</Modulus>")[1].Trim()
        if (-not $modulusFromPriv) {
            Write-Host "エラー: 秘密鍵XMLから <Modulus> が取得できません。"
            return
        }

        # 不一致ならエラー
        if ($modulusFromFile -ne $modulusFromPriv) {
            Write-Host "エラー: この暗号ファイルは別の公開鍵で作られています。(Modulus不一致)"
            return
        }

        # 5) AES鍵をRSA復号
        $aesKey = $rsa.Decrypt($encryptedAesKey, $false)

        # 6) AES復号ストリーム
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.KeySize = 256
        $aes.BlockSize = 128
        $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $aesKey
        $aes.IV  = $iv

        $decryptor = $aes.CreateDecryptor()
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($fsIn, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)

        # (a) ファイル名長(4byte) + ファイル名
        $fnameLenBuf = New-Object byte[] 4
        $count = $cryptoStream.Read($fnameLenBuf, 0, 4)
        if ($count -lt 4) {
            Write-Host "エラー: 復号データからファイル名長が読み取れません"
            return
        }
        $fnameLen = [BitConverter]::ToInt32($fnameLenBuf, 0)

        $fnameBuf = New-Object byte[] $fnameLen
        $count = $cryptoStream.Read($fnameBuf, 0, $fnameLen)
        if ($count -lt $fnameLen) {
            Write-Host "エラー: 復号データからファイル名を読み取れません"
            return
        }
        $originalFileName = [System.Text.Encoding]::UTF8.GetString($fnameBuf)
        Write-Host "元ファイル名: $originalFileName"

        # (b) 残りをファイル出力
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

        Write-Host "復号完了: $outFilePath"

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
# --- メインロジック: 引数チェック -> Normalize-Paths -> Process-Files
###############################################################

# 1) 引数が足りない場合
if ($args.Count -lt 2) {
    Write-Host "【エラー】.pubkey(または .pvtkey) と 暗号化/復号したいファイル を同時にドロップしてください。"
    Pause
    exit 1
}

# 2) パス正規化 (関数に切り出し)
$allPaths = Normalize-Paths -InputArgs $args

# 3) ~ 5) を一括処理 (拡張子判定 → モード判定 → 実行)
Process-Files -AllPaths $allPaths
