Param(
    [int]$KeySize = 4096
)

# --- 1) 鍵長のバリデーション ---
if ($KeySize -ne 2048 -and $KeySize -ne 4096) {
    Write-Host "エラー: 鍵長は 2048 または 4096 のみ指定可能です。"
    Pause
    exit 1
}

# --- 2) "yyyyMMddHHmm"形式のタイムスタンプ文字列を生成 ---
$timeStamp = (Get-Date).ToString("yyyyMMddHHmm")

# --- 3) 出力先のファイル名を決定 (スクリプトのディレクトリに保存) ---
$privateKeyFileName = "$timeStamp.pvtkey"
$publicKeyFileName  = "$timeStamp.pubkey"

$privateKeyPath = Join-Path $PSScriptRoot $privateKeyFileName
$publicKeyPath  = Join-Path $PSScriptRoot $publicKeyFileName

# --- 4) RSAオブジェクト生成 (指定されたビット数) ---
$rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider($KeySize)

# --- 5) 秘密鍵XML (秘密鍵含む) と 公開鍵XML (公開鍵のみ) を取得 ---
$privateKeyXml = $rsa.ToXmlString($true)   # $true = 秘密鍵を含む
$publicKeyXml  = $rsa.ToXmlString($false)  # $false = 公開鍵のみ

# --- 6) ファイルに出力 (UTF-8) ---
Set-Content -Path $privateKeyPath -Value $privateKeyXml -Encoding UTF8
Set-Content -Path $publicKeyPath  -Value $publicKeyXml  -Encoding UTF8

Write-Host "RSA $KeySize bit のキーペアを生成しました。"
Write-Host "秘密鍵ファイル: $privateKeyPath"
Write-Host "公開鍵ファイル: $publicKeyPath"

Pause
