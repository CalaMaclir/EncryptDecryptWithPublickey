Param(
    [int]$KeySize = 4096
)

# --- 1) �����̃o���f�[�V���� ---
if ($KeySize -ne 2048 -and $KeySize -ne 4096) {
    Write-Host "�G���[: ������ 2048 �܂��� 4096 �̂ݎw��\�ł��B"
    Pause
    exit 1
}

# --- 2) "yyyyMMddHHmm"�`���̃^�C���X�^���v������𐶐� ---
$timeStamp = (Get-Date).ToString("yyyyMMddHHmm")

# --- 3) �o�͐�̃t�@�C���������� (�X�N���v�g�̃f�B���N�g���ɕۑ�) ---
$privateKeyFileName = "$timeStamp.pvtkey"
$publicKeyFileName  = "$timeStamp.pubkey"

$privateKeyPath = Join-Path $PSScriptRoot $privateKeyFileName
$publicKeyPath  = Join-Path $PSScriptRoot $publicKeyFileName

# --- 4) RSA�I�u�W�F�N�g���� (�w�肳�ꂽ�r�b�g��) ---
$rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider($KeySize)

# --- 5) �閧��XML (�閧���܂�) �� ���J��XML (���J���̂�) ���擾 ---
$privateKeyXml = $rsa.ToXmlString($true)   # $true = �閧�����܂�
$publicKeyXml  = $rsa.ToXmlString($false)  # $false = ���J���̂�

# --- 6) �t�@�C���ɏo�� (UTF-8) ---
Set-Content -Path $privateKeyPath -Value $privateKeyXml -Encoding UTF8
Set-Content -Path $publicKeyPath  -Value $publicKeyXml  -Encoding UTF8

Write-Host "RSA $KeySize bit �̃L�[�y�A�𐶐����܂����B"
Write-Host "�閧���t�@�C��: $privateKeyPath"
Write-Host "���J���t�@�C��: $publicKeyPath"

Pause
