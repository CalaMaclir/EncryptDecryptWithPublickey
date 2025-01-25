# 必要なアセンブリをロード
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# 現在のスクリプトフォルダを取得
$currentFolder = Split-Path -Parent $MyInvocation.MyCommand.Path
$encryptDecryptScript = Join-Path -Path $currentFolder -ChildPath "EncryptDecrypt.ps1"

# フォームの作成
$form = New-Object System.Windows.Forms.Form
$form.Text = "EncryptDecrypt GUI"
$form.Size = New-Object System.Drawing.Size(500, 400)
$form.StartPosition = "CenterScreen"

# ドロップエリアをラベルとして作成
$dropLabelInit = "ここにファイルをドラッグ＆ドロップしてください"
$dropLabel = New-Object System.Windows.Forms.Label
$dropLabel.Text = $dropLabelInit
$dropLabel.AutoSize = $false
$dropLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$dropLabel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$dropLabel.Size = New-Object System.Drawing.Size(450, 150)
$dropLabel.Location = New-Object System.Drawing.Point(25, 20)
$dropLabel.AllowDrop = $true
$form.Controls.Add($dropLabel)

# ドロップされたファイルのリストを表示するリストボックスを追加
$fileListBox = New-Object System.Windows.Forms.ListBox
$fileListBox.Location = New-Object System.Drawing.Point(25, 190)
$fileListBox.Size = New-Object System.Drawing.Size(450, 120)
$form.Controls.Add($fileListBox)

# ドラッグイベントの設定
$dropLabel.Add_DragEnter({
    param($sender, $e)
    if ($e.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) {
        $e.Effect = [System.Windows.Forms.DragDropEffects]::Copy
    } else {
        $e.Effect = [System.Windows.Forms.DragDropEffects]::None
    }
})

# ドロップイベントの設定
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

# (1) 実行ボタン
$executeButton = New-Object System.Windows.Forms.Button
$executeButton.Text = "実行"
$executeButton.Location = New-Object System.Drawing.Point(100, 330)
$executeButton.Size = New-Object System.Drawing.Size(100, 30)
$executeButton.Add_Click({
    if ($fileListBox.Items.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("ファイルが指定されていません。", "エラー")
        return
    }
    if (-not (Test-Path $encryptDecryptScript)) {
        [System.Windows.Forms.MessageBox]::Show("EncryptDecrypt.ps1 が見つかりません。", "エラー")
        return
    }

    # ファイルパスをダブルクォートで囲んで引数化
    $quotedFiles = $fileListBox.Items | ForEach-Object { '"{0}"' -f $_ }
    $fileArguments = $quotedFiles -join ' '

    try {
        # -PassThru と -Wait を指定し、プロセス情報を受け取る
        $p = Start-Process -FilePath "powershell.exe" `
            -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$encryptDecryptScript`" $fileArguments" `
            -Wait -PassThru

        # プロセス終了後に ExitCode を確認
        if ($p.ExitCode -ne 0) {
            [System.Windows.Forms.MessageBox]::Show("暗号/復号スクリプトがエラー終了しました。(ExitCode: $($p.ExitCode))", "エラー")
        }
        else {
            # 処理成功時はリストをクリアする
            $fileListBox.Items.Clear()
            $dropLabel.Text = $dropLabelInit
            # [System.Windows.Forms.MessageBox]::Show("処理が完了しました！", "成功")
        }

    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("処理中にエラーが発生しました: $_", "例外")
    }
})
$form.Controls.Add($executeButton)

# (2) リストをクリアするボタン
$clearButton = New-Object System.Windows.Forms.Button
$clearButton.Text = "リストクリア"
$clearButton.Location = New-Object System.Drawing.Point(300, 330)
$clearButton.Size = New-Object System.Drawing.Size(100, 30)
$clearButton.Add_Click({
    $fileListBox.Items.Clear()
    $dropLabel.Text = $dropLabelInit
})
$form.Controls.Add($clearButton)

# フォームを表示
$form.ShowDialog()
