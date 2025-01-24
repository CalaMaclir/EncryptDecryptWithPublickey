# �K�v�ȃA�Z���u�������[�h
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ���݂̃X�N���v�g�t�H���_���擾
$currentFolder = Split-Path -Parent $MyInvocation.MyCommand.Path
$encryptDecryptScript = Join-Path -Path $currentFolder -ChildPath "EncryptDecrypt.ps1"

# �t�H�[���̍쐬
$form = New-Object System.Windows.Forms.Form
$form.Text = "EncryptDecrypt GUI"
$form.Size = New-Object System.Drawing.Size(500, 400)
$form.StartPosition = "CenterScreen"

# �h���b�v�G���A�����x���Ƃ��č쐬
$dropLabel = New-Object System.Windows.Forms.Label
$dropLabel.Text = "�����Ƀt�@�C�����h���b�O���h���b�v���Ă�������"
$dropLabel.AutoSize = $false
$dropLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$dropLabel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$dropLabel.Size = New-Object System.Drawing.Size(450, 150)
$dropLabel.Location = New-Object System.Drawing.Point(25, 20)
$dropLabel.AllowDrop = $true
$form.Controls.Add($dropLabel)

# �h���b�v���ꂽ�t�@�C���̃��X�g��\�����郊�X�g�{�b�N�X��ǉ�
$fileListBox = New-Object System.Windows.Forms.ListBox
$fileListBox.Location = New-Object System.Drawing.Point(25, 190)
$fileListBox.Size = New-Object System.Drawing.Size(450, 120)
$form.Controls.Add($fileListBox)

# �h���b�O�C�x���g�̐ݒ�
$dropLabel.Add_DragEnter({
    param($sender, $e)
    if ($e.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) {
        $e.Effect = [System.Windows.Forms.DragDropEffects]::Copy
    } else {
        $e.Effect = [System.Windows.Forms.DragDropEffects]::None
    }
})

# �h���b�v�C�x���g�̐ݒ�
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

# ���s�{�^��
$executeButton = New-Object System.Windows.Forms.Button
$executeButton.Text = "���s"
$executeButton.Location = New-Object System.Drawing.Point(200, 330)
$executeButton.Size = New-Object System.Drawing.Size(100, 30)
$executeButton.Add_Click({
    if ($fileListBox.Items.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("�t�@�C�����w�肳��Ă��܂���B", "�G���[")
        return
    }
    if (-not (Test-Path $encryptDecryptScript)) {
        [System.Windows.Forms.MessageBox]::Show("EncryptDecrypt.ps1 ��������܂���B", "�G���[")
        return
    }
    # �t�@�C�����X�g�������Ƃ��ēn��
    $fileArguments = @($fileListBox.Items) -join " "
    try {
        Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$encryptDecryptScript`" $fileArguments" -Wait
        [System.Windows.Forms.MessageBox]::Show("�������������܂����I", "����")
    } catch {
        [System.Windows.Forms.MessageBox]::Show("�������ɃG���[���������܂���: $_", "�G���[")
    }
})
$form.Controls.Add($executeButton)

# �t�H�[����\��
$form.ShowDialog()
