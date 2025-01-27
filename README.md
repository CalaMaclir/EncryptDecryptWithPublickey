# **公開鍵暗号方式を使用した暗号化・復号**

## **1\. 概要**

PowerShellスクリプトを用いて

1. **RSA鍵ペアの生成**  
2. **ハイブリッド暗号（AES \+ RSA公開鍵）を使ったファイル暗号化**  
3. **RSA秘密鍵を使ったファイル復号**  
   の一連の流れを実行する手順を示します。

なお、暗号化時には元ファイル名を暗号データ内に埋め込み、復号時にその名前を再現する仕組みになっています。

**ファイル一覧**

  * ### **GenerateRSAKeyPair.ps1**   RSA鍵ペアの生成
  * ### **EncryptDecrypt.ps1**     暗号化/復号
  * ### **FormEncryptDecrypt.ps1**     EncryptDecrypt.ps1をフォームにしたもの
* 

---

## **2\. RSA鍵ペアの生成**

### **2.1 スクリプト名: GenerateRSAKeyPair.ps1**

#### **2.1.1 実行例**

PowerShellを開き、本スクリプトがあるディレクトリへ移動

1. PS C:\\work\> .\\GenerateRSAKeyPair.ps1  
2. 実行結果  
   秘密鍵生成のときに管理者権限が必要ですので、権限の昇格について聞いてきます。  
   公開鍵であるか、秘密鍵であるかを末尾の拡張子(pvtkey/pubkey)で判断しているので、末尾の拡張子は変更しないでください。  
   末尾の拡張子以外であれば、ファイル名の変更は問題はありません。  
   * YYYYMMDDHHmm.pvtkey (秘密鍵)  
   * YYYYMMDDHHmm.pubkey (公開鍵)  
     が同じフォルダに作成されます。  
     例: 202501201830.pvtkey, 202501201830.pubkey

---

## **3\. ファイルの暗号化**

### **3.1 スクリプト名: EncryptDecrypt.ps1**

「公開鍵でAES鍵を暗号化し、AES(CBC)でファイル本体を暗号化する」いわゆるハイブリッド暗号です。
AES鍵は256bitのものをその場で生成しています。IVも生成しており、暗号化したファイルに格納しています。
暗号化をざっくり描いたのが下図となります。

![image](https://github.com/user-attachments/assets/b2160d4c-e2bc-4f83-98ca-b0bdf9163428)

さらに、暗号化前に「元ファイル名長＋元ファイル名」をAES暗号ストリームに書き込み、**復号時に元ファイル名**を再現できるようにしています。

#### **3.1.1 実行手順**

1. **公開鍵ファイル**（例: 202501201830.pubkey）を用意しておく。  
2. PS C:\\work\> .\\EncryptDecrypt.ps1 \`  
       "C:\\work\\202501201830.pubkey" \`  
       "C:\\work\\sample.pdf"  
3. 結果  
   * sample.pdf.enc という暗号化ファイルが生成されます(同じディレクトリに作成)。  
   * 平文のファイル名 sample.pdf は暗号データ内部に埋め込まれており、復号時に利用されます。

---

## **4\. ファイルの復号**

### **4.1 スクリプト名: EncryptDecrypt.ps1**

暗号ファイル(.enc)を開き、

1. 先頭16バイト (AES IV)  
2. 続く256バイト (RSA暗号化されたAES鍵)  
3. 残りをAES(CBC)で復号 → 先頭に格納されている「ファイル名」を取り出す → **元ファイル名で出力**

#### **4.1.1 実行手順**

1. **秘密鍵ファイル**（例: 202501201830.pvtkey）を用意しておく。  
2. **暗号化済みファイル**（例: sample.pdf.enc）を用意しておく。  
3. PS C:\\work\> .\\EncryptDecrypt.ps1 \`  
       "C:\\work\\202501201830.pvtkey" \`  
       "C:\\work\\sample.pdf.enc"  
4. 結果  
   * 復号が完了し、「埋め込まれていた元ファイル名」が表示されるとともに、  
     sample.pdf が同じディレクトリに生成されます。

---

## **5\. 全体の流れ**

1. **RSA鍵ペア生成 (GenerateRSAKeyPair.ps1)**  
   * 実行すると、「秘密鍵（.pvtkey）」と「公開鍵（.pubkey）」の2つが同フォルダに作成されます。  
2. **ファイル暗号化 (EncryptDecrypt.ps1)**  
   * 作成した公開鍵（.pubkey）を指定し、暗号化したいファイルを引数に与えて実行。  
   * 「元ファイル名.enc」が生成されます。  
3. **ファイル復号 (EncryptDecrypt.ps1)**  
   * 秘密鍵（.pvtkey）を指定し、暗号化ファイル（.enc）を引数に与えて実行。  
   * 復号完了後、暗号化ファイル内に埋め込まれていた元ファイル名でファイルが再現されます。

---

## **6\. 特徴/注意事項**

1. **EncryptDecrypt.ps1**  
   * この１つのスクリプトで暗号化復号の両方に対応し、与えられたファイルの拡張子で動作の判断しています  
2. **ドロップ対応**  
   * EncryptDecrypt.ps1のショートカットを作成し、ショートカットのリンク先の先頭に「powershell \-NoProfile \-ExecutionPolicy RemoteSigned \-File」を追加するとドロップ対応になります  
3. **複数ファイル対応**  
   * 1つの公開鍵/秘密鍵＋複数ファイルの指定もできます  
     まとめて暗号化、復号が可能です  
4. **FormEncryptDecrypt.ps1**  
   * フォームを表示し、ファイルをドロップして、実行ボタンを押せば暗号化/復号できる簡単インターフェイスです  
   * 同じディレクトリにあるEncryptDecrypt.ps1を呼び出して実行します  
5. **公開鍵と秘密鍵のマッチング**  
   * 暗号化されたときと違う秘密鍵を使った場合、エラー検出します  
6. **パディングモード**  
   * RSA暗号化で $false を指定しており、**PKCS\#1 v1.5** パディングを利用しています。  
7. **大容量ファイル**  
   * **ストリームベース**で暗号化・復号を行うので、大容量ファイルでも一括でメモリに読み込まずに処理できます。  
8. **エラー時の挙動**  
   * ファイルが存在しない、または鍵ファイルが壊れているなどのケースでエラーメッセージを表示し、exit 1 でスクリプトを終了します。  
   * PowerShellとしては「終了コード1」が返るため、呼び出し元でエラー検出が可能です。  
9. **文字コード(ファイル名)の扱い**  
   * ファイル名のやり取りに**UTF-8**を使用しています。日本語ファイル名などを含む場合も基本的には正しく扱えますが、OS環境やファイルシステムの制約により文字化けが起こる可能性もあるため、事前にテストしてください。  
10. **セキュリティ**  
    * 生成された秘密鍵ファイル（.pvtkey）は**慎重に管理**してください。第三者に漏洩した場合、暗号化したファイルを復号されるリスクがあります。  
    * AES鍵とIVは暗号ファイルに埋め込まれますが、AES鍵そのものはRSAで暗号化されているため、秘密鍵がなければ取り出せません。
11. **コードの流用について**  
    * 制作者がCala Maclirであることを明記いただけることを条件に自由に流用してください。

### 

### **7\. 暗号化されたファイル構造**

| 4バイト | Modulus文字列長 (int) |
| :---- | :---- |
| 可変長  | Modulus文字列 (UTF-8, Base64エンコード)  ※公開鍵の\<Modulus\>要素を抽出したもの |
| 16バイト | AESのIV |
| 4バイト    | 公開鍵で暗号化されたAES鍵のサイズ (int) |
| 可変長    | 公開鍵で暗号化されたAES鍵 (encAesKey)  |
| AESで暗号化　 | ファイル名長 (4バイト) ファイル名 (UTF-8, 可変長)  ファイル本体 (バイナリ) |

---

## **8\. 参考リンク**

* Microsoft Docs: RSACryptoServiceProvider Class (System.Security.Cryptography)
   [https://learn.microsoft.com/ja-jp/dotnet/api/system.security.cryptography.rsacryptoserviceprovider](https://learn.microsoft.com/ja-jp/dotnet/api/system.security.cryptography.rsacryptoserviceprovider)  
* Microsoft Docs: Aes Class (System.Security.Cryptography)
   [https://learn.microsoft.com/ja-jp/dotnet/api/system.security.cryptography.aes](https://learn.microsoft.com/ja-jp/dotnet/api/system.security.cryptography.aes)  
* PowerShellを管理者権限に昇格して実行
   [https://qiita.com/sakekasunuts/items/63a4023887348722b416](https://qiita.com/sakekasunuts/items/63a4023887348722b416)  
* PowerShellをダブルクリックやドラッグアンドドロップで実行したい
  [https://qiita.com/devfox/items/dc4371cbf2f215f1801d](https://qiita.com/devfox/items/dc4371cbf2f215f1801d)
