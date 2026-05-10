# ATLASv2 benign 4日分 手続型正常行動分析メモ

作成日: 2026-04-21  
対象: ATLASv2 `benign/h1/msft-security` 4日分 + `benign/h1/firefox` sidecar  
目的: S3 攻撃日だけでは弱かった「手続型の正常行動」が benign 側で補強できるか確認する

---

## 1. 結論

ATLAS benign 4日分を追加で見ると、**ATLAS の印象はかなり改善する**。

- **Firefox 系の手続型正常行動は十分にある**
  - 4日で `firefox.exe` 起動 42件
  - 4日で `firefox.exe` の `EID 5156` 通信 34,567件
  - sidecar から `gmail.com`, `mail.google.com`, `play.google.com`, `docs.microsoft.com`, `goal.com`, `espn.com`, `discord.com`, `uillinois.edu` など具体的な閲覧先が見える
- **Word / Excel も薄いが実在する**
  - `winword.exe` 起動 11件
  - `excel.exe` 起動 8件
  - いずれもユーザー `aalsahee` による複数日出現
- **ただし Outlook 起点の業務手続やメール手続は見えていない**
  - `outlook.exe` は今回確認した範囲では出ていない
  - そのため「メール受信 -> 添付開封 -> Word」のような業務手続を主役にするにはまだ弱い

要するに、

**ATLAS は attack day 単体だと少し苦しいが、benign 4日分まで含めると「ブラウザ中心の正常手続」を主題に据える道がかなり現実的になる。**

---

## 2. 集計対象

対象ファイル:

- `atlasv2/data/benign/h1/msft-security/msft-security-h1-benign-1.xml`
- `atlasv2/data/benign/h1/msft-security/msft-security-h1-benign-2.xml`
- `atlasv2/data/benign/h1/msft-security/msft-security-h1-benign-3.xml`
- `atlasv2/data/benign/h1/msft-security/msft-security-h1-benign-4.xml`
- `atlasv2/data/benign/h1/firefox/firefox-h1-benign-1`
- `atlasv2/data/benign/h1/firefox/firefox-h1-benign-2a`
- `atlasv2/data/benign/h1/firefox/firefox-h1-benign-2b`
- `atlasv2/data/benign/h1/firefox/firefox-h1-benign-3`
- `atlasv2/data/benign/h1/firefox/firefox-h1-benign-4`

---

## 3. benign 4日分の大枠

### 総イベント数

| ファイル | 総イベント数 |
|---|---:|
| benign-1 | 6,513,451 |
| benign-2 | 4,430,301 |
| benign-3 | 4,362,448 |
| benign-4 | 2,736,953 |

### 主な EventID

| EventID | 件数 |
|---|---:|
| 4663 | 5,975,926 |
| 4658 | 5,532,251 |
| 4656 | 5,493,606 |
| 5156 | 259,987 |
| 5158 | 229,087 |
| 4688 | 29,092 |
| 4689 | 29,076 |

この時点で、**プロセス起動と通信の両方を追う土台はある**。

---

## 4. 手続型候補の起動・通信量

### 4.1 4688 起動件数

| プロセス | 件数 | コメント |
|---|---:|---|
| `firefox.exe` | 42 | 最有力の手続型候補 |
| `winword.exe` | 11 | 薄いが複数日で確認 |
| `excel.exe` | 8 | 薄いが複数日で確認 |
| `iexplore.exe` | 9 | 補助的なブラウザ利用 |
| `discord.exe` | 197 | 人手起動アプリだが業務性は弱い |
| `explorer.exe` | 20 | 周辺操作の補助証拠 |
| `cmd.exe` | 19 | 補助証拠、意味解釈は要注意 |

### 4.2 5156 通信件数

| Application | 件数 | コメント |
|---|---:|---|
| `firefox.exe` | 34,567 | 圧倒的に強い |
| `discord.exe` | 859 | 継続利用の痕跡 |
| `iexplore.exe` | 29 | 小さいが存在 |
| `excel.exe` | 1 | 通信手続の主役にはならない |

---

## 5. 日別の出現状況

### 5.1 `firefox.exe`

| 日 | 4688 | 5156 |
|---|---:|---:|
| benign-1 | 27 | 19,747 |
| benign-2 | 6 | 5,189 |
| benign-3 | 6 | 8,703 |
| benign-4 | 3 | 928 |

**4日すべてで出現**しており、単発ではなく継続的な日常利用と見てよい。

### 5.2 `winword.exe`

| 日 | 4688 |
|---|---:|
| benign-1 | 6 |
| benign-2 | 3 |
| benign-3 | 1 |
| benign-4 | 1 |

### 5.3 `excel.exe`

| 日 | 4688 | 5156 |
|---|---:|---:|
| benign-1 | 3 | 0 |
| benign-2 | 4 | 1 |
| benign-3 | 1 | 0 |
| benign-4 | 0 | 0 |

Word / Excel は多くはないが、**S3攻撃日だけを見ていたときより「正常な Office 作業が本当に存在する」と言いやすくなる**。

---

## 6. 起動サンプル

### Firefox 起動例

- `2022-07-16T20:29:22.4897929Z`
- `2022-07-16T17:55:57.4021130Z`
- `2022-07-16T17:01:51.6790967Z`
- `2022-07-16T16:57:54.4764832Z`
- `2022-07-16T15:49:39.3398315Z`

### Word 起動例

- `2022-07-15T13:11:05.0085260Z`
- `2022-07-15T13:11:17.1482204Z`
- `2022-07-15T13:11:55.4994139Z`
- `2022-07-15T13:13:06.6640933Z`
- `2022-07-17T14:08:03.7352372Z`
- `2022-07-18T14:44:04.6311880Z`
- `2022-07-19T12:58:16.6759071Z`

### Excel 起動例

- `2022-07-15T13:32:28.1253644Z`
- `2022-07-15T20:05:03.9607920Z`
- `2022-07-17T13:40:20.8003322Z`
- `2022-07-17T15:54:55.9223184Z`
- `2022-07-17T19:58:37.4611638Z`
- `2022-07-18T18:13:03.9317144Z`

全て `SubjectUserName = aalsahee`。  
つまり **SYSTEM や機械アカウントではなく、ユーザー主体の操作** とみなせる。

---

## 7. Firefox sidecar から見える「人間っぽさ」

`firefox-h1-benign-*` の sidecar には HTTP Host や URI が残っており、単なる「外向き通信」以上の意味が取れる。

### 代表的に確認できたホスト

- `mail.google.com`
- `gmail.com`
- `www.google.com`
- `play.google.com`
- `docs.microsoft.com`
- `forum.sublimetext.com`
- `discord.com`
- `www.goal.com`
- `www.thisisanfield.com`
- `a1.espncdn.com`
- `banner.apps.uillinois.edu`

### sidecar で確認した具体例

- `uri=http://gmail.com/`
- `Location: https://www.google.com/gmail/`
- `Host: mail.google.com`
- `Host: docs.microsoft.com`
- `Host: forum.sublimetext.com`

このため Firefox については、

**`4688 firefox.exe` -> `5156 firefox.exe` の大量通信**

に加えて、

**その先が Gmail / ドキュメント / ニュース / 学内サイト等である**

ことまで見える。  
ここは S3 attack day にはなかった強さ。

---

## 8. 手続型として見たときの評価

### 8.1 強い題材

#### A. Firefox 起動 -> Webアクセス連鎖

一番強い。

- 4日すべてで出現
- 起動件数も通信件数も十分
- sidecar により閲覧先の意味が見える
- `gmail`, `docs.microsoft.com`, `goal.com`, `espn`, `uillinois` など、機械的更新だけではない利用痕跡がある

研究題材としては、

**「中特異性起点: `firefox.exe` 起動」から、どこまで正常手続を復元できるか**

が最も筋が良い。

#### B. Word / Excel の通常業務起動

強さは Firefox よりかなり落ちるが、完全にゼロではない。

- Word 11件
- Excel 8件
- 複数日で出る
- すべてユーザー起動

ただし弱点:

- 件数が少ない
- Outlook が見えない
- 文書名・添付名・メール起点の手続までは届かない

なので、

**「Office 手続の主役」ではなく、「Firefox 主役を補完する通常業務の証拠」**

として使うのが安全。

### 8.2 補助題材

#### C. IE / Discord

- `iexplore.exe` は少数ながら存在
- `discord.exe` は起動 197件、通信 859件でかなり多い

ただし:

- IE は量が少ない
- Discord は人手利用っぽいが、業務行動というより雑多な常用アプリに近い

したがって、主役ではなく補助枠が妥当。

---

## 9. 研究的に何が変わるか

benign 4日分を見たことで、ATLAS に対する評価は次のように変わる。

### 以前

- attack day の Firefox はある
- でも Word 正常手続が薄い
- 背景動作が多く、やや「これじゃない感」が残る

### 今

- **Firefox については、正常手続をかなり自然に語れる**
- **Word / Excel も少量ながら benign 側で支えられる**
- 少なくとも
  - 単発操作型
  - 手続型
  - 背景動作型
  のうち、**手続型が attack day 単独よりだいぶ強化された**

---

## 10. それでも残る弱点

ATLAS benign を掘っても、まだ苦しい点は残る。

1. **Outlook / メール手続が弱い**
   - `outlook.exe` が見えない
   - 「受信 -> 添付 -> Word」の王道業務手続はまだ立てにくい

2. **Office 手続が薄い**
   - Word 11件、Excel 8件は「存在証明」としては十分
   - ただし統計的に厚いとは言いにくい

3. **EVTX ではない**
   - XML -> JSONL 変換を挟む点は変わらない

4. **復元後の正常/攻撃の断定問題は残る**
   - benign 側で正常手続が見えたことで改善はする
   - それでも「復元できた = 二値断定できる」ではない

---

## 11. 今の一番よい落とし所

ATLAS を使うなら、現時点で一番しっくり来る主張はこれ。

> ATLASv2 の benign 4日分と attack day を組み合わせ、  
> 起点アラートの特異性と行動型の違いが、正常行動の復元可能性にどう影響するかを評価する。  
> 特に browser-centric な正常手続は豊富に観測できる一方、Office / mail-centric な手続は薄く、題材依存で復元しやすさが変わる。

つまり、

- **主役: Firefox 系の正常手続**
- **補助: Word / Excel の通常業務起動**
- **比較対象: 背景動作系 (`svchost`, `search*`, `repwmiutils`)**

この構成がいま最も現実的。

---

## 12. いま言える判断

**ATLAS benign を見たことで、ATLAS は「やっぱり違うかも」から「ブラウザ中心ならかなり行ける」に変わった。**

ただし、

- 「メール添付からの業務手続」
- 「Office 中心の豊富な正常業務」

をやりたいなら、まだ少し物足りない。

逆に、

- `firefox.exe` を起点にした手続復元
- 起点特異性と復元難易度の比較
- 背景動作との対比

を主題にするなら、かなり戦える。
