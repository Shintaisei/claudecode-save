# LOF 上位 chunk に含まれる正常行動のユースケース候補分析

## 1. 目的

second pass で得られた `LOF` 上位 chunk から、  
**実際に研究のユースケース候補として使えそうな正常行動の起点があるか** を確認する。

ここで見たいのは、単に normal log が多いかどうかではなく、

- attack 近傍にあるか
- pure normal chunk として切り出せるか
- 背景ノイズではなく、ユーザ行動の起点として意味があるか

である。

---

## 2. 対象

- first pass:
  - `ユーザ単位・10分ごと + 1-2gram TF-IDF + IsolationForest`
- second pass:
  - `100 event chunk`
  - `LOF`
- 確認対象:
  - `LOF top100 chunk`

LOF の圧縮結果は次の通り。

| 範囲 | 総 event 数 | attack | normal |
| --- | ---: | ---: | ---: |
| `top1` | 100 | 6 | 94 |
| `top3` | 300 | 23 | 277 |
| `top10` | 1,000 | 38 | 962 |
| `top100` | 9,994 | 109 | 9,885 |

---

## 3. top100 の全体像

LOF 上位 `100 chunk` の中身をプロセス名ベースで分類すると、次の5群に分かれた。

| 分類 | chunk 数 | 概要 | ユースケース候補としての扱い |
| --- | ---: | --- | --- |
| `attack-mixed` | 7 | attack と normal が混在する chunk | attack 近傍確認用 |
| `office-doc` | 17 | `winword.exe` / `repmgr.exe` を含む文書系 | 有望 |
| `user-app` | 22 | `explorer.exe` / `firefox.exe` を含む操作系 | 有望 |
| `background-vmware` | 50 | `tpautoconnect.exe` / `vmtoolsd.exe` / `spoolsv.exe` 優勢 | 低優先 |
| `ambiguous-system` | 4 | `regsvr32.exe` / `dllhost.exe` / `svchost.exe` など | 注意が必要 |

### 読み

- top100 全体には normal log は大量にある
- ただし、その半分は **VMware / service 背景ノイズ** であり、ユースケース化には向きにくい
- 研究で使いやすいのは `office-doc` と `user-app`

---

## 4. attack 近傍で使えそうな pure normal chunk

特に重要なのは、**上位に出てくる pure normal chunk の中で、ユーザ行動として意味があるもの** である。

### 4.1 文書操作系

| rank | chunk | attack | normal | 主なプロセス |
| --- | --- | ---: | ---: | --- |
| 4 | `chunk203` | 0 | 100 | `tpautoconnect.exe`, `repmgr.exe`, `winword.exe` |
| 5 | `chunk204` | 0 | 100 | `tpautoconnect.exe`, `repmgr.exe`, `winword.exe` |
| 7 | `chunk210` | 0 | 100 | `tpautoconnect.exe`, `winword.exe` |

### 読み

- `winword.exe` が明確に見えており、**文書閲覧・編集系の normal 行動** として解釈しやすい
- `repmgr.exe` も同時に出ており、資料操作や管理系の業務行動に近い文脈として扱える
- pure normal chunk なので、**attack を直接含まない seed 候補** として使いやすい

---

### 4.2 ファイル操作・画面操作系

| rank | chunk | attack | normal | 主なプロセス |
| --- | --- | ---: | ---: | --- |
| 6 | `chunk244` | 0 | 100 | `tpautoconnect.exe`, `explorer.exe` |
| 9 | `chunk243` | 0 | 100 | `tpautoconnect.exe`, `explorer.exe` |

### 読み

- `explorer.exe` が出ているため、**ファイル参照・画面操作の normal 行動** として解釈しやすい
- これも pure normal chunk であり、起点候補としてかなり扱いやすい

---

### 4.3 ブラウザ系

| rank | chunk | attack | normal | 主なプロセス |
| --- | --- | ---: | ---: | --- |
| 43 | `chunk234` | 0 | 100 | `tpautoconnect.exe`, `vmtoolsd.exe`, `explorer.exe`, `firefox.exe` |
| 44 | `chunk231` | 0 | 100 | `tpautoconnect.exe`, `vmtoolsd.exe`, `firefox.exe` |
| 46 | `chunk742` | 0 | 100 | `tpautoconnect.exe`, `vmtoolsd.exe`, `firefox.exe` |
| 47 | `chunk005` | 0 | 100 | `tpautoconnect.exe`, `firefox.exe` |

### 読み

- `firefox.exe` が含まれており、**Web 閲覧系の normal 行動** 候補になる
- ただし rank はやや下がり、attack 近傍性は `top10` より弱い
- ユースケース候補としては使えるが、優先度は文書操作系より低い

---

## 5. ユースケース化しにくい chunk

### 5.1 pure VMware / service 背景ノイズ

| rank 例 | 主なプロセス | 特徴 |
| --- | --- | --- |
| 10〜20 | `tpautoconnect.exe` ほぼ単独 | `4656 / 4658 / 4663` の反復 |
| 74, 79, 80, 83 など | `spoolsv.exe`, `tpautoconnsvc.exe` | サービス系の背景アクセス |

### 読み

- normal ではあるが、**ユーザ行動の起点としては弱い**
- 何かを追跡する seed というより、OS / VMware 背景ノイズに近い
- したがって、ユースケース抽出では低優先でよい

---

### 5.2 解釈が難しい system utility 系

| rank 例 | 主なプロセス | コメント |
| --- | --- | --- |
| 41 | `regsvr32.exe`, `svchost.exe`, `csrss.exe` | normal-only だが意味づけが難しい |
| 55 | `dllhost.exe`, `svchost.exe` | ユーザ行動 seed としては使いにくい |

### 読み

- normal-only ではあるが、**実務上は疑わしく見えやすい**
- 「正常行動ユースケース」として採用すると説明負荷が高い
- 今回の用途では避けた方がよい

---

## 6. どこまで見れば正常行動ユースケースを抽出できそうか

### 結論

**ユースケース候補の抽出だけなら、まずは `LOF top10` までで十分有望。  
特に実用上は `rank 4〜9` が重要。**

### 理由

1. `top3` までは attack-mixed が中心  
   - attack 近傍性は高いが、pure normal seed はまだ少ない

2. `rank 4〜9` に pure normal かつ意味のある chunk が入る  
   - `winword.exe`
   - `repmgr.exe`
   - `explorer.exe`
   - これらは **文書操作 / ファイル操作** として説明しやすい

3. `rank 10` を超えると pure `tpautoconnect.exe` 反復が増える  
   - top20 以降は normal でも background noise の比率が大きい
   - ユースケース候補の密度は落ちる

---

## 7. 推奨する次の進め方

### 優先候補

以下を **正常行動ユースケース候補** として先に精査するのがよい。

1. 文書操作系
   - `chunk203`
   - `chunk204`
   - `chunk210`

2. ファイル操作系
   - `chunk244`
   - `chunk243`

### 保留候補

3. ブラウザ系
   - `chunk234`
   - `chunk231`
   - `chunk742`
   - `chunk005`

### 除外候補

4. VMware / service 背景ノイズ
5. `regsvr32.exe` など解釈が難しい utility 系

---

## 8. まとめ

LOF 上位 chunk には、研究で使えそうな normal 行動候補が実際に含まれていた。  
特に `rank 4〜9` には、

- `winword.exe`
- `repmgr.exe`
- `explorer.exe`

を含む pure normal chunk があり、**攻撃近傍で追跡の起点にできる正常行動 seed** として有望である。

一方で、`top20` 以降は `tpautoconnect.exe` 中心の反復 background noise が増えるため、  
ユースケース抽出段階では **まず LOF top10、特に rank 4〜9 を優先的に見る** のが妥当である。
