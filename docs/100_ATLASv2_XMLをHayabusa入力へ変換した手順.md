# ATLASv2 XMLをHayabusa入力へ変換した手順

作成日: 2026-04-22  
目的: ATLASv2 の素データをどのように Hayabusa へ入力できる形に変換したかを、具体例つきで説明する

---

## 1. 最初に結論

今回やったことは、**ATLASv2 の raw txt を本物の `.evtx` に再構築した**わけではない。

実際にやったのは次の流れである。

1. ATLASv2 の `msft-security-*.xml` / `sysmon-*.xml` を読む
2. 各 `<Event>` を 1 行 1 JSON の **JSONL** にフラット化する
3. Hayabusa の **`csv-timeline -J`** を使って、その JSONL を直接スキャンする

つまり、

> **「txt を evtx に戻した」のではなく、ATLASv2 が持っていた Windows Event Log XML を、Hayabusa が読める JSON 入力形式に変換した」**

というのが正確な説明である。

この違いはかなり大事で、共同研究先から言われた

> txt から evtx への置換は難しい、あるいは情報が足りず無理ではないか

という懸念は、**一般論としては正しい**。  
ただし今回の ATLASv2 `msft-security` / `sysmon` は、単なる自由文 txt ではなく、**Windows Event Log XML** だったため、Hayabusa が必要とするイベント構造をかなりそのまま保持できた。

---

## 2. 何が難しくて、なぜ今回はできたのか

### 2.1 一般に txt -> evtx が難しい理由

ATLAS v1 系の `security_events.txt` は、次のような**表示用テキスト**である。

```text
Keywords	Date and Time	Source	Event ID	Task Category
Audit Success	12/21/2018 4:51:10 PM	Microsoft-Windows-Security-Auditing	4656	File System	"A handle to an object was requested.

Subject:
	Security ID:		SYSTEM
	Account Name:		WIN-D65GVM5K5FO$
	Account Domain:		WORKGROUP
	Logon ID:		0x3e7

Object:
	Object Server:		Security
	Object Type:		File
	Object Name:		C:\Windows\Microsoft.NET\Framework\v4.0.30319
	Handle ID:		0x6c
```

この形式は人間には読めるが、

- どこが `System` セクションでどこが `EventData` か
- 型が何か
- 名前空間や属性が何か
- どのフィールドが正式な Windows Event Log 名なのか

が崩れている。  
したがって、**元の Event Log 構造を厳密に戻して `.evtx` を再生成するのはかなり難しい**。

### 2.2 今回できた理由

一方、ATLASv2 の `msft-security` と `sysmon` は、すでに次のような **Windows Event Log XML** で配布されていた。

```xml
<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<Events>
  <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
    <System>
      <Provider Name='Microsoft-Windows-Security-Auditing'
                Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
      <EventID>4658</EventID>
      <TimeCreated SystemTime='2022-07-19T15:02:00.0586749Z'/>
      <EventRecordID>3420342</EventRecordID>
      <Execution ProcessID='4' ThreadID='64'/>
      <Channel>Security</Channel>
      <Computer>WIN-32-H1</Computer>
    </System>
    <EventData>
      <Data Name='SubjectUserName'>aalsahee</Data>
      <Data Name='ProcessName'>C:\Windows\System32\mmc.exe</Data>
    </EventData>
  </Event>
</Events>
```

ここではすでに

- `EventID`
- `TimeCreated`
- `EventRecordID`
- `Channel`
- `Computer`
- `EventData/Data Name=...`

などが**構造化されたまま**残っている。  
このため、

> **evtx バイナリそのものは無くても、イベント内容を JSON に写し替えることは可能**

だった。

---

## 3. 実際の入力データは何だったか

今回 Hayabusa にかけた主対象は次の2種類である。

- `atlasv2/data/attack/h1/msft-security/msft-security-h1-s3.xml`
- `atlasv2/data/attack/h1/sysmon/sysmon-h1-s3.xml`

ここで先に明確にしておくと、

> **ATLASv2 が持っている全種類のログを Hayabusa に入力できたわけではない**

今回 Hayabusa 入力として扱えたのは、**Windows Event Log XML として配布されていたログ**に限られる。

---

## 3.1 どのログが入力できて、どのログができなかったか

ATLASv2 は複数種類のログを持っているが、Hayabusa 入力としての扱いやすさはかなり違う。

### 入力できたもの

| ログ種別 | 例 | 入力可否 | 理由 |
|---|---|---|---|
| `msft-security` | `msft-security-h1-s3.xml` | ○ | Windows Security Event Log XML であり、`EventID` / `EventRecordID` / `EventData` を保持している |
| `sysmon` | `sysmon-h1-s3.xml` | ○ | Sysmon Event Log XML であり、`Image` / `CommandLine` / `User` などを構造化して持つ |

### そのままは入力できなかったもの

| ログ種別 | 例 | 入力可否 | 主な理由 |
|---|---|---|---|
| `firefox` sidecar | `firefox-h1-s3` | × | ブラウザ開発者ログであり、Windows Event Log ではない |
| `dns` | シナリオに付随する DNS ログ | × | DNS 解決ログであり、Hayabusa の Event Log 前提とは別形式 |
| Carbon Black / EDR系補助ログ | 環境によって JSONL 等 | × | 独自スキーマであり、Windows Event Log XML ではない |
| benign/attack の付帯テキストや sidecar | 各種 | × | Event Log の `System` / `EventData` 構造がない |

### 重要なポイント

Hayabusa は本質的に **Windows Event Log / Sigma ベースの検知器** である。  
そのため、今回素直に入力へ載せられたのは

- Security
- Sysmon

のような **Windows Event Log 系** に限られた。

逆に

- Firefox
- DNS
- Carbon Black

のようなログは、研究上は非常に有用であるが、**今回の Hayabusa 入力パスには直接は載せていない**。

---

## 3.2 それでも Firefox や DNS を見ていた理由

今回の研究では、Hayabusa に直接入れたのは Security / Sysmon だが、Firefox や DNS を全く使っていないわけではない。

それらは主に次の用途で使った。

- **Hayabusa で出たアラートの意味づけ**
  - 例: Firefox 通信が実際にはどのドメイン閲覧だったか
- **正常行動復元の補助**
  - 例: `firefox.exe` 起動後に `google.com` や `tiles.services.mozilla.com` を見ていたことの確認
- **攻撃 / 正常の文脈補強**
  - 例: Security ログだけでは分からない Web 閲覧内容を sidecar で補う

つまり整理すると、

> **Hayabusa の入力対象** と **行動復元で参照する補助ログ** は別である。

今回 Hayabusa に入れたのは前者であり、Firefox / DNS は後者である。

### 3.1 Security XML の例

`msft-security-h1-s3.xml` には、Security 監査イベントが `<Event>` 単位で入っている。

例:

```xml
<Provider Name='Microsoft-Windows-Security-Auditing'
          Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
<EventID>4663</EventID>
<TimeCreated SystemTime='2022-07-19T15:02:00.0430749Z'/>
<EventRecordID>3420340</EventRecordID>
<Channel>Security</Channel>
<Computer>WIN-32-H1</Computer>
...
<Data Name='ObjectName'>C:\Users\aalsahee</Data>
<Data Name='ProcessName'>C:\Windows\System32\mmc.exe</Data>
```

この 1 イベントだけでも、

- イベントID = `4663`
- 時刻 = `2022-07-19T15:02:00.0430749Z`
- レコードID = `3420340`
- 対象ファイル = `C:\Users\aalsahee`
- 実行プロセス = `C:\Windows\System32\mmc.exe`

が明示されている。

### 3.2 Sysmon XML の例

`sysmon-h1-s3.xml` も同様に `<Event>` ごとの XML であり、たとえば Process Create は次のように入っている。

```xml
<Provider Name='Microsoft-Windows-Sysmon'
          Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/>
<EventID>1</EventID>
<TimeCreated SystemTime='2022-07-19T15:01:24.194211900Z'/>
<EventRecordID>4560</EventRecordID>
<Channel>Microsoft-Windows-Sysmon/Operational</Channel>
<Computer>WIN-32-H1</Computer>
...
<Data Name='ProcessId'>2904</Data>
<Data Name='Image'>C:\Windows\System32\dllhost.exe</Data>
<Data Name='CommandLine'>C:\Windows\system32\DllHost.exe /Processid:{...}</Data>
<Data Name='User'>WIN-32-H1\aalsahee</Data>
```

こちらも、

- Sysmon Event ID 1
- Image
- CommandLine
- User
- ProcessId

がそのまま取れる。

---

## 4. 変換の全体像

今回の変換パイプラインは次の通りである。

```text
ATLASv2 XML
  -> Pythonで<Event>ごとにパース
  -> System / EventData を1行1JSONへフラット化
  -> Hayabusa互換JSONLを生成
  -> hayabusa csv-timeline -J
  -> CSV出力
```

対応スクリプトは  
[run_atlasv2_hayabusa.py](C:\Users\komat\OneDrive\Desktop\ATLAS系データセット取得\scripts\run_atlasv2_hayabusa.py)

である。

このスクリプトの先頭にも、目的がかなり率直に書かれている。

```python
"""
Run Hayabusa against ATLASv2 Windows Event Log XML files.

The ATLASv2 XML files are Windows Event Log XML exports, but Hayabusa 3.8.1
does not consume this XML shape directly. This script converts each event to
the flat JSONL layout expected by Hayabusa's `csv-timeline -J` mode, then runs
Hayabusa and writes one CSV per input XML.
"""
```

ここで重要なのは、

- **Hayabusa はこの XML 形式をそのままは読めない**
- しかし **`csv-timeline -J` で JSON 入力は受けられる**

という点である。

---

## 5. XML から JSONL へどう写したか

### 5.1 `<System>` のフラット化

スクリプトの `parse_event()` は、`<System>` の主要要素をトップレベルの JSON キーへ写している。

具体的には次のような対応である。

| XML | JSONL |
|---|---|
| `<Provider Name='...' Guid='...'>` | `Provider`, `ProviderGuid` |
| `<EventID>` | `EventID` |
| `<TimeCreated SystemTime='...'>` | `@timestamp` |
| `<EventRecordID>` | `EventRecordID` |
| `<Execution ProcessID='...' ThreadID='...'>` | `ProcessID`, `ThreadID` |
| `<Channel>` | `Channel` |
| `<Computer>` | `Computer` |

### 5.2 `<EventData>` / `<UserData>` のフラット化

`<Data Name='SubjectUserName'>aalsahee</Data>` のような要素は、

```json
"SubjectUserName": "aalsahee"
```

としてそのまま写される。

たとえば Security XML の次の断片:

```xml
<Data Name='ObjectName'>C:\Users\aalsahee</Data>
<Data Name='AccessMask'>0x1</Data>
<Data Name='ProcessName'>C:\Windows\System32\mmc.exe</Data>
```

は、JSONL では次のようになる。

```json
"ObjectName": "C:\\Users\\aalsahee",
"AccessMask": "0x1",
"ProcessName": "C:\\Windows\\System32\\mmc.exe"
```

### 5.3 実際の JSONL 出力例

生成された JSONL の先頭は次のようになっている。

```json
{"Provider": "Microsoft-Windows-Security-Auditing", "ProviderGuid": "{54849625-5478-4994-a5ba-3e3b0328c30d}", "EventID": 4658, "Version": "0", "Level": "0", "Task": "12800", "Opcode": "0", "Keywords": "0x8020000000000000", "@timestamp": "2022-07-19T15:02:00.0586749Z", "EventRecordID": "3420342", "ProcessID": "4", "ThreadID": "64", "Channel": "Security", "Computer": "WIN-32-H1", "SubjectUserSid": "S-1-5-21-450080267-1945256726-3465656282-1000", "SubjectUserName": "aalsahee", "SubjectDomainName": "WIN-32-H1", "SubjectLogonId": "0x1d3e6", "ObjectServer": "Security", "HandleId": "0xb48", "ProcessId": "0x364", "ProcessName": "C:\\Windows\\System32\\mmc.exe"}
```

この 1 行だけ見ると、もとの XML イベントが

- 1 行 1 レコード
- フラットなキー集合
- Hayabusa が読みやすい構造

に変換されていることが分かる。

---

## 6. Hayabusa向けに追加した工夫

単純に XML を JSON 化しただけでは、Sigma ルール側が期待するフィールド名とずれることがある。  
そこで、`add_sigma_aliases()` で**別名フィールド**を追加している。

### 6.1 4688 Process Create

たとえば Security Event ID 4688 では、

- `NewProcessName` -> `Image`
- `ParentProcessName` -> `ParentImage`

を追加している。

これは Sigma / Hayabusa ルールが `Image` や `ParentImage` を参照することが多いためである。

### 6.2 5156 / 5157 Network Connection

通信系イベントでは、

- `Application` -> `Image`
- `SourceAddress` -> `SourceIp`, `SourceIP`, `SourceHostname`
- `DestAddress` -> `DestinationIp`, `DestinationIP`, `DestinationHostname`
- `DestPort` -> `DestinationPort`

を追加している。

これによって、もとの Windows Security XML が持っている

- `Application`
- `SourceAddress`
- `DestAddress`
- `DestPort`

を、Sigma ルールが参照しやすい形へ寄せている。

### 6.3 4663 File Access

ファイルアクセス系では、

- `ProcessName` -> `Image`
- `ObjectName` -> `TargetFilename`
- `ObjectName` -> `FileName`
- `ObjectName` -> `TargetObject`

を追加している。

ここは特に重要で、**4663 を扱うルールは対象ファイル名のキー名が揺れやすい**ため、別名を足して受けやすくしている。

---

## 7. 実際にどう Hayabusa を呼んだか

Hayabusa は JSON 入力モードで動かしている。

実際のコマンド構築は次の通りである。

```python
cmd = [
    str(hayabusa_exe),
    "csv-timeline",
    "-J",
    "-f",
    str(jsonl_path),
    "-w",
    "-U",
    "-p",
    "verbose",
    "-m",
    min_level,
    "-o",
    str(csv_path),
    "-C",
    "-K",
    "-q",
]
```

ポイントは `-J` で、これが

> **入力は EVTX ではなく JSON**

であることを示している。

したがって、説明としては

> **Hayabusa に EVTX を食わせた**

ではなく、

> **Hayabusa の JSON 入力モードに、ATLASv2 XML を変換した JSONL を食わせた**

が正しい。

---

## 8. 実際の出力で確認できること

変換後に得られる Hayabusa CSV の先頭は次のようになっている。

```csv
"Timestamp","RuleTitle","Level","Computer","Channel","EventID","MitreTactics","MitreTags","OtherTags","RecordID","Details","ExtraFieldInfo","RuleFile","RuleID","EvtxFile"
"2022-07-19 15:01:54.005 +00:00","Proc Exec","info","","Sec",4688,...,"Sec_4688_Info_ProcExec.yml",...,"C:\...\hayabusa\atlasv2_runs\jsonl\msft-security-h1-s3.jsonl"
"2022-07-19 15:01:53.709 +00:00","Net Conn","info","","Sec",5156,...,"Sec_5156_Info_NetConn.yml",...,"C:\...\hayabusa\atlasv2_runs\jsonl\msft-security-h1-s3.jsonl"
```

ここで `EvtxFile` 列に入っているのが

```text
...jsonl\msft-security-h1-s3.jsonl
```

である点が重要である。  
つまり Hayabusa 自身も、今回の入力を **JSONL ファイル**として扱っている。

---

## 9. 具体例で見る「何が保持されたか」

### 9.1 例1: Security 4663

もとの XML:

```xml
<EventID>4663</EventID>
<TimeCreated SystemTime='2022-07-19T15:02:00.0430749Z'/>
<EventRecordID>3420340</EventRecordID>
<Channel>Security</Channel>
<Computer>WIN-32-H1</Computer>
<Data Name='ObjectName'>C:\Users\aalsahee</Data>
<Data Name='ProcessName'>C:\Windows\System32\mmc.exe</Data>
```

JSONL:

```json
{
  "EventID": 4663,
  "@timestamp": "2022-07-19T15:02:00.0430749Z",
  "EventRecordID": "3420340",
  "Channel": "Security",
  "Computer": "WIN-32-H1",
  "ObjectName": "C:\\Users\\aalsahee",
  "ProcessName": "C:\\Windows\\System32\\mmc.exe",
  "Image": "C:\\Windows\\System32\\mmc.exe",
  "TargetFilename": "C:\\Users\\aalsahee"
}
```

保持できている情報:

- Event ID
- タイムスタンプ
- Record ID
- ホスト名
- 対象ファイル
- 実行プロセス

### 9.2 例2: Sysmon Event ID 1

もとの XML:

```xml
<EventID>1</EventID>
<TimeCreated SystemTime='2022-07-19T15:01:24.194211900Z'/>
<EventRecordID>4560</EventRecordID>
<Data Name='Image'>C:\Windows\System32\dllhost.exe</Data>
<Data Name='CommandLine'>C:\Windows\system32\DllHost.exe /Processid:{...}</Data>
<Data Name='User'>WIN-32-H1\aalsahee</Data>
```

JSONL では同様に

```json
{
  "EventID": 1,
  "@timestamp": "2022-07-19T15:01:24.194211900Z",
  "EventRecordID": "4560",
  "Image": "C:\\Windows\\System32\\dllhost.exe",
  "CommandLine": "C:\\Windows\\system32\\DllHost.exe /Processid:{...}",
  "User": "WIN-32-H1\\aalsahee"
}
```

のように取り出せる。

---

## 10. 逆に、何はしていないか

今回の手法で**していないこと**も明確にしておくべきである。

### 10.1 `.evtx` バイナリの再構築はしていない

今回生成したのは `.jsonl` であり、`.evtx` ではない。  
したがって、

- EVTX 固有の内部バイナリ構造
- イベントログファイルとしての完全復元
- Event Viewer にそのまま読み込める真正 EVTX

を作ったわけではない。

### 10.2 どんな txt でも変換できるわけではない

今回うまくいったのは、入力が **Windows Event Log XML** だったからである。  
ATLAS v1 の `security_events.txt` のような表示用テキスト、あるいは Firefox / DNS sidecar のような独自ログは、そのまま同じ方法では扱えない。

### 10.3 情報の一部は落ちうる

今回は Hayabusa が読むのに必要な項目をフラット化しているが、

- XML の階層構造そのもの
- 一部の属性の入れ子関係
- EVTX と完全一致する原表現

までは保持していない。

したがって、目的は

> **Hayabusa に食わせて Sigma ベースの検知・タイムライン化を行うこと**

であって、

> **真正 EVTX を完全復元すること**

ではない。

---

## 11. 実務的にどう説明するのがよいか

共同研究先への説明としては、次の表現が一番誤解が少ない。

### 言ってよいこと

- ATLASv2 の `msft-security` / `sysmon` は単なる txt ではなく、Windows Event Log XML である
- XML には `EventID`, `EventRecordID`, `TimeCreated`, `Channel`, `Computer`, `EventData` が残っている
- そのため、Hayabusa が必要とするイベント項目を JSONL に写し替えることができた
- Hayabusa の `csv-timeline -J` により JSON 入力としてスキャンできた

### 言わない方がよいこと

- txt を完全に evtx に戻した
- EVTX と同一のものを再現した
- あらゆる ATLAS ログをそのまま Hayabusa へ入れられる

### 一番安全なまとめ

> **今回実現したのは、ATLASv2 の Windows Event Log XML を Hayabusa 互換 JSONL に変換し、`csv-timeline -J` で解析する方法である。**  
> **真の `.evtx` 再構築ではないが、Hayabusa の Sigma ルール適用に必要なイベント構造は十分保持できた。**

---

## 12. この手法の意味

この手法の研究上の意味は、次の2点にある。

1. **「ATLASv2 は evtx でないから Hayabusa は無理」という理解は、半分正しく半分違う**
   - 真の evtx ではない
   - しかし XML が十分 structured なので、Hayabusa 入力へ変換できる

2. **一般的な txt -> evtx 復元問題を解いたわけではない**
   - 解いたのは、ATLASv2 の Windows Event Log XML を使った実用変換パスである

この違いを明示しておくことで、

- 何ができたのか
- 何がまだ難しいのか
- どこまでが再現可能だったのか

を誤解なく共有できる。

---

## 13. 参照したファイル

- [run_atlasv2_hayabusa.py](C:\Users\komat\OneDrive\Desktop\ATLAS系データセット取得\scripts\run_atlasv2_hayabusa.py)
- [ATLASv2_Hayabusa_実行手順.md](C:\Users\komat\OneDrive\Desktop\ATLAS系データセット取得\docs\ATLASv2_Hayabusa_実行手順.md)
- [msft-security-h1-s3.xml](C:\Users\komat\OneDrive\Desktop\ATLAS系データセット取得\atlasv2\data\attack\h1\msft-security\msft-security-h1-s3.xml)
- [sysmon-h1-s3.xml](C:\Users\komat\OneDrive\Desktop\ATLAS系データセット取得\atlasv2\data\attack\h1\sysmon\sysmon-h1-s3.xml)
- [msft-security-h1-s3.jsonl](C:\Users\komat\OneDrive\Desktop\ATLAS系データセット取得\hayabusa\atlasv2_runs\jsonl\msft-security-h1-s3.jsonl)
- [msft-security-h1-s3.csv](C:\Users\komat\OneDrive\Desktop\ATLAS系データセット取得\hayabusa\atlasv2_runs\csv\msft-security-h1-s3.csv)
- [security_events.txt](C:\Users\komat\OneDrive\Desktop\ATLAS系データセット取得\atlas\raw_logs\M1\M1\h1\logs\security_events.txt)
