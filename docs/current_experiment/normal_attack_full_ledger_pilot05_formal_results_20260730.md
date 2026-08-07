# 正常・攻撃 full-ledger pilot05 正式結果

正常2ユースケース、攻撃2ユースケースについて、各Stage 1/2/3を1回ずつ、`gpt-4.1-mini`または`gpt-5.4-mini`で実行した12試行の正式集計である。
GPT-5.5およびOpenAI judge API/API scorerは使用していない。

## 実験整合性

- run数: 12/12
- 全ケースの参照時間窓: 5分
- agent call上限: 実験としては無制限
- 1 leadの安全弁: Investigator 20質問、SQL 80回、または20分
- 精度採点: Codex単独review + v5 atomic決定論的監査
- accuracy audit: PASS
- operational audit: PASS

## 全体精度

| Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---:|---:|---:|---:|---:|
| 35/144 (24.31%) | 35/123 (28.46%) | 9/48 (18.75%) | 0/48 (0.00%) | 5/36 (13.89%) |

## モデル別精度

| model | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|
| gpt-4.1-mini | 19/99 (19.19%) | 19/66 (28.79%) | 5/33 (15.15%) | 0/33 (0.00%) | 1/27 (3.70%) |
| gpt-5.4-mini | 16/45 (35.56%) | 16/57 (28.07%) | 4/15 (26.67%) | 0/15 (0.00%) | 4/9 (44.44%) |

## Stage別精度

| stage | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|
| stage1 | 15/48 (31.25%) | 15/42 (35.71%) | 3/16 (18.75%) | 0/16 (0.00%) | 3/12 (25.00%) |
| stage2 | 7/48 (14.58%) | 7/24 (29.17%) | 2/16 (12.50%) | 0/16 (0.00%) | 1/12 (8.33%) |
| stage3 | 13/48 (27.08%) | 13/57 (22.81%) | 4/16 (25.00%) | 0/16 (0.00%) | 1/12 (8.33%) |

## 正常・攻撃別精度

| scenario_group | Action recall | Candidate precision | Behavior-step recall | Critical evidence | Order recall |
|---|---:|---:|---:|---:|---:|
| attack | 22/99 (22.22%) | 22/57 (38.60%) | 5/33 (15.15%) | 0/33 (0.00%) | 4/27 (14.81%) |
| normal | 13/45 (28.89%) | 13/66 (19.70%) | 4/15 (26.67%) | 0/15 (0.00%) | 1/9 (11.11%) |

## 試行別API・token・費用・時間

| group | model | Stage | case | Chief calls | Investigator calls | SQL QA calls | Input | Output | Cached | Cost | Wall min | leads | questions | SQL | guard |
|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| normal | gpt-4.1-mini | stage1 | normal_chain10_gpt41 | 7 | 37 | 148 | 710,887 | 40,115 | 478,720 | $0.204923 | 10.92 | 5 | 40 | 106 | 1 |
| normal | gpt-4.1-mini | stage2 | normal_chain10_gpt41 | 7 | 17 | 39 | 171,257 | 12,141 | 86,144 | $0.062085 | 3.90 | 7 | 14 | 29 | 0 |
| normal | gpt-4.1-mini | stage3 | normal_chain10_gpt41 | 4 | 17 | 79 | 329,852 | 19,542 | 227,712 | $0.094894 | 7.54 | 1 | 21 | 63 | 1 |
| attack | gpt-4.1-mini | stage1 | attack_s4pt03_gpt41 | 7 | 42 | 147 | 712,974 | 44,634 | 400,640 | $0.236412 | 11.31 | 8 | 55 | 109 | 1 |
| attack | gpt-4.1-mini | stage2 | attack_s4pt03_gpt41 | 4 | 2 | 2 | 17,170 | 911 | 7,680 | $0.006022 | 0.34 | 1 | 1 | 1 | 0 |
| attack | gpt-4.1-mini | stage3 | attack_s4pt03_gpt41 | 11 | 103 | 336 | 2,101,656 | 87,378 | 928,896 | $0.701798 | 22.69 | 16 | 122 | 208 | 4 |
| normal | gpt-5.4-mini | stage1 | normal_chain02_gpt54 | 7 | 12 | 37 | 241,128 | 20,055 | 156,672 | $0.165340 | 2.96 | 4 | 9 | 30 | 0 |
| normal | gpt-5.4-mini | stage2 | normal_chain02_gpt54 | 6 | 13 | 51 | 492,657 | 27,408 | 357,376 | $0.251600 | 4.74 | 4 | 9 | 47 | 0 |
| normal | gpt-5.4-mini | stage3 | normal_chain02_gpt54 | 6 | 18 | 78 | 513,380 | 38,255 | 349,440 | $0.321310 | 5.39 | 5 | 16 | 76 | 0 |
| attack | gpt-5.4-mini | stage1 | attack_s3pt01_gpt54 | 5 | 10 | 30 | 312,370 | 29,114 | 171,648 | $0.249428 | 3.08 | 3 | 8 | 26 | 0 |
| attack | gpt-5.4-mini | stage2 | attack_s3pt01_gpt54 | 6 | 12 | 55 | 476,169 | 36,727 | 258,944 | $0.347611 | 3.80 | 3 | 12 | 43 | 0 |
| attack | gpt-5.4-mini | stage3 | attack_s3pt01_gpt54 | 5 | 11 | 41 | 401,141 | 28,617 | 265,728 | $0.250266 | 3.13 | 3 | 8 | 37 | 0 |

## 試行・役割別LLM ledger

| group | model | Stage | case | role | API calls | Input | Output | Cached | LLM sec | Cost | cross-agent tool calls |
|---|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| normal | gpt-4.1-mini | stage1 | normal_chain10_gpt41 | chief | 7 | 32,367 | 4,741 | 22,144 | 64.126 | $0.013889 | 5 |
| normal | gpt-4.1-mini | stage1 | normal_chain10_gpt41 | investigator | 37 | 210,324 | 14,164 | 169,344 | 178.781 | $0.055989 | 40 |
| normal | gpt-4.1-mini | stage1 | normal_chain10_gpt41 | sql_qa | 148 | 468,196 | 21,210 | 287,232 | 311.855 | $0.135045 | 118 |
| normal | gpt-4.1-mini | stage2 | normal_chain10_gpt41 | chief | 7 | 34,351 | 2,170 | 16,384 | 30.906 | $0.012297 | 7 |
| normal | gpt-4.1-mini | stage2 | normal_chain10_gpt41 | investigator | 17 | 39,992 | 5,172 | 23,936 | 63.066 | $0.017091 | 14 |
| normal | gpt-4.1-mini | stage2 | normal_chain10_gpt41 | sql_qa | 39 | 96,914 | 4,799 | 45,824 | 72.502 | $0.032697 | 53 |
| normal | gpt-4.1-mini | stage3 | normal_chain10_gpt41 | chief | 4 | 13,523 | 3,427 | 6,016 | 43.156 | $0.009088 | 1 |
| normal | gpt-4.1-mini | stage3 | normal_chain10_gpt41 | investigator | 17 | 111,633 | 6,680 | 90,368 | 106.595 | $0.028231 | 21 |
| normal | gpt-4.1-mini | stage3 | normal_chain10_gpt41 | sql_qa | 79 | 204,696 | 9,435 | 131,328 | 171.017 | $0.057576 | 64 |
| attack | gpt-4.1-mini | stage1 | attack_s4pt03_gpt41 | chief | 7 | 40,146 | 3,631 | 25,472 | 48.000 | $0.014226 | 8 |
| attack | gpt-4.1-mini | stage1 | attack_s4pt03_gpt41 | investigator | 42 | 234,575 | 15,911 | 173,056 | 224.817 | $0.067371 | 55 |
| attack | gpt-4.1-mini | stage1 | attack_s4pt03_gpt41 | sql_qa | 147 | 438,253 | 25,092 | 202,112 | 376.182 | $0.154815 | 128 |
| attack | gpt-4.1-mini | stage2 | attack_s4pt03_gpt41 | chief | 4 | 9,523 | 608 | 4,096 | 10.985 | $0.003553 | 1 |
| attack | gpt-4.1-mini | stage2 | attack_s4pt03_gpt41 | investigator | 2 | 3,824 | 166 | 1,792 | 3.063 | $0.001258 | 1 |
| attack | gpt-4.1-mini | stage2 | attack_s4pt03_gpt41 | sql_qa | 2 | 3,823 | 137 | 1,792 | 2.781 | $0.001211 | 1 |
| attack | gpt-4.1-mini | stage3 | attack_s4pt03_gpt41 | chief | 11 | 105,167 | 6,093 | 63,104 | 80.516 | $0.032884 | 16 |
| attack | gpt-4.1-mini | stage3 | attack_s4pt03_gpt41 | investigator | 103 | 603,628 | 37,481 | 472,320 | 533.831 | $0.159725 | 122 |
| attack | gpt-4.1-mini | stage3 | attack_s4pt03_gpt41 | sql_qa | 336 | 1,392,861 | 43,804 | 393,472 | 728.644 | $0.509189 | 239 |
| normal | gpt-5.4-mini | stage1 | normal_chain02_gpt54 | chief | 7 | 41,969 | 3,831 | 24,192 | 23.203 | $0.032387 | 4 |
| normal | gpt-5.4-mini | stage1 | normal_chain02_gpt54 | investigator | 12 | 34,551 | 5,508 | 16,256 | 38.782 | $0.039726 | 9 |
| normal | gpt-5.4-mini | stage1 | normal_chain02_gpt54 | sql_qa | 37 | 164,608 | 10,716 | 116,224 | 81.702 | $0.093227 | 30 |
| normal | gpt-5.4-mini | stage2 | normal_chain02_gpt54 | chief | 6 | 42,105 | 5,131 | 22,016 | 27.250 | $0.039807 | 4 |
| normal | gpt-5.4-mini | stage2 | normal_chain02_gpt54 | investigator | 13 | 41,920 | 7,055 | 22,144 | 46.641 | $0.048240 | 9 |
| normal | gpt-5.4-mini | stage2 | normal_chain02_gpt54 | sql_qa | 51 | 408,632 | 15,222 | 313,216 | 118.835 | $0.163552 | 49 |
| normal | gpt-5.4-mini | stage3 | normal_chain02_gpt54 | chief | 6 | 42,645 | 4,858 | 22,528 | 30.625 | $0.038638 | 5 |
| normal | gpt-5.4-mini | stage3 | normal_chain02_gpt54 | investigator | 18 | 61,858 | 8,002 | 33,408 | 56.546 | $0.059852 | 16 |
| normal | gpt-5.4-mini | stage3 | normal_chain02_gpt54 | sql_qa | 78 | 408,877 | 25,395 | 293,504 | 192.355 | $0.222820 | 78 |
| attack | gpt-5.4-mini | stage1 | attack_s3pt01_gpt54 | chief | 5 | 37,025 | 4,791 | 16,768 | 24.564 | $0.038010 | 3 |
| attack | gpt-5.4-mini | stage1 | attack_s3pt01_gpt54 | investigator | 10 | 43,395 | 7,085 | 19,200 | 41.143 | $0.051469 | 8 |
| attack | gpt-5.4-mini | stage1 | attack_s3pt01_gpt54 | sql_qa | 30 | 231,950 | 17,238 | 135,680 | 103.419 | $0.159949 | 26 |
| attack | gpt-5.4-mini | stage2 | attack_s3pt01_gpt54 | chief | 6 | 32,588 | 5,096 | 16,384 | 28.095 | $0.036314 | 3 |
| attack | gpt-5.4-mini | stage2 | attack_s3pt01_gpt54 | investigator | 12 | 69,976 | 5,720 | 43,776 | 37.436 | $0.048673 | 12 |
| attack | gpt-5.4-mini | stage2 | attack_s3pt01_gpt54 | sql_qa | 55 | 373,605 | 25,911 | 198,784 | 158.453 | $0.262624 | 43 |
| attack | gpt-5.4-mini | stage3 | attack_s3pt01_gpt54 | chief | 5 | 27,314 | 6,524 | 12,672 | 34.234 | $0.041290 | 3 |
| attack | gpt-5.4-mini | stage3 | attack_s3pt01_gpt54 | investigator | 11 | 48,177 | 5,257 | 28,160 | 36.484 | $0.040781 | 8 |
| attack | gpt-5.4-mini | stage3 | attack_s3pt01_gpt54 | sql_qa | 41 | 325,650 | 16,836 | 224,896 | 113.332 | $0.168195 | 37 |

## 試行別精度

| group | model | Stage | case | Action recall | Precision | Complete step | Critical evidence | Order |
|---|---|---|---|---:|---:|---:|---:|---:|
| normal | gpt-4.1-mini | stage1 | normal_chain10_gpt41 | 0/6 (0.00%) | 0/18 (0.00%) | 0/2 (0.00%) | 0/2 (0.00%) | 0/1 (0.00%) |
| normal | gpt-4.1-mini | stage2 | normal_chain10_gpt41 | 3/6 (50.00%) | 3/6 (50.00%) | 1/2 (50.00%) | 0/2 (0.00%) | 0/1 (0.00%) |
| normal | gpt-4.1-mini | stage3 | normal_chain10_gpt41 | 6/6 (100.00%) | 6/15 (40.00%) | 2/2 (100.00%) | 0/2 (0.00%) | 0/1 (0.00%) |
| attack | gpt-4.1-mini | stage1 | attack_s4pt03_gpt41 | 7/27 (25.93%) | 7/12 (58.33%) | 1/9 (11.11%) | 0/9 (0.00%) | 1/8 (12.50%) |
| attack | gpt-4.1-mini | stage2 | attack_s4pt03_gpt41 | 0/27 (0.00%) | 0/0 (n/a) | 0/9 (0.00%) | 0/9 (0.00%) | 0/8 (0.00%) |
| attack | gpt-4.1-mini | stage3 | attack_s4pt03_gpt41 | 3/27 (11.11%) | 3/15 (20.00%) | 1/9 (11.11%) | 0/9 (0.00%) | 0/8 (0.00%) |
| normal | gpt-5.4-mini | stage1 | normal_chain02_gpt54 | 4/9 (44.44%) | 4/6 (66.67%) | 1/3 (33.33%) | 0/3 (0.00%) | 1/2 (50.00%) |
| normal | gpt-5.4-mini | stage2 | normal_chain02_gpt54 | 0/9 (0.00%) | 0/9 (0.00%) | 0/3 (0.00%) | 0/3 (0.00%) | 0/2 (0.00%) |
| normal | gpt-5.4-mini | stage3 | normal_chain02_gpt54 | 0/9 (0.00%) | 0/12 (0.00%) | 0/3 (0.00%) | 0/3 (0.00%) | 0/2 (0.00%) |
| attack | gpt-5.4-mini | stage1 | attack_s3pt01_gpt54 | 4/6 (66.67%) | 4/6 (66.67%) | 1/2 (50.00%) | 0/2 (0.00%) | 1/1 (100.00%) |
| attack | gpt-5.4-mini | stage2 | attack_s3pt01_gpt54 | 4/6 (66.67%) | 4/9 (44.44%) | 1/2 (50.00%) | 0/2 (0.00%) | 1/1 (100.00%) |
| attack | gpt-5.4-mini | stage3 | attack_s3pt01_gpt54 | 4/6 (66.67%) | 4/15 (26.67%) | 1/2 (50.00%) | 0/2 (0.00%) | 1/1 (100.00%) |

## 未取得・精度低下の原因

### gpt-4.1-mini / stage1 / normal_chain10_gpt41

対象のDiscord.exe→reg.exe生成とreg.exe→Run値書込みを候補stepとして表現できず、近傍のDiscord関連処理を6件接続した。固定18 slotはすべて非TP。

```json
{
  "causal_edge_missing": [
    "Discord.exe -> reg.exe create-process edge",
    "reg.exe -> Run\\Discord registry-value write edge"
  ],
  "early_stop": false,
  "hallucination": [
    "fabricated E12345-E12362 evidence identifiers",
    "unsupported process instances and nearby registry/file actions"
  ],
  "investigation_behavior": "Five Chief leads were issued and one lead hit the 20-question guard; broad nearby-process exploration did not resolve the two target atomic actions.",
  "missing_gold_steps": [
    "N8V3-06-S01",
    "N8V3-06-S02"
  ],
  "nearby_behavior_overconnection": true,
  "stage_specific_cause": "Stage 1 output focused on nearby Discord housekeeping and a later reg.exe instance rather than the two-step target component."
}
```

### gpt-4.1-mini / stage2 / normal_chain10_gpt41

Run\Discordへの書込みは1候補claimでsubject/operation/objectを取得した。一方、Discord.exe→reg.exe生成はexecution_contextに留まり独立stepにならず、critical evidenceの識別子は裏付けられない。

```json
{
  "causal_edge_missing": [
    "Discord.exe -> reg.exe create-process edge was present only as execution_context, not as a scored candidate claim"
  ],
  "early_stop": false,
  "hallucination": [
    "fabricated PID 1234/5678 and event_record_id 10001/10002"
  ],
  "investigation_behavior": "Seven distinct Chief leads covered parent, child, file, registry, and process-start checks without hitting the lead guard.",
  "missing_gold_steps": [
    "N8V3-06-S01"
  ],
  "nearby_behavior_overconnection": false,
  "stage_specific_cause": "The Run-key write was reconstructed, but the output schema flattened the parent process into execution_context and therefore omitted the first atomic behavior step."
}
```

### gpt-4.1-mini / stage3 / normal_chain10_gpt41

2 Gold stepのsubject/operation/objectは取得したが、出力順が逆転しorderは未取得。critical evidenceは原行ではなく生成された値で、近傍のupdate/setup/firefox chainを追加してprecisionを下げた。

```json
{
  "causal_edge_missing": [],
  "early_stop": false,
  "hallucination": [
    "unsupported user path/version, PID values, timestamps, and msft-security evidence provenance"
  ],
  "investigation_behavior": "One Chief lead expanded to 20 Investigator questions and 64 SQL calls before the guard returned an unresolved frontier; it also searched far outside the declared five-minute reference window.",
  "missing_gold_steps": [],
  "nearby_behavior_overconnection": true,
  "order_failure": "The two correct target claims were emitted in reverse order: registry write before process creation.",
  "stage_specific_cause": "The semantic component was recovered, but the legacy Stage 3 TEMP VIEW monkeypatch bypassed shared guards and raised one process-tree tool exception; the completed thought is retained and explicitly confounded rather than rerun."
}
```

既知の技術的交絡:

```json
[
  {
    "defect_id": "legacy_stage3_temp_view_guard_bypass",
    "effect": "Stage3 TEMP VIEW monkeypatch bypassed the shared SQL and process-tree guards during this already-completed thought.",
    "tool_exception_count": 1,
    "scoring_treatment": "included once as observed architecture behavior; reported separately and not silently rerun"
  }
]
```

### gpt-4.1-mini / stage1 / attack_s4pt03_gpt41

svchost→mshta、mshta→PowerShell、PowerShell→PowerShellの一部を表現したが、candidate subjectの配置ずれにより完全stepはPowerShell→PowerShellだけ。ネットワーク3 edgeと後半cmd/payload chainを失い、4候補12 slot中7 slotがTP。

```json
{
  "causal_edge_missing": [
    "mshta network 8080 edge",
    "PowerShell network 8443 edge",
    "PowerShell -> cmd -> payload -> payload downstream chain",
    "payload network 9999 edge"
  ],
  "early_stop": false,
  "hallucination": [
    "fabricated Sysmon event_record_id 123456-123460 and common timestamp 00:56:14",
    "unsupported claim that target network connections were absent"
  ],
  "investigation_behavior": "Eight unique Chief leads generated 55 Investigator questions and 109 SQL queries. One file-centric lead hit 20 questions, while the later payload lead still failed to recover the observed network edge.",
  "missing_gold_steps": [
    "A8V5-07-S02",
    "A8V5-07-S05",
    "A8V5-07-S06",
    "A8V5-07-S07",
    "A8V5-07-S08",
    "A8V5-07-S09"
  ],
  "nearby_behavior_overconnection": true,
  "order_failure": "Only S03 -> S04 was represented by distinct aligned claims in the correct order.",
  "stage_specific_cause": "The investigation spent 260.765 seconds on broad mshta file activity and later payload file-size exploration. It found parts of the process chain but failed to pivot from the observed PowerShell/payload processes to the three network edges and downstream cmd/payload creation edges."
}
```

### gpt-4.1-mini / stage2 / attack_s4pt03_gpt41

1 lead・1質問・1 SQLで終了し、candidate slotは0。時刻完全一致の初回検索が外れ、Investigatorが時間緩和を提案したのにChiefが追跡せず全9 stepを未取得。回数制限ではなく早期停止である。

```json
{
  "causal_edge_missing": [
    "all nine Gold steps"
  ],
  "early_stop": true,
  "hallucination": [],
  "investigation_behavior": "The Chief issued one lead. Its single exact-timestamp SQL query returned no rows; the Investigator explicitly proposed broadening the time condition, but the Chief finalized an empty chain instead of issuing a follow-up lead.",
  "missing_gold_steps": [
    "A8V5-07-S01",
    "A8V5-07-S02",
    "A8V5-07-S03",
    "A8V5-07-S04",
    "A8V5-07-S05",
    "A8V5-07-S06",
    "A8V5-07-S07",
    "A8V5-07-S08",
    "A8V5-07-S09"
  ],
  "nearby_behavior_overconnection": false,
  "order_failure": "No candidate claims were emitted.",
  "stage_specific_cause": "The 00:53:30 anchor preceded the first Gold event at 00:53:39.975. An overly exact first query missed the event, and semantic frontier closure did not convert the explicit request to relax the time condition into another investigate_lead call. No hard call limit fired."
}
```

### gpt-4.1-mini / stage3 / attack_s4pt03_gpt41

最終のpayload.exe→10.193.66.115:9999だけを完全取得した。前段の8 Gold stepは、関連プロセスやファイルを見つけても独立した因果行動として出力できず、15 candidate slot中3 slotのみTP。

```json
{
  "causal_edge_missing": [
    "svchost -> mshta process creation",
    "mshta network 8080 edge",
    "mshta -> PowerShell creation",
    "PowerShell -> PowerShell creation",
    "PowerShell network 8443 edge",
    "PowerShell -> cmd creation",
    "cmd -> payload creation",
    "payload -> payload creation"
  ],
  "early_stop": false,
  "hallucination": [
    "fabricated event_record_id values 123456-567890 and Sysmon provenance",
    "unsupported exact timestamps and Base64 placeholder evidence",
    "supporting file materialization/lifecycle actions promoted to candidate behavior steps"
  ],
  "investigation_behavior": "Sixteen unique Chief leads generated 122 Investigator questions and 208 SQL queries. Four leads hit the 20-question guard. The run continued into unrelated dllhost.exe/wmiprvse.exe and file-size/hash exploration after the central process/network frontier was already visible.",
  "missing_gold_steps": [
    "A8V5-07-S01",
    "A8V5-07-S02",
    "A8V5-07-S03",
    "A8V5-07-S04",
    "A8V5-07-S05",
    "A8V5-07-S06",
    "A8V5-07-S07",
    "A8V5-07-S08"
  ],
  "nearby_behavior_overconnection": true,
  "order_failure": "Only S09 was aligned, so no adjacent Gold order pair could be credited.",
  "stage_specific_cause": "Stage 3 had no alert summary, but primary CBC telemetry remained available. The failure was not lack of evidence: the search found the relevant PowerShell, cmd, payload, and network entities, then flattened process-creation edges into execution_context or supporting file actions and spent most of its 450 model calls on low-value nearby activity."
}
```

### gpt-5.4-mini / stage1 / normal_chain02_gpt54

cmd.exeによるrun_http_server.bat実行は完全取得した。python.exeは対象として出したが、行動を「HTTPサーバを起動」と子プロセス中心に表現したため、cmd.exe→python.exeのprocess-creation actionとsubjectを取得できなかった。explorer.exe→cmd.exeはexecution_contextに留まり独立stepになっていない。

```json
{
  "causal_edge_missing": [
    "explorer.exe -> cmd.exe process creation",
    "cmd.exe -> python.exe process creation as an atomic subject-operation-object claim"
  ],
  "early_stop": false,
  "hallucination": [
    "critical evidence was attributed to msft-security without the canonical CBC row/action identifiers"
  ],
  "investigation_behavior": "Four unique Chief leads generated nine Investigator questions and 30 SQL queries with no guard trigger. The process lineage and command lines were found; one malformed truncated lead (`C:\\`) was also issued, but the search otherwise stayed near the target component.",
  "missing_gold_steps": [
    "N8V3-01-S01",
    "N8V3-01-S03"
  ],
  "nearby_behavior_overconnection": false,
  "order_failure": "S02 -> S03 was represented by distinct aligned claims in order; S01 was never emitted as a candidate claim.",
  "stage_specific_cause": "The missing recall came from output granularity rather than missing telemetry or a call limit. Parent/child edges were stored in execution_context while the code_steps described the child process or application behavior, so the atomic parent process-creation actions were not scoreable."
}
```

### gpt-5.4-mini / stage2 / normal_chain02_gpt54

対象のpython SimpleHTTPServer chainではなく、38秒前のstart_dns_logs.bat→tshark.exe→dumpcap.exe chainを再構成した。3 candidate claim・9 slotはすべて別プロセス系列でありTPなし。

```json
{
  "causal_edge_missing": [
    "explorer.exe -> target cmd.exe PID 336 process creation",
    "target cmd.exe -> run_http_server.bat execution",
    "target cmd.exe -> python.exe PID 720 process creation"
  ],
  "early_stop": false,
  "hallucination": [],
  "investigation_behavior": "Four unique Chief leads generated nine Investigator questions and 47 SQL queries. Eight unsafe or over-scale SQL attempts were aborted by the SQL guard and the model recovered with safer queries. No lead-expansion guard fired.",
  "missing_gold_steps": [
    "N8V3-01-S01",
    "N8V3-01-S02",
    "N8V3-01-S03"
  ],
  "nearby_behavior_overconnection": true,
  "order_failure": "All emitted candidate claims belonged to the neighboring DNS packet-capture chain, so no target order pair was represented.",
  "stage_specific_cause": "The Stage 2 input had the correct target timestamp 13:13:39, but the first broad process search selected cmd.exe PID 3344 at 13:13:01 and followed its start_dns_logs.bat/tshark/dumpcap frontier. Process-instance disambiguation failed before the first pivot; this was model search selection error rather than an experiment call limit."
}
```

### gpt-5.4-mini / stage3 / normal_chain02_gpt54

Stage 2と同じく、対象のpython SimpleHTTPServer chainではなく、13:13:01のstart_dns_logs.bat→tshark.exe→dumpcap.exe chainを出力した。4 claim・12 candidate slotはすべて対象外。

```json
{
  "causal_edge_missing": [
    "explorer.exe -> target cmd.exe PID 336 process creation",
    "target cmd.exe -> run_http_server.bat execution",
    "target cmd.exe -> python.exe PID 720 process creation"
  ],
  "early_stop": false,
  "hallucination": [],
  "investigation_behavior": "Five unique Chief leads generated 16 Investigator questions and 76 SQL queries. One unsafe SQL attempt was aborted and nine SQL syntax/schema errors were recovered from. No lead-expansion guard fired.",
  "missing_gold_steps": [
    "N8V3-01-S01",
    "N8V3-01-S02",
    "N8V3-01-S03"
  ],
  "nearby_behavior_overconnection": true,
  "order_failure": "All four candidate claims were from the neighboring DNS-capture chain; no target adjacent order pair was represented.",
  "stage_specific_cause": "The Stage 3 physical filter correctly removed all 232 CBC alert-summary rows while preserving 1,010,918 CBC event rows and shared guards. Despite sufficient primary telemetry, the model again selected cmd.exe PID 3344 at 13:13:01 instead of the target instance at 13:13:39. More search increased detail on the wrong chain rather than correcting the initial process-instance pivot."
}
```

### gpt-5.4-mini / stage1 / attack_s3pt01_gpt54

WINWORD.EXE→WINWORD.EXEの子プロセス起動は完全取得した。文書を開くstepは対象WINWORD.EXEを取得したが、operationを「起動」、objectを親explorer.exeとして出したため、msf.rtfを開いた行動のoperation/objectが欠落した。

```json
{
  "causal_edge_missing": [
    "WINWORD.EXE -> msf.rtf document-open action as a complete atomic claim"
  ],
  "early_stop": false,
  "hallucination": [
    "evidence identifiers 9807/4163 and source attribution did not match the canonical CBC row 8705/8727 signatures"
  ],
  "investigation_behavior": "Three unique Chief leads generated eight Investigator questions and 26 SQL queries. No guard fired, and exploration stayed on the target WINWORD process family.",
  "missing_gold_steps": [
    "A8V5-01-S01"
  ],
  "nearby_behavior_overconnection": false,
  "order_failure": "The partial document-open claim and complete child-process claim were emitted in the correct order, so the adjacent order pair was credited.",
  "stage_specific_cause": "The necessary command line and document path were observed, but output field binding chose explorer.exe as the object and labeled the operation as process startup. This is candidate construction/granularity error, not missing evidence or premature stopping."
}
```

### gpt-5.4-mini / stage2 / attack_s3pt01_gpt54

WINWORD.EXEが別のWINWORD.EXEを起動したstepは完全取得した。文書オープンstepは対象WINWORD.EXEとmsf.rtfのパスを証拠中で確認できていたが、候補では汎用的なプロセス起動として構成され、operationとobjectがGoldに対応しなかった。追加の一時ファイル作成候補はGold外でありprecisionを下げた。

```json
{
  "causal_edge_missing": [
    "WINWORD.EXE -> msf.rtf document-open action as a complete atomic claim"
  ],
  "early_stop": false,
  "hallucination": [
    "Sysmon-style event identifier 4162 did not match the canonical CBC row 8705/8727 evidence identifiers"
  ],
  "investigation_behavior": "Three unique Chief leads generated 12 Investigator questions and 43 SQL queries. No question, SQL, or wall-time guard fired.",
  "missing_gold_steps": [
    "A8V5-01-S01"
  ],
  "nearby_behavior_overconnection": true,
  "order_failure": "The partial document-open claim and complete child-process claim were emitted in the correct order, so the adjacent order pair was credited.",
  "stage_specific_cause": "The document path was present in the observed command line, but candidate construction bound the action to generic process startup and the object to WINWORD.EXE rather than the opened msf.rtf. The extra Office temporary-file lifecycle claim was evidence-backed but outside the fixed Gold chain."
}
```

### gpt-5.4-mini / stage3 / attack_s3pt01_gpt54

WINWORD.EXEからWINWORD.EXE /Embeddingへの子プロセス起動は完全取得した。msf.rtfのパスと親WINWORD.EXEは証拠中に存在したが、候補C1は文書オープンではなくWINWORD.EXEのprocess createとして構成されたため、Gold文書オープンstepはsubjectのみ一致した。後続の一時ファイル作成2件とmodule loadは観測事実だが固定Gold外で、candidate precisionを下げた。

```json
{
  "causal_edge_missing": [
    "WINWORD.EXE -> msf.rtf document-open action as a complete atomic claim"
  ],
  "early_stop": false,
  "hallucination": [],
  "investigation_behavior": "Three unique Chief leads generated eight unique Investigator questions and 37 unique SQL queries. No lead guard fired. Three SQL errors and three truncated-result outcomes were recovered without terminating the run.",
  "missing_gold_steps": [
    "A8V5-01-S01"
  ],
  "nearby_behavior_overconnection": true,
  "order_failure": "C1 and C2 were emitted in the correct order, so the adjacent S01-to-S02 order pair was credited despite C1 being only partially aligned.",
  "stage_specific_cause": "The model retrieved the target msf.rtf command-line context and the WINWORD parent-child edge, but candidate construction typed the first atomic action as process creation with WINWORD.EXE as the object. It then promoted evidence-backed Office temporary-file and module-load activity into three additional Gold-external claims, reducing precision without improving Gold coverage."
}
```

## 解釈上の制約

- モデルごとに割り当てた正常・攻撃ケースが異なるため、モデル集計は記述統計であり、同一ケースでの厳密な優劣比較ではない。
- `gpt-4.1-mini`の正常Stage 3は、修正前TEMP VIEW wrapperの共通ガード迂回を含む完了済み思考である。再実行せず、技術的交絡として明示した。
- PIDおよびhidden alert mappingは非採点であり、critical evidenceとorderはactionとは別に評価した。

## 機械可読成果物

- `docs\current_experiment\normal_attack_full_ledger_pilot05_formal_results_20260730.json`
- `docs\current_experiment\results_2026-07-30\normal_attack_full_ledger_pilot_05\analysis_codex_single_review_v1\operational_ledger_v1.json`
- `docs\current_experiment\results_2026-07-30\normal_attack_full_ledger_pilot_05\analysis_codex_single_review_v1\formal_accuracy_aggregate_v1.json`
- `docs\current_experiment\results_2026-07-30\normal_attack_full_ledger_pilot_05\analysis_codex_single_review_v1\formal_accuracy_audit_v1.json`
