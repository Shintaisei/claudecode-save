# 分析データ整理

このフォルダには、研究ドキュメント作成時に使った中間CSVを置く。

元の apt-persistence データセット本体は `../apt-persistence/` にあり、このフォルダには分析しやすいように抽出・集計したデータだけを置いている。

## フォルダ構成

```text
analysis_data/
├── host_selection/
│   ├── apt_persistence_host_inventory.csv
│   └── apt_persistence_host_scores_top25.csv
│
├── C_Data97/
│   ├── C_Data97_Wazuh_alerts_flat.csv
│   ├── C_Data97_Wazuh_hourly_summary.csv
│   ├── C_Data97_Sysmon_flat.csv
│   ├── C_Data97_Sysmon_hourly_summary.csv
│   └── C_Data97_ProcessCreate_hourly.csv
│
├── C_Data42/
│   ├── C_Data42_Wazuh_alerts_flat.csv
│   ├── C_Data42_Wazuh_hourly_summary.csv
│   ├── C_Data42_Sysmon_flat.csv
│   ├── C_Data42_Sysmon_hourly_summary.csv
│   └── C_Data42_ProcessCreate_hourly.csv
│
├── C_Data45/
│   ├── C_Data45_Wazuh_alerts_flat.csv
│   ├── C_Data45_Wazuh_hourly_summary.csv
│   ├── C_Data45_Sysmon_flat.csv
│   ├── C_Data45_Sysmon_hourly_summary.csv
│   └── C_Data45_ProcessCreate_hourly.csv
│
├── C_Data96/
│   ├── C_Data96_Wazuh_alerts_flat.csv
│   ├── C_Data96_起点アラート分類表.csv
│   ├── C_Data96_Wazuh_hourly_summary.csv
│   ├── C_Data96_Sysmon_flat.csv
│   ├── C_Data96_Sysmon_hourly_summary.csv
│   └── C_Data96_ProcessCreate_hourly.csv
│
└── legacy/
    └── analysis_raw.csv
```

## host_selection

| ファイル | 用途 |
| --- | --- |
| `apt_persistence_host_inventory.csv` | apt-persistence の各ホストについて、EVTX有無・サイズ・Wazuhアラート有無などを整理した一覧 |
| `apt_persistence_host_scores_top25.csv` | ホスト選定のスコア上位25件。C_Data/96 を選ぶ根拠に使用 |
| `apt_persistence_host_daily_behavior_rescore_top25.csv` | 旧上位25件に対して、日常行動らしさとセットアップ偏りを加えて再スコアしたもの |
| `apt_persistence_host_daily_behavior_rescore_user_candidates.csv` | ユーザー系ソフトを含む候補ホストを追加し、日常行動重視で再スコアしたもの |

対応ドキュメント:

- `../docs/03_ホスト選定分析.md`
- `../docs/03b_ホスト再選定_日常行動重視.md`

## C_Data97

| ファイル | 用途 |
| --- | --- |
| `C_Data97_Wazuh_alerts_flat.csv` | C_Data/97 の Wazuh alerts.json を表形式に展開したもの |
| `C_Data97_Wazuh_hourly_summary.csv` | Wazuhアラートを時間帯別に集計したもの |
| `C_Data97_Sysmon_flat.csv` | C_Data/97 の Sysmon.evtx を表形式に展開したもの |
| `C_Data97_Sysmon_hourly_summary.csv` | Sysmonイベントを時間帯別に集計したもの |
| `C_Data97_ProcessCreate_hourly.csv` | Sysmon Event ID 1 のプロセス作成を時間帯別に集計したもの |
| `C_Data97_ProcessCreate_detail.csv` | Sysmon Event ID 1 のプロセス作成詳細 |
| `C_Data97_FileCreate_detail.csv` | Sysmon Event ID 11 のファイル作成詳細 |
| `C_Data97_Registry_detail.csv` | Sysmon Event ID 12/13/14 のレジストリ操作詳細 |
| `C_Data97_ImageLoad_notable.csv` | taskschd.dllやアプリ更新に関係しそうなイメージロード |
| `C_Data97_ProcessAccess_detail.csv` | Sysmon Event ID 10 のプロセスアクセス詳細 |
| `C_Data97_Security_selected_events.csv` | Securityの主要イベントIDだけを抽出したもの |

対応ドキュメント:

- `../docs/03b_ホスト再選定_日常行動重視.md`
- `../docs/04_実験計画.md`
- `../docs/07_C_Data97_42_45_タイムライン比較と偽陽性候補.md`
- `../docs/08_C_Data97_EVTX詳細行動分析.md`

## C_Data42 / C_Data45

| ファイル | 用途 |
| --- | --- |
| `C_Data42_*` | C_Data/42 のWazuh/Sysmon展開CSV。開発者寄り比較ホストの分析に使用 |
| `C_Data45_*` | C_Data/45 のWazuh/Sysmon展開CSV。業務・コミュニケーション寄り補助ホストの分析に使用 |
| `host_selection/C_Data97_42_45_hourly_behavior_alert_overlap.csv` | C_Data/97, 42, 45 の時間帯別プロセス作成とWazuhアラートの重なり |

対応ドキュメント:

- `../docs/07_C_Data97_42_45_タイムライン比較と偽陽性候補.md`

## C_Data96

| ファイル | 用途 |
| --- | --- |
| `C_Data96_Wazuh_alerts_flat.csv` | C_Data/96 の Wazuh alerts.json を表形式に展開したもの |
| `C_Data96_起点アラート分類表.csv` | Wazuhアラートを正常行動候補・起点アラート種別として分類したもの |
| `C_Data96_Wazuh_hourly_summary.csv` | Wazuhアラートを時間帯別に集計したもの |
| `C_Data96_Sysmon_flat.csv` | C_Data/96 の Sysmon.evtx を表形式に展開したもの |
| `C_Data96_Sysmon_hourly_summary.csv` | Sysmonイベントを時間帯別に集計したもの |
| `C_Data96_ProcessCreate_hourly.csv` | Sysmon Event ID 1 のプロセス作成を時間帯別に集計したもの |

対応ドキュメント:

- `../docs/05_C_Data96_ホスト行動タイムライン整理.md`
- `../docs/06_C_Data96_正常行動_起点アラート分類.md`

## legacy

| ファイル | 用途 |
| --- | --- |
| `analysis_raw.csv` | 初期分析時の作業用CSV。現在の主要根拠は `host_selection/` と `C_Data96/` に整理済み |
