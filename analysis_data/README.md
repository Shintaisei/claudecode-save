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

対応ドキュメント:

- `../docs/03_ホスト選定分析.md`

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

