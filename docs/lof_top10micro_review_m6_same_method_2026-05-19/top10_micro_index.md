# LOF top10 micro-chunk 生ログレビュー

更新日: 2026-05-19

## 1. 前提

- 対象は `docs_active\thirdpass_m6_topwindows_micro10_same_method_2026-05-19\results.json` の `lof top10 micro-chunk`
- 各 micro-chunk は `10 event` 単位
- したがって今回の実観察対象は `計 100 event`
- 目的は、実務者が実際に見るログの粒度と中身をそのまま確認すること

## 2. micro-chunk 一覧

| micro rank | micro-chunk | attack / normal | 主なプロセス |
| --- | --- | ---: | --- |
| `1` | `chunk022 micro06` | `0 / 10` | `cmd.exe, tpautoconnect.exe` |
| `2` | `chunk007 micro02` | `0 / 10` | `tshark.exe` |
| `3` | `chunk007 micro05` | `0 / 10` | `tshark.exe` |
| `4` | `chunk007 micro08` | `0 / 10` | `tshark.exe` |
| `5` | `chunk008 micro01` | `0 / 10` | `tshark.exe` |
| `6` | `chunk008 micro07` | `0 / 10` | `tshark.exe` |
| `7` | `chunk009 micro02` | `0 / 10` | `tshark.exe` |
| `8` | `chunk009 micro08` | `0 / 10` | `tshark.exe` |
| `9` | `chunk009 micro09` | `0 / 10` | `tshark.exe` |
| `10` | `chunk013 micro07` | `0 / 10` | `tshark.exe` |

## 3. event 一覧

### micro rank 1: `chunk022 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `cmd.exe, tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `cmd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=cmd.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `cmd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=cmd.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `cmd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=cmd.exe` |
| `4` | `0` | `4656` | `cmd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=cmd.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `cmd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=cmd.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `cmd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=cmd.exe` |
| `7` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `10` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 2: `chunk007 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `tshark.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |
| `2` | `0` | `4656` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tshark.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tshark.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |
| `5` | `0` | `4656` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tshark.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tshark.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |
| `8` | `0` | `4656` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tshark.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tshark.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |

### micro rank 3: `chunk007 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `tshark.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |
| `2` | `0` | `4656` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tshark.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tshark.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |
| `5` | `0` | `4656` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tshark.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tshark.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |
| `8` | `0` | `4656` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tshark.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tshark.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |

### micro rank 4: `chunk007 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `tshark.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |
| `2` | `0` | `4656` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tshark.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tshark.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |
| `5` | `0` | `4656` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tshark.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tshark.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |
| `8` | `0` | `4656` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tshark.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tshark.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |

### micro rank 5: `chunk008 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `tshark.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |
| `2` | `0` | `4656` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tshark.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tshark.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |
| `5` | `0` | `4656` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tshark.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tshark.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |
| `8` | `0` | `4656` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tshark.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tshark.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |

### micro rank 6: `chunk008 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `tshark.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |
| `2` | `0` | `4656` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tshark.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tshark.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |
| `5` | `0` | `4656` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tshark.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tshark.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |
| `8` | `0` | `4656` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tshark.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tshark.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |

### micro rank 7: `chunk009 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `tshark.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |
| `2` | `0` | `4656` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tshark.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tshark.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |
| `5` | `0` | `4656` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tshark.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tshark.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |
| `8` | `0` | `4656` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tshark.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tshark.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |

### micro rank 8: `chunk009 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `tshark.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |
| `2` | `0` | `4656` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tshark.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tshark.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |
| `5` | `0` | `4656` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tshark.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tshark.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |
| `8` | `0` | `4656` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tshark.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tshark.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |

### micro rank 9: `chunk009 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `tshark.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |
| `2` | `0` | `4656` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tshark.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tshark.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |
| `5` | `0` | `4656` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tshark.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tshark.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |
| `8` | `0` | `4656` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tshark.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tshark.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |

### micro rank 10: `chunk013 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `tshark.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |
| `2` | `0` | `4656` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tshark.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tshark.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |
| `5` | `0` | `4656` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tshark.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tshark.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |
| `8` | `0` | `4656` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tshark.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tshark.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `tshark.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tshark.exe` |
