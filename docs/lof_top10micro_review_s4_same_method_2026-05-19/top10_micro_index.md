# LOF top10 micro-chunk 生ログレビュー

更新日: 2026-05-19

## 1. 前提

- 対象は `docs_active\thirdpass_s4_topwindows_micro10_same_method_2026-05-19\results.json` の `lof top10 micro-chunk`
- 各 micro-chunk は `10 event` 単位
- したがって今回の実観察対象は `計 100 event`
- 目的は、実務者が実際に見るログの粒度と中身をそのまま確認すること

## 2. micro-chunk 一覧

| micro rank | micro-chunk | attack / normal | 主なプロセス |
| --- | --- | ---: | --- |
| `1` | `chunk199 micro00` | `0 / 10` | `wmiprvse.exe` |
| `2` | `chunk180 micro00` | `0 / 10` | `upd.exe` |
| `3` | `chunk180 micro01` | `0 / 10` | `upd.exe` |
| `4` | `chunk180 micro02` | `0 / 10` | `upd.exe` |
| `5` | `chunk180 micro05` | `0 / 10` | `scanhost.exe` |
| `6` | `chunk180 micro06` | `0 / 10` | `scanhost.exe` |
| `7` | `chunk180 micro07` | `0 / 10` | `scanhost.exe` |
| `8` | `chunk180 micro08` | `0 / 10` | `scanhost.exe` |
| `9` | `chunk181 micro00` | `0 / 10` | `scanhost.exe` |
| `10` | `chunk181 micro01` | `0 / 10` | `scanhost.exe` |

## 3. event 一覧

### micro rank 1: `chunk199 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `wmiprvse.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=wmiprvse.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=wmiprvse.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=wmiprvse.exe` |
| `4` | `0` | `4656` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=wmiprvse.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=wmiprvse.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=wmiprvse.exe` |
| `7` | `0` | `4656` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=wmiprvse.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=wmiprvse.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=wmiprvse.exe` |
| `10` | `0` | `4656` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=wmiprvse.exe \| ObjectType=file` |

### micro rank 2: `chunk180 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `upd.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `upd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=upd.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `upd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=upd.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `upd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=upd.exe \| ObjectType=file` |
| `4` | `0` | `4660` | `upd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=upd.exe` |
| `5` | `0` | `4658` | `upd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=upd.exe` |
| `6` | `0` | `4658` | `upd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=upd.exe` |
| `7` | `0` | `4656` | `upd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=upd.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `upd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=upd.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `upd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=upd.exe \| ObjectType=file` |
| `10` | `0` | `4660` | `upd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=upd.exe` |

### micro rank 3: `chunk180 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `upd.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `upd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=upd.exe` |
| `2` | `0` | `4656` | `upd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=upd.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `upd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=upd.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `upd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=upd.exe` |
| `5` | `0` | `4656` | `upd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=upd.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `upd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=upd.exe \| ObjectType=file` |
| `7` | `0` | `4656` | `upd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=upd.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `upd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=upd.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `upd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=upd.exe \| ObjectType=file` |
| `10` | `0` | `4660` | `upd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=upd.exe` |

### micro rank 4: `chunk180 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `upd.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `upd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=upd.exe` |
| `2` | `0` | `4658` | `upd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=upd.exe` |
| `3` | `0` | `4656` | `upd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=upd.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `upd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=upd.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `upd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=upd.exe \| ObjectType=file` |
| `6` | `0` | `4660` | `upd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=upd.exe` |
| `7` | `0` | `4658` | `upd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=upd.exe` |
| `8` | `0` | `4658` | `upd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=upd.exe` |
| `9` | `0` | `4689` | `upd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4689 \| ProcessName=upd.exe` |
| `10` | `0` | `4658` | `upd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=upd.exe` |

### micro rank 5: `chunk180 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `scanhost.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=scanhost.exe` |
| `3` | `0` | `4656` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=scanhost.exe` |
| `6` | `0` | `4656` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=scanhost.exe` |
| `9` | `0` | `4656` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `10` | `0` | `4656` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=scanhost.exe \| ObjectType=file` |

### micro rank 6: `chunk180 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `scanhost.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=scanhost.exe` |
| `3` | `0` | `4656` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=scanhost.exe` |
| `6` | `0` | `4656` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=scanhost.exe` |
| `9` | `0` | `4656` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=scanhost.exe \| ObjectType=file` |

### micro rank 7: `chunk180 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `scanhost.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=scanhost.exe` |
| `2` | `0` | `4663` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `3` | `0` | `4656` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=scanhost.exe` |
| `6` | `0` | `4656` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=scanhost.exe` |
| `9` | `0` | `4656` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=scanhost.exe \| ObjectType=file` |

### micro rank 8: `chunk180 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `scanhost.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=scanhost.exe` |
| `2` | `0` | `4656` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=scanhost.exe` |
| `5` | `0` | `4656` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=scanhost.exe` |
| `8` | `0` | `4656` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=scanhost.exe` |

### micro rank 9: `chunk181 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `scanhost.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=scanhost.exe` |
| `3` | `0` | `4656` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=scanhost.exe` |
| `6` | `0` | `4656` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=scanhost.exe` |
| `9` | `0` | `4656` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=scanhost.exe \| ObjectType=file` |

### micro rank 10: `chunk181 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `scanhost.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=scanhost.exe` |
| `2` | `0` | `4656` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=scanhost.exe` |
| `5` | `0` | `4656` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=scanhost.exe` |
| `8` | `0` | `4656` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=scanhost.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `scanhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=scanhost.exe` |
