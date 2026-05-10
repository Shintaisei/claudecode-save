# LOF top10 micro-chunk 生ログレビュー

更新日: 2026-05-10

## 1. 前提

- 対象は `docs\thirdpass_top10chunk_micro10_2026-05-10\results.json` の `lof top10 micro-chunk`
- 各 micro-chunk は `10 event` 単位
- したがって今回の実観察対象は `計 100 event`
- 目的は、実務者が実際に見るログの粒度と中身をそのまま確認すること

## 2. micro-chunk 一覧

| micro rank | micro-chunk | attack / normal | 主なプロセス |
| --- | --- | ---: | --- |
| `1` | `chunk330 micro05` | `1 / 9` | `payload.exe, tpautoconnect.exe, csrss.exe` |
| `2` | `chunk325 micro02` | `0 / 10` | `tpautoconnect.exe, payload.exe, csrss.exe` |
| `3` | `chunk325 micro05` | `3 / 7` | `payload.exe, tpautoconnect.exe` |
| `4` | `chunk325 micro07` | `3 / 7` | `payload.exe, tpautoconnect.exe` |
| `5` | `chunk324 micro07` | `3 / 7` | `payload.exe, tpautoconnect.exe` |
| `6` | `chunk204 micro02` | `0 / 10` | `tpautoconnect.exe, repmgr.exe` |
| `7` | `chunk244 micro08` | `0 / 10` | `tpautoconnect.exe, explorer.exe` |
| `8` | `chunk325 micro08` | `1 / 9` | `tpautoconnect.exe, payload.exe` |
| `9` | `chunk203 micro05` | `0 / 10` | `tpautoconnect.exe, repmgr.exe` |
| `10` | `chunk203 micro07` | `0 / 10` | `tpautoconnect.exe, winword.exe` |

## 3. event 一覧

### micro rank 1: `chunk330 micro05`

- attack / normal: `1 / 9`
- 主なプロセス: `payload.exe, tpautoconnect.exe, csrss.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `csrss.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=csrss.exe` |
| `2` | `0` | `4658` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=payload.exe` |
| `3` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `6` | `0` | `4656` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=payload.exe \| ObjectType=file` |
| `7` | `1` | `4663` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=payload.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=payload.exe` |
| `9` | `0` | `4656` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=payload.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=payload.exe \| ObjectType=file` |

### micro rank 2: `chunk325 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe, payload.exe, csrss.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=payload.exe` |
| `2` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4656` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=payload.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=payload.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `7` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `10` | `0` | `4656` | `csrss.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=csrss.exe \| ObjectType=file` |

### micro rank 3: `chunk325 micro05`

- attack / normal: `3 / 7`
- 主なプロセス: `payload.exe, tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=payload.exe \| ObjectType=file` |
| `2` | `1` | `4663` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=payload.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=payload.exe` |
| `4` | `0` | `4656` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=payload.exe \| ObjectType=file` |
| `5` | `1` | `4663` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=payload.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=payload.exe` |
| `7` | `0` | `4656` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=payload.exe \| ObjectType=file` |
| `8` | `1` | `4663` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=payload.exe \| ObjectType=file` |
| `9` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 4: `chunk325 micro07`

- attack / normal: `3 / 7`
- 主なプロセス: `payload.exe, tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=payload.exe` |
| `2` | `0` | `4656` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=payload.exe \| ObjectType=file` |
| `3` | `1` | `4663` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=payload.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=payload.exe` |
| `5` | `0` | `4656` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=payload.exe \| ObjectType=file` |
| `6` | `1` | `4663` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=payload.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=payload.exe` |
| `8` | `0` | `4656` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=payload.exe \| ObjectType=file` |
| `9` | `1` | `4663` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=payload.exe \| ObjectType=file` |
| `10` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 5: `chunk324 micro07`

- attack / normal: `3 / 7`
- 主なプロセス: `payload.exe, tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=payload.exe \| ObjectType=file` |
| `2` | `1` | `4663` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=payload.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=payload.exe` |
| `4` | `0` | `4656` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=payload.exe \| ObjectType=file` |
| `5` | `1` | `4663` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=payload.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=payload.exe` |
| `7` | `0` | `4656` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=payload.exe \| ObjectType=file` |
| `8` | `1` | `4663` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=payload.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=payload.exe` |
| `10` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 6: `chunk204 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe, repmgr.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `3` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `6` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `7` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |
| `10` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 7: `chunk244 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe, explorer.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `2` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `5` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `8` | `0` | `4656` | `explorer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=explorer.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `explorer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=explorer.exe \| ObjectType=file` |
| `10` | `0` | `4656` | `explorer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=explorer.exe \| ObjectType=file` |

### micro rank 8: `chunk325 micro08`

- attack / normal: `1 / 9`
- 主なプロセス: `tpautoconnect.exe, payload.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `3` | `0` | `4658` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=payload.exe` |
| `4` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `7` | `0` | `4656` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=payload.exe \| ObjectType=file` |
| `8` | `1` | `4663` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=payload.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=payload.exe` |
| `10` | `0` | `4656` | `payload.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=payload.exe \| ObjectType=file` |

### micro rank 9: `chunk203 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe, repmgr.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `4` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `7` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `10` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |

### micro rank 10: `chunk203 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe, winword.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `winword.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=winword.exe` |
| `2` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `5` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `8` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
