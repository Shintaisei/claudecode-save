# LOF top60 micro-chunk 生ログレビュー

更新日: 2026-05-10

## 1. 前提

- 対象は `docs_active\thirdpass_browser_ranks42_47_micro10_2026-05-10\results.json` の `lof top60 micro-chunk`
- 各 micro-chunk は `10 event` 単位
- したがって今回の実観察対象は `計 600 event`
- 目的は、実務者が実際に見るログの粒度と中身をそのまま確認すること

## 2. micro-chunk 一覧

| micro rank | micro-chunk | attack / normal | 主なプロセス |
| --- | --- | ---: | --- |
| `1` | `chunk761 micro01` | `0 / 10` | `tpautoconnect.exe` |
| `2` | `chunk761 micro04` | `0 / 10` | `tpautoconnect.exe` |
| `3` | `chunk234 micro03` | `0 / 10` | `tpautoconnect.exe` |
| `4` | `chunk234 micro06` | `0 / 10` | `tpautoconnect.exe` |
| `5` | `chunk234 micro09` | `0 / 10` | `tpautoconnect.exe` |
| `6` | `chunk231 micro02` | `0 / 10` | `tpautoconnect.exe` |
| `7` | `chunk231 micro05` | `0 / 10` | `tpautoconnect.exe` |
| `8` | `chunk050 micro03` | `0 / 10` | `tpautoconnect.exe` |
| `9` | `chunk050 micro06` | `0 / 10` | `tpautoconnect.exe` |
| `10` | `chunk050 micro09` | `0 / 10` | `tpautoconnect.exe` |
| `11` | `chunk742 micro02` | `0 / 10` | `tpautoconnect.exe` |
| `12` | `chunk742 micro05` | `0 / 10` | `tpautoconnect.exe` |
| `13` | `chunk742 micro08` | `0 / 10` | `tpautoconnect.exe` |
| `14` | `chunk005 micro00` | `0 / 10` | `tpautoconnect.exe` |
| `15` | `chunk005 micro04` | `0 / 10` | `tpautoconnect.exe` |
| `16` | `chunk005 micro07` | `0 / 10` | `tpautoconnect.exe` |
| `17` | `chunk761 micro00` | `0 / 10` | `tpautoconnect.exe` |
| `18` | `chunk761 micro03` | `0 / 10` | `tpautoconnect.exe` |
| `19` | `chunk761 micro06` | `0 / 10` | `tpautoconnect.exe` |
| `20` | `chunk234 micro02` | `0 / 10` | `tpautoconnect.exe` |
| `21` | `chunk234 micro05` | `0 / 10` | `tpautoconnect.exe` |
| `22` | `chunk234 micro08` | `0 / 10` | `tpautoconnect.exe` |
| `23` | `chunk231 micro01` | `0 / 10` | `tpautoconnect.exe` |
| `24` | `chunk231 micro04` | `0 / 10` | `tpautoconnect.exe` |
| `25` | `chunk231 micro07` | `0 / 10` | `tpautoconnect.exe` |
| `26` | `chunk050 micro02` | `0 / 10` | `tpautoconnect.exe` |
| `27` | `chunk050 micro05` | `0 / 10` | `tpautoconnect.exe` |
| `28` | `chunk050 micro08` | `0 / 10` | `tpautoconnect.exe` |
| `29` | `chunk742 micro01` | `0 / 10` | `tpautoconnect.exe` |
| `30` | `chunk742 micro04` | `0 / 10` | `tpautoconnect.exe` |
| `31` | `chunk742 micro07` | `0 / 10` | `tpautoconnect.exe` |
| `32` | `chunk005 micro03` | `0 / 10` | `tpautoconnect.exe` |
| `33` | `chunk005 micro06` | `0 / 10` | `tpautoconnect.exe` |
| `34` | `chunk005 micro09` | `0 / 10` | `tpautoconnect.exe` |
| `35` | `chunk761 micro02` | `0 / 10` | `tpautoconnect.exe` |
| `36` | `chunk761 micro05` | `0 / 10` | `tpautoconnect.exe` |
| `37` | `chunk234 micro04` | `0 / 10` | `tpautoconnect.exe` |
| `38` | `chunk234 micro07` | `0 / 10` | `tpautoconnect.exe` |
| `39` | `chunk231 micro00` | `0 / 10` | `tpautoconnect.exe` |
| `40` | `chunk231 micro03` | `0 / 10` | `tpautoconnect.exe` |
| `41` | `chunk231 micro06` | `0 / 10` | `tpautoconnect.exe` |
| `42` | `chunk050 micro01` | `0 / 10` | `tpautoconnect.exe` |
| `43` | `chunk050 micro04` | `0 / 10` | `tpautoconnect.exe` |
| `44` | `chunk742 micro00` | `0 / 10` | `tpautoconnect.exe` |
| `45` | `chunk742 micro03` | `0 / 10` | `tpautoconnect.exe` |
| `46` | `chunk742 micro06` | `0 / 10` | `tpautoconnect.exe` |
| `47` | `chunk005 micro01` | `0 / 10` | `tpautoconnect.exe` |
| `48` | `chunk005 micro05` | `0 / 10` | `tpautoconnect.exe` |
| `49` | `chunk005 micro08` | `0 / 10` | `tpautoconnect.exe` |
| `50` | `chunk231 micro08` | `0 / 10` | `tpautoconnect.exe, vmtoolsd.exe` |
| `51` | `chunk761 micro08` | `0 / 10` | `vmtoolsd.exe, explorer.exe` |
| `52` | `chunk231 micro09` | `0 / 10` | `tpautoconnect.exe, vmtoolsd.exe, firefox.exe` |
| `53` | `chunk234 micro01` | `0 / 10` | `vmtoolsd.exe, firefox.exe` |
| `54` | `chunk742 micro09` | `0 / 10` | `tpautoconnect.exe, vmtoolsd.exe, firefox.exe` |
| `55` | `chunk761 micro07` | `0 / 10` | `tpautoconnect.exe, vmtoolsd.exe` |
| `56` | `chunk761 micro09` | `0 / 4` | `vmtoolsd.exe` |
| `57` | `chunk050 micro07` | `0 / 10` | `tpautoconnect.exe, vmtoolsd.exe` |
| `58` | `chunk234 micro00` | `0 / 10` | `explorer.exe, taskhost.exe, vmtoolsd.exe` |
| `59` | `chunk050 micro00` | `0 / 10` | `tpautoconnect.exe, vmtoolsd.exe` |
| `60` | `chunk005 micro02` | `0 / 10` | `tpautoconnect.exe, firefox.exe` |

## 3. event 一覧

### micro rank 1: `chunk761 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `3` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `6` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `9` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 2: `chunk761 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `3` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `6` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `9` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 3: `chunk234 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `3` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `6` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `9` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 4: `chunk234 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `3` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `6` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `9` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 5: `chunk234 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `3` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `6` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `9` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 6: `chunk231 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `3` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `6` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `9` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 7: `chunk231 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `3` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `6` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `9` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 8: `chunk050 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `3` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `6` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `9` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 9: `chunk050 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `3` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `6` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `9` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 10: `chunk050 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `3` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `6` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `9` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 11: `chunk742 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `3` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `6` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `9` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 12: `chunk742 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `3` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `6` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `9` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 13: `chunk742 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `3` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `6` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `9` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 14: `chunk005 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `3` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `6` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `9` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 15: `chunk005 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `3` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `6` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `9` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 16: `chunk005 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `3` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `6` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `9` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 17: `chunk761 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

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
| `10` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 18: `chunk761 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

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
| `10` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 19: `chunk761 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

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
| `10` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 20: `chunk234 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

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
| `10` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 21: `chunk234 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

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
| `10` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 22: `chunk234 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

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
| `10` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 23: `chunk231 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

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
| `10` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 24: `chunk231 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

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
| `10` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 25: `chunk231 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

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
| `10` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 26: `chunk050 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

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
| `10` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 27: `chunk050 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

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
| `10` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 28: `chunk050 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

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
| `10` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 29: `chunk742 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

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
| `10` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 30: `chunk742 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

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
| `10` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 31: `chunk742 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

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
| `10` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 32: `chunk005 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

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
| `10` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 33: `chunk005 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

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
| `10` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 34: `chunk005 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

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
| `10` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 35: `chunk761 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `2` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `5` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `8` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |

### micro rank 36: `chunk761 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `2` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `5` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `8` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |

### micro rank 37: `chunk234 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `2` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `5` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `8` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |

### micro rank 38: `chunk234 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `2` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `5` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `8` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |

### micro rank 39: `chunk231 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `2` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `5` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `8` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |

### micro rank 40: `chunk231 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `2` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `5` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `8` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |

### micro rank 41: `chunk231 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `2` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `5` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `8` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |

### micro rank 42: `chunk050 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `2` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `5` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `8` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |

### micro rank 43: `chunk050 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `2` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `5` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `8` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |

### micro rank 44: `chunk742 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `2` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `5` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `8` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |

### micro rank 45: `chunk742 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `2` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `5` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `8` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |

### micro rank 46: `chunk742 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `2` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `5` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `8` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |

### micro rank 47: `chunk005 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `2` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `5` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `8` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |

### micro rank 48: `chunk005 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `2` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `5` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `8` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |

### micro rank 49: `chunk005 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `2` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `5` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `8` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |

### micro rank 50: `chunk231 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe, vmtoolsd.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `3` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |
| `6` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `9` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 51: `chunk761 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `vmtoolsd.exe, explorer.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |
| `2` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |
| `5` | `0` | `4656` | `explorer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=explorer.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `explorer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=explorer.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `explorer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=explorer.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `explorer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=explorer.exe` |
| `9` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |

### micro rank 52: `chunk231 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe, vmtoolsd.exe, firefox.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `2` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `5` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `7` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |
| `10` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |

### micro rank 53: `chunk234 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `vmtoolsd.exe, firefox.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |
| `2` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |
| `5` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `8` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |

### micro rank 54: `chunk742 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe, vmtoolsd.exe, firefox.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `2` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `5` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |
| `8` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `10` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |

### micro rank 55: `chunk761 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe, vmtoolsd.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `3` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `6` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |
| `9` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |

### micro rank 56: `chunk761 micro09`

- attack / normal: `0 / 4`
- 主なプロセス: `vmtoolsd.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |
| `2` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |

### micro rank 57: `chunk050 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe, vmtoolsd.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `2` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `5` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `8` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |

### micro rank 58: `chunk234 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `explorer.exe, taskhost.exe, vmtoolsd.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `taskhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=taskhost.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `taskhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=taskhost.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `taskhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=taskhost.exe` |
| `4` | `0` | `4656` | `explorer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=explorer.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `explorer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=explorer.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `explorer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=explorer.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `explorer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=explorer.exe` |
| `8` | `0` | `4658` | `explorer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=explorer.exe` |
| `9` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |

### micro rank 59: `chunk050 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe, vmtoolsd.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |
| `3` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `6` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `9` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |

### micro rank 60: `chunk005 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe, firefox.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
| `4` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `7` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `8` | `0` | `4656` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnect.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `tpautoconnect.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnect.exe` |
