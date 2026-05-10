# LOF top100 生ログレビュー用一覧

更新日: 2026-05-10

## 1. 前提

- 対象は `analysis_data\model_runs\phase4_secondpass_lof_top100inspect_s3_cu10\results.json` の `top100 chunk`
- 各 chunk は `100 event` 単位
- rank 順に、人手観察しやすいように category と代表プロセスを付けた

## 2. 一覧

| rank | chunk | category | attack / normal | 主なプロセス |
| --- | --- | --- | ---: | --- |
| `1` | `chunk330` | `attack-mixed` | `6 / 94` | `payload.exe, tpautoconnect.exe, csrss.exe` |
| `2` | `chunk308` | `attack-mixed` | `3 / 97` | `tpautoconnect.exe, cmd.exe, csrss.exe, payload.exe` |
| `3` | `chunk325` | `attack-mixed` | `14 / 86` | `payload.exe, tpautoconnect.exe, csrss.exe` |
| `4` | `chunk203` | `office-doc` | `0 / 100` | `tpautoconnect.exe, repmgr.exe, winword.exe` |
| `5` | `chunk204` | `office-doc` | `0 / 100` | `tpautoconnect.exe, repmgr.exe, winword.exe` |
| `6` | `chunk244` | `user-file` | `0 / 100` | `tpautoconnect.exe, explorer.exe` |
| `7` | `chunk210` | `office-doc` | `0 / 100` | `tpautoconnect.exe, winword.exe` |
| `8` | `chunk324` | `attack-mixed` | `15 / 85` | `payload.exe, tpautoconnect.exe, -` |
| `9` | `chunk243` | `user-file` | `0 / 100` | `tpautoconnect.exe, explorer.exe` |
| `10` | `chunk741` | `background-vmware` | `0 / 100` | `tpautoconnect.exe, vmtoolsd.exe` |
| `11` | `chunk006` | `background-vmware` | `0 / 100` | `tpautoconnect.exe` |
| `12` | `chunk024` | `background-vmware` | `0 / 100` | `tpautoconnect.exe` |
| `13` | `chunk035` | `background-vmware` | `0 / 100` | `tpautoconnect.exe` |
| `14` | `chunk053` | `background-vmware` | `0 / 100` | `tpautoconnect.exe` |
| `15` | `chunk062` | `background-vmware` | `0 / 100` | `tpautoconnect.exe` |
| `16` | `chunk224` | `background-vmware` | `0 / 100` | `tpautoconnect.exe` |
| `17` | `chunk230` | `background-vmware` | `0 / 100` | `tpautoconnect.exe` |
| `18` | `chunk237` | `background-vmware` | `0 / 100` | `tpautoconnect.exe` |
| `19` | `chunk302` | `background-vmware` | `0 / 100` | `tpautoconnect.exe` |
| `20` | `chunk756` | `background-vmware` | `0 / 100` | `tpautoconnect.exe` |
| `21` | `chunk759` | `background-vmware` | `0 / 100` | `tpautoconnect.exe` |
| `22` | `chunk019` | `background-vmware` | `0 / 100` | `tpautoconnect.exe` |
| `23` | `chunk020` | `background-vmware` | `0 / 100` | `tpautoconnect.exe` |
| `24` | `chunk023` | `background-vmware` | `0 / 100` | `tpautoconnect.exe` |
| `25` | `chunk025` | `background-vmware` | `0 / 100` | `tpautoconnect.exe` |
| `26` | `chunk032` | `background-vmware` | `0 / 100` | `tpautoconnect.exe` |
| `27` | `chunk051` | `background-vmware` | `0 / 100` | `tpautoconnect.exe` |
| `28` | `chunk052` | `background-vmware` | `0 / 100` | `tpautoconnect.exe` |
| `29` | `chunk054` | `background-vmware` | `0 / 100` | `tpautoconnect.exe` |
| `30` | `chunk061` | `background-vmware` | `0 / 100` | `tpautoconnect.exe` |
| `31` | `chunk222` | `background-vmware` | `0 / 100` | `tpautoconnect.exe` |
| `32` | `chunk223` | `background-vmware` | `0 / 100` | `tpautoconnect.exe` |
| `33` | `chunk225` | `background-vmware` | `0 / 100` | `tpautoconnect.exe` |
| `34` | `chunk228` | `background-vmware` | `0 / 100` | `tpautoconnect.exe` |
| `35` | `chunk229` | `background-vmware` | `0 / 100` | `tpautoconnect.exe` |
| `36` | `chunk235` | `background-vmware` | `0 / 100` | `tpautoconnect.exe` |
| `37` | `chunk236` | `background-vmware` | `0 / 100` | `tpautoconnect.exe` |
| `38` | `chunk754` | `background-vmware` | `0 / 100` | `tpautoconnect.exe` |
| `39` | `chunk755` | `background-vmware` | `0 / 100` | `tpautoconnect.exe` |
| `40` | `chunk760` | `background-vmware` | `0 / 100` | `tpautoconnect.exe` |
| `41` | `chunk184` | `ambiguous-system` | `0 / 100` | `tpautoconnect.exe, regsvr32.exe, svchost.exe, csrss.exe` |
| `42` | `chunk761` | `user-file` | `0 / 94` | `tpautoconnect.exe, vmtoolsd.exe, explorer.exe` |
| `43` | `chunk234` | `user-file` | `0 / 100` | `tpautoconnect.exe, vmtoolsd.exe, explorer.exe, taskhost.exe` |
| `44` | `chunk231` | `browser` | `0 / 100` | `tpautoconnect.exe, vmtoolsd.exe, firefox.exe` |
| `45` | `chunk050` | `background-vmware` | `0 / 100` | `tpautoconnect.exe, vmtoolsd.exe` |
| `46` | `chunk742` | `browser` | `0 / 100` | `tpautoconnect.exe, vmtoolsd.exe, firefox.exe` |
| `47` | `chunk005` | `browser` | `0 / 100` | `tpautoconnect.exe, firefox.exe` |
| `48` | `chunk239` | `background-vmware` | `0 / 100` | `tpautoconnect.exe, vmtoolsd.exe` |
| `49` | `chunk758` | `background-vmware` | `0 / 100` | `tpautoconnect.exe, vmtoolsd.exe` |
| `50` | `chunk018` | `background-vmware` | `0 / 100` | `tpautoconnect.exe, vmtoolsd.exe` |
| `51` | `chunk033` | `browser` | `0 / 100` | `tpautoconnect.exe, firefox.exe` |
| `52` | `chunk736` | `browser` | `0 / 100` | `tpautoconnect.exe, firefox.exe, vmtoolsd.exe` |
| `53` | `chunk060` | `browser` | `0 / 100` | `tpautoconnect.exe, firefox.exe` |
| `54` | `chunk221` | `browser` | `0 / 100` | `tpautoconnect.exe, firefox.exe` |
| `55` | `chunk211` | `ambiguous-system` | `0 / 100` | `dllhost.exe, tpautoconnect.exe, svchost.exe, -` |
| `56` | `chunk063` | `browser` | `0 / 100` | `tpautoconnect.exe, firefox.exe, vmtoolsd.exe` |
| `57` | `chunk031` | `browser` | `0 / 100` | `tpautoconnect.exe, firefox.exe` |
| `58` | `chunk034` | `browser` | `0 / 100` | `tpautoconnect.exe, firefox.exe` |
| `59` | `chunk017` | `browser` | `0 / 100` | `tpautoconnect.exe, firefox.exe` |
| `60` | `chunk737` | `office-doc` | `0 / 100` | `tpautoconnect.exe, firefox.exe, vmtoolsd.exe, winword.exe` |
| `61` | `chunk220` | `browser` | `0 / 100` | `tpautoconnect.exe, firefox.exe, vmtoolsd.exe` |
| `62` | `chunk753` | `browser` | `0 / 100` | `tpautoconnect.exe, firefox.exe, vmtoolsd.exe` |
| `63` | `chunk238` | `background-vmware` | `0 / 100` | `tpautoconnect.exe, vmtoolsd.exe` |
| `64` | `chunk757` | `browser` | `0 / 100` | `tpautoconnect.exe, vmtoolsd.exe, firefox.exe` |
| `65` | `chunk026` | `browser` | `0 / 100` | `tpautoconnect.exe, vmtoolsd.exe, firefox.exe` |
| `66` | `chunk055` | `browser` | `0 / 100` | `tpautoconnect.exe, firefox.exe, vmtoolsd.exe` |
| `67` | `chunk326` | `attack-mixed` | `16 / 84` | `payload.exe, tpautoconnect.exe` |
| `68` | `chunk328` | `attack-mixed` | `31 / 69` | `payload.exe, tpautoconnect.exe` |
| `69` | `chunk329` | `attack-mixed` | `24 / 76` | `payload.exe, tpautoconnect.exe` |
| `70` | `chunk357` | `background-vmware` | `0 / 100` | `payload.exe, tpautoconnect.exe` |
| `71` | `chunk359` | `background-vmware` | `0 / 100` | `payload.exe, tpautoconnect.exe` |
| `72` | `chunk233` | `browser` | `0 / 100` | `taskhost.exe, csrss.exe, vmtoolsd.exe, firefox.exe` |
| `73` | `chunk070` | `background-vmware` | `0 / 100` | `spoolsv.exe, tpautoconnsvc.exe, wmiprvse.exe` |
| `74` | `chunk086` | `office-doc` | `0 / 100` | `spoolsv.exe, tpautoconnsvc.exe, repmgr.exe, -` |
| `75` | `chunk224` | `background-vmware` | `0 / 100` | `spoolsv.exe, tpautoconnsvc.exe, vmtoolsd.exe` |
| `76` | `chunk165` | `background-vmware` | `0 / 100` | `spoolsv.exe, tpautoconnsvc.exe, vmtoolsd.exe` |
| `77` | `chunk126` | `background-vmware` | `0 / 100` | `spoolsv.exe, tpautoconnsvc.exe` |
| `78` | `chunk069` | `background-vmware` | `0 / 100` | `spoolsv.exe, tpautoconnsvc.exe` |
| `79` | `chunk180` | `office-doc` | `0 / 100` | `spoolsv.exe, tpautoconnsvc.exe, repmgr.exe, -` |
| `80` | `chunk012` | `office-doc` | `0 / 100` | `spoolsv.exe, tpautoconnsvc.exe, repmgr.exe, wmiprvse.exe` |
| `81` | `chunk186` | `background-vmware` | `0 / 100` | `spoolsv.exe, tpautoconnsvc.exe` |
| `82` | `chunk104` | `background-vmware` | `0 / 100` | `spoolsv.exe, tpautoconnsvc.exe` |
| `83` | `chunk146` | `office-doc` | `0 / 100` | `spoolsv.exe, tpautoconnsvc.exe, sysmon.exe, repmgr.exe` |
| `84` | `chunk033` | `background-vmware` | `0 / 100` | `spoolsv.exe, tpautoconnsvc.exe` |
| `85` | `chunk028` | `background-vmware` | `0 / 100` | `spoolsv.exe, tpautoconnsvc.exe, wmiprvse.exe` |
| `86` | `chunk115` | `background-vmware` | `0 / 100` | `spoolsv.exe, tpautoconnsvc.exe` |
| `87` | `chunk128` | `background-vmware` | `0 / 100` | `spoolsv.exe, tpautoconnsvc.exe` |
| `88` | `chunk194` | `office-doc` | `0 / 100` | `spoolsv.exe, tpautoconnsvc.exe, repmgr.exe, vmtoolsd.exe` |
| `89` | `chunk110` | `background-vmware` | `0 / 100` | `searchprotocolhost.exe, spoolsv.exe, sysmon.exe, tpautoconnsvc.exe` |
| `90` | `chunk041` | `browser` | `0 / 100` | `firefox.exe, vmtoolsd.exe` |
| `91` | `chunk018` | `office-doc` | `0 / 100` | `tpautoconnsvc.exe, spoolsv.exe, msiexec.exe, vmtoolsd.exe` |
| `92` | `chunk043` | `background-vmware` | `0 / 100` | `spoolsv.exe, tpautoconnsvc.exe` |
| `93` | `chunk240` | `office-doc` | `0 / 100` | `tpautoconnect.exe, firefox.exe, vmtoolsd.exe, winword.exe` |
| `94` | `chunk005` | `office-doc` | `0 / 100` | `repwmiutils.exe, vmtoolsd.exe, sysmon.exe, repmgr.exe` |
| `95` | `chunk183` | `office-doc` | `0 / 100` | `repwmiutils.exe, searchindexer.exe, tpautoconnsvc.exe, repmgr.exe` |
| `96` | `chunk003` | `office-doc` | `0 / 100` | `tpautoconnsvc.exe, spoolsv.exe, sysmon.exe, csrss.exe` |
| `97` | `chunk160` | `ambiguous-system` | `0 / 100` | `flashplayerupdateservice.exe, wmiprvse.exe, svchost.exe, services.exe` |
| `98` | `chunk226` | `office-doc` | `0 / 100` | `tpautoconnect.exe, repmgr.exe, firefox.exe, vmtoolsd.exe` |
| `99` | `chunk101` | `ambiguous-system` | `0 / 100` | `repwmiutils.exe, tpautoconnsvc.exe, sysmon.exe, vmtoolsd.exe` |
| `100` | `chunk163` | `office-doc` | `0 / 100` | `repwmiutils.exe, sysmon.exe, repmgr.exe, -` |

## 3. すぐ見たい候補

- 文書操作系: `rank 4, 5, 7`
- ファイル操作系: `rank 6, 9`
- browser 系を追加で見たいなら: `rank 43, 44, 46, 47`
- background noise が増え始める境目: `rank 10` 以降