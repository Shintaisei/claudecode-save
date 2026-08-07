# LOF top10 micro-chunk の非 payload / 非 tpautoconnect プロセス分析

更新日: 2026-05-10

## 1. 前提

- 対象は `docs_active\lof_background_ranks74_100_review_2026-05-10\top10_micro_raw_events.json`
- 母集団は `LOF top10 micro-chunk = 100 event`
- `payload.exe` と `tpautoconnect.exe` を除いた残りのプロセスだけを見る
- 今回ここで出てくるプロセスが、そのままユースケース候補の母集団になる

## 2. 全体像

- 残ったプロセス種別数: `18`
- 残った event 数: `2614`
- 出てきたプロセスは `repmgr.exe`, `explorer.exe`, `winword.exe`, `csrss.exe` の4種だけ
- このうちユースケース対象として自然なのは `repmgr.exe`, `explorer.exe`, `winword.exe`
- `csrss.exe` は system-side noise とみなすのが自然

## 3. プロセス別集計

| process | event数 | 出現micro数 | 出現rank | attack label数 | normal label数 | ユースケース対象 | 見え方 |
| --- | ---: | ---: | --- | ---: | ---: | --- | --- |
| `spoolsv.exe` | `986` | `122` | `1, 3, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 147, 148, 152, 153, 154, 155, 156, 157, 158, 159, 160, 163, 166, 168, 169, 170, 174, 175, 181, 183, 184, 185, 186, 187, 188, 189, 190, 191, 193, 194, 195, 196, 197, 198, 201, 202, 214, 215, 216, 217, 218, 220, 221, 223, 224, 225, 226, 227, 228, 231, 232, 235, 237, 238, 240, 241, 242, 243, 244, 250, 256, 265, 266, 267, 268, 269, 270` | `0` | `986` | `maybe` | `needs manual interpretation` |
| `tpautoconnsvc.exe` | `753` | `92` | `2, 49, 50, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 152, 153, 161, 162, 171, 186, 187, 188, 189, 190, 193, 194, 195, 196, 197, 198, 202, 214, 215, 216, 217, 218, 220, 221, 223, 224, 225, 240, 241, 242, 243, 244, 245, 259` | `0` | `753` | `maybe` | `needs manual interpretation` |
| `repwmiutils.exe` | `284` | `31` | `7, 8, 9, 10, 11, 12, 13, 18, 19, 20, 21, 22, 23, 24, 25, 27, 28, 29, 30, 31, 32, 33, 34, 35, 146, 246, 252, 257, 258, 261, 264` | `0` | `284` | `maybe` | `needs manual interpretation` |
| `firefox.exe` | `134` | `16` | `164, 172, 182, 203, 206, 207, 208, 209, 210, 211, 212, 213, 230, 234, 248, 255` | `0` | `134` | `yes` | `browser candidate` |
| `repmgr.exe` | `101` | `23` | `155, 156, 157, 159, 172, 173, 176, 181, 192, 199, 204, 219, 222, 229, 235, 246, 249, 252, 253, 254, 257, 258, 261` | `0` | `101` | `yes` | `document-access chain candidate` |
| `vmtoolsd.exe` | `66` | `18` | `157, 164, 177, 178, 182, 205, 231, 232, 235, 239, 247, 248, 249, 250, 255, 258, 260, 264` | `0` | `66` | `maybe` | `needs manual interpretation` |
| `sysmon.exe` | `51` | `15` | `1, 167, 179, 181, 222, 233, 236, 237, 238, 245, 246, 252, 253, 254, 261` | `0` | `51` | `maybe` | `needs manual interpretation` |
| `wmiprvse.exe` | `45` | `7` | `26, 36, 69, 149, 177, 199, 249` | `0` | `45` | `maybe` | `needs manual interpretation` |
| `flashplayerupdateservice.exe` | `41` | `5` | `112, 150, 151, 180, 200` | `0` | `41` | `maybe` | `needs manual interpretation` |
| `searchprotocolhost.exe` | `27` | `4` | `233, 236, 262, 263` | `0` | `27` | `maybe` | `needs manual interpretation` |
| `searchindexer.exe` | `25` | `6` | `167, 176, 179, 233, 259, 260` | `0` | `25` | `maybe` | `needs manual interpretation` |
| `-` | `23` | `13` | `2, 155, 156, 159, 165, 167, 179, 181, 222, 233, 237, 253, 254` | `0` | `23` | `maybe` | `needs manual interpretation` |
| `svchost.exe` | `19` | `6` | `146, 157, 177, 180, 200, 239` | `0` | `19` | `no` | `needs manual interpretation` |
| `csrss.exe` | `16` | `12` | `2, 159, 165, 167, 179, 222, 233, 236, 237, 253, 254, 261` | `0` | `16` | `no` | `system-side noise` |
| `winword.exe` | `15` | `2` | `178, 251` | `0` | `15` | `yes` | `document-viewing candidate` |
| `msiexec.exe` | `13` | `2` | `173, 239` | `0` | `13` | `maybe` | `needs manual interpretation` |
| `services.exe` | `11` | `2` | `165, 259` | `0` | `11` | `maybe` | `needs manual interpretation` |
| `conhost.exe` | `4` | `1` | `200` | `0` | `4` | `maybe` | `needs manual interpretation` |

## 4. micro rank ごとの出現

| micro rank | micro-chunk | 非coreプロセス | event数 | attack / normal |
| --- | --- | --- | ---: | ---: |
| `1` | `chunk003 micro07` | `spoolsv.exe:7, sysmon.exe:3` | `10` | `0 / 10` |
| `2` | `chunk003 micro02` | `tpautoconnsvc.exe:7, csrss.exe:2, -:1` | `10` | `0 / 10` |
| `3` | `chunk028 micro00` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `7` | `chunk101 micro03` | `repwmiutils.exe:10` | `10` | `0 / 10` |
| `8` | `chunk005 micro07` | `repwmiutils.exe:10` | `10` | `0 / 10` |
| `9` | `chunk183 micro03` | `repwmiutils.exe:10` | `10` | `0 / 10` |
| `10` | `chunk101 micro02` | `repwmiutils.exe:10` | `10` | `0 / 10` |
| `11` | `chunk101 micro04` | `repwmiutils.exe:10` | `10` | `0 / 10` |
| `12` | `chunk163 micro04` | `repwmiutils.exe:10` | `10` | `0 / 10` |
| `13` | `chunk163 micro08` | `repwmiutils.exe:10` | `10` | `0 / 10` |
| `18` | `chunk163 micro01` | `repwmiutils.exe:10` | `10` | `0 / 10` |
| `19` | `chunk005 micro04` | `repwmiutils.exe:10` | `10` | `0 / 10` |
| `20` | `chunk005 micro06` | `repwmiutils.exe:10` | `10` | `0 / 10` |
| `21` | `chunk183 micro00` | `repwmiutils.exe:10` | `10` | `0 / 10` |
| `22` | `chunk183 micro02` | `repwmiutils.exe:10` | `10` | `0 / 10` |
| `23` | `chunk101 micro01` | `repwmiutils.exe:10` | `10` | `0 / 10` |
| `24` | `chunk101 micro06` | `repwmiutils.exe:10` | `10` | `0 / 10` |
| `25` | `chunk163 micro03` | `repwmiutils.exe:10` | `10` | `0 / 10` |
| `26` | `chunk160 micro07` | `wmiprvse.exe:10` | `10` | `0 / 10` |
| `27` | `chunk005 micro03` | `repwmiutils.exe:10` | `10` | `0 / 10` |
| `28` | `chunk005 micro05` | `repwmiutils.exe:10` | `10` | `0 / 10` |
| `29` | `chunk005 micro08` | `repwmiutils.exe:10` | `10` | `0 / 10` |
| `30` | `chunk183 micro01` | `repwmiutils.exe:10` | `10` | `0 / 10` |
| `31` | `chunk183 micro04` | `repwmiutils.exe:10` | `10` | `0 / 10` |
| `32` | `chunk101 micro05` | `repwmiutils.exe:10` | `10` | `0 / 10` |
| `33` | `chunk163 micro00` | `repwmiutils.exe:10` | `10` | `0 / 10` |
| `34` | `chunk163 micro02` | `repwmiutils.exe:10` | `10` | `0 / 10` |
| `35` | `chunk163 micro09` | `repwmiutils.exe:10` | `10` | `0 / 10` |
| `36` | `chunk160 micro09` | `wmiprvse.exe:10` | `10` | `0 / 10` |
| `37` | `chunk069 micro03` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `38` | `chunk180 micro02` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `39` | `chunk180 micro08` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `40` | `chunk012 micro01` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `41` | `chunk012 micro07` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `42` | `chunk104 micro03` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `43` | `chunk194 micro00` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `44` | `chunk018 micro00` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `45` | `chunk003 micro00` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `46` | `chunk086 micro02` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `47` | `chunk086 micro08` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `48` | `chunk028 micro02` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `49` | `chunk180 micro07` | `spoolsv.exe:9, tpautoconnsvc.exe:1` | `10` | `0 / 10` |
| `50` | `chunk012 micro06` | `spoolsv.exe:9, tpautoconnsvc.exe:1` | `10` | `0 / 10` |
| `51` | `chunk126 micro02` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `52` | `chunk186 micro04` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `53` | `chunk033 micro03` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `54` | `chunk028 micro08` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `55` | `chunk003 micro08` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `56` | `chunk126 micro01` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `57` | `chunk186 micro03` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `58` | `chunk033 micro02` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `59` | `chunk069 micro09` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `60` | `chunk180 micro00` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `61` | `chunk018 micro06` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `62` | `chunk224 micro02` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `63` | `chunk165 micro02` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `64` | `chunk146 micro01` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `65` | `chunk028 micro01` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `66` | `chunk115 micro05` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `67` | `chunk128 micro05` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `68` | `chunk110 micro02` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `69` | `chunk028 micro09` | `wmiprvse.exe:8, spoolsv.exe:2` | `10` | `0 / 10` |
| `70` | `chunk028 micro07` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `71` | `chunk115 micro00` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `72` | `chunk128 micro00` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `73` | `chunk043 micro01` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `74` | `chunk224 micro08` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `75` | `chunk165 micro08` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `76` | `chunk186 micro00` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `77` | `chunk104 micro00` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `78` | `chunk104 micro09` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `79` | `chunk146 micro07` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `80` | `chunk115 micro01` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `81` | `chunk128 micro01` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `82` | `chunk194 micro06` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `83` | `chunk126 micro08` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `84` | `chunk186 micro01` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `85` | `chunk033 micro00` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `86` | `chunk033 micro09` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `87` | `chunk043 micro00` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `88` | `chunk115 micro03` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `89` | `chunk128 micro03` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `90` | `chunk180 micro04` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `91` | `chunk180 micro05` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `92` | `chunk180 micro06` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `93` | `chunk012 micro03` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `94` | `chunk012 micro04` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `95` | `chunk012 micro05` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `96` | `chunk043 micro07` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `97` | `chunk043 micro08` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `98` | `chunk043 micro09` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `99` | `chunk224 micro04` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `100` | `chunk224 micro05` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `101` | `chunk224 micro06` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `102` | `chunk165 micro04` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `103` | `chunk165 micro05` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `104` | `chunk165 micro06` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `105` | `chunk146 micro03` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `106` | `chunk146 micro04` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `107` | `chunk146 micro05` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `108` | `chunk028 micro03` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `109` | `chunk028 micro04` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `110` | `chunk028 micro05` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `111` | `chunk028 micro06` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `112` | `chunk160 micro03` | `flashplayerupdateservice.exe:10` | `10` | `0 / 10` |
| `113` | `chunk086 micro04` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `114` | `chunk086 micro05` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `115` | `chunk086 micro06` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `116` | `chunk126 micro04` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `117` | `chunk126 micro05` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `118` | `chunk126 micro06` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `119` | `chunk069 micro05` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `120` | `chunk069 micro06` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `121` | `chunk069 micro07` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `122` | `chunk186 micro06` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `123` | `chunk186 micro07` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `124` | `chunk186 micro08` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `125` | `chunk104 micro05` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `126` | `chunk104 micro06` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `127` | `chunk104 micro07` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `128` | `chunk033 micro05` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `129` | `chunk033 micro06` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `130` | `chunk033 micro07` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `131` | `chunk115 micro07` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `132` | `chunk115 micro08` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `133` | `chunk115 micro09` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `134` | `chunk128 micro07` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `135` | `chunk128 micro08` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `136` | `chunk128 micro09` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `137` | `chunk194 micro02` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `138` | `chunk194 micro03` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `139` | `chunk194 micro04` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `140` | `chunk110 micro00` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `141` | `chunk018 micro02` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `142` | `chunk018 micro03` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `143` | `chunk018 micro04` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `144` | `chunk003 micro03` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `145` | `chunk003 micro04` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `146` | `chunk005 micro09` | `repwmiutils.exe:5, svchost.exe:5` | `10` | `0 / 10` |
| `147` | `chunk180 micro01` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `148` | `chunk012 micro00` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `149` | `chunk160 micro08` | `wmiprvse.exe:10` | `10` | `0 / 10` |
| `150` | `chunk160 micro01` | `flashplayerupdateservice.exe:10` | `10` | `0 / 10` |
| `151` | `chunk160 micro02` | `flashplayerupdateservice.exe:10` | `10` | `0 / 10` |
| `152` | `chunk086 micro07` | `spoolsv.exe:7, tpautoconnsvc.exe:3` | `10` | `0 / 10` |
| `153` | `chunk110 micro01` | `spoolsv.exe:8, tpautoconnsvc.exe:2` | `10` | `0 / 10` |
| `154` | `chunk043 micro04` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `155` | `chunk086 micro09` | `spoolsv.exe:5, repmgr.exe:3, -:2` | `10` | `0 / 10` |
| `156` | `chunk146 micro08` | `spoolsv.exe:7, repmgr.exe:2, -:1` | `10` | `0 / 10` |
| `157` | `chunk194 micro08` | `repmgr.exe:5, vmtoolsd.exe:3, spoolsv.exe:1, svchost.exe:1` | `10` | `0 / 10` |
| `158` | `chunk069 micro01` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `159` | `chunk003 micro09` | `repmgr.exe:6, spoolsv.exe:2, -:1, csrss.exe:1` | `10` | `0 / 10` |
| `160` | `chunk104 micro02` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `161` | `chunk101 micro08` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `162` | `chunk101 micro09` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `163` | `chunk194 micro07` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `164` | `chunk226 micro04` | `vmtoolsd.exe:8, firefox.exe:2` | `10` | `0 / 10` |
| `165` | `chunk160 micro00` | `services.exe:8, -:1, csrss.exe:1` | `10` | `0 / 10` |
| `166` | `chunk126 micro09` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `167` | `chunk110 micro05` | `searchindexer.exe:4, sysmon.exe:3, -:2, csrss.exe:1` | `10` | `0 / 10` |
| `168` | `chunk224 micro01` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `169` | `chunk165 micro01` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `170` | `chunk146 micro00` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `171` | `chunk183 micro09` | `tpautoconnsvc.exe:10` | `10` | `0 / 10` |
| `172` | `chunk226 micro06` | `firefox.exe:5, repmgr.exe:5` | `10` | `0 / 10` |
| `173` | `chunk018 micro09` | `msiexec.exe:7, repmgr.exe:3` | `10` | `0 / 10` |
| `174` | `chunk069 micro02` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `175` | `chunk043 micro05` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `176` | `chunk183 micro06` | `repmgr.exe:8, searchindexer.exe:2` | `10` | `0 / 10` |
| `177` | `chunk160 micro06` | `svchost.exe:6, vmtoolsd.exe:3, wmiprvse.exe:1` | `10` | `0 / 10` |
| `178` | `chunk240 micro08` | `vmtoolsd.exe:5, winword.exe:5` | `10` | `0 / 10` |
| `179` | `chunk110 micro04` | `-:3, searchindexer.exe:3, sysmon.exe:3, csrss.exe:1` | `10` | `0 / 10` |
| `180` | `chunk160 micro04` | `flashplayerupdateservice.exe:8, svchost.exe:2` | `10` | `0 / 10` |
| `181` | `chunk180 micro09` | `repmgr.exe:4, spoolsv.exe:3, -:2, sysmon.exe:1` | `10` | `0 / 10` |
| `182` | `chunk240 micro07` | `vmtoolsd.exe:7, firefox.exe:3` | `10` | `0 / 10` |
| `183` | `chunk086 micro01` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `184` | `chunk115 micro04` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `185` | `chunk128 micro04` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `186` | `chunk115 micro06` | `tpautoconnsvc.exe:8, spoolsv.exe:2` | `10` | `0 / 10` |
| `187` | `chunk128 micro06` | `tpautoconnsvc.exe:8, spoolsv.exe:2` | `10` | `0 / 10` |
| `188` | `chunk180 micro03` | `tpautoconnsvc.exe:9, spoolsv.exe:1` | `10` | `0 / 10` |
| `189` | `chunk012 micro02` | `tpautoconnsvc.exe:9, spoolsv.exe:1` | `10` | `0 / 10` |
| `190` | `chunk003 micro01` | `tpautoconnsvc.exe:9, spoolsv.exe:1` | `10` | `0 / 10` |
| `191` | `chunk086 micro00` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `192` | `chunk226 micro09` | `repmgr.exe:10` | `10` | `0 / 10` |
| `193` | `chunk126 micro07` | `tpautoconnsvc.exe:8, spoolsv.exe:2` | `10` | `0 / 10` |
| `194` | `chunk186 micro09` | `tpautoconnsvc.exe:8, spoolsv.exe:2` | `10` | `0 / 10` |
| `195` | `chunk104 micro08` | `tpautoconnsvc.exe:9, spoolsv.exe:1` | `10` | `0 / 10` |
| `196` | `chunk033 micro08` | `tpautoconnsvc.exe:8, spoolsv.exe:2` | `10` | `0 / 10` |
| `197` | `chunk194 micro05` | `tpautoconnsvc.exe:9, spoolsv.exe:1` | `10` | `0 / 10` |
| `198` | `chunk086 micro03` | `tpautoconnsvc.exe:7, spoolsv.exe:3` | `10` | `0 / 10` |
| `199` | `chunk012 micro09` | `repmgr.exe:6, wmiprvse.exe:4` | `10` | `0 / 10` |
| `200` | `chunk160 micro05` | `conhost.exe:4, flashplayerupdateservice.exe:3, svchost.exe:3` | `10` | `0 / 10` |
| `201` | `chunk043 micro02` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `202` | `chunk043 micro06` | `spoolsv.exe:6, tpautoconnsvc.exe:4` | `10` | `0 / 10` |
| `203` | `chunk041 micro01` | `firefox.exe:10` | `10` | `0 / 10` |
| `204` | `chunk226 micro07` | `repmgr.exe:10` | `10` | `0 / 10` |
| `205` | `chunk240 micro04` | `vmtoolsd.exe:3` | `3` | `0 / 10` |
| `206` | `chunk226 micro05` | `firefox.exe:10` | `10` | `0 / 10` |
| `207` | `chunk041 micro03` | `firefox.exe:10` | `10` | `0 / 10` |
| `208` | `chunk041 micro04` | `firefox.exe:10` | `10` | `0 / 10` |
| `209` | `chunk041 micro05` | `firefox.exe:10` | `10` | `0 / 10` |
| `210` | `chunk041 micro06` | `firefox.exe:10` | `10` | `0 / 10` |
| `211` | `chunk041 micro07` | `firefox.exe:10` | `10` | `0 / 10` |
| `212` | `chunk041 micro08` | `firefox.exe:10` | `10` | `0 / 10` |
| `213` | `chunk041 micro09` | `firefox.exe:10` | `10` | `0 / 10` |
| `214` | `chunk224 micro03` | `spoolsv.exe:5, tpautoconnsvc.exe:5` | `10` | `0 / 10` |
| `215` | `chunk165 micro03` | `spoolsv.exe:5, tpautoconnsvc.exe:5` | `10` | `0 / 10` |
| `216` | `chunk146 micro02` | `spoolsv.exe:5, tpautoconnsvc.exe:5` | `10` | `0 / 10` |
| `217` | `chunk069 micro04` | `tpautoconnsvc.exe:6, spoolsv.exe:4` | `10` | `0 / 10` |
| `218` | `chunk018 micro01` | `tpautoconnsvc.exe:6, spoolsv.exe:4` | `10` | `0 / 10` |
| `219` | `chunk194 micro09` | `repmgr.exe:10` | `10` | `0 / 10` |
| `220` | `chunk069 micro08` | `spoolsv.exe:6, tpautoconnsvc.exe:4` | `10` | `0 / 10` |
| `221` | `chunk018 micro05` | `spoolsv.exe:6, tpautoconnsvc.exe:4` | `10` | `0 / 10` |
| `222` | `chunk163 micro06` | `repmgr.exe:3, -:3, sysmon.exe:3, csrss.exe:1` | `10` | `0 / 10` |
| `223` | `chunk224 micro07` | `tpautoconnsvc.exe:5, spoolsv.exe:5` | `10` | `0 / 10` |
| `224` | `chunk165 micro07` | `tpautoconnsvc.exe:5, spoolsv.exe:5` | `10` | `0 / 10` |
| `225` | `chunk146 micro06` | `tpautoconnsvc.exe:5, spoolsv.exe:5` | `10` | `0 / 10` |
| `226` | `chunk224 micro00` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `227` | `chunk165 micro00` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `228` | `chunk069 micro00` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `229` | `chunk226 micro08` | `repmgr.exe:10` | `10` | `0 / 10` |
| `230` | `chunk240 micro05` | `firefox.exe:10` | `10` | `0 / 10` |
| `231` | `chunk224 micro09` | `spoolsv.exe:7, vmtoolsd.exe:3` | `10` | `0 / 10` |
| `232` | `chunk165 micro09` | `spoolsv.exe:7, vmtoolsd.exe:3` | `10` | `0 / 10` |
| `233` | `chunk110 micro06` | `searchindexer.exe:3, sysmon.exe:3, csrss.exe:2, searchprotocolhost.exe:1, -:1` | `10` | `0 / 10` |
| `234` | `chunk041 micro00` | `firefox.exe:10` | `10` | `0 / 10` |
| `235` | `chunk012 micro08` | `repmgr.exe:4, spoolsv.exe:3, vmtoolsd.exe:3` | `10` | `0 / 10` |
| `236` | `chunk110 micro07` | `searchprotocolhost.exe:6, sysmon.exe:3, csrss.exe:1` | `10` | `0 / 10` |
| `237` | `chunk003 micro06` | `csrss.exe:3, spoolsv.exe:3, sysmon.exe:3, -:1` | `10` | `0 / 10` |
| `238` | `chunk110 micro03` | `sysmon.exe:6, spoolsv.exe:4` | `10` | `0 / 10` |
| `239` | `chunk018 micro08` | `msiexec.exe:6, vmtoolsd.exe:2, svchost.exe:2` | `10` | `0 / 10` |
| `240` | `chunk126 micro03` | `spoolsv.exe:8, tpautoconnsvc.exe:2` | `10` | `0 / 10` |
| `241` | `chunk186 micro05` | `spoolsv.exe:8, tpautoconnsvc.exe:2` | `10` | `0 / 10` |
| `242` | `chunk104 micro04` | `spoolsv.exe:9, tpautoconnsvc.exe:1` | `10` | `0 / 10` |
| `243` | `chunk033 micro04` | `spoolsv.exe:8, tpautoconnsvc.exe:2` | `10` | `0 / 10` |
| `244` | `chunk194 micro01` | `spoolsv.exe:9, tpautoconnsvc.exe:1` | `10` | `0 / 10` |
| `245` | `chunk003 micro05` | `sysmon.exe:6, tpautoconnsvc.exe:4` | `10` | `0 / 10` |
| `246` | `chunk005 micro02` | `repwmiutils.exe:7, sysmon.exe:2, repmgr.exe:1` | `10` | `0 / 10` |
| `247` | `chunk226 micro03` | `vmtoolsd.exe:1` | `1` | `0 / 10` |
| `248` | `chunk041 micro02` | `firefox.exe:7, vmtoolsd.exe:3` | `10` | `0 / 10` |
| `249` | `chunk005 micro00` | `vmtoolsd.exe:6, wmiprvse.exe:2, repmgr.exe:2` | `10` | `0 / 10` |
| `250` | `chunk018 micro07` | `spoolsv.exe:6, vmtoolsd.exe:4` | `10` | `0 / 10` |
| `251` | `chunk240 micro09` | `winword.exe:10` | `10` | `0 / 10` |
| `252` | `chunk163 micro07` | `repwmiutils.exe:6, sysmon.exe:3, repmgr.exe:1` | `10` | `0 / 10` |
| `253` | `chunk146 micro09` | `sysmon.exe:5, -:2, repmgr.exe:2, csrss.exe:1` | `10` | `0 / 10` |
| `254` | `chunk005 micro01` | `sysmon.exe:4, -:3, repmgr.exe:2, csrss.exe:1` | `10` | `0 / 10` |
| `255` | `chunk240 micro06` | `firefox.exe:7, vmtoolsd.exe:3` | `10` | `0 / 10` |
| `256` | `chunk043 micro03` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `257` | `chunk163 micro05` | `repwmiutils.exe:9, repmgr.exe:1` | `10` | `0 / 10` |
| `258` | `chunk183 micro05` | `repwmiutils.exe:5, vmtoolsd.exe:3, repmgr.exe:2` | `10` | `0 / 10` |
| `259` | `chunk183 micro08` | `searchindexer.exe:6, services.exe:3, tpautoconnsvc.exe:1` | `10` | `0 / 10` |
| `260` | `chunk183 micro07` | `searchindexer.exe:7, vmtoolsd.exe:3` | `10` | `0 / 10` |
| `261` | `chunk101 micro00` | `repwmiutils.exe:5, sysmon.exe:3, csrss.exe:1, repmgr.exe:1` | `10` | `0 / 10` |
| `262` | `chunk110 micro08` | `searchprotocolhost.exe:10` | `10` | `0 / 10` |
| `263` | `chunk110 micro09` | `searchprotocolhost.exe:10` | `10` | `0 / 10` |
| `264` | `chunk101 micro07` | `repwmiutils.exe:7, vmtoolsd.exe:3` | `10` | `0 / 10` |
| `265` | `chunk115 micro02` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `266` | `chunk128 micro02` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `267` | `chunk126 micro00` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `268` | `chunk186 micro02` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `269` | `chunk104 micro01` | `spoolsv.exe:10` | `10` | `0 / 10` |
| `270` | `chunk033 micro01` | `spoolsv.exe:10` | `10` | `0 / 10` |

## 5. 解釈

- `repmgr.exe`
  文書関連アクセスの中心候補。`rank 6, 9` に出ていて、今回もっとも手続型ユースケースに近い。
- `explorer.exe`
  `rank 7` にまとまって出ており、単発のファイル操作ユースケースとして扱いやすい。
- `winword.exe`
  出現は `rank 10` の1 eventだけだが、文書閲覧起点として意味が明確。
- `csrss.exe`
  `rank 1, 2` に少量出るだけで、今回のユースケース対象にはしない方が自然。

## 6. 今回のユースケース対象

| 優先度 | process | 主な型 | 根拠 |
| --- | --- | --- | --- |
| `高` | `repmgr.exe` | 手続型 | `rank 6, 9` に計5 event 出現し、文書アクセス連鎖として読める |
| `高` | `explorer.exe` | 単発操作型 | `rank 7` に計3 event 出現し、ファイル操作として説明しやすい |
| `中` | `winword.exe` | 単発操作型 | `rank 10` に1 event だが、文書閲覧の意味が明確 |
| `低` | `csrss.exe` | 対象外 | system-side noise であり、関連ログ調達の起点にしにくい |

## 7. まとめ

- 今回の `100 event` で、ユースケース対象として本当に見るべきプロセスは実質 `3種`
- `repmgr.exe` と `explorer.exe` が主対象、`winword.exe` が補助対象
- 研究上は、この `3種` を起点候補として自動化可否を評価するのがちょうどよい