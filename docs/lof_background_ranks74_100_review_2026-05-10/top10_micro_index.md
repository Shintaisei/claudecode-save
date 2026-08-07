# LOF top270 micro-chunk 生ログレビュー

更新日: 2026-05-10

## 1. 前提

- 対象は `docs_active\thirdpass_background_ranks74_100_micro10_2026-05-10\results.json` の `lof top270 micro-chunk`
- 各 micro-chunk は `10 event` 単位
- したがって今回の実観察対象は `計 2700 event`
- 目的は、実務者が実際に見るログの粒度と中身をそのまま確認すること

## 2. micro-chunk 一覧

| micro rank | micro-chunk | attack / normal | 主なプロセス |
| --- | --- | ---: | --- |
| `1` | `chunk003 micro07` | `0 / 10` | `spoolsv.exe, sysmon.exe` |
| `2` | `chunk003 micro02` | `0 / 10` | `tpautoconnsvc.exe, csrss.exe, -` |
| `3` | `chunk028 micro00` | `0 / 10` | `spoolsv.exe` |
| `4` | `chunk240 micro00` | `0 / 10` | `tpautoconnect.exe` |
| `5` | `chunk240 micro03` | `0 / 10` | `tpautoconnect.exe` |
| `6` | `chunk226 micro01` | `0 / 10` | `tpautoconnect.exe` |
| `7` | `chunk101 micro03` | `0 / 10` | `repwmiutils.exe` |
| `8` | `chunk005 micro07` | `0 / 10` | `repwmiutils.exe` |
| `9` | `chunk183 micro03` | `0 / 10` | `repwmiutils.exe` |
| `10` | `chunk101 micro02` | `0 / 10` | `repwmiutils.exe` |
| `11` | `chunk101 micro04` | `0 / 10` | `repwmiutils.exe` |
| `12` | `chunk163 micro04` | `0 / 10` | `repwmiutils.exe` |
| `13` | `chunk163 micro08` | `0 / 10` | `repwmiutils.exe` |
| `14` | `chunk240 micro02` | `0 / 10` | `tpautoconnect.exe` |
| `15` | `chunk226 micro00` | `0 / 10` | `tpautoconnect.exe` |
| `16` | `chunk240 micro01` | `0 / 10` | `tpautoconnect.exe` |
| `17` | `chunk226 micro02` | `0 / 10` | `tpautoconnect.exe` |
| `18` | `chunk163 micro01` | `0 / 10` | `repwmiutils.exe` |
| `19` | `chunk005 micro04` | `0 / 10` | `repwmiutils.exe` |
| `20` | `chunk005 micro06` | `0 / 10` | `repwmiutils.exe` |
| `21` | `chunk183 micro00` | `0 / 10` | `repwmiutils.exe` |
| `22` | `chunk183 micro02` | `0 / 10` | `repwmiutils.exe` |
| `23` | `chunk101 micro01` | `0 / 10` | `repwmiutils.exe` |
| `24` | `chunk101 micro06` | `0 / 10` | `repwmiutils.exe` |
| `25` | `chunk163 micro03` | `0 / 10` | `repwmiutils.exe` |
| `26` | `chunk160 micro07` | `0 / 10` | `wmiprvse.exe` |
| `27` | `chunk005 micro03` | `0 / 10` | `repwmiutils.exe` |
| `28` | `chunk005 micro05` | `0 / 10` | `repwmiutils.exe` |
| `29` | `chunk005 micro08` | `0 / 10` | `repwmiutils.exe` |
| `30` | `chunk183 micro01` | `0 / 10` | `repwmiutils.exe` |
| `31` | `chunk183 micro04` | `0 / 10` | `repwmiutils.exe` |
| `32` | `chunk101 micro05` | `0 / 10` | `repwmiutils.exe` |
| `33` | `chunk163 micro00` | `0 / 10` | `repwmiutils.exe` |
| `34` | `chunk163 micro02` | `0 / 10` | `repwmiutils.exe` |
| `35` | `chunk163 micro09` | `0 / 10` | `repwmiutils.exe` |
| `36` | `chunk160 micro09` | `0 / 10` | `wmiprvse.exe` |
| `37` | `chunk069 micro03` | `0 / 10` | `spoolsv.exe` |
| `38` | `chunk180 micro02` | `0 / 10` | `spoolsv.exe` |
| `39` | `chunk180 micro08` | `0 / 10` | `spoolsv.exe` |
| `40` | `chunk012 micro01` | `0 / 10` | `spoolsv.exe` |
| `41` | `chunk012 micro07` | `0 / 10` | `spoolsv.exe` |
| `42` | `chunk104 micro03` | `0 / 10` | `spoolsv.exe` |
| `43` | `chunk194 micro00` | `0 / 10` | `spoolsv.exe` |
| `44` | `chunk018 micro00` | `0 / 10` | `spoolsv.exe` |
| `45` | `chunk003 micro00` | `0 / 10` | `spoolsv.exe` |
| `46` | `chunk086 micro02` | `0 / 10` | `spoolsv.exe` |
| `47` | `chunk086 micro08` | `0 / 10` | `spoolsv.exe` |
| `48` | `chunk028 micro02` | `0 / 10` | `spoolsv.exe` |
| `49` | `chunk180 micro07` | `0 / 10` | `spoolsv.exe, tpautoconnsvc.exe` |
| `50` | `chunk012 micro06` | `0 / 10` | `spoolsv.exe, tpautoconnsvc.exe` |
| `51` | `chunk126 micro02` | `0 / 10` | `spoolsv.exe` |
| `52` | `chunk186 micro04` | `0 / 10` | `spoolsv.exe` |
| `53` | `chunk033 micro03` | `0 / 10` | `spoolsv.exe` |
| `54` | `chunk028 micro08` | `0 / 10` | `spoolsv.exe` |
| `55` | `chunk003 micro08` | `0 / 10` | `spoolsv.exe` |
| `56` | `chunk126 micro01` | `0 / 10` | `spoolsv.exe` |
| `57` | `chunk186 micro03` | `0 / 10` | `spoolsv.exe` |
| `58` | `chunk033 micro02` | `0 / 10` | `spoolsv.exe` |
| `59` | `chunk069 micro09` | `0 / 10` | `spoolsv.exe` |
| `60` | `chunk180 micro00` | `0 / 10` | `spoolsv.exe` |
| `61` | `chunk018 micro06` | `0 / 10` | `spoolsv.exe` |
| `62` | `chunk224 micro02` | `0 / 10` | `spoolsv.exe` |
| `63` | `chunk165 micro02` | `0 / 10` | `spoolsv.exe` |
| `64` | `chunk146 micro01` | `0 / 10` | `spoolsv.exe` |
| `65` | `chunk028 micro01` | `0 / 10` | `spoolsv.exe` |
| `66` | `chunk115 micro05` | `0 / 10` | `spoolsv.exe` |
| `67` | `chunk128 micro05` | `0 / 10` | `spoolsv.exe` |
| `68` | `chunk110 micro02` | `0 / 10` | `spoolsv.exe` |
| `69` | `chunk028 micro09` | `0 / 10` | `wmiprvse.exe, spoolsv.exe` |
| `70` | `chunk028 micro07` | `0 / 10` | `spoolsv.exe` |
| `71` | `chunk115 micro00` | `0 / 10` | `spoolsv.exe` |
| `72` | `chunk128 micro00` | `0 / 10` | `spoolsv.exe` |
| `73` | `chunk043 micro01` | `0 / 10` | `spoolsv.exe` |
| `74` | `chunk224 micro08` | `0 / 10` | `spoolsv.exe` |
| `75` | `chunk165 micro08` | `0 / 10` | `spoolsv.exe` |
| `76` | `chunk186 micro00` | `0 / 10` | `spoolsv.exe` |
| `77` | `chunk104 micro00` | `0 / 10` | `spoolsv.exe` |
| `78` | `chunk104 micro09` | `0 / 10` | `spoolsv.exe` |
| `79` | `chunk146 micro07` | `0 / 10` | `spoolsv.exe` |
| `80` | `chunk115 micro01` | `0 / 10` | `spoolsv.exe` |
| `81` | `chunk128 micro01` | `0 / 10` | `spoolsv.exe` |
| `82` | `chunk194 micro06` | `0 / 10` | `spoolsv.exe` |
| `83` | `chunk126 micro08` | `0 / 10` | `spoolsv.exe` |
| `84` | `chunk186 micro01` | `0 / 10` | `spoolsv.exe` |
| `85` | `chunk033 micro00` | `0 / 10` | `spoolsv.exe` |
| `86` | `chunk033 micro09` | `0 / 10` | `spoolsv.exe` |
| `87` | `chunk043 micro00` | `0 / 10` | `spoolsv.exe` |
| `88` | `chunk115 micro03` | `0 / 10` | `spoolsv.exe` |
| `89` | `chunk128 micro03` | `0 / 10` | `spoolsv.exe` |
| `90` | `chunk180 micro04` | `0 / 10` | `tpautoconnsvc.exe` |
| `91` | `chunk180 micro05` | `0 / 10` | `tpautoconnsvc.exe` |
| `92` | `chunk180 micro06` | `0 / 10` | `tpautoconnsvc.exe` |
| `93` | `chunk012 micro03` | `0 / 10` | `tpautoconnsvc.exe` |
| `94` | `chunk012 micro04` | `0 / 10` | `tpautoconnsvc.exe` |
| `95` | `chunk012 micro05` | `0 / 10` | `tpautoconnsvc.exe` |
| `96` | `chunk043 micro07` | `0 / 10` | `tpautoconnsvc.exe` |
| `97` | `chunk043 micro08` | `0 / 10` | `tpautoconnsvc.exe` |
| `98` | `chunk043 micro09` | `0 / 10` | `tpautoconnsvc.exe` |
| `99` | `chunk224 micro04` | `0 / 10` | `tpautoconnsvc.exe` |
| `100` | `chunk224 micro05` | `0 / 10` | `tpautoconnsvc.exe` |
| `101` | `chunk224 micro06` | `0 / 10` | `tpautoconnsvc.exe` |
| `102` | `chunk165 micro04` | `0 / 10` | `tpautoconnsvc.exe` |
| `103` | `chunk165 micro05` | `0 / 10` | `tpautoconnsvc.exe` |
| `104` | `chunk165 micro06` | `0 / 10` | `tpautoconnsvc.exe` |
| `105` | `chunk146 micro03` | `0 / 10` | `tpautoconnsvc.exe` |
| `106` | `chunk146 micro04` | `0 / 10` | `tpautoconnsvc.exe` |
| `107` | `chunk146 micro05` | `0 / 10` | `tpautoconnsvc.exe` |
| `108` | `chunk028 micro03` | `0 / 10` | `tpautoconnsvc.exe` |
| `109` | `chunk028 micro04` | `0 / 10` | `tpautoconnsvc.exe` |
| `110` | `chunk028 micro05` | `0 / 10` | `tpautoconnsvc.exe` |
| `111` | `chunk028 micro06` | `0 / 10` | `tpautoconnsvc.exe` |
| `112` | `chunk160 micro03` | `0 / 10` | `flashplayerupdateservice.exe` |
| `113` | `chunk086 micro04` | `0 / 10` | `tpautoconnsvc.exe` |
| `114` | `chunk086 micro05` | `0 / 10` | `tpautoconnsvc.exe` |
| `115` | `chunk086 micro06` | `0 / 10` | `tpautoconnsvc.exe` |
| `116` | `chunk126 micro04` | `0 / 10` | `tpautoconnsvc.exe` |
| `117` | `chunk126 micro05` | `0 / 10` | `tpautoconnsvc.exe` |
| `118` | `chunk126 micro06` | `0 / 10` | `tpautoconnsvc.exe` |
| `119` | `chunk069 micro05` | `0 / 10` | `tpautoconnsvc.exe` |
| `120` | `chunk069 micro06` | `0 / 10` | `tpautoconnsvc.exe` |
| `121` | `chunk069 micro07` | `0 / 10` | `tpautoconnsvc.exe` |
| `122` | `chunk186 micro06` | `0 / 10` | `tpautoconnsvc.exe` |
| `123` | `chunk186 micro07` | `0 / 10` | `tpautoconnsvc.exe` |
| `124` | `chunk186 micro08` | `0 / 10` | `tpautoconnsvc.exe` |
| `125` | `chunk104 micro05` | `0 / 10` | `tpautoconnsvc.exe` |
| `126` | `chunk104 micro06` | `0 / 10` | `tpautoconnsvc.exe` |
| `127` | `chunk104 micro07` | `0 / 10` | `tpautoconnsvc.exe` |
| `128` | `chunk033 micro05` | `0 / 10` | `tpautoconnsvc.exe` |
| `129` | `chunk033 micro06` | `0 / 10` | `tpautoconnsvc.exe` |
| `130` | `chunk033 micro07` | `0 / 10` | `tpautoconnsvc.exe` |
| `131` | `chunk115 micro07` | `0 / 10` | `tpautoconnsvc.exe` |
| `132` | `chunk115 micro08` | `0 / 10` | `tpautoconnsvc.exe` |
| `133` | `chunk115 micro09` | `0 / 10` | `tpautoconnsvc.exe` |
| `134` | `chunk128 micro07` | `0 / 10` | `tpautoconnsvc.exe` |
| `135` | `chunk128 micro08` | `0 / 10` | `tpautoconnsvc.exe` |
| `136` | `chunk128 micro09` | `0 / 10` | `tpautoconnsvc.exe` |
| `137` | `chunk194 micro02` | `0 / 10` | `tpautoconnsvc.exe` |
| `138` | `chunk194 micro03` | `0 / 10` | `tpautoconnsvc.exe` |
| `139` | `chunk194 micro04` | `0 / 10` | `tpautoconnsvc.exe` |
| `140` | `chunk110 micro00` | `0 / 10` | `tpautoconnsvc.exe` |
| `141` | `chunk018 micro02` | `0 / 10` | `tpautoconnsvc.exe` |
| `142` | `chunk018 micro03` | `0 / 10` | `tpautoconnsvc.exe` |
| `143` | `chunk018 micro04` | `0 / 10` | `tpautoconnsvc.exe` |
| `144` | `chunk003 micro03` | `0 / 10` | `tpautoconnsvc.exe` |
| `145` | `chunk003 micro04` | `0 / 10` | `tpautoconnsvc.exe` |
| `146` | `chunk005 micro09` | `0 / 10` | `repwmiutils.exe, svchost.exe` |
| `147` | `chunk180 micro01` | `0 / 10` | `spoolsv.exe` |
| `148` | `chunk012 micro00` | `0 / 10` | `spoolsv.exe` |
| `149` | `chunk160 micro08` | `0 / 10` | `wmiprvse.exe` |
| `150` | `chunk160 micro01` | `0 / 10` | `flashplayerupdateservice.exe` |
| `151` | `chunk160 micro02` | `0 / 10` | `flashplayerupdateservice.exe` |
| `152` | `chunk086 micro07` | `0 / 10` | `spoolsv.exe, tpautoconnsvc.exe` |
| `153` | `chunk110 micro01` | `0 / 10` | `spoolsv.exe, tpautoconnsvc.exe` |
| `154` | `chunk043 micro04` | `0 / 10` | `spoolsv.exe` |
| `155` | `chunk086 micro09` | `0 / 10` | `spoolsv.exe, repmgr.exe, -` |
| `156` | `chunk146 micro08` | `0 / 10` | `spoolsv.exe, repmgr.exe, -` |
| `157` | `chunk194 micro08` | `0 / 10` | `repmgr.exe, vmtoolsd.exe, spoolsv.exe, svchost.exe` |
| `158` | `chunk069 micro01` | `0 / 10` | `spoolsv.exe` |
| `159` | `chunk003 micro09` | `0 / 10` | `repmgr.exe, spoolsv.exe, -, csrss.exe` |
| `160` | `chunk104 micro02` | `0 / 10` | `spoolsv.exe` |
| `161` | `chunk101 micro08` | `0 / 10` | `tpautoconnsvc.exe` |
| `162` | `chunk101 micro09` | `0 / 10` | `tpautoconnsvc.exe` |
| `163` | `chunk194 micro07` | `0 / 10` | `spoolsv.exe` |
| `164` | `chunk226 micro04` | `0 / 10` | `vmtoolsd.exe, firefox.exe` |
| `165` | `chunk160 micro00` | `0 / 10` | `services.exe, -, csrss.exe` |
| `166` | `chunk126 micro09` | `0 / 10` | `spoolsv.exe` |
| `167` | `chunk110 micro05` | `0 / 10` | `searchindexer.exe, sysmon.exe, -, csrss.exe` |
| `168` | `chunk224 micro01` | `0 / 10` | `spoolsv.exe` |
| `169` | `chunk165 micro01` | `0 / 10` | `spoolsv.exe` |
| `170` | `chunk146 micro00` | `0 / 10` | `spoolsv.exe` |
| `171` | `chunk183 micro09` | `0 / 10` | `tpautoconnsvc.exe` |
| `172` | `chunk226 micro06` | `0 / 10` | `firefox.exe, repmgr.exe` |
| `173` | `chunk018 micro09` | `0 / 10` | `msiexec.exe, repmgr.exe` |
| `174` | `chunk069 micro02` | `0 / 10` | `spoolsv.exe` |
| `175` | `chunk043 micro05` | `0 / 10` | `spoolsv.exe` |
| `176` | `chunk183 micro06` | `0 / 10` | `repmgr.exe, searchindexer.exe` |
| `177` | `chunk160 micro06` | `0 / 10` | `svchost.exe, vmtoolsd.exe, wmiprvse.exe` |
| `178` | `chunk240 micro08` | `0 / 10` | `vmtoolsd.exe, winword.exe` |
| `179` | `chunk110 micro04` | `0 / 10` | `-, searchindexer.exe, sysmon.exe, csrss.exe` |
| `180` | `chunk160 micro04` | `0 / 10` | `flashplayerupdateservice.exe, svchost.exe` |
| `181` | `chunk180 micro09` | `0 / 10` | `repmgr.exe, spoolsv.exe, -, sysmon.exe` |
| `182` | `chunk240 micro07` | `0 / 10` | `vmtoolsd.exe, firefox.exe` |
| `183` | `chunk086 micro01` | `0 / 10` | `spoolsv.exe` |
| `184` | `chunk115 micro04` | `0 / 10` | `spoolsv.exe` |
| `185` | `chunk128 micro04` | `0 / 10` | `spoolsv.exe` |
| `186` | `chunk115 micro06` | `0 / 10` | `tpautoconnsvc.exe, spoolsv.exe` |
| `187` | `chunk128 micro06` | `0 / 10` | `tpautoconnsvc.exe, spoolsv.exe` |
| `188` | `chunk180 micro03` | `0 / 10` | `tpautoconnsvc.exe, spoolsv.exe` |
| `189` | `chunk012 micro02` | `0 / 10` | `tpautoconnsvc.exe, spoolsv.exe` |
| `190` | `chunk003 micro01` | `0 / 10` | `tpautoconnsvc.exe, spoolsv.exe` |
| `191` | `chunk086 micro00` | `0 / 10` | `spoolsv.exe` |
| `192` | `chunk226 micro09` | `0 / 10` | `repmgr.exe` |
| `193` | `chunk126 micro07` | `0 / 10` | `tpautoconnsvc.exe, spoolsv.exe` |
| `194` | `chunk186 micro09` | `0 / 10` | `tpautoconnsvc.exe, spoolsv.exe` |
| `195` | `chunk104 micro08` | `0 / 10` | `tpautoconnsvc.exe, spoolsv.exe` |
| `196` | `chunk033 micro08` | `0 / 10` | `tpautoconnsvc.exe, spoolsv.exe` |
| `197` | `chunk194 micro05` | `0 / 10` | `tpautoconnsvc.exe, spoolsv.exe` |
| `198` | `chunk086 micro03` | `0 / 10` | `tpautoconnsvc.exe, spoolsv.exe` |
| `199` | `chunk012 micro09` | `0 / 10` | `repmgr.exe, wmiprvse.exe` |
| `200` | `chunk160 micro05` | `0 / 10` | `conhost.exe, flashplayerupdateservice.exe, svchost.exe` |
| `201` | `chunk043 micro02` | `0 / 10` | `spoolsv.exe` |
| `202` | `chunk043 micro06` | `0 / 10` | `spoolsv.exe, tpautoconnsvc.exe` |
| `203` | `chunk041 micro01` | `0 / 10` | `firefox.exe` |
| `204` | `chunk226 micro07` | `0 / 10` | `repmgr.exe` |
| `205` | `chunk240 micro04` | `0 / 10` | `tpautoconnect.exe, vmtoolsd.exe` |
| `206` | `chunk226 micro05` | `0 / 10` | `firefox.exe` |
| `207` | `chunk041 micro03` | `0 / 10` | `firefox.exe` |
| `208` | `chunk041 micro04` | `0 / 10` | `firefox.exe` |
| `209` | `chunk041 micro05` | `0 / 10` | `firefox.exe` |
| `210` | `chunk041 micro06` | `0 / 10` | `firefox.exe` |
| `211` | `chunk041 micro07` | `0 / 10` | `firefox.exe` |
| `212` | `chunk041 micro08` | `0 / 10` | `firefox.exe` |
| `213` | `chunk041 micro09` | `0 / 10` | `firefox.exe` |
| `214` | `chunk224 micro03` | `0 / 10` | `spoolsv.exe, tpautoconnsvc.exe` |
| `215` | `chunk165 micro03` | `0 / 10` | `spoolsv.exe, tpautoconnsvc.exe` |
| `216` | `chunk146 micro02` | `0 / 10` | `spoolsv.exe, tpautoconnsvc.exe` |
| `217` | `chunk069 micro04` | `0 / 10` | `tpautoconnsvc.exe, spoolsv.exe` |
| `218` | `chunk018 micro01` | `0 / 10` | `tpautoconnsvc.exe, spoolsv.exe` |
| `219` | `chunk194 micro09` | `0 / 10` | `repmgr.exe` |
| `220` | `chunk069 micro08` | `0 / 10` | `spoolsv.exe, tpautoconnsvc.exe` |
| `221` | `chunk018 micro05` | `0 / 10` | `spoolsv.exe, tpautoconnsvc.exe` |
| `222` | `chunk163 micro06` | `0 / 10` | `repmgr.exe, -, sysmon.exe, csrss.exe` |
| `223` | `chunk224 micro07` | `0 / 10` | `tpautoconnsvc.exe, spoolsv.exe` |
| `224` | `chunk165 micro07` | `0 / 10` | `tpautoconnsvc.exe, spoolsv.exe` |
| `225` | `chunk146 micro06` | `0 / 10` | `tpautoconnsvc.exe, spoolsv.exe` |
| `226` | `chunk224 micro00` | `0 / 10` | `spoolsv.exe` |
| `227` | `chunk165 micro00` | `0 / 10` | `spoolsv.exe` |
| `228` | `chunk069 micro00` | `0 / 10` | `spoolsv.exe` |
| `229` | `chunk226 micro08` | `0 / 10` | `repmgr.exe` |
| `230` | `chunk240 micro05` | `0 / 10` | `firefox.exe` |
| `231` | `chunk224 micro09` | `0 / 10` | `spoolsv.exe, vmtoolsd.exe` |
| `232` | `chunk165 micro09` | `0 / 10` | `spoolsv.exe, vmtoolsd.exe` |
| `233` | `chunk110 micro06` | `0 / 10` | `searchindexer.exe, sysmon.exe, csrss.exe, searchprotocolhost.exe` |
| `234` | `chunk041 micro00` | `0 / 10` | `firefox.exe` |
| `235` | `chunk012 micro08` | `0 / 10` | `repmgr.exe, spoolsv.exe, vmtoolsd.exe` |
| `236` | `chunk110 micro07` | `0 / 10` | `searchprotocolhost.exe, sysmon.exe, csrss.exe` |
| `237` | `chunk003 micro06` | `0 / 10` | `csrss.exe, spoolsv.exe, sysmon.exe, -` |
| `238` | `chunk110 micro03` | `0 / 10` | `sysmon.exe, spoolsv.exe` |
| `239` | `chunk018 micro08` | `0 / 10` | `msiexec.exe, vmtoolsd.exe, svchost.exe` |
| `240` | `chunk126 micro03` | `0 / 10` | `spoolsv.exe, tpautoconnsvc.exe` |
| `241` | `chunk186 micro05` | `0 / 10` | `spoolsv.exe, tpautoconnsvc.exe` |
| `242` | `chunk104 micro04` | `0 / 10` | `spoolsv.exe, tpautoconnsvc.exe` |
| `243` | `chunk033 micro04` | `0 / 10` | `spoolsv.exe, tpautoconnsvc.exe` |
| `244` | `chunk194 micro01` | `0 / 10` | `spoolsv.exe, tpautoconnsvc.exe` |
| `245` | `chunk003 micro05` | `0 / 10` | `sysmon.exe, tpautoconnsvc.exe` |
| `246` | `chunk005 micro02` | `0 / 10` | `repwmiutils.exe, sysmon.exe, repmgr.exe` |
| `247` | `chunk226 micro03` | `0 / 10` | `tpautoconnect.exe, vmtoolsd.exe` |
| `248` | `chunk041 micro02` | `0 / 10` | `firefox.exe, vmtoolsd.exe` |
| `249` | `chunk005 micro00` | `0 / 10` | `vmtoolsd.exe, wmiprvse.exe, repmgr.exe` |
| `250` | `chunk018 micro07` | `0 / 10` | `spoolsv.exe, vmtoolsd.exe` |
| `251` | `chunk240 micro09` | `0 / 10` | `winword.exe` |
| `252` | `chunk163 micro07` | `0 / 10` | `repwmiutils.exe, sysmon.exe, repmgr.exe` |
| `253` | `chunk146 micro09` | `0 / 10` | `sysmon.exe, -, repmgr.exe, csrss.exe` |
| `254` | `chunk005 micro01` | `0 / 10` | `sysmon.exe, -, repmgr.exe, csrss.exe` |
| `255` | `chunk240 micro06` | `0 / 10` | `firefox.exe, vmtoolsd.exe` |
| `256` | `chunk043 micro03` | `0 / 10` | `spoolsv.exe` |
| `257` | `chunk163 micro05` | `0 / 10` | `repwmiutils.exe, repmgr.exe` |
| `258` | `chunk183 micro05` | `0 / 10` | `repwmiutils.exe, vmtoolsd.exe, repmgr.exe` |
| `259` | `chunk183 micro08` | `0 / 10` | `searchindexer.exe, services.exe, tpautoconnsvc.exe` |
| `260` | `chunk183 micro07` | `0 / 10` | `searchindexer.exe, vmtoolsd.exe` |
| `261` | `chunk101 micro00` | `0 / 10` | `repwmiutils.exe, sysmon.exe, csrss.exe, repmgr.exe` |
| `262` | `chunk110 micro08` | `0 / 10` | `searchprotocolhost.exe` |
| `263` | `chunk110 micro09` | `0 / 10` | `searchprotocolhost.exe` |
| `264` | `chunk101 micro07` | `0 / 10` | `repwmiutils.exe, vmtoolsd.exe` |
| `265` | `chunk115 micro02` | `0 / 10` | `spoolsv.exe` |
| `266` | `chunk128 micro02` | `0 / 10` | `spoolsv.exe` |
| `267` | `chunk126 micro00` | `0 / 10` | `spoolsv.exe` |
| `268` | `chunk186 micro02` | `0 / 10` | `spoolsv.exe` |
| `269` | `chunk104 micro01` | `0 / 10` | `spoolsv.exe` |
| `270` | `chunk033 micro01` | `0 / 10` | `spoolsv.exe` |

## 3. event 一覧

### micro rank 1: `chunk003 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe, sysmon.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4656` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=sysmon.exe` |
| `7` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 2: `chunk003 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe, csrss.exe, -`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `2` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4690` | `-` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4690` |
| `6` | `0` | `4663` | `csrss.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=csrss.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `csrss.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=csrss.exe` |
| `8` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 3: `chunk028 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |

### micro rank 4: `chunk240 micro00`

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

### micro rank 5: `chunk240 micro03`

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

### micro rank 6: `chunk226 micro01`

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

### micro rank 7: `chunk101 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `3` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `6` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `9` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |

### micro rank 8: `chunk005 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `2` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `5` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `8` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |

### micro rank 9: `chunk183 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `2` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `5` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `8` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |

### micro rank 10: `chunk101 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `2` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `5` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `8` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |

### micro rank 11: `chunk101 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `2` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `5` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `8` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |

### micro rank 12: `chunk163 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `2` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `5` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `8` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |

### micro rank 13: `chunk163 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `2` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `5` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `8` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |

### micro rank 14: `chunk240 micro02`

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

### micro rank 15: `chunk226 micro00`

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

### micro rank 16: `chunk240 micro01`

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

### micro rank 17: `chunk226 micro02`

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

### micro rank 18: `chunk163 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `3` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `5` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `8` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |

### micro rank 19: `chunk005 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `3` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `6` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `9` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |

### micro rank 20: `chunk005 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `3` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `6` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `9` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |

### micro rank 21: `chunk183 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `3` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `6` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `9` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |

### micro rank 22: `chunk183 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `3` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `6` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `9` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |

### micro rank 23: `chunk101 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `3` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `6` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `9` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |

### micro rank 24: `chunk101 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `3` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `6` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `9` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |

### micro rank 25: `chunk163 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `3` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `6` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `9` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |

### micro rank 26: `chunk160 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `wmiprvse.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=wmiprvse.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=wmiprvse.exe` |
| `3` | `0` | `4656` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=wmiprvse.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=wmiprvse.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=wmiprvse.exe` |
| `6` | `0` | `4656` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=wmiprvse.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=wmiprvse.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=wmiprvse.exe` |
| `9` | `0` | `4656` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=wmiprvse.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=wmiprvse.exe \| ObjectType=file` |

### micro rank 27: `chunk005 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `4` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `7` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `10` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |

### micro rank 28: `chunk005 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `4` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `7` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `10` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |

### micro rank 29: `chunk005 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `4` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `7` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `10` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |

### micro rank 30: `chunk183 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `4` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `7` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `10` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |

### micro rank 31: `chunk183 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `4` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `7` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `10` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |

### micro rank 32: `chunk101 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `4` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `7` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `10` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |

### micro rank 33: `chunk163 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `4` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `7` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `10` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |

### micro rank 34: `chunk163 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `4` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `7` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `10` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |

### micro rank 35: `chunk163 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `4` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `7` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `10` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |

### micro rank 36: `chunk160 micro09`

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

### micro rank 37: `chunk069 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 38: `chunk180 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 39: `chunk180 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 40: `chunk012 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 41: `chunk012 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 42: `chunk104 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 43: `chunk194 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 44: `chunk018 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 45: `chunk003 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 46: `chunk086 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |

### micro rank 47: `chunk086 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |

### micro rank 48: `chunk028 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |

### micro rank 49: `chunk180 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe, tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `2` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |

### micro rank 50: `chunk012 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe, tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `2` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |

### micro rank 51: `chunk126 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 52: `chunk186 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 53: `chunk033 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 54: `chunk028 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 55: `chunk003 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 56: `chunk126 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 57: `chunk186 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 58: `chunk033 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 59: `chunk069 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |

### micro rank 60: `chunk180 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |

### micro rank 61: `chunk018 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |

### micro rank 62: `chunk224 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 63: `chunk165 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 64: `chunk146 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 65: `chunk028 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 66: `chunk115 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 67: `chunk128 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 68: `chunk110 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 69: `chunk028 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `wmiprvse.exe, spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4656` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=wmiprvse.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=wmiprvse.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=wmiprvse.exe` |
| `6` | `0` | `4656` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=wmiprvse.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=wmiprvse.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=wmiprvse.exe` |
| `9` | `0` | `4656` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=wmiprvse.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=wmiprvse.exe \| ObjectType=file` |

### micro rank 70: `chunk028 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 71: `chunk115 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 72: `chunk128 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 73: `chunk043 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 74: `chunk224 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 75: `chunk165 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 76: `chunk186 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 77: `chunk104 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 78: `chunk104 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 79: `chunk146 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 80: `chunk115 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 81: `chunk128 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 82: `chunk194 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 83: `chunk126 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |

### micro rank 84: `chunk186 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |

### micro rank 85: `chunk033 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |

### micro rank 86: `chunk033 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |

### micro rank 87: `chunk043 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |

### micro rank 88: `chunk115 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 89: `chunk128 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 90: `chunk180 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `2` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `6` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `7` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 91: `chunk180 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `2` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `6` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `7` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 92: `chunk180 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `2` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `6` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `7` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 93: `chunk012 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `2` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `6` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `7` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 94: `chunk012 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `2` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `6` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `7` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 95: `chunk012 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `2` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `6` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `7` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 96: `chunk043 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `2` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `6` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `7` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 97: `chunk043 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `2` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `6` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `7` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 98: `chunk043 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `2` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `6` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `7` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 99: `chunk224 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `6` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 100: `chunk224 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `6` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 101: `chunk224 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `6` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 102: `chunk165 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `6` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 103: `chunk165 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `6` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 104: `chunk165 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `6` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 105: `chunk146 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `6` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 106: `chunk146 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `6` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 107: `chunk146 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `6` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 108: `chunk028 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `6` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 109: `chunk028 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `6` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 110: `chunk028 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `6` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 111: `chunk028 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `6` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 112: `chunk160 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `flashplayerupdateservice.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=flashplayerupdateservice.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=flashplayerupdateservice.exe` |
| `3` | `0` | `4656` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=flashplayerupdateservice.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=flashplayerupdateservice.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=flashplayerupdateservice.exe` |
| `6` | `0` | `4656` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=flashplayerupdateservice.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=flashplayerupdateservice.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=flashplayerupdateservice.exe` |
| `9` | `0` | `4656` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=flashplayerupdateservice.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=flashplayerupdateservice.exe \| ObjectType=file` |

### micro rank 113: `chunk086 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `3` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `8` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 114: `chunk086 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `3` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `8` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 115: `chunk086 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `3` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `8` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 116: `chunk126 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `3` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `8` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 117: `chunk126 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `3` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `8` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 118: `chunk126 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `3` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `8` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 119: `chunk069 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 120: `chunk069 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 121: `chunk069 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 122: `chunk186 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `3` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `8` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 123: `chunk186 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `3` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `8` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 124: `chunk186 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `3` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `8` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 125: `chunk104 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 126: `chunk104 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 127: `chunk104 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 128: `chunk033 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `3` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `8` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 129: `chunk033 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `3` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `8` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 130: `chunk033 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `3` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `8` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 131: `chunk115 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `2` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `3` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `7` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `8` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 132: `chunk115 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `2` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `3` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `7` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `8` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 133: `chunk115 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `2` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `3` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `7` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `8` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 134: `chunk128 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `2` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `3` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `7` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `8` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 135: `chunk128 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `2` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `3` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `7` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `8` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 136: `chunk128 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `2` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `3` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `7` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `8` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 137: `chunk194 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 138: `chunk194 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 139: `chunk194 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 140: `chunk110 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `2` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `3` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `7` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `8` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 141: `chunk018 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 142: `chunk018 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 143: `chunk018 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 144: `chunk003 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 145: `chunk003 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 146: `chunk005 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe, svchost.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `3` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `4` | `0` | `4689` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4689 \| ProcessName=repwmiutils.exe` |
| `5` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `6` | `0` | `4656` | `svchost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=svchost.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `svchost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=svchost.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `svchost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=svchost.exe` |
| `9` | `0` | `4656` | `svchost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=svchost.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `svchost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=svchost.exe \| ObjectType=file` |

### micro rank 147: `chunk180 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |

### micro rank 148: `chunk012 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |

### micro rank 149: `chunk160 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `wmiprvse.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=wmiprvse.exe` |
| `2` | `0` | `4656` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=wmiprvse.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=wmiprvse.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=wmiprvse.exe` |
| `5` | `0` | `4656` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=wmiprvse.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=wmiprvse.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=wmiprvse.exe` |
| `8` | `0` | `4656` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=wmiprvse.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=wmiprvse.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=wmiprvse.exe` |

### micro rank 150: `chunk160 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `flashplayerupdateservice.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=flashplayerupdateservice.exe \| ObjectType=file` |
| `2` | `0` | `4656` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=flashplayerupdateservice.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=flashplayerupdateservice.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=flashplayerupdateservice.exe` |
| `5` | `0` | `4656` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=flashplayerupdateservice.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=flashplayerupdateservice.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=flashplayerupdateservice.exe` |
| `8` | `0` | `4656` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=flashplayerupdateservice.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=flashplayerupdateservice.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=flashplayerupdateservice.exe` |

### micro rank 151: `chunk160 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `flashplayerupdateservice.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=flashplayerupdateservice.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=flashplayerupdateservice.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=flashplayerupdateservice.exe` |
| `4` | `0` | `4656` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=flashplayerupdateservice.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=flashplayerupdateservice.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=flashplayerupdateservice.exe` |
| `7` | `0` | `4656` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=flashplayerupdateservice.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=flashplayerupdateservice.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=flashplayerupdateservice.exe` |
| `10` | `0` | `4656` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=flashplayerupdateservice.exe \| ObjectType=file` |

### micro rank 152: `chunk086 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe, tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `3` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 153: `chunk110 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe, tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `2` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `3` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 154: `chunk043 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 155: `chunk086 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe, repmgr.exe, -`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `8` | `0` | `4688` | `-` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4688` |
| `9` | `0` | `4690` | `-` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4690` |
| `10` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |

### micro rank 156: `chunk146 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe, repmgr.exe, -`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `10` | `0` | `4688` | `-` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4688` |

### micro rank 157: `chunk194 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `repmgr.exe, vmtoolsd.exe, spoolsv.exe, svchost.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4656` | `svchost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=svchost.exe \| ObjectType=security` |
| `3` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |
| `6` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |
| `9` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |

### micro rank 158: `chunk069 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 159: `chunk003 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `repmgr.exe, spoolsv.exe, -, csrss.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4690` | `-` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4690` |
| `4` | `0` | `4658` | `csrss.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=csrss.exe` |
| `5` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |
| `8` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |

### micro rank 160: `chunk104 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |

### micro rank 161: `chunk101 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 162: `chunk101 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 163: `chunk194 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |

### micro rank 164: `chunk226 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `vmtoolsd.exe, firefox.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |
| `3` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |
| `6` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |
| `9` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |

### micro rank 165: `chunk160 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `services.exe, -, csrss.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `services.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=services.exe` |
| `2` | `0` | `4690` | `-` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4690` |
| `3` | `0` | `4658` | `csrss.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=csrss.exe` |
| `4` | `0` | `4656` | `services.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=services.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `services.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=services.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `services.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=services.exe` |
| `7` | `0` | `4656` | `services.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=services.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `services.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=services.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `services.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=services.exe` |
| `10` | `0` | `4658` | `services.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=services.exe` |

### micro rank 166: `chunk126 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |

### micro rank 167: `chunk110 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `searchindexer.exe, sysmon.exe, -, csrss.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `searchindexer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=searchindexer.exe \| ObjectType=file` |
| `2` | `0` | `4688` | `-` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4688` |
| `3` | `0` | `4656` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=sysmon.exe` |
| `6` | `0` | `4690` | `-` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4690` |
| `7` | `0` | `4658` | `csrss.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=csrss.exe` |
| `8` | `0` | `4656` | `searchindexer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=searchindexer.exe \| ObjectType=file` |
| `9` | `0` | `4656` | `searchindexer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=searchindexer.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `searchindexer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=searchindexer.exe \| ObjectType=file` |

### micro rank 168: `chunk224 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |

### micro rank 169: `chunk165 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |

### micro rank 170: `chunk146 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |

### micro rank 171: `chunk183 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 172: `chunk226 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `firefox.exe, repmgr.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `2` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `5` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `6` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |
| `8` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `9` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |

### micro rank 173: `chunk018 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `msiexec.exe, repmgr.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `msiexec.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=msiexec.exe` |
| `2` | `0` | `4658` | `msiexec.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=msiexec.exe` |
| `3` | `0` | `4658` | `msiexec.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=msiexec.exe` |
| `4` | `0` | `4658` | `msiexec.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=msiexec.exe` |
| `5` | `0` | `4658` | `msiexec.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=msiexec.exe` |
| `6` | `0` | `4658` | `msiexec.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=msiexec.exe` |
| `7` | `0` | `4658` | `msiexec.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=msiexec.exe` |
| `8` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |

### micro rank 174: `chunk069 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |

### micro rank 175: `chunk043 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |

### micro rank 176: `chunk183 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `repmgr.exe, searchindexer.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `4` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |
| `7` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |
| `8` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |
| `9` | `0` | `4656` | `searchindexer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=searchindexer.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `searchindexer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=searchindexer.exe` |

### micro rank 177: `chunk160 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `svchost.exe, vmtoolsd.exe, wmiprvse.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `svchost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=svchost.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `svchost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=svchost.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `svchost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=svchost.exe` |
| `4` | `0` | `4656` | `svchost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=svchost.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `svchost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=svchost.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `svchost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=svchost.exe` |
| `7` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |
| `10` | `0` | `4656` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=wmiprvse.exe \| ObjectType=file` |

### micro rank 178: `chunk240 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `vmtoolsd.exe, winword.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |
| `3` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |
| `6` | `0` | `4656` | `winword.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=winword.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `winword.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=winword.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `winword.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=winword.exe` |
| `9` | `0` | `4656` | `winword.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=winword.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `winword.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=winword.exe \| ObjectType=file` |

### micro rank 179: `chunk110 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `-, searchindexer.exe, sysmon.exe, csrss.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4690` | `-` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4690` |
| `2` | `0` | `4658` | `csrss.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=csrss.exe` |
| `3` | `0` | `4656` | `searchindexer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=searchindexer.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `searchindexer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=searchindexer.exe \| ObjectType=file` |
| `5` | `0` | `4688` | `-` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4688` |
| `6` | `0` | `4656` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=sysmon.exe` |
| `9` | `0` | `4690` | `-` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4690` |
| `10` | `0` | `4658` | `searchindexer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=searchindexer.exe` |

### micro rank 180: `chunk160 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `flashplayerupdateservice.exe, svchost.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=flashplayerupdateservice.exe` |
| `2` | `0` | `4656` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=flashplayerupdateservice.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=flashplayerupdateservice.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=flashplayerupdateservice.exe` |
| `5` | `0` | `4656` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=flashplayerupdateservice.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=flashplayerupdateservice.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=flashplayerupdateservice.exe` |
| `8` | `0` | `4656` | `svchost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=svchost.exe \| ObjectType=security` |
| `9` | `0` | `4656` | `svchost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=svchost.exe \| ObjectType=security` |
| `10` | `0` | `4689` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4689 \| ProcessName=flashplayerupdateservice.exe` |

### micro rank 181: `chunk180 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `repmgr.exe, spoolsv.exe, -, sysmon.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `6` | `0` | `4688` | `-` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4688` |
| `7` | `0` | `4690` | `-` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4690` |
| `8` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |
| `9` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `10` | `0` | `4656` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=sysmon.exe \| ObjectType=file` |

### micro rank 182: `chunk240 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `vmtoolsd.exe, firefox.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |
| `4` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |
| `7` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `10` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |

### micro rank 183: `chunk086 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 184: `chunk115 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 185: `chunk128 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 186: `chunk115 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe, spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `7` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `8` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 187: `chunk128 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe, spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `7` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `8` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 188: `chunk180 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe, spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `6` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `7` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 189: `chunk012 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe, spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `6` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `7` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 190: `chunk003 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe, spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `6` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `7` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 191: `chunk086 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 192: `chunk226 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `repmgr.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |
| `4` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |
| `7` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `10` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |

### micro rank 193: `chunk126 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe, spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `3` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `8` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 194: `chunk186 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe, spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `3` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `8` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 195: `chunk104 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe, spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 196: `chunk033 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe, spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `3` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `8` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 197: `chunk194 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe, spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 198: `chunk086 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe, spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `8` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 199: `chunk012 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `repmgr.exe, wmiprvse.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `2` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |
| `5` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |
| `6` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |
| `7` | `0` | `4656` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=wmiprvse.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=wmiprvse.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=wmiprvse.exe` |
| `10` | `0` | `4656` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=wmiprvse.exe \| ObjectType=file` |

### micro rank 200: `chunk160 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `conhost.exe, flashplayerupdateservice.exe, svchost.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=flashplayerupdateservice.exe` |
| `2` | `0` | `4689` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4689 \| ProcessName=flashplayerupdateservice.exe` |
| `3` | `0` | `4658` | `flashplayerupdateservice.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=flashplayerupdateservice.exe` |
| `4` | `0` | `4689` | `conhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4689 \| ProcessName=conhost.exe` |
| `5` | `0` | `4658` | `conhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=conhost.exe` |
| `6` | `0` | `4658` | `conhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=conhost.exe` |
| `7` | `0` | `4658` | `conhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=conhost.exe` |
| `8` | `0` | `4656` | `svchost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=svchost.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `svchost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=svchost.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `svchost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=svchost.exe` |

### micro rank 201: `chunk043 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |

### micro rank 202: `chunk043 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe, tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 203: `chunk041 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `firefox.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `2` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `5` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `7` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `9` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |

### micro rank 204: `chunk226 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `repmgr.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |
| `4` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |
| `7` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |
| `10` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |

### micro rank 205: `chunk240 micro04`

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

### micro rank 206: `chunk226 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `firefox.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `2` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `5` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `8` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `9` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |

### micro rank 207: `chunk041 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `firefox.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `2` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `5` | `0` | `4660` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=firefox.exe` |
| `6` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `7` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `10` | `0` | `4660` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=firefox.exe` |

### micro rank 208: `chunk041 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `firefox.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `2` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `5` | `0` | `4660` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=firefox.exe` |
| `6` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `7` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `10` | `0` | `4660` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=firefox.exe` |

### micro rank 209: `chunk041 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `firefox.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `2` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `5` | `0` | `4660` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=firefox.exe` |
| `6` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `7` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `10` | `0` | `4660` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=firefox.exe` |

### micro rank 210: `chunk041 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `firefox.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `2` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `5` | `0` | `4660` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=firefox.exe` |
| `6` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `7` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `10` | `0` | `4660` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=firefox.exe` |

### micro rank 211: `chunk041 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `firefox.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `2` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `5` | `0` | `4660` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=firefox.exe` |
| `6` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `7` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `10` | `0` | `4660` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=firefox.exe` |

### micro rank 212: `chunk041 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `firefox.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `2` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `5` | `0` | `4660` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=firefox.exe` |
| `6` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `7` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `10` | `0` | `4660` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=firefox.exe` |

### micro rank 213: `chunk041 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `firefox.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `2` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `5` | `0` | `4660` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=firefox.exe` |
| `6` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `7` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `10` | `0` | `4660` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=firefox.exe` |

### micro rank 214: `chunk224 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe, tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 215: `chunk165 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe, tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 216: `chunk146 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe, tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `9` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |

### micro rank 217: `chunk069 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe, spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 218: `chunk018 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe, spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `8` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `9` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `10` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 219: `chunk194 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `repmgr.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |
| `2` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |
| `5` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |
| `8` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |

### micro rank 220: `chunk069 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe, tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |

### micro rank 221: `chunk018 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe, tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |

### micro rank 222: `chunk163 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `repmgr.exe, -, sysmon.exe, csrss.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `2` | `0` | `4688` | `-` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4688` |
| `3` | `0` | `4690` | `-` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4690` |
| `4` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |
| `5` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `6` | `0` | `4656` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `7` | `0` | `4690` | `-` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4690` |
| `8` | `0` | `4663` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=sysmon.exe` |
| `10` | `0` | `4658` | `csrss.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=csrss.exe` |

### micro rank 223: `chunk224 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe, spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `6` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 224: `chunk165 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe, spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `6` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 225: `chunk146 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnsvc.exe, spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `4` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `6` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 226: `chunk224 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |

### micro rank 227: `chunk165 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |

### micro rank 228: `chunk069 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |

### micro rank 229: `chunk226 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `repmgr.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |
| `3` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |
| `6` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |
| `9` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |
| `10` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |

### micro rank 230: `chunk240 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `firefox.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `4` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `7` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `10` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |

### micro rank 231: `chunk224 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe, vmtoolsd.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |

### micro rank 232: `chunk165 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe, vmtoolsd.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |

### micro rank 233: `chunk110 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `searchindexer.exe, sysmon.exe, csrss.exe, searchprotocolhost.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `searchindexer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=searchindexer.exe` |
| `2` | `0` | `4658` | `searchindexer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=searchindexer.exe` |
| `3` | `0` | `4658` | `searchindexer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=searchindexer.exe` |
| `4` | `0` | `4656` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `5` | `0` | `4656` | `searchprotocolhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=searchprotocolhost.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=sysmon.exe` |
| `8` | `0` | `4690` | `-` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4690` |
| `9` | `0` | `4663` | `csrss.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=csrss.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `csrss.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=csrss.exe` |

### micro rank 234: `chunk041 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `firefox.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `3` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `6` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `9` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `10` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |

### micro rank 235: `chunk012 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `repmgr.exe, spoolsv.exe, vmtoolsd.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |
| `7` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `9` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |

### micro rank 236: `chunk110 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `searchprotocolhost.exe, sysmon.exe, csrss.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `csrss.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=csrss.exe` |
| `2` | `0` | `4656` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=sysmon.exe` |
| `5` | `0` | `4656` | `searchprotocolhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=searchprotocolhost.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `searchprotocolhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=searchprotocolhost.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `searchprotocolhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=searchprotocolhost.exe` |
| `8` | `0` | `4656` | `searchprotocolhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=searchprotocolhost.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `searchprotocolhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=searchprotocolhost.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `searchprotocolhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=searchprotocolhost.exe` |

### micro rank 237: `chunk003 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `csrss.exe, spoolsv.exe, sysmon.exe, -`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `csrss.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=csrss.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `csrss.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=csrss.exe \| ObjectType=file` |
| `3` | `0` | `4688` | `-` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4688` |
| `4` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `csrss.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=csrss.exe` |
| `7` | `0` | `4656` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=sysmon.exe` |
| `10` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |

### micro rank 238: `chunk110 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `sysmon.exe, spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4656` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=sysmon.exe` |
| `8` | `0` | `4656` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=sysmon.exe` |

### micro rank 239: `chunk018 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `msiexec.exe, vmtoolsd.exe, svchost.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |
| `3` | `0` | `4656` | `svchost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=svchost.exe \| ObjectType=security` |
| `4` | `0` | `4656` | `svchost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=svchost.exe \| ObjectType=security` |
| `5` | `0` | `4658` | `msiexec.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=msiexec.exe` |
| `6` | `0` | `4658` | `msiexec.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=msiexec.exe` |
| `7` | `0` | `4658` | `msiexec.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=msiexec.exe` |
| `8` | `0` | `4689` | `msiexec.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4689 \| ProcessName=msiexec.exe` |
| `9` | `0` | `4658` | `msiexec.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=msiexec.exe` |
| `10` | `0` | `4658` | `msiexec.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=msiexec.exe` |

### micro rank 240: `chunk126 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe, tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 241: `chunk186 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe, tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 242: `chunk104 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe, tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 243: `chunk033 micro04`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe, tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 244: `chunk194 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe, tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `2` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 245: `chunk003 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `sysmon.exe, tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |
| `3` | `0` | `4660` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=tpautoconnsvc.exe` |
| `4` | `0` | `4658` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=tpautoconnsvc.exe` |
| `5` | `0` | `4656` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=sysmon.exe` |
| `8` | `0` | `4656` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=sysmon.exe` |

### micro rank 246: `chunk005 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe, sysmon.exe, repmgr.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |
| `3` | `0` | `4658` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=sysmon.exe` |
| `4` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `5` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `8` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |

### micro rank 247: `chunk226 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `tpautoconnect.exe, vmtoolsd.exe`

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
| `10` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |

### micro rank 248: `chunk041 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `firefox.exe, vmtoolsd.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `2` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `4` | `0` | `4670` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4670 \| ProcessName=firefox.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `6` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |
| `9` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |

### micro rank 249: `chunk005 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `vmtoolsd.exe, wmiprvse.exe, repmgr.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=wmiprvse.exe` |
| `2` | `0` | `4658` | `wmiprvse.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=wmiprvse.exe` |
| `3` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |
| `6` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |
| `9` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |

### micro rank 250: `chunk018 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe, vmtoolsd.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `5` | `0` | `4660` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4660 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |
| `10` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |

### micro rank 251: `chunk240 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `winword.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `winword.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=winword.exe` |
| `2` | `0` | `4656` | `winword.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=winword.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `winword.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=winword.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `winword.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=winword.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `winword.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=winword.exe` |
| `6` | `0` | `4656` | `winword.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=winword.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `winword.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=winword.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `winword.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=winword.exe` |
| `9` | `0` | `4656` | `winword.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=winword.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `winword.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=winword.exe \| ObjectType=file` |

### micro rank 252: `chunk163 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe, sysmon.exe, repmgr.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |
| `2` | `0` | `4656` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=sysmon.exe` |
| `5` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `6` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `9` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |

### micro rank 253: `chunk146 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `sysmon.exe, -, repmgr.exe, csrss.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4690` | `-` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4690` |
| `2` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |
| `3` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `4` | `0` | `4656` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=sysmon.exe` |
| `7` | `0` | `4690` | `-` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4690` |
| `8` | `0` | `4658` | `csrss.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=csrss.exe` |
| `9` | `0` | `4656` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=sysmon.exe \| ObjectType=file` |

### micro rank 254: `chunk005 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `sysmon.exe, -, repmgr.exe, csrss.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4688` | `-` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4688` |
| `2` | `0` | `4690` | `-` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4690` |
| `3` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |
| `4` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `5` | `0` | `4656` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `6` | `0` | `4663` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `7` | `0` | `4658` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=sysmon.exe` |
| `8` | `0` | `4690` | `-` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4690` |
| `9` | `0` | `4658` | `csrss.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=csrss.exe` |
| `10` | `0` | `4656` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=sysmon.exe \| ObjectType=file` |

### micro rank 255: `chunk240 micro06`

- attack / normal: `0 / 10`
- 主なプロセス: `firefox.exe, vmtoolsd.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `4` | `0` | `4656` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=firefox.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=firefox.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `7` | `0` | `4658` | `firefox.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=firefox.exe` |
| `8` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |

### micro rank 256: `chunk043 micro03`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `9` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 257: `chunk163 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe, repmgr.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `4` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `7` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `8` | `0` | `4689` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4689 \| ProcessName=repwmiutils.exe` |
| `9` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `10` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |

### micro rank 258: `chunk183 micro05`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe, vmtoolsd.exe, repmgr.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `3` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `4` | `0` | `4689` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4689 \| ProcessName=repwmiutils.exe` |
| `5` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `6` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |
| `9` | `0` | `4656` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repmgr.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repmgr.exe \| ObjectType=file` |

### micro rank 259: `chunk183 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `searchindexer.exe, services.exe, tpautoconnsvc.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `searchindexer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=searchindexer.exe` |
| `2` | `0` | `4656` | `searchindexer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=searchindexer.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `searchindexer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=searchindexer.exe` |
| `4` | `0` | `4656` | `searchindexer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=searchindexer.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `searchindexer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=searchindexer.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `searchindexer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=searchindexer.exe` |
| `7` | `0` | `4656` | `services.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=services.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `services.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=services.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `services.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=services.exe` |
| `10` | `0` | `4656` | `tpautoconnsvc.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=tpautoconnsvc.exe \| ObjectType=file` |

### micro rank 260: `chunk183 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `searchindexer.exe, vmtoolsd.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `searchindexer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=searchindexer.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `searchindexer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=searchindexer.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `searchindexer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=searchindexer.exe` |
| `4` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |
| `7` | `0` | `4656` | `searchindexer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=searchindexer.exe \| ObjectType=file` |
| `8` | `0` | `4658` | `searchindexer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=searchindexer.exe` |
| `9` | `0` | `4656` | `searchindexer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=searchindexer.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `searchindexer.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=searchindexer.exe \| ObjectType=file` |

### micro rank 261: `chunk101 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe, sysmon.exe, csrss.exe, repmgr.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `csrss.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=csrss.exe` |
| `2` | `0` | `4658` | `repmgr.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repmgr.exe` |
| `3` | `0` | `4656` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=sysmon.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `sysmon.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=sysmon.exe` |
| `6` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `7` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `10` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |

### micro rank 262: `chunk110 micro08`

- attack / normal: `0 / 10`
- 主なプロセス: `searchprotocolhost.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4656` | `searchprotocolhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=searchprotocolhost.exe \| ObjectType=file` |
| `2` | `0` | `4663` | `searchprotocolhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=searchprotocolhost.exe \| ObjectType=file` |
| `3` | `0` | `4658` | `searchprotocolhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=searchprotocolhost.exe` |
| `4` | `0` | `4656` | `searchprotocolhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=searchprotocolhost.exe \| ObjectType=file` |
| `5` | `0` | `4663` | `searchprotocolhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=searchprotocolhost.exe \| ObjectType=file` |
| `6` | `0` | `4658` | `searchprotocolhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=searchprotocolhost.exe` |
| `7` | `0` | `4656` | `searchprotocolhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=searchprotocolhost.exe \| ObjectType=file` |
| `8` | `0` | `4663` | `searchprotocolhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=searchprotocolhost.exe \| ObjectType=file` |
| `9` | `0` | `4658` | `searchprotocolhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=searchprotocolhost.exe` |
| `10` | `0` | `4656` | `searchprotocolhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=searchprotocolhost.exe \| ObjectType=file` |

### micro rank 263: `chunk110 micro09`

- attack / normal: `0 / 10`
- 主なプロセス: `searchprotocolhost.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4663` | `searchprotocolhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=searchprotocolhost.exe \| ObjectType=file` |
| `2` | `0` | `4658` | `searchprotocolhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=searchprotocolhost.exe` |
| `3` | `0` | `4656` | `searchprotocolhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=searchprotocolhost.exe \| ObjectType=file` |
| `4` | `0` | `4663` | `searchprotocolhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=searchprotocolhost.exe \| ObjectType=file` |
| `5` | `0` | `4658` | `searchprotocolhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=searchprotocolhost.exe` |
| `6` | `0` | `4656` | `searchprotocolhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=searchprotocolhost.exe \| ObjectType=file` |
| `7` | `0` | `4663` | `searchprotocolhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=searchprotocolhost.exe \| ObjectType=file` |
| `8` | `0` | `4656` | `searchprotocolhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=searchprotocolhost.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `searchprotocolhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=searchprotocolhost.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `searchprotocolhost.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=searchprotocolhost.exe` |

### micro rank 264: `chunk101 micro07`

- attack / normal: `0 / 10`
- 主なプロセス: `repwmiutils.exe, vmtoolsd.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `2` | `0` | `4656` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=repwmiutils.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `5` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `6` | `0` | `4689` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4689 \| ProcessName=repwmiutils.exe` |
| `7` | `0` | `4658` | `repwmiutils.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=repwmiutils.exe` |
| `8` | `0` | `4656` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `9` | `0` | `4663` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=vmtoolsd.exe \| ObjectType=file` |
| `10` | `0` | `4658` | `vmtoolsd.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=vmtoolsd.exe` |

### micro rank 265: `chunk115 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |

### micro rank 266: `chunk128 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `3` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |

### micro rank 267: `chunk126 micro00`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 268: `chunk186 micro02`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 269: `chunk104 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `10` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |

### micro rank 270: `chunk033 micro01`

- attack / normal: `0 / 10`
- 主なプロセス: `spoolsv.exe`

| event | label | EventID | process | template |
| --- | ---: | --- | --- | --- |
| `1` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `2` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `3` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `4` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `5` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `6` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `7` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `8` | `0` | `4658` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4658 \| ProcessName=spoolsv.exe` |
| `9` | `0` | `4656` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4656 \| ProcessName=spoolsv.exe \| ObjectType=file` |
| `10` | `0` | `4663` | `spoolsv.exe` | `Provider=microsoft-windows-security-auditing \| Channel=Security \| EventID=4663 \| ProcessName=spoolsv.exe \| ObjectType=file` |
