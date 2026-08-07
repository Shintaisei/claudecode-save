$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Python = "python"
$Runner = Join-Path $Root "src\clouseau_process_time\run_formal_27_chain_run_only_parallel_guarded.py"
$Cases = Join-Path $Root "data\current_experiment\cases\cbc_23_chain_stage_cases_2026-06-12.jsonl"
$BaseResult = Join-Path $Root "docs\current_experiment\results_2026-06-09\formal_23_chain_experiment_2rep_20260612"
$LogDir = Join-Path $BaseResult "_logs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

$Models = "gpt-4.1-mini,gpt-5.4-mini"
$CommonArgs = @(
  "--cases", $Cases,
  "--models", $Models,
  "--workers", "2",
  "--max-investigations", "300",
  "--max-questions", "800",
  "--max-queries", "1600",
  "--max-tokens", "24576",
  "--sql-playbook", "none",
  "--cost-check-usd", "20",
  "--resume",
  "--log-cost"
)

foreach ($Rep in @("replicate_01", "replicate_02")) {
  $ResultRoot = Join-Path $BaseResult $Rep
  $OutLog = Join-Path $LogDir "$Rep.out.log"
  $ErrLog = Join-Path $LogDir "$Rep.err.log"
  $Started = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  "[$Started] START $Rep result_root=$ResultRoot models=$Models cases=$Cases" | Out-File -FilePath $OutLog -Encoding utf8 -Append
  & $Python $Runner "--result-root" $ResultRoot @CommonArgs 1>> $OutLog 2>> $ErrLog
  $Finished = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  "[$Finished] FINISH $Rep" | Out-File -FilePath $OutLog -Encoding utf8 -Append
}
