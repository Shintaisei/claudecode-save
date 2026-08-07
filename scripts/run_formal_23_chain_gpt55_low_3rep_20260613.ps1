$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Python = "python"
$Runner = Join-Path $Root "src\clouseau_process_time\run_formal_27_chain_run_only_parallel_guarded.py"
$Cases = Join-Path $Root "data\current_experiment\cases\cbc_23_chain_stage_cases_2026-06-12.jsonl"
$BaseResult = Join-Path $Root "docs\current_experiment\results_2026-06-09\formal_23_chain_gpt55_low_3rep_20260613"
$LogDir = Join-Path $BaseResult "_logs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

$Models = "gpt-5.5"
$CommonArgs = @(
  "--cases", $Cases,
  "--models", $Models,
  "--workers", "4",
  "--max-investigations", "300",
  "--max-questions", "800",
  "--max-queries", "1600",
  "--max-tokens", "24576",
  "--reasoning-effort", "low",
  "--sql-playbook", "none",
  "--cost-check-usd", "120",
  "--resume",
  "--log-cost"
)

foreach ($Rep in @("replicate_01", "replicate_02", "replicate_03")) {
  $ResultRoot = Join-Path $BaseResult $Rep
  New-Item -ItemType Directory -Force -Path $ResultRoot | Out-Null
  $LogPath = Join-Path $LogDir "$Rep.run.log"
  Write-Host "Starting $Rep -> $ResultRoot"
  & $Python $Runner "--result-root" $ResultRoot @CommonArgs 2>&1 | Tee-Object -FilePath $LogPath
  if ($LASTEXITCODE -ne 0) {
    throw "Runner failed for $Rep with exit code $LASTEXITCODE"
  }
}
