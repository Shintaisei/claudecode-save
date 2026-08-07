param(
  [string]$Models = "claude-sonnet-4-6",
  [string]$ResultLabel = "formal_27_chain_claude_20260617",
  [int]$Replicates = 1,
  [int]$Workers = 2,
  [double]$CostCheckUsd = 120,
  [string]$Cases = ""
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Python = "python"
$Runner = Join-Path $Root "src\clouseau_process_time\run_formal_27_chain_run_only_parallel_guarded.py"
if (-not $Cases) {
  $Cases = Join-Path $Root "data\current_experiment\cases\cbc_27_chain_stage_cases_2026-06-09.jsonl"
}
$BaseResult = Join-Path $Root "docs\current_experiment\results_2026-06-09\$ResultLabel"
$LogDir = Join-Path $BaseResult "_logs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

$CommonArgs = @(
  "--cases", $Cases,
  "--models", $Models,
  "--workers", "$Workers",
  "--max-investigations", "300",
  "--max-questions", "800",
  "--max-queries", "1600",
  "--max-tokens", "24576",
  "--sql-playbook", "none",
  "--cost-check-usd", "$CostCheckUsd",
  "--resume",
  "--log-cost"
)

foreach ($Index in 1..$Replicates) {
  $Rep = "replicate_{0:D2}" -f $Index
  $ResultRoot = Join-Path $BaseResult $Rep
  New-Item -ItemType Directory -Force -Path $ResultRoot | Out-Null
  $LogPath = Join-Path $LogDir "$Rep.run.log"
  Write-Host "Starting Claude run $Rep ($Models) -> $ResultRoot"
  & $Python $Runner "--result-root" $ResultRoot @CommonArgs 2>&1 | Tee-Object -FilePath $LogPath
  if ($LASTEXITCODE -ne 0) {
    throw "Runner failed for $Rep with exit code $LASTEXITCODE"
  }
}
