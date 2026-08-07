param(
  [int]$Workers = 2
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Python = "python"
$Runner = Join-Path $Root "src\clouseau_process_time\run_formal_27_chain_run_only_parallel_guarded.py"
$Cases = Join-Path $Root "data\current_experiment\cases\cbc_23_chain_stage_cases_2026-06-12.jsonl"
$Smoke = Join-Path $Root "scripts\test_clouseau_api_smoke.py"
$BaseResult = Join-Path $Root "docs\current_experiment\results_2026-06-09\formal_23_chain_experiment_replicate03_20260614"
$ResultRoot = Join-Path $BaseResult "replicate_03"
$LogDir = Join-Path $BaseResult "_logs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
New-Item -ItemType Directory -Force -Path $ResultRoot | Out-Null

Write-Host "Checking OpenAI quota with a minimal call..."
& $Python $Smoke --model gpt-5-nano --prompt "Reply with exactly: OK"
if ($LASTEXITCODE -ne 0) {
  throw "OpenAI quota smoke test failed. Fix .env.clouseau OPENAI_API_KEY/quota before running replicate_03."
}

$Models = "gpt-4.1-mini,gpt-5.4-mini"
$CommonArgs = @(
  "--cases", $Cases,
  "--models", $Models,
  "--workers", "$Workers",
  "--max-investigations", "300",
  "--max-questions", "800",
  "--max-queries", "1600",
  "--max-tokens", "24576",
  "--sql-playbook", "none",
  "--cost-check-usd", "20",
  "--resume",
  "--log-cost"
)

$Ts = Get-Date -Format "yyyyMMdd_HHmmss"
$LogPath = Join-Path $LogDir "replicate_03_$Ts.log"
Write-Host "Starting replicate_03 -> $ResultRoot models=$Models workers=$Workers"
& $Python $Runner "--result-root" $ResultRoot @CommonArgs 2>&1 | Tee-Object -FilePath $LogPath
if ($LASTEXITCODE -ne 0) {
  throw "Runner failed for replicate_03 with exit code $LASTEXITCODE"
}

Write-Host "replicate_03 finished. Log: $LogPath"
