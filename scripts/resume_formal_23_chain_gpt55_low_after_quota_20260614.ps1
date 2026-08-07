param(
  [int]$Workers = 1,
  [int]$BatchLimit = 20,
  [int]$MinBatchSize = 10
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Python = "python"
$Runner = Join-Path $Root "src\clouseau_process_time\run_formal_27_chain_run_only_parallel_guarded.py"
$Cases = Join-Path $Root "data\current_experiment\cases\cbc_23_chain_stage_cases_2026-06-12.jsonl"
$BaseResult = Join-Path $Root "docs\current_experiment\results_2026-06-09\formal_23_chain_gpt55_low_3rep_20260613"
$LogDir = Join-Path $BaseResult "_logs"
$PrepareQueue = Join-Path $Root "scripts\prepare_formal_23_chain_gpt55_low_review_queue_20260613.py"
$Summarize = Join-Path $Root "scripts\summarize_formal_23_chain_gpt55_low_3rep_progress_20260613.py"
$Smoke = Join-Path $Root "scripts\test_clouseau_api_smoke.py"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

Write-Host "Checking OpenAI quota with a minimal gpt-5.5 call..."
& $Python $Smoke --model gpt-5.5 --prompt "Reply with exactly: OK"
if ($LASTEXITCODE -ne 0) {
  throw "OpenAI quota/model smoke test failed. Update billing/quota or .env.clouseau OPENAI_API_KEY before resuming."
}

$CommonArgs = @(
  "--cases", $Cases,
  "--models", "gpt-5.5",
  "--workers", "$Workers",
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

foreach ($Rep in @("replicate_02", "replicate_03")) {
  $ResultRoot = Join-Path $BaseResult $Rep
  New-Item -ItemType Directory -Force -Path $ResultRoot | Out-Null
  $Ts = Get-Date -Format "yyyyMMdd_HHmmss"
  $LogPath = Join-Path $LogDir "$Rep.resume_after_quota_$Ts.log"
  Write-Host "Resuming $Rep with $Workers worker(s)..."
  & $Python $Runner "--result-root" $ResultRoot @CommonArgs 2>&1 | Tee-Object -FilePath $LogPath
  if ($LASTEXITCODE -ne 0) {
    throw "Runner failed for $Rep with exit code $LASTEXITCODE"
  }

  Write-Host "Preparing review queue after $Rep..."
  & $Python $PrepareQueue --limit $BatchLimit --min-batch-size $MinBatchSize
  if ($LASTEXITCODE -ne 0) {
    throw "Review queue preparation failed after $Rep"
  }
}

Write-Host "Preparing final small review batch if needed..."
& $Python $PrepareQueue --limit $BatchLimit --min-batch-size $MinBatchSize --flush-small-batch
if ($LASTEXITCODE -ne 0) {
  throw "Final review queue preparation failed"
}

Write-Host "Current experiment progress:"
& $Python $Summarize
