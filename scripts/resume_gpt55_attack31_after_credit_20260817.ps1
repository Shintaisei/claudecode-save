$ErrorActionPreference = 'Stop'

$workspaceRoot = Split-Path -Parent $PSScriptRoot
$smokeScript = Join-Path $PSScriptRoot 'test_clouseau_api_smoke.py'
$retryScript = Join-Path $PSScriptRoot 'retry_gpt55_normal_attack8_three_replicates_20260807.py'
$envFile = Join-Path $workspaceRoot '.env.clouseau'

if (-not (Test-Path -LiteralPath $envFile -PathType Leaf)) {
    throw "Missing API configuration: $envFile"
}

Push-Location $workspaceRoot
try {
    Write-Host 'Checking GPT-5.5 API credit with one minimal request...'
    & python $smokeScript --env-file $envFile --model 'gpt-5.5' --prompt 'Reply with exactly: OK'
    if ($LASTEXITCODE -ne 0) {
        throw 'GPT-5.5 API smoke test failed. The attack experiment was not started.'
    }

    Write-Host 'Credit check passed. Starting the 31 remaining attack runs...'
    & python $retryScript --run --phase attack8
    if ($LASTEXITCODE -ne 0) {
        throw 'GPT-5.5 attack retry stopped with an error. Inspect the retry audit before another attempt.'
    }
}
finally {
    Pop-Location
}
