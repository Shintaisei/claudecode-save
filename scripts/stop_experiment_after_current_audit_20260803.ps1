param(
    [Parameter(Mandatory = $true)]
    [string]$ResultRoot,
    [Parameter(Mandatory = $true)]
    [int]$ExperimentParentPid,
    [Parameter(Mandatory = $true)]
    [int]$TargetAuditCount
)

$ErrorActionPreference = "Stop"
$resolvedRoot = (Resolve-Path -LiteralPath $ResultRoot).Path
$deadline = (Get-Date).AddHours(2)

while ((Get-Date) -lt $deadline) {
    $auditCount = @(
        Get-ChildItem -LiteralPath $resolvedRoot -Recurse -Filter "*.json" |
            Where-Object { $_.DirectoryName -match "\\audits\\" }
    ).Count
    if ($auditCount -ge $TargetAuditCount) {
        $children = @(
            Get-CimInstance Win32_Process |
                Where-Object { $_.ParentProcessId -eq $ExperimentParentPid }
        )
        Stop-Process -Id $ExperimentParentPid -Force -ErrorAction SilentlyContinue
        foreach ($child in $children) {
            if ($child.CommandLine -match "run_clouseau_official_cbc_dense_eval\.py") {
                Stop-Process -Id $child.ProcessId -Force -ErrorAction SilentlyContinue
            }
        }
        [pscustomobject]@{
            stopped_at = (Get-Date).ToString("o")
            parent_pid = $ExperimentParentPid
            audit_count = $auditCount
            stopped_child_pids = @($children.ProcessId)
            status = "PAUSED_AFTER_REQUESTED_CURRENT_RUN"
        } | ConvertTo-Json -Depth 4
        exit 0
    }
    if (-not (Get-Process -Id $ExperimentParentPid -ErrorAction SilentlyContinue)) {
        [pscustomobject]@{
            stopped_at = (Get-Date).ToString("o")
            parent_pid = $ExperimentParentPid
            audit_count = $auditCount
            status = "PARENT_EXITED_BEFORE_TARGET"
        } | ConvertTo-Json -Depth 4
        exit 2
    }
    Start-Sleep -Milliseconds 250
}

[pscustomobject]@{
    stopped_at = (Get-Date).ToString("o")
    parent_pid = $ExperimentParentPid
    audit_count = $auditCount
    status = "WATCHER_TIMEOUT"
} | ConvertTo-Json -Depth 4
exit 3
