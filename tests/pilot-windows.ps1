# A native Windows audit rehearsal using only disposable control files.
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'Run this audit-policy rehearsal on a disposable GitHub-hosted Windows VM.'
}
$root = Join-Path $env:RUNNER_TEMP ('arachne-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
$backup = Join-Path $root 'audit-policy.csv'
$auditSubcategory = '{0CCE921D-69AE-11D9-BED3-505054503030}'
& auditpol.exe /backup "/file:$backup" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not back up Windows audit policy.' }
try {
    & auditpol.exe /set "/subcategory:$auditSubcategory" /success:enable | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not enable Windows file-system auditing.' }
    $fixture = Join-Path $root 'fixtures'
    New-Item -ItemType Directory -Path $fixture | Out-Null
    $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = Get-Acl -LiteralPath $fixture -Audit
    $auditRule = [System.Security.AccessControl.FileSystemAuditRule]::new(
        $sid, [System.Security.AccessControl.FileSystemRights]'WriteData, AppendData',
        [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
        [System.Security.AccessControl.PropagationFlags]::InheritOnly,
        [System.Security.AccessControl.AuditFlags]::Success
    )
    $acl.AddAuditRule($auditRule)
    Set-Acl -LiteralPath $fixture -AclObject $acl

    $cases = @(
        @{ id='routine'; count=3; approved=3; expected=$false },
        @{ id='approved-batch'; count=25; approved=25; expected=$false },
        @{ id='unapproved-batch'; count=25; approved=0; expected=$true },
        @{ id='out-of-scope-batch'; count=25; approved=24; expected=$true }
    )
    $writer = Join-Path $root 'writer.py'
    @'
import pathlib
import sys

folder = pathlib.Path(sys.argv[1])
for entry in sorted(folder.iterdir()):
    with entry.open("ab") as out:
        out.write(b"benign audit control\n")
'@ | Set-Content -LiteralPath $writer -Encoding utf8
    $python = (Get-Command python).Source
    foreach ($case in $cases) {
        $case.folder = Join-Path $fixture $case.id
        New-Item -ItemType Directory -Path $case.folder | Out-Null
        $case.paths = @(for ($i=0; $i -lt $case.count; $i++) {
            $file = Join-Path $case.folder ('file-{0:D3}.txt' -f $i)
            Set-Content -LiteralPath $file -Value 'benign control'
            $file.ToLowerInvariant()
        })
    }

    $started = Get-Date
    foreach ($case in $cases) {
        $process = Start-Process -FilePath $python -ArgumentList @(('"' + $writer + '"'), ('"' + $case.folder + '"')) -PassThru -Wait
        if ($process.ExitCode -ne 0) { throw "Windows control workload failed: $($case.id)" }
        $case.pid = $process.Id
    }
    $coverage = @{}
    for ($attempt=0; $attempt -lt 24; $attempt++) {
        $coverage = @{}
        foreach ($case in $cases) { $coverage[$case.id] = @{} }
        $records = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663; StartTime=$started} -ErrorAction SilentlyContinue)
        foreach ($record in $records) {
            $payload = @{}
            foreach ($field in ([xml]$record.ToXml()).Event.EventData.Data) {
                $payload[$field.Name] = [string]$field.'#text'
            }
            if ($payload.ObjectType -ne 'File' -or $payload.ProcessId -notmatch '^0x[0-9a-f]+$' -or
                $payload.AccessMask -notmatch '^0x[0-9a-f]+$' -or -not $payload.ObjectName) { continue }
            $mask = [Convert]::ToUInt32($payload.AccessMask.Substring(2), 16)
            if (($mask -band 6) -eq 0) { continue }
            $pidValue = [Convert]::ToUInt32($payload.ProcessId.Substring(2), 16)
            $path = $payload.ObjectName.ToLowerInvariant()
            foreach ($case in $cases) {
                if ($pidValue -eq $case.pid -and $path -in $case.paths) {
                    $coverage[$case.id][$path] = @{path=$path; record_id=$record.RecordId}
                }
            }
        }
        $incomplete = @($cases | Where-Object { $coverage[$_.id].Count -ne $_.count })
        if ($incomplete.Count -eq 0) { break }
        Start-Sleep -Milliseconds 500
    }
    $data = foreach ($case in $cases) {
        Write-Host ("{0}: Windows 4663 covered {1}/{2} control files" -f $case.id,$coverage[$case.id].Count,$case.count)
        @{
            id=$case.id; threshold=20; expected_escalation=$case.expected
            written_paths=@($case.paths); approval=@($case.paths | Select-Object -First $case.approved)
            writes=@($coverage[$case.id].Values)
        }
    }
    $result = Join-Path $root 'trial.json'
    ConvertTo-Json -InputObject @($data) -Depth 6 | Set-Content -LiteralPath $result -Encoding utf8
    & $python -c "import runpy; runpy.run_path('tests/windows_pilot_score.py', run_name='__main__')" $result
    if ($LASTEXITCODE -ne 0) { throw 'Windows pilot scoring failed.' }
}
finally {
    & auditpol.exe /restore "/file:$backup" | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Remove-Item -LiteralPath $root -Recurse -Force
    } else {
        throw "Could not restore audit policy. Backup: $backup"
    }
}
