# Remove the SmsNotifier logon task, firewall rule, URL reservation, and helper registrations.
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$TaskName = 'SmsNotifier'
$LegacyTaskName = 'SmsForwarderWebhook'
$Failed = $false

function Test-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Wait-Close {
    Write-Host ''
    [void](Read-Host '按回车键关闭')
}

function Note-Failure([string]$Message) {
    Write-Host $Message
    $script:Failed = $true
}

function Get-ListenPort {
    $path = Join-Path $Root 'config.json'
    try {
        $raw = [System.IO.File]::ReadAllText($path, [System.Text.UTF8Encoding]::new($false))
        $cfg = $raw | ConvertFrom-Json
        $port = [int]$cfg.port
        if ($port -gt 0 -and $port -lt 65536) { return $port }
    } catch {
        Write-Host '未能读取 config.json 的端口，改用 17890。'
    }
    return 17890
}

function Remove-NotifierTask([string]$Name, [switch]$QuietIfMissing) {
    $task = Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
    if (-not $task) {
        if (-not $QuietIfMissing) {
            Write-Host "计划任务 $Name 不存在。"
        }
        return
    }
    foreach ($item in @($task)) {
        if ($item.State -eq 'Running' -or $item.State -eq 'Queued') {
            Stop-ScheduledTask -TaskName $item.TaskName -TaskPath $item.TaskPath -ErrorAction SilentlyContinue
        }
        Unregister-ScheduledTask -TaskName $item.TaskName -TaskPath $item.TaskPath -Confirm:$false
        Write-Host ("已删除计划任务 {0}。" -f $item.TaskName)
    }
}

function Stop-NotifierProcess([switch]$Quiet) {
    $procs = @(Get-CimInstance -ClassName Win32_Process | Where-Object {
        $_.ProcessId -ne $PID -and
        $_.CommandLine -and
        ($_.CommandLine -match '\\SmsNotifier\\server\.ps1' -or $_.CommandLine -match '\\SmsNotifier\\start\.vbs')
    })
    $stopped = $false
    foreach ($proc in $procs) {
        if (-not $proc) { continue }
        try {
            Stop-Process -Id $proc.ProcessId -Force -ErrorAction Stop
            Write-Host ("已结束进程 {0} ({1})。" -f $proc.Name, $proc.ProcessId)
            $stopped = $true
        } catch {
            $stillThere = Get-Process -Id $proc.ProcessId -ErrorAction SilentlyContinue
            if ($stillThere) {
                Note-Failure ("无法结束进程 {0} ({1})。" -f $proc.Name, $proc.ProcessId)
            }
        }
    }
    if (-not $stopped -and -not $Quiet) {
        Write-Host '服务进程未在运行。'
    }
}

function Test-Listening([int]$Port) {
    try {
        $response = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/health" -UseBasicParsing -TimeoutSec 2
        return $response.StatusCode -eq 200
    } catch {
        return $false
    }
}

function Remove-FirewallRule {
    & netsh.exe advfirewall firewall delete rule name="SmsNotifier" | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host '已删除防火墙规则 SmsNotifier。'
    } else {
        Write-Host '防火墙规则 SmsNotifier 不存在。'
    }
}

function Remove-UrlAcl([int]$Port) {
    $prefix = "http://+:$Port/"
    & netsh.exe http delete urlacl url=$prefix | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "已删除 URL 保留 $prefix。"
    } else {
        Write-Host "URL 保留 $prefix 不存在。"
    }
}

function Remove-Shortcut {
    $shortcut = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\短信通知.lnk'
    if (Test-Path -LiteralPath $shortcut) {
        Remove-Item -LiteralPath $shortcut -Force
        Write-Host '已删除开始菜单快捷方式。'
    } else {
        Write-Host '开始菜单快捷方式不存在。'
    }
}

function Remove-CopyProtocol {
    $base = 'HKCU:\Software\Classes\smsnotifier'
    if (Test-Path -LiteralPath $base) {
        Remove-Item -LiteralPath $base -Recurse -Force
        Write-Host '已删除 smsnotifier: 协议。'
    } else {
        Write-Host 'smsnotifier: 协议不存在。'
    }
}

if (-not (Test-Elevated)) {
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    try {
        Start-Process -FilePath $ps -Verb RunAs -ArgumentList @(
            '-NoProfile',
            '-ExecutionPolicy', 'Bypass',
            '-File', $PSCommandPath
        )
        exit 0
    } catch {
        Write-Host '需要管理员权限才能卸载，已取消。'
        Wait-Close
        exit 1
    }
}

try { $Host.UI.RawUI.WindowTitle = '卸载短信通知' } catch {}
$ProgressPreference = 'SilentlyContinue'

Write-Host '正在卸载短信通知服务...'
Write-Host ''

$port = Get-ListenPort

try { Remove-NotifierTask -Name $TaskName } catch { Note-Failure ("删除计划任务失败：{0}" -f $_.Exception.Message) }
try { Remove-NotifierTask -Name $LegacyTaskName -QuietIfMissing } catch { Note-Failure ("删除旧计划任务失败：{0}" -f $_.Exception.Message) }

Start-Sleep -Milliseconds 400
try { Stop-NotifierProcess } catch { Note-Failure ("结束服务进程失败：{0}" -f $_.Exception.Message) }

if (Test-Listening $port) {
    Start-Sleep -Milliseconds 500
    try { Stop-NotifierProcess -Quiet } catch { Note-Failure ("结束服务进程失败：{0}" -f $_.Exception.Message) }
    Start-Sleep -Milliseconds 400
}
if (Test-Listening $port) {
    Note-Failure '服务仍在响应。请在任务管理器中结束对应的 PowerShell 进程后再次运行。'
}

try { Remove-FirewallRule } catch { Note-Failure ("删除防火墙规则失败：{0}" -f $_.Exception.Message) }
try { Remove-UrlAcl -Port $port } catch { Note-Failure ("删除 URL 保留失败：{0}" -f $_.Exception.Message) }
try { Remove-Shortcut } catch { Note-Failure ("删除快捷方式失败：{0}" -f $_.Exception.Message) }
try { Remove-CopyProtocol } catch { Note-Failure ("删除协议注册失败：{0}" -f $_.Exception.Message) }

Write-Host ''
if ($Failed) {
    Write-Host '卸载未全部完成。'
    Wait-Close
    exit 1
}

Write-Host '卸载完成。'
Write-Host '程序文件仍保留在当前目录，确认不再使用后可手动删除整个文件夹。'
Wait-Close
exit 0
