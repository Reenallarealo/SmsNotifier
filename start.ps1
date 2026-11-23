# Start SmsNotifier, make sure it runs at logon, and show connection information.
param(
    [switch]$InstallOnly,
    [int]$Port = 0,
    [switch]$SetStaticIp,
    [string]$IpAlias = '',
    [string]$IpAddress = '',
    [string]$Mask = '',
    [string]$Gateway = '',
    [string]$DnsList = ''
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$TaskName = 'SmsNotifier'
$GuideUrl = 'https://github.com/Reenallarealo/SmsNotifier'

function Test-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Read-Config {
    $path = Join-Path $Root 'config.json'
    if (-not (Test-Path -LiteralPath $path)) {
        return [pscustomobject]@{
            port = 17890
            path = '/webhook'
            token = ''
            dedupeSeconds = 5
            listenPath = '/webhook'
        }
    }
    $raw = [System.IO.File]::ReadAllText($path, [System.Text.UTF8Encoding]::new($false))
    try {
        $cfg = $raw | ConvertFrom-Json
    } catch {
        Write-Host ''
        Write-Host '  config.json 格式有误，无法读取。' -ForegroundColor Red
        Write-Host ('  ' + $path) -ForegroundColor DarkGray
        Write-Host '  请修正该文件，或删除后重新运行 启动.bat。' -ForegroundColor DarkGray
        exit 1
    }
    if (-not $cfg) { $cfg = [pscustomobject]@{} }
    if (-not $cfg.port) { $cfg | Add-Member -NotePropertyName port -NotePropertyValue 17890 -Force }
    if (-not $cfg.path) { $cfg | Add-Member -NotePropertyName path -NotePropertyValue '/webhook' -Force }
    if (-not ($cfg.PSObject.Properties.Name -contains 'token')) {
        $cfg | Add-Member -NotePropertyName token -NotePropertyValue '' -Force
    }
    if (-not ($cfg.PSObject.Properties.Name -contains 'dedupeSeconds')) {
        $cfg | Add-Member -NotePropertyName dedupeSeconds -NotePropertyValue 5 -Force
    }
    if (-not ($cfg.PSObject.Properties.Name -contains 'logEnabled')) {
        $cfg | Add-Member -NotePropertyName logEnabled -NotePropertyValue $false -Force
    }
    $listenPath = [string]$cfg.path
    if (-not $listenPath.StartsWith('/')) { $listenPath = "/$listenPath" }
    if ($listenPath.Length -gt 1) { $listenPath = $listenPath.TrimEnd('/') }
    $cfg | Add-Member -NotePropertyName listenPath -NotePropertyValue $listenPath -Force
    return $cfg
}

function Save-Config($Config) {
    $path = Join-Path $Root 'config.json'
    $obj = [ordered]@{
        port = [int]$Config.port
        path = [string]$Config.path
        token = [string]$Config.token
        dedupeSeconds = [int]$Config.dedupeSeconds
        logEnabled = [bool]$Config.logEnabled
    }
    $json = $obj | ConvertTo-Json
    [System.IO.File]::WriteAllText($path, $json.Trim() + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
}

function Test-UserConfigured($Config) {
    return ([string]$Config.token).Trim().Length -ge 16
}

function New-NotifierToken {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    return ([System.BitConverter]::ToString($bytes) -replace '-', '').ToLower()
}

function ConvertTo-SubnetMask([int]$PrefixLength) {
    $bits = ('1' * $PrefixLength).PadRight(32, '0')
    $value = [Convert]::ToUInt32($bits, 2)
    $bytes = [System.BitConverter]::GetBytes($value)
    [Array]::Reverse($bytes)
    return ($bytes[0..3] -join '.')
}

function Test-IPv4([string]$Text) {
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($Text, [ref]$parsed)) { return $false }
    return $parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork
}

function Get-LanAdapter {
    $items = New-Object System.Collections.Generic.List[object]
    try {
        $configs = @(Get-NetIPConfiguration -ErrorAction SilentlyContinue)
    } catch {
        return @()
    }
    foreach ($item in $configs) {
        if (-not $item) { continue }
        $mac = ''
        if ($item.NetAdapter) { $mac = [string]$item.NetAdapter.MacAddress }
        $gateway = ''
        foreach ($hop in @($item.IPv4DefaultGateway)) {
            if ($hop -and $hop.NextHop) { $gateway = [string]$hop.NextHop; break }
        }
        $dns = New-Object System.Collections.Generic.List[string]
        foreach ($entry in @($item.DNSServer)) {
            if (-not $entry) { continue }
            foreach ($server in @($entry.ServerAddresses)) {
                if ((Test-IPv4 $server) -and -not $dns.Contains($server)) { $dns.Add($server) }
            }
        }
        foreach ($addr in @($item.IPv4Address)) {
            if (-not $addr) { continue }
            $ip = [string]$addr.IPAddress
            $parsed = $null
            if (-not [System.Net.IPAddress]::TryParse($ip, [ref]$parsed)) { continue }
            $raw = $parsed.GetAddressBytes()
            $skip = ($raw[0] -eq 127) -or ($raw[0] -eq 169 -and $raw[1] -eq 254) -or ($raw[0] -eq 198 -and ($raw[1] -eq 18 -or $raw[1] -eq 19))
            $prefix = [int]$addr.PrefixLength
            if ($skip -or $prefix -le 0 -or $prefix -gt 32) { continue }
            $items.Add([pscustomobject]@{
                Alias = [string]$item.InterfaceAlias
                IP = $ip
                Prefix = $prefix
                Mask = (ConvertTo-SubnetMask $prefix)
                Gateway = $gateway
                Mac = $mac
                Dns = ($dns.ToArray() -join ',')
                HasGateway = [bool]$gateway
            })
        }
    }
    return @($items | Sort-Object @{ Expression = { -not $_.HasGateway } }, Alias, IP)
}

function Invoke-Netsh([string]$Arguments) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = Join-Path $env:SystemRoot 'System32\netsh.exe'
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $proc = [System.Diagnostics.Process]::Start($psi)
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    $text = (($stdout + [Environment]::NewLine + $stderr).Trim())
    if ($proc.ExitCode -ne 0 -and $text) {
        $log = Join-Path $env:TEMP 'SmsNotifier-static-ip.log'
        [System.IO.File]::AppendAllText($log, $text + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
    }
    return [int]$proc.ExitCode
}

function Enable-StaticIp([string]$Alias, [string]$Address, [string]$Mask, [string]$Gateway, [string]$DnsList) {
    if ($Gateway -eq 'none') { $Gateway = '' }
    if ($DnsList -eq 'none') { $DnsList = '' }
    $dns = New-Object System.Collections.Generic.List[string]
    foreach ($server in @($DnsList -split ',')) {
        $server = $server.Trim()
        if ((Test-IPv4 $server) -and -not $dns.Contains($server)) { $dns.Add($server) }
    }
    if ($dns.Count -eq 0 -and (Test-IPv4 $Gateway)) { $dns.Add($Gateway) }

    $addressArgs = 'interface ipv4 set address name="{0}" source=static address={1} mask={2}' -f $Alias, $Address, $Mask
    if ($Gateway) { $addressArgs += (' gateway={0}' -f $Gateway) }
    $code = Invoke-Netsh $addressArgs
    if ($code -ne 0) { return $code }
    if ($dns.Count -gt 0) {
        $code = Invoke-Netsh ('interface ipv4 set dnsservers name="{0}" source=static address={1} validate=no' -f $Alias, $dns[0])
        if ($code -ne 0) { return $code }
        for ($i = 1; $i -lt $dns.Count; $i++) {
            $code = Invoke-Netsh ('interface ipv4 add dnsservers name="{0}" address={1} index={2} validate=no' -f $Alias, $dns[$i], ($i + 1))
            if ($code -ne 0) { return $code }
        }
    }
    foreach ($try in 1..5) {
        $now = Get-NetIPAddress -InterfaceAlias $Alias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -eq $Address }
        if ($now) { return 0 }
        Start-Sleep -Milliseconds 300
    }
    return 1
}

function Invoke-ElevatedStaticIp($Adapter) {
    $log = Join-Path $env:TEMP 'SmsNotifier-static-ip.log'
    if (Test-Path -LiteralPath $log) { Remove-Item -LiteralPath $log -Force }
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $gatewayArg = if ($Adapter.Gateway) { $Adapter.Gateway } else { 'none' }
    $dnsArg = if ([string]$Adapter.Dns) { [string]$Adapter.Dns } else { 'none' }
    try {
        $proc = Start-Process -FilePath $ps -Verb RunAs -Wait -PassThru -ArgumentList @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath,
            '-SetStaticIp',
            '-IpAlias', $Adapter.Alias,
            '-IpAddress', $Adapter.IP,
            '-Mask', $Adapter.Mask,
            '-Gateway', $gatewayArg,
            '-DnsList', $dnsArg
        )
    } catch {
        Write-Host '未获得管理员权限，IP 未修改。'
        return
    }
    if ($proc -and $proc.ExitCode -eq 0) {
        Write-Host '已把当前地址设为静态 IP。'
        return
    }
    Write-Host '静态 IP 设置失败，可以改在路由器里绑定 MAC。'
    if (Test-Path -LiteralPath $log) {
        $detail = [System.IO.File]::ReadAllText($log, [System.Text.UTF8Encoding]::new($false)).Trim()
        if ($detail) { Write-Host $detail }
    }
}

function Test-Autostart {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $task) { return $false }
    $logon = $false
    foreach ($trigger in @($task.Triggers)) {
        if ($trigger.CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger' -and $trigger.Enabled) {
            $logon = $true
        }
    }
    $execute = [string]$task.Actions[0].Execute
    $argument = [string]$task.Actions[0].Arguments
    $expected = Join-Path $Root 'start.vbs'
    return $logon -and ($execute -match 'wscript\.exe$') -and ($argument -like ('*' + $expected + '*'))
}

function Install-Autostart([int]$ListenPort) {
    $user = "$env:USERDOMAIN\$env:USERNAME"
    $prefix = "http://+:$ListenPort/"
    netsh http delete urlacl url=$prefix | Out-Null
    netsh http add urlacl url=$prefix user=$user | Out-Null
    netsh advfirewall firewall delete rule name="SmsNotifier" | Out-Null
    netsh advfirewall firewall add rule name="SmsNotifier" dir=in action=allow protocol=TCP localport=$ListenPort profile=any | Out-Null

    Unregister-ScheduledTask -TaskName 'SmsForwarderWebhook' -Confirm:$false -ErrorAction SilentlyContinue
    $vbs = Join-Path $Root 'start.vbs'
    $action = New-ScheduledTaskAction `
        -Execute (Join-Path $env:SystemRoot 'System32\wscript.exe') `
        -Argument ('//B //Nologo "{0}"' -f $vbs) `
        -WorkingDirectory $Root
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -MultipleInstances IgnoreNew `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $taskPrincipal -Settings $settings -Force | Out-Null
}

function Ensure-Autostart([int]$ListenPort) {
    if (Test-Autostart) { return $true }
    if (Test-Elevated) {
        try {
            Install-Autostart -ListenPort $ListenPort
            return $true
        } catch {
            return $false
        }
    }
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    try {
        $proc = Start-Process -FilePath $ps -Verb RunAs -Wait -PassThru -ArgumentList @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath,
            '-InstallOnly', '-Port', $ListenPort
        )
    } catch {
        return $false
    }
    if (-not $proc -or $proc.ExitCode -ne 0) { return $false }
    return $true
}

function Test-Listening([int]$ListenPort) {
    try {
        $response = Invoke-WebRequest -Uri "http://127.0.0.1:$ListenPort/health" -UseBasicParsing -TimeoutSec 2
        return $response.StatusCode -eq 200
    } catch {
        return $false
    }
}

function Stop-RunningServer {
    $serverPath = [regex]::Escape((Join-Path $Root 'server.ps1'))
    $vbsPath = [regex]::Escape((Join-Path $Root 'start.vbs'))
    $procs = @(Get-CimInstance -ClassName Win32_Process | Where-Object {
        $_.ProcessId -ne $PID -and $_.CommandLine -and (
            $_.CommandLine -match $serverPath -or
            $_.CommandLine -match $vbsPath
        )
    })
    foreach ($proc in $procs) {
        if (-not $proc) { continue }
        Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 400
}

function Test-ServerOutdated {
    $serverPath = Join-Path $Root 'server.ps1'
    if (-not (Test-Path -LiteralPath $serverPath)) { return $false }
    $fileTime = (Get-Item -LiteralPath $serverPath).LastWriteTime
    $escaped = [regex]::Escape($serverPath)
    $procs = @(Get-CimInstance -ClassName Win32_Process | Where-Object {
        $_.ProcessId -ne $PID -and $_.CommandLine -and $_.CommandLine -match $escaped
    })
    foreach ($proc in $procs) {
        if (-not $proc) { continue }
        $started = $proc.CreationDate
        if ($started -and $started -lt $fileTime.AddSeconds(-5)) { return $true }
    }
    return $false
}

function Start-Server([int]$ListenPort) {
    if (Test-Listening $ListenPort) {
        if (-not (Test-ServerOutdated)) { return $true }
        Stop-RunningServer
        foreach ($try in 1..10) {
            if (-not (Test-Listening $ListenPort)) { break }
            Start-Sleep -Milliseconds 300
        }
    }
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task -and (Test-Autostart) -and $task.State -ne 'Running') {
        Start-ScheduledTask -TaskName $TaskName
    } else {
        Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\wscript.exe') -ArgumentList '//B', '//Nologo', (Join-Path $Root 'start.vbs') -WindowStyle Hidden
    }
    foreach ($try in 1..20) {
        Start-Sleep -Milliseconds 500
        if (Test-Listening $ListenPort) { return $true }
    }
    return $false
}

function Test-InteractiveConsole {
    try {
        if ([Console]::IsInputRedirected) { return $false }
        if ([Console]::IsOutputRedirected) { return $false }
        if ($Host.Name -ne 'ConsoleHost') { return $false }
        $null = [Console]::WindowWidth
        $null = [Console]::WindowHeight
        return $true
    } catch {
        return $false
    }
}

function Get-DisplayWidth([string]$Text) {
    $width = 0
    foreach ($ch in $Text.ToCharArray()) {
        $code = [int]$ch
        if (($code -ge 0x1100 -and $code -le 0x115F) -or
            ($code -ge 0x2E80 -and $code -le 0xA4CF) -or
            ($code -ge 0xAC00 -and $code -le 0xD7A3) -or
            ($code -ge 0xF900 -and $code -le 0xFAFF) -or
            ($code -ge 0xFE30 -and $code -le 0xFE6F) -or
            ($code -ge 0xFF00 -and $code -le 0xFF60) -or
            ($code -ge 0xFFE0 -and $code -le 0xFFE6)) {
            $width += 2
        } else {
            $width += 1
        }
    }
    return $width
}

function Clear-Screen {
    try { Clear-Host } catch { }
}

function Show-Banner {
    Write-Host ''
    Write-Host '  短信通知' -ForegroundColor White
    Write-Host ''
}

function Write-StatusLine {
    param(
        [string]$Label,
        [string]$Value,
        [ConsoleColor]$ValueColor = [ConsoleColor]::White
    )
    $target = 12
    $pad = $target - (Get-DisplayWidth $Label)
    if ($pad -lt 0) { $pad = 0 }
    Write-Host ('  ' + $Label + (' ' * $pad)) -ForegroundColor DarkGray -NoNewline
    Write-Host $Value -ForegroundColor $ValueColor
}

function Read-MenuByNumber {
    param(
        [string[]]$Items,
        [int]$StartIndex = 0
    )
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $mark = ' '
        if ($i -eq $StartIndex) { $mark = '>' }
        Write-Host ('  {0} {1}. {2}' -f $mark, ($i + 1), $Items[$i])
    }
    while ($true) {
        $text = Read-Host '请输入数字'
        $number = 0
        if ([int]::TryParse([string]$text, [ref]$number) -and $number -ge 1 -and $number -le $Items.Count) {
            return ($number - 1)
        }
        Write-Host '请输入上面列出的数字。'
    }
}

function Read-Menu {
    param(
        [string[]]$Items,
        [int]$StartIndex = 0,
        [string]$Hint = '[↑↓] 移动    [Enter] 确认    [Esc] 返回'
    )
    if ($Items.Count -eq 0) { return -1 }
    if (-not (Test-InteractiveConsole)) {
        return (Read-MenuByNumber $Items $StartIndex)
    }

    $selected = $StartIndex
    if ($selected -lt 0) { $selected = 0 }
    if ($selected -ge $Items.Count) { $selected = $Items.Count - 1 }

    $top = 0
    try { $top = [Console]::CursorTop } catch { $top = 0 }
    $left = 0
    $cursorWasVisible = $true
    try { $cursorWasVisible = [Console]::CursorVisible } catch { }
    try { [Console]::CursorVisible = $false } catch { }

    try {
        $maxWidth = 60
        try {
            $windowWidth = [Console]::WindowWidth
            if ($windowWidth -gt 2) {
                $maxWidth = [Math]::Min($maxWidth, $windowWidth - 2)
            }
        } catch { }

        while ($true) {
            for ($i = 0; $i -lt $Items.Count; $i++) {
                try { [Console]::SetCursorPosition($left, $top + $i) } catch { break }
                $prefix = '    '
                if ($i -eq $selected) { $prefix = '  > ' }
                $text = $prefix + $Items[$i]
                $pad = $maxWidth - (Get-DisplayWidth $text)
                if ($pad -lt 0) { $pad = 0 }
                $line = $text + (' ' * $pad)
                if ($i -eq $selected) {
                    Write-Host $line -ForegroundColor Cyan -NoNewline
                } else {
                    Write-Host $line -ForegroundColor Gray -NoNewline
                }
            }

            try {
                [Console]::SetCursorPosition($left, $top + $Items.Count + 1)
                Write-Host $Hint -ForegroundColor DarkGray
            } catch { }

            $key = [Console]::ReadKey($true)
            if ($key.Key -eq [ConsoleKey]::UpArrow) {
                if ($selected -gt 0) { $selected-- }
            } elseif ($key.Key -eq [ConsoleKey]::DownArrow) {
                if ($selected -lt ($Items.Count - 1)) { $selected++ }
            } elseif ($key.Key -eq [ConsoleKey]::Enter) {
                try { [Console]::SetCursorPosition($left, $top + $Items.Count + 2) } catch { }
                return $selected
            } elseif ($key.Key -eq [ConsoleKey]::Escape) {
                try { [Console]::SetCursorPosition($left, $top + $Items.Count + 2) } catch { }
                return -1
            }
        }
    } finally {
        try { [Console]::CursorVisible = $cursorWasVisible } catch { }
    }
}

function Wait-AnyKey {
    param([string]$Prompt = '按任意键返回')
    Write-Host ''
    Write-Host ('  ' + $Prompt) -ForegroundColor DarkGray
    if (Test-InteractiveConsole) {
        try { [void][Console]::ReadKey($true) } catch { [void](Read-Host) }
    } else {
        [void](Read-Host)
    }
}

function Read-ConfirmMenu {
    param(
        [string]$Prompt,
        [bool]$DefaultYes = $false
    )
    Write-Host ('  ' + $Prompt) -ForegroundColor White
    Write-Host ''
    $items = @('否', '是')
    $start = 0
    if ($DefaultYes) { $start = 1 }
    $choice = Read-Menu $items $start '[↑↓] 选择    [Enter] 确认    [Esc] 取消'
    return ($choice -eq 1)
}

function Open-GuidePage {
    try {
        Start-Process $GuideUrl | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Show-StatusPanel {
    param($Config)
    Clear-Screen
    Show-Banner
    $running = Test-Listening ([int]$Config.port)
    $adapters = @(Get-LanAdapter)
    $ip = '未检测到'
    if ($adapters.Count -gt 0) { $ip = $adapters[0].IP }
    $token = [string]$Config.token
    $masked = '已保存'
    if ($token.Length -ge 8) {
        $masked = $token.Substring(0, 4) + '...' + $token.Substring($token.Length - 4)
    }
    if ($running) {
        Write-StatusLine '服务' ('运行中 · 端口 ' + $Config.port) ([ConsoleColor]::Green)
    } else {
        Write-StatusLine '服务' '未运行' ([ConsoleColor]::Yellow)
    }
    Write-StatusLine '电脑 IP' $ip ([ConsoleColor]::White)
    Write-StatusLine '密钥' ('已保存 · ' + $masked) ([ConsoleColor]::Gray)
    if ([bool]$Config.logEnabled) {
        Write-StatusLine '日志' '开启' ([ConsoleColor]::Green)
    } else {
        Write-StatusLine '日志' '关闭' ([ConsoleColor]::DarkGray)
    }
    Write-Host ''
    Write-Host '  ────────────────────────────────────────────' -ForegroundColor DarkGray
    Write-Host ''
}

function Show-FirstRunPanel {
    param($Config, [bool]$AutostartOk, [bool]$ServiceOk)
    Clear-Screen
    Show-Banner
    Write-Host '  首次配置完成，密钥已保存。' -ForegroundColor Green
    Write-Host ''
    $adapters = @(Get-LanAdapter)
    if ($adapters.Count -eq 0) {
        Write-Host '  未检测到局域网地址。' -ForegroundColor Yellow
        Write-Host '  请先连接 Wi-Fi 或网线，再重新双击 启动.bat。' -ForegroundColor DarkGray
    } else {
        $adapter = $adapters[0]
        Write-Host '  电脑 IP 地址' -ForegroundColor DarkGray
        Write-Host ('    ' + $adapter.IP + '  ' + $adapter.Alias + '  推荐') -ForegroundColor White
        Write-Host ('    http://' + $adapter.IP + ':' + $Config.port + $Config.listenPath) -ForegroundColor Gray
        if ($adapters.Count -gt 1) {
            Write-Host '    检测到多个地址，可在菜单中查看全部。' -ForegroundColor DarkGray
        }
    }
    Write-Host ''
    Write-Host '  密钥' -ForegroundColor DarkGray
    Write-Host ('    ' + $Config.token) -ForegroundColor White
    Write-Host ''
    Write-Host '  手机端 Headers' -ForegroundColor DarkGray
    Write-Host ('    Authorization: Bearer ' + $Config.token) -ForegroundColor White
    Write-Host ''
    if ($ServiceOk) {
        Write-Host '  服务已启动。' -ForegroundColor Green
    } else {
        Write-Host '  服务未启动，请查看 logs\server.log。' -ForegroundColor Yellow
    }
    if (-not $AutostartOk) {
        Write-Host '  开机自启未安装，重启后需要再次双击 启动.bat。' -ForegroundColor Yellow
    }
    Write-Host ''
    Write-Host '  使用教程' -ForegroundColor DarkGray
    Write-Host ('    ' + $GuideUrl) -ForegroundColor Gray
    Write-Host ''
    Write-Host '  仅在可信局域网使用。' -ForegroundColor DarkGray
    Write-Host ''
}

function Show-SecretPage {
    param($Config)
    Clear-Screen
    Show-Banner
    Write-Host '  密钥' -ForegroundColor Cyan
    Write-Host ''
    Write-Host ('  ' + $Config.token) -ForegroundColor White
    Write-Host ''
    Write-Host '  手机端 Headers' -ForegroundColor DarkGray
    Write-Host ('  Authorization: Bearer ' + $Config.token) -ForegroundColor White
    Write-Host ''
    Write-Host '  请勿在公共环境展示。' -ForegroundColor DarkGray
    Wait-AnyKey
}

function Show-LanPage {
    param($Config)
    Clear-Screen
    Show-Banner
    Write-Host '  电脑 IP 地址' -ForegroundColor Cyan
    Write-Host ''
    $adapters = @(Get-LanAdapter)
    if ($adapters.Count -eq 0) {
        Write-Host '  没有检测到可用的局域网地址。' -ForegroundColor Yellow
        Write-Host '  请先连接 Wi-Fi 或网线。' -ForegroundColor DarkGray
        Wait-AnyKey
        return
    }
    $recommendedIp = $adapters[0].IP
    foreach ($adapter in $adapters) {
        $mark = ''
        if ($adapter.IP -eq $recommendedIp) { $mark = '  推荐' }
        Write-Host ('  ' + $adapter.IP + '  ' + $adapter.Alias + $mark) -ForegroundColor White
        Write-Host ('  http://' + $adapter.IP + ':' + $Config.port + $Config.listenPath) -ForegroundColor Gray
        Write-Host ''
    }
    Write-Host '  手机要填的是与电脑同一个 Wi-Fi 的那个地址。' -ForegroundColor DarkGray
    Wait-AnyKey
}

function Invoke-RegenerateSecret {
    param($Config)
    Clear-Screen
    Show-Banner
    Write-Host '  重新生成密钥' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  旧密钥会立即失效，手机端的 Authorization 需要同步更新。' -ForegroundColor Gray
    Write-Host '  服务将自动重启。' -ForegroundColor Gray
    Write-Host ''
    if (-not (Read-ConfirmMenu '是否继续？' $false)) {
        return $Config
    }

    $Config.token = New-NotifierToken
    Save-Config $Config

    $restarted = $false
    if (Test-Listening ([int]$Config.port)) {
        Stop-RunningServer
        $restarted = Start-Server -ListenPort ([int]$Config.port)
    }

    Clear-Screen
    Show-Banner
    Write-Host '  已生成新密钥' -ForegroundColor Green
    Write-Host ''
    Write-Host ('  ' + $Config.token) -ForegroundColor White
    Write-Host ''
    Write-Host '  手机端 Headers' -ForegroundColor DarkGray
    Write-Host ('  Authorization: Bearer ' + $Config.token) -ForegroundColor White
    Write-Host ''
    if ($restarted) {
        Write-Host '  服务已重启。' -ForegroundColor Green
    } elseif (Test-Listening ([int]$Config.port)) {
        Write-Host '  服务正在运行，新密钥已生效。' -ForegroundColor Green
    } else {
        Write-Host '  服务当前未运行，新密钥将在下次启动时生效。' -ForegroundColor Yellow
    }
    Write-Host '  请到手机端更新 Header。' -ForegroundColor DarkGray
    Wait-AnyKey
    return $Config
}

function Invoke-ToggleLog {
    param($Config)
    $Config.logEnabled = -not [bool]$Config.logEnabled
    Save-Config $Config

    $restarted = $false
    if (Test-Listening ([int]$Config.port)) {
        Stop-RunningServer
        $restarted = Start-Server -ListenPort ([int]$Config.port)
    }

    Clear-Screen
    Show-Banner
    if ([bool]$Config.logEnabled) {
        Write-Host '  日志记录已开启。' -ForegroundColor Green
        Write-Host ''
        Write-Host '  日志文件：logs\server.log' -ForegroundColor Gray
        Write-Host '  日志记录连接来源、App 名称和请求结果，可能包含短信标题。' -ForegroundColor DarkGray
    } else {
        Write-Host '  日志记录已关闭。' -ForegroundColor Green
        Write-Host ''
        Write-Host '  不会写入新的日志。已有日志不会自动删除。' -ForegroundColor DarkGray
    }
    if ($restarted) {
        Write-Host '  服务已重启，设置已生效。' -ForegroundColor Green
    } elseif (Test-Listening ([int]$Config.port)) {
        Write-Host '  服务正在运行，设置已生效。' -ForegroundColor Green
    } else {
        Write-Host '  服务当前未运行，设置将在下次启动时生效。' -ForegroundColor Yellow
    }
    Wait-AnyKey
    return $Config
}

function Enter-MainMenu {
    param($Config)
    while ($true) {
        Show-StatusPanel $Config
        $logLabel = '日志记录：关闭'
        if ([bool]$Config.logEnabled) { $logLabel = '日志记录：开启' }
        $items = @('显示密钥', '重新生成密钥', '电脑 IP 地址查看', $logLabel, '打开使用教程', '退出')
        $choice = Read-Menu $items 0 '[↑↓] 移动    [Enter] 确认    [Esc] 退出'
        if ($choice -eq -1 -or $choice -eq 5) { return }
        if ($choice -eq 0) {
            Show-SecretPage $Config
        } elseif ($choice -eq 1) {
            $Config = Invoke-RegenerateSecret $Config
        } elseif ($choice -eq 2) {
            Show-LanPage $Config
        } elseif ($choice -eq 3) {
            $Config = Invoke-ToggleLog $Config
        } elseif ($choice -eq 4) {
            if (-not (Open-GuidePage)) {
                Write-Host ''
                Write-Host '  未能打开浏览器，请手动访问：' -ForegroundColor Yellow
                Write-Host ('  ' + $GuideUrl) -ForegroundColor Gray
                Wait-AnyKey
            }
        }
    }
}

if ($SetStaticIp) {
    if (-not (Test-Elevated)) { exit 1 }
    $log = Join-Path $env:TEMP 'SmsNotifier-static-ip.log'
    if (Test-Path -LiteralPath $log) { Remove-Item -LiteralPath $log -Force }
    $code = Enable-StaticIp -Alias $IpAlias -Address $IpAddress -Mask $Mask -Gateway $Gateway -DnsList $DnsList
    exit $code
}

if ($InstallOnly) {
    if (-not (Test-Elevated)) {
        Write-Host '需要管理员权限。'
        exit 1
    }
    $listenPort = $Port
    if ($listenPort -le 0) { $listenPort = [int](Read-Config).port }
    Install-Autostart -ListenPort $listenPort
    exit 0
}

$ProgressPreference = 'SilentlyContinue'
try { $Host.UI.RawUI.WindowTitle = '短信通知' } catch { }

$cfg = Read-Config
$firstRun = -not (Test-UserConfigured $cfg)

if ($firstRun) {
    $cfg.token = New-NotifierToken
    Save-Config $cfg
}

$autostartOk = $false
try { $autostartOk = Ensure-Autostart -ListenPort ([int]$cfg.port) } catch { $autostartOk = $false }

$serviceOk = $false
try { $serviceOk = Start-Server -ListenPort ([int]$cfg.port) } catch { $serviceOk = $false }

if ($firstRun) {
    Show-FirstRunPanel $cfg $autostartOk $serviceOk
    if (-not (Open-GuidePage)) {
        Write-Host '  未能打开浏览器，请手动访问上面的教程地址。' -ForegroundColor Yellow
        Write-Host ''
    }
    $choice = Read-Menu @('进入菜单', '退出') 0 '[↑↓] 移动    [Enter] 确认    [Esc] 退出'
    if ($choice -eq 1 -or $choice -eq -1) { exit 0 }
}

Enter-MainMenu $cfg
exit 0
