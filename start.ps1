# Start SmsNotifier and make sure it runs again at the next logon.
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
$DownloadUrl = 'https://github.com/pppscn/SmsForwarder/releases'

function Test-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Read-Config {
    $path = Join-Path $Root 'config.json'
    $raw = [System.IO.File]::ReadAllText($path, [System.Text.UTF8Encoding]::new($false))
    $cfg = $raw | ConvertFrom-Json
    if (-not $cfg.port) { $cfg | Add-Member -NotePropertyName port -NotePropertyValue 17890 -Force }
    if (-not $cfg.path) { $cfg | Add-Member -NotePropertyName path -NotePropertyValue '/webhook' -Force }
    if (-not ($cfg.PSObject.Properties.Name -contains 'token')) {
        $cfg | Add-Member -NotePropertyName token -NotePropertyValue '' -Force
    }
    if (-not ($cfg.PSObject.Properties.Name -contains 'dedupeSeconds')) {
        $cfg | Add-Member -NotePropertyName dedupeSeconds -NotePropertyValue 5 -Force
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
    }
    $json = $obj | ConvertTo-Json
    [System.IO.File]::WriteAllText($path, $json.Trim() + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
}

function Test-UserConfigured($Config) {
    return [string]$Config.token.Trim().Length -ge 16
}

function ConvertTo-HalfWidth([string]$Text) {
    if (-not $Text) { return '' }
    $builder = New-Object System.Text.StringBuilder
    foreach ($ch in $Text.Trim().ToCharArray()) {
        $code = [int]$ch
        if ($code -ge 0xFF10 -and $code -le 0xFF19) {
            [void]$builder.Append([char]($code - 0xFF10 + 48))
        } elseif ($code -ge 0xFF21 -and $code -le 0xFF3A) {
            [void]$builder.Append([char]($code - 0xFF21 + 65))
        } elseif ($code -ge 0xFF41 -and $code -le 0xFF5A) {
            [void]$builder.Append([char]($code - 0xFF41 + 97))
        } else {
            [void]$builder.Append($ch)
        }
    }
    return $builder.ToString()
}

function Read-Choice([string]$Prompt, [int[]]$Allowed) {
    while ($true) {
        $text = ConvertTo-HalfWidth (Read-Host $Prompt)
        $number = 0
        if ([int]::TryParse($text, [ref]$number) -and ($Allowed -contains $number)) {
            return $number
        }
        Write-Host '请输入上面列出的数字。'
    }
}

function Read-YesNo([string]$Prompt) {
    while ($true) {
        $text = (ConvertTo-HalfWidth (Read-Host $Prompt)).ToLowerInvariant()
        if ($text -eq 'y') { return $true }
        if ($text -eq 'n') { return $false }
        Write-Host '请输入 y 或 n。'
    }
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

function Format-AdapterDetail($Adapter) {
    $gateway = if ($Adapter.Gateway) { $Adapter.Gateway } else { '无' }
    $mac = if ($Adapter.Mac) { $Adapter.Mac } else { '未能读取' }
    $dns = if ([string]$Adapter.Dns) { ([string]$Adapter.Dns) -replace ',', ', ' } else { '无' }
    return @(
        ("网卡：{0}" -f $Adapter.Alias),
        ("IP：{0}" -f $Adapter.IP),
        ("掩码：{0}" -f $Adapter.Mask),
        ("网关：{0}" -f $gateway),
        ("MAC：{0}" -f $mac),
        ("DNS：{0}" -f $dns)
    )
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

function Enter-GuideStep([string]$Name) {
    $script:GuideIndex++
    Write-Host ''
    Write-Host ('【{0}/{1}】{2}' -f $script:GuideIndex, $script:GuideTotal, $Name)
}

function Write-GuideTitle {
    Write-Host ('【{0}/{1}】{2}' -f $script:GuideIndex, $script:GuideTotal, $args[0])
}

function Confirm-SafeNetwork {
    Write-Host ''
    Write-Host '警告'
    Write-Host '请在安全的家庭网络或可信局域网内运行该软件。'
    Write-Host '请勿在不可靠的校园网、公司局域网、不可信网络、公共网络下使用该软件，否则会造成隐私丢失等问题。'
    Write-Host '如果不知道局域网相关知识，应立即停止使用该软件，确保您的隐私安全。'
    Write-Host ''
    if (-not (Read-YesNo '是否已了解上述风险，并确认当前处于安全的家庭网络或可信局域网？请输入 y 或 n')) {
        Write-Host '已停止。请在了解局域网相关知识，并处于安全的家庭网络或可信局域网后再运行。'
        exit 1
    }
}

function Step-DownloadApp {
    while ($true) {
        Enter-GuideStep '下载手机软件'
        Write-Host '请在 Android 手机上安装 SmsForwarder，并允许短信和通知权限。'
        Write-Host ("下载页面：{0}" -f $DownloadUrl)
        Write-Host ''
        Write-Host '1. 在电脑上打开下载页面'
        Write-Host '2. 手机已经安装好，继续'
        $choice = Read-Choice '请输入数字' @(1, 2)
        if ($choice -eq 2) { return }
        Start-Process $DownloadUrl
        if (Read-YesNo '手机上是否已经安装完成？请输入 y 或 n') { return }
        Write-Host '请先安装完成，再继续。'
        $script:GuideIndex--
    }
}

function Step-Token($Config, [switch]$Modify) {
    $keepCurrent = $Modify -and (Test-UserConfigured $Config)
    Enter-GuideStep '生成密钥'
    while ($true) {
        Write-Host '密钥至少 16 位，会写入 config.json。'
        Write-Host ''
        if ($keepCurrent) {
            Write-Host '1. 保留当前密钥'
            Write-Host '2. 自动生成新密钥'
            Write-Host '3. 手动输入'
            $choice = Read-Choice '请输入数字' @(1, 2, 3)
            if ($choice -eq 1) {
                Write-Host ("当前密钥：{0}" -f $Config.token.Trim())
                return $Config
            }
            $generate = $choice -eq 2
        } else {
            Write-Host '1. 自动生成'
            Write-Host '2. 手动输入'
            $choice = Read-Choice '请输入数字' @(1, 2)
            $generate = $choice -eq 1
        }
        if ($generate) {
            $token = New-NotifierToken
        } else {
            $token = ''
            while ($token.Length -lt 16) {
                $token = (ConvertTo-HalfWidth (Read-Host '请输入密钥')).Trim()
                if ($token.Length -lt 16) { Write-Host '长度不足 16 位，请重新输入。' }
            }
        }
        Write-Host ("密钥：{0}" -f $token)
        if (Read-YesNo '是否写入 config.json？请输入 y 或 n') {
            $Config.token = $token
            Save-Config $Config
            Write-Host '已写入 config.json。'
            return $Config
        }
        Write-Host ''
        Write-GuideTitle '生成密钥'
    }
}

function Step-FixIp($Config) {
    Enter-GuideStep '固定电脑 IP'
    Write-Host ("手机里的 Webhook 会使用 http://<电脑IP>:{0}{1}" -f $Config.port, $Config.listenPath)
    Write-Host '路由器如果重新分配了 IP，手机里的地址就要跟着改。'
    Write-Host '正在读取网卡...'
    $adapters = @(Get-LanAdapter)
    if ($adapters.Count -eq 0) {
        Write-Host '没有发现可用的局域网 IPv4。先继续，连上局域网后再运行一次启动。'
        return
    }
    if ($adapters.Count -gt 1) {
        Write-Host ''
        Write-Host '检测到多个局域网地址，请选择手机要访问的那个：'
        for ($i = 0; $i -lt $adapters.Count; $i++) {
            $mac = if ($adapters[$i].Mac) { $adapters[$i].Mac } else { 'MAC 未知' }
            $gateway = if ($adapters[$i].Gateway) { $adapters[$i].Gateway } else { '无网关' }
            Write-Host ('{0}. {1}  {2}  网关 {3}  {4}' -f ($i + 1), $adapters[$i].IP, $adapters[$i].Alias, $gateway, $mac)
        }
        $pick = Read-Choice '请输入数字' @(1..$adapters.Count)
        $selected = $adapters[$pick - 1]
    } else {
        $selected = $adapters[0]
    }
    Write-Host ''
    Write-Host '将使用这块网卡：'
    Format-AdapterDetail $selected | ForEach-Object { Write-Host $_ }
    Write-Host ''
    Write-Host '1. 到路由器把 MAC 绑定到这个 IP'
    Write-Host '2. 把这个地址设为本机静态 IP'
    Write-Host '3. 暂时不固定，继续'
    $choice = Read-Choice '请输入数字' @(1, 2, 3)
    if ($choice -eq 3) { return }
    if ($choice -eq 1) {
        $mac = if ($selected.Mac) { $selected.Mac } else { '（未能读取）' }
        Write-Host ''
        Write-Host '在路由器里找到 DHCP 静态分配或地址保留，填写：'
        Write-Host ("MAC：{0}" -f $mac)
        Write-Host ("IP：{0}" -f $selected.IP)
        if (-not (Read-YesNo '是否已经绑定？请输入 y 或 n')) {
            Write-Host '可以稍后再绑定。IP 变化后，需要把手机里的地址改成新的 IP。'
        }
        return
    }
    $gateway = if ($selected.Gateway) { $selected.Gateway } else { '无' }
    $dns = if ([string]$selected.Dns) { ([string]$selected.Dns) -replace ',', ', ' } else { '沿用网关' }
    Write-Host ''
    Write-Host ("将把「{0}」的 {1} 设为静态地址。" -f $selected.Alias, $selected.IP)
    Write-Host ("掩码 {0}，网关 {1}，DNS {2}。" -f $selected.Mask, $gateway, $dns)
    if (-not $selected.Gateway -and -not [string]$selected.Dns) {
        Write-Host '这块网卡没有网关和 DNS，设成静态 IP 后可能上不了网。'
    }
    Write-Host '设置时网络可能会短暂中断。'
    if (Read-YesNo '是否继续？请输入 y 或 n') {
        Invoke-ElevatedStaticIp $selected
    }
}

function Invoke-SetupWizard($Config, [switch]$Modify) {
    Step-DownloadApp
    $Config = Step-Token $Config -Modify:$Modify
    Step-FixIp $Config
    return (Read-Config)
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
    if (Test-Autostart) { return }
    if (Test-Elevated) {
        Install-Autostart -ListenPort $ListenPort
        return
    }
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    try {
        $proc = Start-Process -FilePath $ps -Verb RunAs -Wait -PassThru -ArgumentList @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath,
            '-InstallOnly', '-Port', $ListenPort
        )
    } catch {
        Write-Host '需要管理员权限才能完成首次配置，已取消。'
        exit 1
    }
    if (-not $proc -or $proc.ExitCode -ne 0) {
        Write-Host '首次配置未完成。'
        exit 1
    }
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
    $procs = @(Get-CimInstance -ClassName Win32_Process | Where-Object {
        $_.ProcessId -ne $PID -and $_.CommandLine -and (
            $_.CommandLine -match '\\SmsNotifier\\server\.ps1' -or
            $_.CommandLine -match '\\SmsNotifier\\start\.vbs'
        )
    })
    foreach ($proc in $procs) {
        if (-not $proc) { continue }
        Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 400
}

function Start-Server([int]$ListenPort) {
    if (Test-Listening $ListenPort) { return $true }
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

function Get-LanUrls([int]$ListenPort, [string]$ListenPath) {
    $urls = @()
    Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {
        $bytes = $null
        if (-not [System.Net.IPAddress]::TryParse($_.IPAddress, [ref]$bytes)) { return }
        $raw = $bytes.GetAddressBytes()
        $skip = ($raw[0] -eq 127) -or ($raw[0] -eq 169 -and $raw[1] -eq 254) -or ($raw[0] -eq 198 -and ($raw[1] -eq 18 -or $raw[1] -eq 19))
        if (-not $skip) {
            $urls += ('http://{0}:{1}{2}' -f $_.IPAddress, $ListenPort, $ListenPath)
        }
    }
    return $urls
}

function Select-WebhookUrl($Config) {
    $urls = @(Get-LanUrls ([int]$Config.port) ([string]$Config.listenPath))
    if ($urls.Count -eq 0) {
        return ('http://<电脑局域网IP>:{0}{1}' -f $Config.port, $Config.listenPath)
    }
    if ($urls.Count -eq 1) { return $urls[0] }
    Write-Host ''
    Write-Host '有多个局域网地址，请选择要填进手机的那个：'
    for ($i = 0; $i -lt $urls.Count; $i++) {
        Write-Host ('{0}. {1}' -f ($i + 1), $urls[$i])
    }
    $pick = Read-Choice '请输入数字' @(1..$urls.Count)
    return $urls[$pick - 1]
}

function Complete-GuideStep([string]$Name, [string[]]$Lines, [string]$Prompt, [string]$Retry) {
    Enter-GuideStep $Name
    while ($true) {
        foreach ($line in $Lines) { Write-Host $line }
        if (Read-YesNo $Prompt) { return }
        if ($Retry) { Write-Host $Retry }
        else { Write-Host '请先完成这一步，完成后再输入 y。' }
        Write-Host ''
        Write-GuideTitle $Name
    }
}

function Step-PhoneGuide($Config) {
    $url = Select-WebhookUrl $Config
    $secret = 'Bearer {0}' -f $Config.token.Trim()
    $template = @(
        '{'
        '  "packageName": "{{PACKAGE_NAME}}",'
        '  "appName": "{{APP_NAME}}",'
        '  "title": "{{TITLE}}",'
        '  "body": "{{MSG}}",'
        '  "receivedAt": "{{RECEIVE_TIME}}",'
        '  "uid": "{{UID}}",'
        '  "device": "[device_mark]",'
        '  "timestamp": "[timestamp]"'
        '}'
    )

    Complete-GuideStep '新建发送通道' @(
        '打开 SmsForwarder。'
        '点击下方栏的「发送通道」。'
        '点击屏幕左上角的「+」号。'
        '选择「webhook」。'
        '随意命名一个「通道名称」。'
    ) '是否已经完成？请输入 y 或 n'

    Complete-GuideStep '填写 Webhook 地址' @(
        '在「webhook server」中填写下面这个地址：'
        $url
    ) '是否已经填入该地址？请输入 y 或 n'

    $templateLines = @('把消息模板配置成下面这一段：') + $template
    Complete-GuideStep '配置消息模板' $templateLines '是否已经配置该消息模板？请输入 y 或 n'

    Complete-GuideStep '配置请求头' @(
        '滑动屏幕到下方「Headers」。'
        '点击「Headers」旁边的「+」号。'
        'Key 填写 Authorization'
        'Value 填写下面这一整段。Bearer 后面有一个空格，空格后面是密钥：'
        $secret
        '填写完成后点击手机屏幕右下角绿色的测试按钮，电脑屏幕右侧应出现通知弹窗。'
    ) '电脑右侧是否已经出现通知弹窗？请输入 y 或 n' '手机若显示测试失败，请确认已经点击 Headers 旁边的 +，并且 Value 与上面那一整段完全一致，然后再次点击测试。'

    Complete-GuideStep '新建转发规则' @(
        '点击屏幕下方的「转发规则」。'
        '点击右上角的「+」号。'
        '选择之前创建的发送通道。'
        '选择对应的卡槽。'
        '点击右下角的「测试」。'
    ) '是否已经完成？请输入 y 或 n'
}

function Show-Ready($Config) {
    if (Test-Autostart) {
        Write-Host '登录后自动启动：已开启。'
    } else {
        Write-Host '登录后自动启动：未开启。'
    }
    Write-Host ''
    Write-Host '手机 Webhook 地址：'
    $urls = @(Get-LanUrls ([int]$Config.port) ([string]$Config.listenPath))
    if ($urls.Count -eq 0) {
        Write-Host ("http://<电脑局域网IP>:{0}{1}" -f $Config.port, $Config.listenPath)
    } else {
        $urls | ForEach-Object { Write-Host $_ }
    }
    Write-Host ''
    Write-Host '请求头：'
    Write-Host ('Authorization: Bearer {0}' -f $Config.token.Trim())
    Write-Host 'Content-Type: application/json; charset=utf-8'
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
Confirm-SafeNetwork
$cfg = Read-Config
$runGuide = $false
if (Test-UserConfigured $cfg) {
    Write-Host ''
    Write-Host '检测到已有配置。'
    if (Read-YesNo '是否要修改此前的配置？请输入 y 或 n') {
        $script:GuideIndex = 0
        $script:GuideTotal = 8
        $cfg = Invoke-SetupWizard $cfg -Modify
        Stop-RunningServer
        $runGuide = $true
    }
} else {
    Write-Host ''
    Write-Host '尚未配置，开始新手教程。'
    $script:GuideIndex = 0
    $script:GuideTotal = 8
    $cfg = Invoke-SetupWizard $cfg
    Stop-RunningServer
    $runGuide = $true
}

if (-not (Test-UserConfigured $cfg)) {
    Write-Host 'token 尚未设置，启动已取消。'
    exit 1
}

if ($runGuide) {
    Write-Host ''
    Write-Host '正在创建对应的 Windows 服务...'
}
Ensure-Autostart -ListenPort ([int]$cfg.port)
if (-not (Start-Server -ListenPort ([int]$cfg.port))) {
    Write-Host '启动失败。查看 logs\server.log'
    exit 1
}

Write-Host ''
Write-Host '服务已在运行。'
Show-Ready $cfg
if ($runGuide) { Step-PhoneGuide $cfg }
exit 0
