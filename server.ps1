# SmsNotifier — receive SmsForwarder webhooks and show a Windows toast.
param(
    [int]$Port = 0,
    [switch]$LocalOnly,
    [switch]$Test
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogDir = Join-Path $Root 'logs'
$DataDir = Join-Path $Root 'data'
$AppId = 'SmsNotifier.Desktop'
$FallbackAppId = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
New-Item -ItemType Directory -Force -Path $LogDir, $DataDir | Out-Null

function Write-Log([string]$Message) {
    $line = '{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    $path = Join-Path $LogDir 'server.log'
    try {
        if ((Test-Path -LiteralPath $path) -and ((Get-Item -LiteralPath $path).Length -gt 2MB)) {
            Move-Item -LiteralPath $path -Destination ($path + '.old') -Force
        }
        [System.IO.File]::AppendAllText($path, $line + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
    } catch {
        # Logging must not take down the listener.
    }
}

function Get-Config {
    $path = Join-Path $Root 'config.json'
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Missing config.json at $path"
    }
    $raw = [System.IO.File]::ReadAllText($path, [System.Text.UTF8Encoding]::new($false))
    $cfg = $raw | ConvertFrom-Json
    if (-not $cfg.token -or [string]$cfg.token.Length -lt 16) {
        throw 'config.json token is missing or too short'
    }
    $cfg | Add-Member -NotePropertyName listenPort -NotePropertyValue ([int]$(if ($Port -gt 0) { $Port } else { $cfg.port })) -Force
    $listenPath = [string]$cfg.path
    if (-not $listenPath) { $listenPath = '/webhook' }
    if (-not $listenPath.StartsWith('/')) { $listenPath = "/$listenPath" }
    if ($listenPath.Length -gt 1) { $listenPath = $listenPath.TrimEnd('/') }
    $cfg | Add-Member -NotePropertyName listenPath -NotePropertyValue $listenPath -Force
    return $cfg
}

function Test-SameSecret([string]$Got, [string]$Expect) {
    $a = [System.Text.Encoding]::UTF8.GetBytes([string]$Got)
    $b = [System.Text.Encoding]::UTF8.GetBytes([string]$Expect)
    if ($a.Length -ne $b.Length -or $a.Length -eq 0) { return $false }
    $diff = 0
    for ($i = 0; $i -lt $a.Length; $i++) { $diff = $diff -bor ($a[$i] -bxor $b[$i]) }
    return $diff -eq 0
}

function ConvertTo-XmlText([string]$Value) {
    if ($null -eq $Value) { return '' }
    $safe = $Value -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', ''
    return [System.Security.SecurityElement]::Escape($safe)
}

function Get-Otp([string]$Title, [string]$Body) {
    $builder = New-Object System.Text.StringBuilder
    foreach ($ch in ($Title + "`n" + $Body).ToCharArray()) {
        $code = [int]$ch
        if ($code -ge 0xFF10 -and $code -le 0xFF19) {
            [void]$builder.Append([char]($code - 0xFF10 + 0x30))
        } else {
            [void]$builder.Append($ch)
        }
    }
    $text = $builder.ToString()
    if ($text -notmatch '验证码|校验码|动态码|动态密码|短信码|短信验证|登录码|确认码|授权码|安全码|识别码|提取码|兑换码|OTP|verification\s*code|security\s*code') {
        return ''
    }
    $patterns = @(
        '(?:验证码|校验码|动态码|动态密码|短信码|登录码|确认码|授权码|安全码|识别码|提取码|兑换码|OTP)[^\d]{0,16}(\d(?:[ \t-]?\d){3,7})',
        '(\d(?:[ \t-]?\d){3,7})[^\d]{0,8}(?:验证码|校验码|动态码|动态密码|登录码|OTP)',
        '(?:码为|码是|码：|码:)[^\d]{0,8}(\d(?:[ \t-]?\d){3,7})'
    )
    foreach ($pattern in $patterns) {
        $m = [regex]::Match($text, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($m.Success) {
            $digits = ($m.Groups[1].Value -replace '\D', '')
            if ($digits.Length -ge 4 -and $digits.Length -le 8 -and $digits -notmatch '^0+$' -and $digits -notmatch '^(19|20)\d{2}$') {
                return $digits
            }
        }
    }
    $all = [regex]::Matches($text, '(?<!\d)\d{4,8}(?!\d)')
    foreach ($item in $all) {
        $digits = $item.Value
        if ($digits -match '^0+$' -or $digits -match '^(19|20)\d{2}$') { continue }
        if ($digits.Length -eq 6) { return $digits }
    }
    foreach ($item in $all) {
        if ($item.Value -notmatch '^0+$' -and $item.Value -notmatch '^(19|20)\d{2}$') { return $item.Value }
    }
    return ''
}

function Register-NotifierApp {
    $shortcutPath = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\短信通知.lnk'
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = Join-Path $env:SystemRoot 'System32\wscript.exe'
    $shortcut.Arguments = '//B //Nologo "{0}"' -f (Join-Path $Root 'start.vbs')
    $shortcut.WorkingDirectory = $Root
    $shortcut.WindowStyle = 7
    $shortcut.Description = '短信通知'
    $shortcut.Save()

    if (-not ('SmsAppId' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class SmsAppId {
    [ComImport, Guid("00021401-0000-0000-C000-000000000046")]
    private class CShellLink {}

    [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("000214F9-0000-0000-C000-000000000046")]
    private interface IShellLinkW {
        void GetPath([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszFile, int cch, IntPtr pfd, int fFlags);
        void GetIDList(out IntPtr ppidl);
        void SetIDList(IntPtr pidl);
        void GetDescription([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszName, int cch);
        void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string pszName);
        void GetWorkingDirectory([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszDir, int cch);
        void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string pszDir);
        void GetArguments([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszArgs, int cch);
        void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string pszArgs);
        void GetHotkey(out short pwHotkey);
        void SetHotkey(short wHotkey);
        void GetShowCmd(out int piShowCmd);
        void SetShowCmd(int iShowCmd);
        void GetIconLocation([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszIconPath, int cch, out int piIcon);
        void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string pszIconPath, int iIcon);
        void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string pszPathRel, int dwReserved);
        void Resolve(IntPtr hwnd, int fFlags);
        void SetPath([MarshalAs(UnmanagedType.LPWStr)] string pszFile);
    }

    [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("0000010b-0000-0000-C000-000000000046")]
    private interface IPersistFile {
        void GetClassID(out Guid pClassID);
        [PreserveSig] int IsDirty();
        void Load([MarshalAs(UnmanagedType.LPWStr)] string pszFileName, uint dwMode);
        void Save([MarshalAs(UnmanagedType.LPWStr)] string pszFileName, bool fRemember);
        void SaveCompleted([MarshalAs(UnmanagedType.LPWStr)] string pszFileName);
        void GetCurFile([MarshalAs(UnmanagedType.LPWStr)] out string ppszFileName);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROPERTYKEY {
        public Guid fmtid;
        public uint pid;
    }

    [StructLayout(LayoutKind.Explicit)]
    private struct PROPVARIANT {
        [FieldOffset(0)] public ushort vt;
        [FieldOffset(2)] public ushort wReserved1;
        [FieldOffset(4)] public ushort wReserved2;
        [FieldOffset(6)] public ushort wReserved3;
        [FieldOffset(8)] public IntPtr pszVal;
    }

    [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99")]
    private interface IPropertyStore {
        void GetCount(out uint cProps);
        void GetAt(uint iProp, out PROPERTYKEY pkey);
        void GetValue(ref PROPERTYKEY key, out PROPVARIANT pv);
        void SetValue(ref PROPERTYKEY key, ref PROPVARIANT pv);
        void Commit();
    }

    [DllImport("ole32.dll")]
    private static extern int PropVariantClear(ref PROPVARIANT pvar);

    public static void Apply(string shortcutPath, string appId) {
        IShellLinkW link = (IShellLinkW)new CShellLink();
        IPersistFile file = (IPersistFile)link;
        file.Load(shortcutPath, 2);
        IPropertyStore store = (IPropertyStore)link;
        PROPERTYKEY key = new PROPERTYKEY();
        key.fmtid = new Guid("9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3");
        key.pid = 5;
        PROPVARIANT pv = new PROPVARIANT();
        pv.vt = 31;
        pv.pszVal = Marshal.StringToCoTaskMemUni(appId);
        store.SetValue(ref key, ref pv);
        store.Commit();
        file.Save(shortcutPath, true);
        PropVariantClear(ref pv);
    }
}
'@
    }

    [SmsAppId]::Apply($shortcutPath, $AppId)
    [System.IO.File]::WriteAllText((Join-Path $DataDir 'appid.txt'), $AppId, [System.Text.UTF8Encoding]::new($false))
}

function Register-CopyProtocol {
    $command = '"{0}" //B //Nologo "{1}" "%1"' -f `
        (Join-Path $env:SystemRoot 'System32\wscript.exe'),
        (Join-Path $Root 'copy.vbs')
    $base = 'HKCU:\Software\Classes\smsnotifier'
    New-Item -Path $base -Force | Out-Null
    New-ItemProperty -Path $base -Name '(default)' -Value 'URL:SmsNotifier' -Force | Out-Null
    New-ItemProperty -Path $base -Name 'URL Protocol' -Value '' -Force | Out-Null
    New-Item -Path "$base\shell\open\command" -Force | Out-Null
    New-ItemProperty -Path "$base\shell\open\command" -Name '(default)' -Value $command -Force | Out-Null
}

function Initialize-ToastApi {
    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
    [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom, ContentType = WindowsRuntime] | Out-Null
}

function Save-Clip([string]$Id, [string]$Kind, [string]$Text) {
    $file = Join-Path $DataDir "clip-$Id-$Kind.txt"
    [System.IO.File]::WriteAllText($file, $Text, [System.Text.UTF8Encoding]::new($false))
}

function Show-Notice {
    param(
        [string]$Heading,
        [string]$Body,
        [string]$Otp,
        [string]$Tag
    )
    $id = [guid]::NewGuid().ToString('N').Substring(0, 12)
    $actions = New-Object System.Collections.Generic.List[string]
    if ($Otp) {
        Save-Clip $id 'otp' $Otp
        $actions.Add('<action content="复制验证码" arguments="smsnotifier:otp/{0}" activationType="protocol"/>' -f $id)
    }
    $copyText = $(if ($Otp) { $Otp } else { $Body })
    if ($copyText) {
        Save-Clip $id 'body' $(if ($Otp) { "$Heading`n$Body`n$Otp" } else { "$Heading`n$Body" })
        $actions.Add('<action content="复制内容" arguments="smsnotifier:body/{0}" activationType="protocol"/>' -f $id)
    }
    $actionXml = ''
    if ($actions.Count -gt 0) {
        $actionXml = '<actions>' + ($actions -join '') + '</actions>'
    }
    $xmlText = @"
<toast duration="long">
  <visual>
    <binding template="ToastGeneric">
      <text>$(ConvertTo-XmlText $Heading)</text>
      <text>$(ConvertTo-XmlText $Body)</text>
    </binding>
  </visual>
  $actionXml
  <audio src="ms-winsoundevent:Notification.SMS"/>
</toast>
"@
    $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
    $xml.LoadXml($xmlText)
    $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
    if ($Tag) {
        $toast.Tag = $Tag.Substring(0, [Math]::Min(16, $Tag.Length))
        $toast.Group = 'SmsNotifier'
    }
    $toast.ExpirationTime = [DateTimeOffset]::Now.AddHours(8)
    try {
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AppId).Show($toast)
    } catch {
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($FallbackAppId).Show($toast)
    }
}

function Get-Field($Object, [string[]]$Names) {
    foreach ($name in $Names) {
        $prop = $Object.PSObject.Properties[$name]
        if ($prop -and $null -ne $prop.Value -and [string]$prop.Value -ne '') {
            return [string]$prop.Value
        }
    }
    return ''
}

function ConvertTo-Notice($Raw) {
    $packageName = Get-Field $Raw @('packageName', 'package_name', 'pkg')
    $appName = Get-Field $Raw @('appName', 'app_name', 'app')
    $title = Get-Field $Raw @('title', 'subject')
    $body = Get-Field $Raw @('body', 'msg', 'message', 'content', 'text', 'sms')
    if (-not $appName) { $appName = $packageName }
    if (-not $appName) { $appName = '短信通知' }
    if (-not $body -and $title.Length -gt 20) {
        $body = $title
        $title = $appName
    }
    if (-not $body) { $body = $title }
    if (-not $title) { $title = $appName }
    if ($title.Length -gt 120) { $title = $title.Substring(0, 120) }
    if ($body.Length -gt 600) { $body = $body.Substring(0, 599) + '…' }
    $heading = $appName
    if ($title -and $title -ne $appName) { $heading = "$appName · $title" }
    return [pscustomobject]@{
        Heading = $heading
        Body    = $body
        App     = $appName
        Title   = $title
        Otp     = (Get-Otp $title $body)
    }
}

function Send-Json($Context, [int]$Status, $Object) {
    $json = $Object | ConvertTo-Json -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $response = $Context.Response
    $response.StatusCode = $Status
    $response.ContentType = 'application/json; charset=utf-8'
    $response.ContentLength64 = $bytes.Length
    $response.OutputStream.Write($bytes, 0, $bytes.Length)
    $response.Close()
}

function Test-UsableLanAddress([string]$Address) {
    $bytes = [System.Net.IPAddress]::Parse($Address).GetAddressBytes()
    if ($bytes[0] -eq 127) { return $false }
    if ($bytes[0] -eq 169 -and $bytes[1] -eq 254) { return $false }
    if ($bytes[0] -eq 198 -and ($bytes[1] -eq 18 -or $bytes[1] -eq 19)) { return $false }
    return $true
}

function Get-WebhookUrls([int]$ListenPort, [string]$ListenPath) {
    $urls = @()
    Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {
        if (Test-UsableLanAddress $_.IPAddress) {
            $urls += ('http://{0}:{1}{2}' -f $_.IPAddress, $ListenPort, $ListenPath)
        }
    }
    return $urls
}

$script:Seen = @{}

function Test-Duplicate([string]$Key, [int]$WindowSeconds) {
    if ($WindowSeconds -le 0) { return $false }
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $stale = @($script:Seen.Keys | Where-Object { $script:Seen[$_] -le $now })
    foreach ($item in $stale) { $script:Seen.Remove($item) }
    if ($script:Seen.ContainsKey($Key) -and $script:Seen[$Key] -gt $now) { return $true }
    $script:Seen[$Key] = $now + $WindowSeconds
    return $false
}

Initialize-ToastApi
try {
    Register-CopyProtocol
} catch {
    Write-Log ("copy protocol registration failed: " + $_.Exception.Message)
}
try {
    Register-NotifierApp
} catch {
    Write-Log ("notifier registration failed, toasts may show as PowerShell: " + $_.Exception.Message)
    $AppId = $FallbackAppId
}

if ($Test) {
    Show-Notice -Heading '短信通知 · 测试' -Body '这是一条本机测试。验证码 123456。看到右下角这张卡片就说明 Windows 通知是通的。' -Otp '123456' -Tag 'localtest'
    Write-Log 'local test toast sent'
    Write-Host '已发送一条 Windows 测试通知。'
    exit 0
}

$cfg = Get-Config
$mutex = New-Object System.Threading.Mutex($false, 'Local\SmsNotifierWebhook')
if (-not $mutex.WaitOne(0)) {
    Write-Log 'another SmsNotifier instance is already running'
    exit 0
}

Get-ChildItem -LiteralPath $DataDir -Filter 'clip-*.txt' -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-1) } |
    Remove-Item -Force -ErrorAction SilentlyContinue

$prefix = $(if ($LocalOnly) { "http://127.0.0.1:$($cfg.listenPort)/" } else { "http://+:$($cfg.listenPort)/" })
Write-Log ("starting listener " + $prefix + " path " + $cfg.listenPath)
$urls = Get-WebhookUrls $cfg.listenPort $cfg.listenPath
if ($urls.Count -eq 0) {
    Write-Log 'no usable LAN IPv4. Phone must not use 198.18.0.1 or 169.254.x.x.'
} else {
    Write-Log ('phone webhook url: ' + ($urls -join ' | '))
}

$listener = $null
while ($true) {
    $candidate = New-Object System.Net.HttpListener
    $candidate.Prefixes.Add($prefix)
    try {
        $candidate.Start()
        $listener = $candidate
        Write-Log 'listening'
        break
    } catch {
        $message = $_.Exception.Message
        Write-Log ("bind failed: " + $message)
        try { $candidate.Close() } catch {}
        if ($message -match '拒绝访问|Access is denied|5\)') {
            Write-Log 'run install.ps1 as administrator once, then start this script again'
            exit 1
        }
        Start-Sleep -Seconds 5
    }
}

try {
    while ($listener.IsListening) {
        $context = $null
        try {
            $context = $listener.GetContext()
            $request = $context.Request
            $path = $request.Url.AbsolutePath.TrimEnd('/')
            if (-not $path) { $path = '/' }
            $method = $request.HttpMethod.ToUpperInvariant()
            $ip = $request.RemoteEndPoint.Address.ToString()

            if ($path -eq '/health' -and $method -eq 'GET') {
                Send-Json $context 200 @{ ok = $true; path = $cfg.listenPath }
                continue
            }

            if ($path -ne $cfg.listenPath) {
                Send-Json $context 404 @{ ok = $false; error = 'not found' }
                Write-Log ("404 {0} {1} {2}" -f $ip, $method, $path)
                continue
            }

            if ($method -ne 'POST') {
                Send-Json $context 405 @{ ok = $false; error = 'method not allowed' }
                continue
            }

            $header = [string]$request.Headers['Authorization']
            $got = $header.Trim()
            while ($got -match '^(?i)Bearer\s+(.*)$') { $got = $Matches[1].Trim() }
            if (-not (Test-SameSecret $got $cfg.token)) {
                Send-Json $context 401 @{ ok = $false; error = 'unauthorized' }
                if (-not $header.Trim()) {
                    Write-Log ("401 from {0} missing Authorization" -f $ip)
                } else {
                    Write-Log ("401 from {0} Authorization mismatch" -f $ip)
                }
                continue
            }

            $reader = New-Object System.IO.StreamReader($request.InputStream, [System.Text.Encoding]::UTF8)
            try { $text = $reader.ReadToEnd() } finally { $reader.Close() }
            if ($text.Length -gt 65536) {
                Send-Json $context 413 @{ ok = $false; error = 'payload too large' }
                continue
            }

            try {
                $raw = $text | ConvertFrom-Json
            } catch {
                Send-Json $context 400 @{ ok = $false; error = 'invalid json' }
                Write-Log ("400 invalid json from " + $ip)
                continue
            }

            $notice = ConvertTo-Notice $raw
            $dedupeKey = '{0}|{1}|{2}' -f $notice.App, $notice.Title, $notice.Body
            $window = 5
            if ($cfg.PSObject.Properties['dedupeSeconds']) { $window = [int]$cfg.dedupeSeconds }
            if (Test-Duplicate $dedupeKey $window) {
                Send-Json $context 200 @{ ok = $true; deduped = $true }
                Write-Log ("deduped from {0} app={1}" -f $ip, $notice.App)
                continue
            }

            $hashBytes = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($dedupeKey))
            $tag = ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').Substring(0, 16)
            Show-Notice -Heading $notice.Heading -Body $notice.Body -Otp $notice.Otp -Tag $tag
            Send-Json $context 200 @{ ok = $true }
            Write-Log ("accepted from {0} app={1} title={2} otp={3}" -f $ip, $notice.App, $notice.Title, [bool]$notice.Otp)
        } catch {
            Write-Log ("request error: " + $_.Exception.Message)
            if ($context) {
                try { Send-Json $context 500 @{ ok = $false; error = 'internal error' } } catch {}
            }
        }
    }
} finally {
    if ($listener) { $listener.Close() }
    $mutex.ReleaseMutex() | Out-Null
    $mutex.Dispose()
}
