# Copies a toast payload to the clipboard. Invoked hidden by copy.vbs.
param(
    [Parameter(Position = 0)]
    [string]$Uri = ''
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

if ($Uri -notmatch 'smsnotifier:(otp|body)/([A-Za-z0-9]+)') {
    exit 1
}

$file = Join-Path $root ("data\clip-{0}-{1}.txt" -f $Matches[2], $Matches[1])
if (-not (Test-Path -LiteralPath $file)) {
    exit 1
}

$text = [System.IO.File]::ReadAllText($file, [System.Text.UTF8Encoding]::new($false))
if ([string]::IsNullOrWhiteSpace($text)) {
    exit 1
}

Set-Clipboard -Value $text.TrimEnd("`r", "`n")
exit 0
