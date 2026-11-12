Option Explicit
If WScript.Arguments.Count < 1 Then WScript.Quit 1

Dim shell, fso, scriptDir, ps, cmd
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
ps = shell.ExpandEnvironmentStrings("%SystemRoot%") & "\System32\WindowsPowerShell\v1.0\powershell.exe"
cmd = """" & ps & """ -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File """ & scriptDir & "\copy.ps1"" """ & WScript.Arguments(0) & """"
shell.Run cmd, 0, True
