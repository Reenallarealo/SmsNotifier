Option Explicit
Dim shell, fso, scriptDir, root, ps, hostExe, cmd
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
root = shell.ExpandEnvironmentStrings("%SystemRoot%")
ps = root & "\System32\WindowsPowerShell\v1.0\powershell.exe"
hostExe = root & "\System32\conhost.exe"
cmd = """" & hostExe & """ --headless """ & ps & """ -NoProfile -NonInteractive -ExecutionPolicy Bypass -File """ & scriptDir & "\server.ps1"""
shell.Run cmd, 0, True
