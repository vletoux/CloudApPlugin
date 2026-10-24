<#
.SYNOPSIS
    Registers or removes the CloudApCp credential provider. Elevated prompt.

.DESCRIPTION
    Register copies the DLL to System32 under a new name each time (LogonUI keeps the previous one
    loaded), then writes the COM class and the Credential Providers entry LogonUI enumerates.
#>
param([Parameter(Mandatory)][ValidateSet('Register', 'Unregister')][string]$Step,
    [string]$Dll = "$PSScriptRoot\..\credprov\bin\CloudApCp.dll")
$ErrorActionPreference = 'Stop'
$clsid = '{A52F0DC0-248F-469F-B8B7-3284B490519B}'
$cp = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid"
$com = "HKLM:\SOFTWARE\Classes\CLSID\$clsid"
if ($Step -eq 'Register') {
    $target = "$env:SystemRoot\System32\CloudApCp-$(Get-Date -Format yyyyMMddHHmmss).dll"
    Copy-Item $Dll $target
    New-Item "$com\InprocServer32" -Force | Out-Null
    Set-ItemProperty $com '(default)' 'CloudApCp'
    Set-ItemProperty "$com\InprocServer32" '(default)' $target
    Set-ItemProperty "$com\InprocServer32" 'ThreadingModel' 'Apartment'
    New-Item $cp -Force | Out-Null
    Set-ItemProperty $cp '(default)' 'CloudApCp'
    "registered $clsid -> $target"
} else {
    Remove-Item $cp -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $com -Recurse -Force -ErrorAction SilentlyContinue
    "unregistered $clsid"
}
