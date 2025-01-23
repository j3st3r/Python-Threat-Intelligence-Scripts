# =====================================================================
# Script Name: AlienVault_filehash_Lookup.ps1
# Purpose: Hopefully this provides as much useful information available
#          from AlienVaults' OTX Threat Exchange. Requires PowerShell.
# Script Written By: William Armijo
# Created: 01/23/2025
# Version 1.0 (Just the beginning, folks!)
# =====================================================================

function Open-FileDialog {
    Param (
        [Parameter(Mandatory=$false)]
        [String]$Filter = 'All files (*.*)| *.*',
        [Parameter(Mandatory=$false)]
        [String]$InitialDirectory = [Environment]::GetFolderPath('Desktop'),
        [Parameter(Mandatory=$false)]
        [String]$Title = $null
    )
    if (-not ([System.AppDomain]::CurrentDomain.GetAssemblies() | ?{$_.Location -match "System.Windows.Forms"})) {
        Add-Type -AssemblyName System.Windows.Forms
    }
    $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
        InitialDirectory = $InitialDirectory
        Filter = $Filter
        Title = $Title
    }
    $null = $FileBrowser.ShowDialog()
    return $FileBrowser.FileName
}
$file = Open-FileDialog -InitialDirectory "C:\Temp"
Write-Output "Selected file: $file"
$sha1 = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider # You can change the SHA between SHA1 & SHA256
$file_hash = [System.BitConverter]::ToString($sha1.ComputeHash([System.IO.File]::ReadAllBytes($file))).Replace('-', '')

# Assign URL variables here
$gen_url = "https://otx.alienvault.com/api/v1/indicators/file/$file_hash/general"
$analysis_url = "https://otx.alienvault.com/api/v1/indicators/file/$file_hash/analysis"

# Retrieving each URL
$gen_response = Invoke-RestMethod -Method GET -Uri $gen_url
$analysis_response = Invoke-RestMethod -Method GET -Uri $analysis_url

if($analysis_response.analysis -match ""){
    Write-Host "No Malicious Information for this file: "
    Write-Host `t$file
    Write-Host `t$file_hash
}else{
# The Reporting Process
Write-Host "=========================================================="
Write-Host "IoC Information for: $file_hash"
Write-Host "=========================================================="
Write-Host "FileType: " $gen_response.type_title
Write-Host ""
foreach($pulse in $gen_response.pulse_info.pulses){

    $ioc_name = $pulse.name
    $ioc_desc = $pulse.description
    $ioc_created = $pulse.created
    $ioc_modified = $pulse.modified
    $ioc_tags = $pulse.tags
    $ioc_references = $pulse.references

   
    Write-Host "Name: " $ioc_name
    Write-Host "Description: "
    Write-Host "Created: "
    Write-Host "Modified: "
    Write-Host "tags: "
        foreach($tag in $ioc_tags){
        Write-Host "`t" $tag
        }
    Write-Host "References: "
        foreach($ref in $ioc_references){
        Write-Host "`t" $ref
        }
    Write-Host ""
    Write-Host "========================================================"
    Write-Host ""
   
}
}
