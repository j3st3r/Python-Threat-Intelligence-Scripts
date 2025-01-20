# =====================================================================
# Script Name: AlienVault_IP_Lookup.ps1
# Purpose: Hopefully this provides as much useful information available
#          from AlienVaults' OTX Threat Exchange. Requires PowerShell.
# Script Written By: William Armijo
# Created: 01/19/2025
# Version 1.0 (Just the beginning, folks!)
# =====================================================================

# Input an IP Address here
$ip_add = Read-Host -Prompt "Please enter an IP Adress"

# Assign URL variables here
$gen_url = "https://otx.alienvault.com/api/v1/indicators/IPv4/$ip_add/general"
$malware_url = "https://otx.alienvault.com/api/v1/indicators/IPv4/$ip_add/malware"
$urls_url = "https://otx.alienvault.com/api/v1/indicators/IPv4/$ip_add/url_list"
$dns_url = "https://otx.alienvault.com/api/v1/indicators/IPv4/$ip_add/passive_dns"

# Retrieving each URL
$gen_response = Invoke-RestMethod -Method GET -Uri $gen_url
$malware__response = Invoke-RestMethod -Method GET -Uri $malware_url
$urls__response = Invoke-RestMethod -Method GET -Uri $urls_url
$dns__response = Invoke-RestMethod -Method GET -Uri $dns_url

# The Reporting Process
Write-Host "=========================================================="
Write-Host "IoC Location Information for: $ip_add"
Write-Host "=========================================================="
Write-Host "`tASN: " $gen_response.asn
Write-Host "`tCity: " $gen_response.city
Write-host "`tCountry: " $gen_response.country_name
Write-Host "`tLatitude: " $gen_response.latitude
Write-Host "`tLongitude:" $gen_response.longitude
Write-Host ""
Write-Host "=========================================================="
Write-Host "Asssociated Malware Information"
Write-Host "=========================================================="
foreach($mal in $malware__response.data){
   
    $avast = $mal.detections.avast
    $avg = $mal.detections.avg
    $clamav = $mal.detections.clamav
    $msdefend = $mal.detections.msdefender
    $file_hashes = $mal.hash

    Foreach($file_hash in $file_hashes){

        Write-Host "`tFor File Hash: $file_hash"
        Write-Host "`tAvast Detection:" $avast
        Write-Host "`tAVG Detection:" $avg
        Write-Host "`tClamAV Detection:" $clamav    
        Write-Host "`tMS Defender Detection:" $msdefend
        Write-Host ""
    }
}
Write-Host ""
Write-Host "=========================================================="
Write-host "Associated URLS"
Write-Host "=========================================================="
Write-Host "`tURLs:"
foreach($urls in $urls__response.url_list){
    Write-Host "`t`t" $urls.url
}
Write-Host ""
Write-Host "`tHostnames:"
foreach($urls in $urls__response.url_list){
    Write-Host "`t`t" $urls.hostname
}
Write-Host ""
Write-Host "==============================================================================="
Write-host "Associated Hostnames/Domains observed by AlienVault pointing to this IP address"
Write-Host "==============================================================================="
foreach($dns in $dns__response){
      $dns_info = $dns.passive_dns
    foreach($dns in $dns_info){
        Write-Host "`t" $dns.hostname
    }  
}
