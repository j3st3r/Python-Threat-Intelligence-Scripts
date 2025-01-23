# Script Name: Secure_VirusTotal_IP_Lookup.ps1
# Purpose: To lookup AV detection information for an IP Address and give a summary for quick decision making.

if($apikey -cmatch ""){
    Write-Host "No Key exists"
    $apikey = Read-Host -Prompt "Please enter your API Key " -AsSecureString
   
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($apikey)
    $DecryptedAPI = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
   

    $ip = Read-Host -Prompt "Please enter an IP Address "
    $url = "https://www.virustotal.com/api/v3/ip_addresses/$ip"
   

    $header = @{
    "content-Type" = "application/json"
    "X-Apikey"= $DecryptedAPI
    }

    $response = Invoke-RestMethod -Method GET -Uri $url -Headers $header -UseBasicParsing

    $owner = $response.data.attributes.as_owner
    $country = $response.data.attributes.country
    $stats = $response.data.attributes.last_analysis_stats
    $results = $response.data.attributes.last_analysis_results
    $tags = $response.data.attributes.tags
    $last_analysis_dt = $response.data.attributes.last_analysis_date



    Write-Host "The IP belongs to: $owner"
    Write-Host "IP Located in: $country"
    Write-Host "Last Analyzed: $last_analysis_dt"
    Write-Host "IoC Detection Results:"
    Write-Host "`tMalicious Detections: "$stats.malicious
    Write-Host "`tSuspicious Detections: "$stats.suspicious
    Write-Host "`tHarmless Detections: "$stats.harmless
    Write-Host "`tTimeouts: "$stats.timeout
    Write-Host "`tUndetected: "$stats.undetected
    Write-Host ""
    Write-Host "Related Tags:"
    foreach($tag in $tags){
        write-host $tag
    }


} else{
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($apikey)
    $DecryptedAPI = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

    $ip = Read-Host -Prompt "Please enter an IP Address "
    $url = "https://www.virustotal.com/api/v3/ip_addresses/$ip"
    $api_key = $DecryptedAPI

    $header = @{
    "content-Type" = "application/json"
    "X-Apikey"=$DecryptedAPI
    }

    $response = Invoke-RestMethod -Method GET -Uri $url -Headers $header -UseBasicParsing

    $owner = $response.data.attributes.as_owner
    $country = $response.data.attributes.country
    $stats = $response.data.attributes.last_analysis_stats
    $results = $response.data.attributes.last_analysis_results
    $tags = $response.data.attributes.tags
    $last_analysis_dt = $response.data.attributes.last_analysis_date



    Write-Host "The IP belongs to: $owner"
    Write-Host "IP Located in: $country"
    Write-Host "Last Analyzed: $last_analysis_dt"
    Write-Host "IoC Detection Results:"
    Write-Host "'tMalicious Detections: "$stats.malicious
    Write-Host "'tSuspicious Detections: "$stats.suspicious
    Write-Host "'tHarmless Detections: "$stats.harmless
    Write-Host "'tTimeouts: "$stats.timeout
    Write-Host "'tUndetected: "$stats.undetected
    Write-Host ""
    Write-Host "Related Tags:"
    foreach($tag in $tags){
    write-host $tag
    }
}

#$clear_api = Read-Host -Prompt "Would you like to clear your API Key? (Y or N)"
#
#if($clear_api -cmatch "y"){
#    $DecryptedAPI = ""
#    $apikey = ""
#}else{
#    Write-Host "Key kept secured."
#}
