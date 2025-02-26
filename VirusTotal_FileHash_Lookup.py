#!/usr/bin/python3
# Script Name: VirusTotal_FileHash_Lookup.py
# Purpose: Use to lookup Virus Total Stats for any file hash.
# Accepted Hashes, SHA-1, SHA-256, and MD5
# Written By: Will Armijo
# Created on: 01/11/2025

'''
Please note that this script is not compliant with security as the API key is statically assigned. 
This can be updated to retrieve the API key from a protected file, user input, or user environment variable. 
'''

import requests
import json
import pandas as pd
from pandas import json_normalize

# Use one of the following hashes to test script with. These are known bad files hashes.
#hash = "33edac8a75cac4a0a1d084174b3dc912b9744386" # SHA-1
#hash = "720eea739bd033b804b98c0190b06d864dd61053aab14cb19d1c56d390686313" #SHA-256
#hash = "beb1de229b374cd778107c8268e191ac" # MD5

# Comment the 'hash' variable out if you choose one of the hashes above.
hash = input("Please enter a file hash: ")
api_key = "<Replace this with your own API key from Virus Total>"
url = f"https://www.virustotal.com/api/v3/files/{hash}"

# Set up the headers
header = {
    'X-Apikey': f'{api_key}',
    'Content-Type': 'application/json'
}

response = requests.get(url, headers=header)
print("Retrieving ", {url})
print("")


if response.status_code == 200:
    vt_data = response.text
    
    df = pd.read_json(vt_data)

    ioc_total = df['data']
    
    print("")
    print("")
    print("============================")
    print("")
    print("Detected as: ", ioc_total['attributes']['popular_threat_classification']['suggested_threat_label'])
    print("============================")
    print("")
    ioc_analysis = ioc_total['attributes']['last_analysis_stats']
    print("Number of Antivirus to find file hash...") 
    print("\tMalicious:", ioc_analysis['malicious'])
    print("\tSuspicious:", ioc_analysis['suspicious'])
    print("\tUndetected:", ioc_analysis['undetected'])
    print("\tHarmlessby :", ioc_analysis['harmless'])
    print("\tTimedout by :", ioc_analysis['timeout'])
    print("\tFailure by :", ioc_analysis['failure'])
    print("\tType-Unsupported:", ioc_analysis['type-unsupported'])
    print("")

elif response.status_code == 400:
    print("ERROR: Invalid file hash")
elif response.status_code == 404:
    print("ERROR: No IoC records for this file hash")
else:
    print("ERROR: Request failed with status", {response.status_code}, {response.text})
