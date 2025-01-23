# Threat_Intelligence

Scripts used to gather Threat Intelligence (Indicators of Compromise) information from AlienVault OTX and VirusTotal. 
=====================================================================================================================

PowerShell Scripts:
  + AlienVault_IP_Lookup.ps1
  + AlienVault_filehash_Lookup.ps1

Python Scripts
  + AlienVault_Domain_Lookup.py
  + AlienVault_FileHash_Lookup.py
  + AlienVault_IP_Lookup.py
  + AlienVault_URL_Lookup.py
  + VirusTotal_FileHash_Lookup.py
  + VirusTotal_IP_Lookup.py


Required Modules:
  AlienVault scripts require the following modules:
  + requests
  + json


   VirusTotal_FileHash_Lookup.py and VirusTotal_IP_Lookup.py both require the following modules:
  + request
  + json
  + pandas
