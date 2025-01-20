#!/usr/bin/python3
# Script Name: domain_otx.py
# Description: Use to retreive possible IoC (Indcator of Compromise) info for Domain Names from otx.alienvault.com API.
# Written by Will Armijo

import requests
import json

print("============================================================")
print("This script is used to lookup reputational data for a Domain")
print("============================================================")
print("")
domain = input("Please Enter a Domain name: ")

gen_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
geo_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/geo"
urls_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"
malware_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/malware"
dns_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"


print("Retreiving Information Now...")
gen_response = requests.get(gen_url)
geo_response = requests.get(geo_url)
urls_response = requests.get(urls_url)
malware_response = requests.get(malware_url)
dns_response = requests.get(dns_url)

if geo_response.status_code == 200:
    geo_ip_info = geo_response.json()
    city = geo_ip_info['city']
    country = geo_ip_info['country_name']

else:
        print("Request failed with status", {geo_response.status_code}) # Error Code here

if gen_response.status_code == 200:
    gen_ip_info = gen_response.json()

    if gen_ip_info['false_positive']:
        print("False Positive - Not  Malicious")
        exit()
    else:
            pulses = gen_ip_info['pulse_info']['pulses']
            related_pulses = gen_ip_info
    for items in pulses:
        name = items['name']
        descr = items['description']
        tags = items['tags']
        created = items['created']
        modified = items['modified']
        refs = items['references']
        adversary = items['adversary']
        trgt_countries = items['targeted_countries']

        # Reporting Section
        print("====================")
        print("Related IoC Record: ")
        print("====================")
        print("")
        print("IoC Name: ", name)
        print("IOC Location Info: ")
        print("\tCity Name: ", city)
        print("\tCountry: ", country)
        print("Adversary: ", adversary)
        print("IoC Description: ", descr)
        print("IoC Created on: ", created)
        print("Last Updated", modified)
        print("")
        print("Related Tags: ")
        #for tag in tags:
            #print("\t", tag)
        #print("")
        print("References:")
        for ref in refs:
            print("\t", ref)
        print("")
    print("Targeted Countries: ")
    for country in trgt_countries:
        print("\t", country)
    print("")
    print("===============")
    print("Identified by: ")
    print("===============")
    for items in pulses:
        source_name = items['name']
        print("\t", source_name)
    print("")

    if dns_response.status_code == 200:
        dns_info = dns_response.json()
    
        dns_info = dns_info['passive_dns']
        print("=============================")
        print("Associated Hostnames: ")
        print("=============================")
        for dns in dns_info:
            print("\t", dns['hostname'])
        print("")
    else:
        print("Request failed with status", {dns_response.status_code}) # Error Code here

    if urls_response.status_code == 200:
        urls_info = urls_response.json()
    
        urls_list = urls_info['url_list']
        print("=============================")
        print("****** Associated URLS ******")
        print("=============================")
        for listing in urls_list:
            ass_urls = listing['url']
            print("\t", ass_urls)
            print("")
    else:
        print("Request failed with status", {urls_response.status_code}) # Error Code here

    if malware_response.status_code == 200:
        malware_info = malware_response.json()
        malware_data = malware_info['data']
    print("=============================")
    print("Associated Malware: ")
    print("=============================")
    print("\tDetection Info: ")
    for malware_detection in malware_data:
        print("\t\t", malware_detection['detections'])
        print("")
    print("\tAssociated Hash(s): ")
    for malware_hash in malware_data:
        print("\t\t", malware_hash['hash'])
        print("")   
    else:
        print("Request failed with status", {malware_response.status_code}) # Error Code here
else:
    print("Request failed with status", {gen_response.status_code}) # Error Code here
