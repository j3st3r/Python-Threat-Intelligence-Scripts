#!/usr/bin/python3
# Script Name: AlienVault_URL_Lookup.py
# Description: Use to retreive possible IoC (Indcator of Compromise) info for URLs from otx.alienvault.com API.
# Written by Will Armijo

import requests
import json

print("=========================================================")
print("This script is used to lookup reputational data for a URL")
print("=========================================================")

url = input("Please Enter a URL: ")

gen_url = f"https://otx.alienvault.com/api/v1/indicators/url/{url}/general"
urls_url = f"https://otx.alienvault.com/api/v1/indicators/url/{url}/url_list"

print("Retrieving Information Now...")
gen_response = requests.get(gen_url)
urls_response = requests.get(urls_url)

if gen_response.status_code == 200:
    gen_ip_info = gen_response.json()

    if gen_ip_info['false_positive']:
        print("False Positive - Not  Malicious")
        exit()
    elif gen_ip_info['validation']:
        print("White Listed Domain")
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
else:
    print("Request failed with status", {gen_response.status_code}) # Error Code here
