#!/usr/bin/python

import json
import os
import csv
import sys
import zipfile
import requests
import io
from versions import *


def get_json(url):
    file = [i for i in url.split('/')][7]
    print('Getting file {}'.format(file)),
    r = requests.get(url, stream=True)
    if r.ok:
        # Unzip the file if the download was successful
        z = zipfile.ZipFile(io.BytesIO(r.content)).extractall()
        print(' [OK]')
    else:
        print(' [ERROR]')


def f5_cve_parser(file, version, severity, dict_list, device_platform):

    with open(file, 'r') as file:
        file = file.read()
        json_file = json.loads(file)
        for data in json_file['CVE_Items']:
            for k, v in data.items():
                try:
                    cve_dict = {}
                    if data['cve']['affects']['vendor']['vendor_data'][0]['vendor_name'] == 'jenkins':
                        for i in data['cve']['affects']['vendor']['vendor_data'][0]['product']['product_data']:
                            if i['product_name'] == device_platform:
                                if data['impact']['baseMetricV2']['severity'] in severity:
                                    sev = data['impact'][
                                        'baseMetricV2']['severity']
                                    cve = data['cve']['CVE_data_meta']['ID']
                                    cve_dict[cve] = {}
                                    cve_dict[cve]['CVE ID'] = cve
                                    cve_dict[cve]['version'] = []
                                    cve_dict[cve]['severity'] = sev

                                for i in data['cve']['affects']['vendor']['vendor_data'][0]['product']['product_data'][0]['version']['version_data']:
                                    if i['version_value'] in version:
                                        cve_dict[cve]['version'].append(
                                            i['version_value'])

                                if cve_dict[cve]['version']:
                                    description = data['cve']['description'][
                                        'description_data'][0]['value']
                                    cve_dict[cve]['description'] = description
                                    cve_dict[cve]['notes'] = ''

                                    for i in data['cve']['references']['reference_data']:
                                        vendor_link = i['url']
                                    cve_dict[cve]['link'] = vendor_link

                                    if not cve_dict[cve] in dict_list:
                                        dict_list.append(cve_dict[cve])

                except:
                    continue


def cve_parser(file, version, severity, dict_list, device_platform):

    with open(file, 'r') as file:
        file = file.read()
        json_file = json.loads(file)
        for data in json_file['CVE_Items']:
            for k, v in data.items():
                try:
                    cve_dict = {}
                    if data['cve']['affects']['vendor']['vendor_data'][0]['product']['product_data'][0]['product_name'] == device_platform:
                        if data['impact']['baseMetricV2']['severity'] in severity:
                            sev = data['impact']['baseMetricV2']['severity']
                            cve = data['cve']['CVE_data_meta']['ID']
                            cve_dict[cve] = {}
                            cve_dict[cve]['CVE ID'] = cve
                            cve_dict[cve]['version'] = []
                            cve_dict[cve]['severity'] = sev

                            for i in data['cve']['affects']['vendor']['vendor_data'][0]['product']['product_data'][0]['version']['version_data']:
                                if i['version_value'] in version:
                                    cve_dict[cve]['version'].append(
                                        i['version_value'])

                            if cve_dict[cve]['version']:
                                description = data['cve']['description'][
                                    'description_data'][0]['value']
                                cve_dict[cve]['description'] = description
                                cve_dict[cve]['notes'] = ''

                                for i in data['cve']['references']['reference_data']:
                                    vendor_link = i['url']
                                cve_dict[cve]['link'] = vendor_link

                                if not cve_dict[cve] in dict_list:
                                    dict_list.append(cve_dict[cve])

                except:
                    continue


def file_writer(dict_list):

    order = ['CVE ID', 'severity', 'description', 'notes', 'link', 'version']
    with open('{}_cve.csv'.format(sys.argv[1]), 'w') as output_file:
        dict_writer = csv.DictWriter(output_file, order)
        dict_writer.writeheader()
        for cve in dict_list:
            dict_writer.writerow({k: ' '.join(v) if isinstance(
                v, list) else v for k, v in cve.items()})


def main():

    severity = ['MEDIUM', 'HIGH', 'CRITICAL']

    dict_list = []

    if len(sys.argv) < 2:
        sys.exit(
            'Please specify the device type (jenkins, aws, kubernetes) or -i to initialize')

    if sys.argv[1] == '-i':
        cve_recent = 'https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.json.zip'
        cve_2019 = 'https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2019.json.zip'
        json_recent = get_json(cve_recent)
        json_2019 = get_json(cve_2019)
        sys.exit()

    #Versions are found in the versions.py file
    #To add more device platforms, add to the dictionary below and versions.py
    plat_dict = {'kubernetes': {'version': kubernetes_version, 'platform': 'kubernetes'},
                 'aws': {'version': aws_version, 'platform': 'aws'},
                 'jenkins': {'version':jenkins_version, 'platform': 'jenkins'}}
                 

    try:
        device = sys.argv[1]
        version = plat_dict[device]['version']
        device_platform = plat_dict[device]['platform']

    except:
        print('Invalid device type: {}'.format(sys.argv[1]))
        sys.exit(
            'Please specify the device type (asa, nxos, f5, paloalto, juniper) or -i to initialize')

    location = os.getcwd()
    for file in os.listdir(location):
        if file.endswith(".json"):
            print('Parsing CVE list {}'.format(file)),
            if device == 'f5':
                f5_cve_parser(file, version, severity,
                              dict_list, device_platform)
                print(' [OK]')
            else:
                cve_parser(file, version, severity, dict_list, device_platform)
                print(' [OK]')
    print('Number of CVEs found: {}'.format(len(dict_list)))
    # Writes file to csv, can be opened with Excel, Numbers, etc
    file_writer(dict_list)


if __name__ == '__main__':
    main()
