from __future__ import print_function
import json
import re
import csv
import os.path
import pynetbox
import pprint
import urllib3
import gspread
import pip
import numpy as np
import random
import randomcolor
import matplotlib.pyplot as plt
from string import digits
import requests as req
import pandas as pd
from google.auth.transport import requests
from requests.auth import HTTPBasicAuth
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from tabulate import tabulate
from atlassian import Confluence
from collections import OrderedDict
urllib3.disable_warnings()

# If modifying these scopes, delete the file credentials.json.
SCOPES = ['https://www.googleapis.com/auth/spreadsheets.readonly']


####################################################################
#               Get Data From SpreadsSheet
####################################################################
def getDataFromSpreadsheet(spreadSheet_id, range_name):
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    try:
        service = build('sheets', 'v4', credentials=creds)
        # Call the Sheets API
        sheet = service.spreadsheets()
        result = sheet.values().get(spreadsheetId=spreadSheet_id,
                                    range=range_name).execute()
        values = result.get('values', [])

        if not values:
            print('No data found.')
            return

        # spreadsheet_data = []
        #
        # for row in values:
        #
        #     if 'Out Of Band control' in range_name and len(row) > 5 and len(row[5]) > 0 and len(row[2]) > 0:
        #         spreadsheet_data.append({'hostname': row[2], 'switch': row[5], 'port': row[6]})
        #     elif 'In Band control' in range_name and len(row) > 13 and len(row[10]) > 0 and len(row[2]) > 0:
        #         spreadsheet_data.append({'hostname': row[2], 'switch': row[10], 'port': row[14]})
        #     elif 'In Band control' in range_name and len(row) > 21 and len(row[10]) == 0:
        #         spreadsheet_data.append({'hostname': row[2], 'switch': row[21], 'port': row[25]})
        #     # else:
        #     #     print('data not imported :' + str(row))
        #     else:
        #         spreadsheet_data = values
        #
        # return spreadsheet_data

        return values

    except HttpError as err:
        print(err)


####################################################################
#                   Check key if exist in Dictionary
####################################################################
def checkKey(dic, key):
    if key in dic.keys():
        return True
    else:
        return False


####################################################################
#                      Get Token
####################################################################
def get_token():
    url_dev = 'https://pywire-app-dev.cbc-rc.ca/api/v2/template_data_from_device/?hostname='
    url_prod = 'https://pywire-app.cbc-rc.ca/api/v2/get_token/'

    headers = {
        'Accept': 'application/json',
        'Authorization': 'Basic SWRyaXNzaUs6UlQ2NTEyeHUwMWV4NTI='
    }
    response = req.request("GET", url_prod, headers=headers)
    responseData = response.json()
    return responseData['token']


####################################################################
#                      Get Device Info from Pywire
#      call the API : DEVICE/template_data_from_device
####################################################################
def get_device_info(device, token):
    url_dev = 'https://pywire-app-dev.cbc-rc.ca/api/v2/template_data_from_device/?hostname='
    url_prod = 'https://pywire-app.cbc-rc.ca/api/v2/template_data_from_device/?hostname='
    url = url_dev + device['hostname']

    headers = {
        'Accept': 'application/json',
        'X-Access-Token': token
    }
    response = req.request("GET", url, headers=headers)
    data = {}
    rack = rack_elevation = schematics = equipment_type = equipment_description_pywire = manufacturer = ''

    if response.status_code == 200:
        responseData = response.json()
        if responseData['result'] == 'found':
            if checkKey(responseData['device_infos'], 'rack'):
                rack = responseData['device_infos']['rack']
            if checkKey(responseData['device_infos'], 'rack_elevation'):
                rack_elevation = responseData['device_infos']['rack_elevation']
            if checkKey(responseData['device_infos'], 'schematics'):
                schematics = responseData['device_infos']['schematics']
            if checkKey(responseData['template_infos'], 'equipment_type'):
                equipment_type = responseData['template_infos']['equipment_type']
            if checkKey(responseData['template_infos'], 'equipment_description'):
                equipment_description_pywire = responseData['template_infos']['equipment_description']
            if checkKey(responseData['template_infos'], 'manufacturer'):
                manufacturer = responseData['template_infos']['manufacturer']

            if not checkKey(device, 'red_switch'):
                data = {
                    'hostname': device['hostname'],
                    'description_spreadsheet': device['description'],
                    'description_pywire': equipment_description_pywire,
                    'switch': device['switch'],
                    'port': device['port'],
                    'ip_address': device['ip_address'],
                    'vlan': device['vlan'],
                    'rack': rack,
                    'rack_elevation': rack_elevation,
                    'rack_elevation': rack_elevation,
                    'schematics': schematics,
                    'equipment_type': equipment_type,
                    'manufacturer': manufacturer,
                    'result': responseData['result']
                }
            if checkKey(device, 'red_switch'):
                data = {
                    'hostname': device['hostname'],
                    'description_spreadsheet': device['description'],
                    'description_pywire': equipment_description_pywire,
                    'red_switch': device['red_switch'],
                    'red_port': device['red_port'],
                    'red_ip_address': device['red_ip_address'],
                    'blue_switch': device['blue_switch'],
                    'blue_port': device['blue_port'],
                    'blue_ip_address': device['blue_ip_address'],
                    'rack': rack,
                    'rack_elevation': rack_elevation,
                    'rack_elevation': rack_elevation,
                    'schematics': schematics,
                    'equipment_type': equipment_type,
                    'manufacturer': manufacturer,
                    'result': responseData['result']
                }


    else:
        print(str(response.status_code) + ' : ' + response.text + str(device))

    return data

####################################################################
#                      Write Dictionary in a CSV File
####################################################################
def writeData(header, data, file_name: str):
    if len(data) > 0:
        with open(file_name + '.csv', 'a', encoding='UTF8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=header)
            writer.writeheader()
            writer.writerows(data)


####################################################################
#                      Write Hostnames in a file
####################################################################
def writeNoneHostname(hostname: str, file_name: str):
    with open(file_name + '.txt', 'a') as file_object:
        file_object.write(hostname)
        file_object.write('\n')
        file_object.close()

####################################################################
#                 Trace path by switch and port
####################################################################
def trace_path_byswitch_and_port(hostname, switch, port, token):
    if switch == '' or port == '':
        return {'result': 'not found'}

    if 'B' in port:
        port = port.split('P')[1]

    if '*' in port:
        port = re.findall(r'\d+', port)[0]

    url = 'https://pywire-app-dev.cbc-rc.ca/api/v2/tracedpathbyswitchandport/?switch=' + switch + '&port=' \
          + port + '&regex=true&selected_page=1&items_per_page=100'
    headers = {
        'Accept': 'application/json',
        'X-Access-Token': token
    }
    response = req.request("GET", url, headers=headers)
    if response.status_code == 200:
        responseData = response.json()
        if len(responseData) > 0:

            return {
                'hostname in spreadsheet': hostname,
                'alias': responseData[0]['path_ep2']['alias'].split('\n')[0],
                'equipment_name': responseData[0]['path_ep2']['equipment_name'].split('\n')[0],
                'equipment_type': responseData[0]['path_ep2']['equipment_type'].split('\n')[0],
                'sys_name': responseData[0]['path_ep2']['sys_name'].split('\n')[0],
                'schem': responseData[0]['path_ep2']['schem'].split('\n')[0],
                'location': responseData[0]['path_ep2']['location'].split('\n')[0],
                'rack_elevation': responseData[0]['path_ep2']['rack_elevation'].split('\n')[0],
                'switch': switch,
                'port': port,
                'result': 'found'
            }
        else:
            return {'result': 'not found'}

    else:
        print(str(response.status_code) + ': ' + switch + ' : ' + port)


####################################################################
#                      Match device name
####################################################################
def match_device_name(device_name, token):
    url_dev = 'https://pywire-app-dev.cbc-rc.ca/api/v2/match_device_name/?device_name='
    url_prod = 'https://pywire-app.cbc-rc.ca/api/v2/match_device_name/?device_name='
    url = url_dev + device_name
    headers = {
        'Accept': 'application/json',
        'X-Access-Token': token
    }
    response = req.request("GET", url, headers=headers)
    if response.status_code == 200:
        responseData = response.json()
        device_temp = ''
        if checkKey(responseData, 'result') and responseData['result'] == 'no match':
            return device_name
        else:
            for res in responseData['all_results']:
                if re.findall(r'\d+', res)[0] == re.findall(r'\d+', device_name)[0]:
                    device_temp = res
                    break
            if device_temp != device_name:
                return device_temp
            else:
                return device_name
    else:
        print(str(response.status_code) + ' : ' + response.text + str(device_name))

####################################################################
#                      Remove VMS and Switches
####################################################################
def remove_vms_switches(hostnames):
    list_devices = []
    with open('config.json', 'r') as f:
        config = json.load(f)

    for host in hostnames:
        if 'VLAN' not in host['hostname'] and 'A_changer' not in host['hostname'] and 'REF' not in host['hostname'] \
                and 'Hostname' not in host['hostname'] and 'MTL-.*' not in host['hostname'] \
                and not re.match(config['patterns']['switch_pattern'], host['hostname']) \
                and not re.match(config['patterns']['computing_virtual_machine_pattern'], host['hostname']):
            list_devices.append(host)
        else:
            print(host['hostname'] + ' : ' + host['description'])
    return list_devices

####################################################################
#                      get_device_data
####################################################################
def get_device_info_from_pywire(devices_list, token, roles):
    device_in_netbox = []
    data_found = []
    data_wrong_hostname = []
    data_wrong_switch = []
    data_not_found = []
    data_hostname_respect_grammaire = []
    data_no_respect_grammaire = []

    for device in devices_list:
        # chercher les infos du device en appelant l'API : DEVICE/template_data_from_device
        result = get_device_info(device, token)
        role = get_device_role(device['hostname'], roles)
        if len(result) > 0:
            # validr le hostname selon Grammaire Larlk
            is_valid_hostname = validate_hostname(device['hostname'])
            result.update({'is_valid_hostname': is_valid_hostname, 'role': role})
            data_found.append(result)

        # else:
        #     # si l'API template_data_from_device ne retourne rien appeler l'API du switch et port
        #     result = trace_path_byswitch_and_port(device['hostname'], device['red_switch'], device['red_port'], token)
        #     if result['result'] == 'found':
        #         data_wrong_hostname.append(result)
        #     else:
        #         # si l'api du switch et port ne retourne rien, verifier si le switch
        #         # est bon en appelant l'api match_device_name
        #         switch_temp = match_device_name(device['switch'], token)
        #         # si le switch n'est pas correcte, on recupere le switch correcte on appelle
        #         # de nouveau l'api switche et port avec le nouveau switch
        #         if switch_temp != device['switch']:
        #             result = trace_path_byswitch_and_port(device['hostname'], switch_temp, device['port'], token)
        #             # si on recupere un resultat avec le nouveau switch, on enregistre le resultat
        #             if result['result'] == 'found':
        #                 tmp = []
        #                 hostname_spreadsheet = device['hostname'].split('\n')[0]
        #                 hostname_pywire = result['alias'].split('\n')[0]
        #                 wrong_switch = device['switch'].split('\n')[0]
        #                 correct_switch = switch_temp
        #                 port = result['port'].split('\n')[0]
        #                 equipment_name = result['equipment_name'].split('\n')[0]
        #                 equipment_type = result['equipment_type'].split('\n')[0]
        #                 sys_name = result['sys_name'].split('\n')[0]
        #                 schem = result['schem'].split('\n')[0]
        #                 location = result['location'].split('\n')[0]
        #                 rack_elevation = result['rack_elevation'].split('\n')[0]
        #                 data_wrong_switch.append({'hostname_spreadsheet':hostname_spreadsheet, 'hostname_pywire':hostname_pywire, 'wrong_switch':wrong_switch,
        #                                           'correct_switch':correct_switch, 'port':port, 'equipment_name':equipment_name, 'equipment_type':equipment_type,
        #                                           'sys_name':sys_name, 'schem':schem, 'location':location, 'rack_elevation':rack_elevation})
        #             else:
        #                 # si on recupere aucun resultat avec le nouveau switch on a aucune information sur le device
        #                 data_not_found.append(device)
        #         else:
        #             # si le switch est bon,on a aucune information sur le device
        #             data_not_found.append(device)

    return data_found, data_not_found, data_wrong_hostname, data_wrong_switch, device_in_netbox, data_hostname_respect_grammaire, data_no_respect_grammaire

####################################################################
#                     Dessiner le piechart
####################################################################
def draw_pie_chart(data_found, data_not_found, data_wrong_hostname, data_wrong_switch, title):

    title_tmp = ''
    if 'MPX' in title:
        title_tmp = 'IP_Pord'
    else:
        title_tmp = 'IP_Pres'

    y = np.array([len(data_found), len(data_not_found), len(data_wrong_hostname), len(data_wrong_switch)])
    mylabels = ['hostnames trouves', 'hostnames non trouves', 'hostname different', 'switch different']
    mycolors = ["#008000", "r", "#FF8C00", "b"]
    plt.pie(y, labels=mylabels, autopct='%1.1f%%', startangle=90, colors=mycolors)
    plt.title(title_tmp, color="#000000", fontsize=15)
    plt.show(block=False)
    plt.savefig(title_tmp + ' ' + title)

####################################################################
#                  Recuperer le role du hostname
####################################################################
def get_device_role(hostname, roles):

    found = False
    role = ''
    for elem in roles:
        if elem in hostname:
            found = True
            #print(elem + ' : ' + hostname + ' : ' + 'Yes')
            role = elem
            break
    if found == False:
        #print(hostname + ' : ' + 'NO Role Found')
        role = '****'
    return role

####################################################################
#          Recuperer les datas du spreadsheet (out of band)
####################################################################
def get_hostnames_from_out_of_band_spreadsheet(data_spreadsheet):

    hostnames_list = []
    hostnames_no_ip = []

    for row in data_spreadsheet[3:]:
        if len(row) >= 12 and row[5] != '' and row[12] != '':
            hostnames_list.append({'hostname': row[2],
                                   'description': row[0],
                                   'switch': row[5],
                                   'port': row[6],
                                   'ip_address': row[12],
                                   'vlan': row[10],
                                   })

        else:
            hostnames_no_ip.append(row)

    return hostnames_list

####################################################################
#          Recuperer les datas du spreadsheet (in band)
####################################################################
def get_hostnames_from_in_band_spreadsheet(data_spreadsheet):

    hostnames_list = []
    hostnames_no_ip = []

    for row in data_spreadsheet[3:]:
        if len(row) >= 31 and (row[17] != '' or row[28] != ''):
            hostnames_list.append({'hostname': row[2],
                                   'description': row[0],
                                   'red_switch': row[10],
                                   'red_port': row[14],
                                   'red_ip_address': row[17],
                                   'blue_switch': row[21],
                                   'blue_port': row[25],
                                   'blue_ip_address': row[28]
                                   })

        elif len(row) == 20 and row[17] != '':
            hostnames_list.append({'hostname': row[2],
                                   'description': row[0],
                                   'red_switch': row[10],
                                   'red_port': row[14],
                                   'red_ip_address': row[17],
                                   'blue_switch': '',
                                   'blue_port': '',
                                   'blue_ip_address': ''
                                   })
        else:
            hostnames_no_ip.append(row)

    return hostnames_list
def main_traitment(spreadSheet_id, range_name, roles):
    # spreadSheet_id = config['Ip_Production_MTL']['out_of_band']['SAMPLE_SPREADSHEET_ID']
    # range_name = config['Ip_Production_MTL']['out_of_band']['SAMPLE_RANGE_NAME']
    title_tmp = ''
    if 'MPX' in range_name:
        title_tmp = 'IP_Pord'
    else:
        title_tmp = 'IP_Pres'
    print('0- Traitement du spreadsheet : ' + title_tmp + ' ' + range_name)
    print('1- Recuperer la liste des devices a partir du spreadsheet:')
    data = getDataFromSpreadsheet(spreadSheet_id, range_name)
    print('\tTotal des hostnames dans le spreadsheet : ' + str(len(data)))
    if 'In Band' in range_name:
        hostnames = get_hostnames_from_in_band_spreadsheet(data)
    elif 'Out Of Band' in range_name:
        hostnames = get_hostnames_from_out_of_band_spreadsheet(data)

    print('\tTotal des hostnames qui ont une adreresse IP : ' + str(len(hostnames)))
    print('2- Eliminer les switches et les machines virtuelles:')
    devices_list = remove_vms_switches(hostnames)
    print('Total des hostnames apres suppression des switches et des machines virtuelles : ' + str(len(devices_list)))
    # Get template info from device hostname
    print('3- Recuperer les infos des equipements: ')
    # # get roles :
    # array_device = []
    # for elem in devices_list:
    #     array_device.append(elem['hostname'])
    #
    # device_not_duplicated = list(OrderedDict.fromkeys(array_device))
    # found = False
    # for dev in device_not_duplicated:
    #     for elem in roles:
    #         if elem in dev:
    #             found = True
    #             print(elem + ' : ' + dev + ' : ' + 'Yes')
    #
    #     if found == False:
    #         print(dev + ' : ' + 'NO')
    #     found = False
    token = get_token()
    data_found, data_not_found, data_wrong_hostname, data_wrong_switch, device_in_netbox, data_hostname_respect_grammaire, data_no_respect_grammaire = get_device_info_from_pywire(devices_list, token, roles)

    header_wrong_hostname = ['hostname in spreadsheet', 'alias', 'equipment_name', 'equipment_type', 'sys_name', 'schem', 'location', 'rack_elevation', 'switch', 'port','result']
    header_wrong_switch = ['hostname_spreadsheet', 'hostname_pywire', 'wrong_switch', 'correct_switch', 'port',
                           'equipment_name', 'equipment_type', 'sys_name', 'schem', 'location', 'rack_elevation']
    header_data_not_found = ['hostname', 'switch', 'port']

    print('---------------------------------------------------------------------')
    print('data_found:')
    print(data_found)
    # print(title_tmp + ' ' + range_name)
    # for host in data_found:
    #     get_device_role(host, roles)
    #
    # print('---------------------------------------------------------------------')
    # print('wrong_hostname: ' + str(len(data_wrong_hostname)))
    # print(data_wrong_hostname)
    # writeData(header_wrong_hostname, data_wrong_hostname, 'wrong_hostname')
    # print('---------------------------------------------------------------------')
    # print('data_wrong_switch: ' + str(len(data_wrong_switch)))
    # print(data_wrong_switch)
    # writeData(header_wrong_switch, data_wrong_switch, 'wrong_switch')
    # print('---------------------------------------------------------------------')
    # print('data_not_found: ' + str(len(data_not_found)))
    # print(data_not_found)
    # writeData(header_data_not_found, data_not_found, 'data_not_found')
    # print('---------------------------------------------------------------------')
    # print('4- Les hostnames trouves dans pywire :' + str(len(data_found)))
    # print(tabulate(data_found))
    # print('5- Donnes trouvees avec un hostname different entre spreadsheet et pywire :'
    #       + str(len(data_wrong_hostname)))
    # print(tabulate(data_wrong_hostname))
    # print('6- Donnes trouvees avec un switch different entre spreadsheet et pywire : '
    #       + str(len(data_wrong_switch)))
    # print(tabulate(data_wrong_switch))
    # print('7- Hostnames non trouves :' + str(len(data_not_found)))
    # print(tabulate(data_not_found))
    # print('8- Hostname respect grammaire Lark: ' + str(len(data_hostname_respect_grammaire)))
    # for dev in data_hostname_respect_grammaire:
    #     print(dev)
    #
    # print('9- hostname non respect grammaire:  ')
    # for dev in data_no_respect_grammaire:
    #     print(dev)

    #update_confluencepage(data_wrong_hostname, data_wrong_switch, data_not_found, title_tmp + ' ' + range_name)
    #draw_pie_chart(data_found, data_not_found, data_wrong_hostname, data_wrong_switch, range_name)


def get_devices_from_netbox():
    # nb = pynetbox.api(
    #     url='https://netbox-lab.cbc-rc.ca/',
    #     token='aeb8079c02cafe0f28d898dd97aeb02aff4529af'
    # )
    nb = pynetbox.api(
        url='https://netbox.cbc-rc.ca/',
        token='048bf3943797d831c88f95c4faef8ae3b3d9b084'
    )
    nb.http_session.verify = False
    # pprint.pprint(nb.status())
    devices = list(nb.dcim.devices.all())
    return devices
def check_device_exist_netbox(device_name):
    # nb = pynetbox.api(
    #     url='https://netbox-lab.cbc-rc.ca/',
    #     token='aeb8079c02cafe0f28d898dd97aeb02aff4529af'
    # )

    nb = pynetbox.api(
        url='https://netbox.cbc-rc.ca/',
        token='048bf3943797d831c88f95c4faef8ae3b3d9b084'
    )
    nb.http_session.verify = False
    device = nb.dcim.devices.get(name=device_name)

    return device
def confluence_attach_file(filename):
    confluence = Confluence(
        url='https://cbcradiocanada.atlassian.net/',
        username='khalid.hafdi.idrissi@radio-canada.ca',
        password='0PDh7Nk9p0jkR7geKd0999EA',
        cloud=True)
    page_id = confluence.get_page_id('ADOPS', 'IP_Pord Ansible - MPX In Band control')
    confluence.attach_file(filename, name=None, content_type=None, page_id=page_id, title='wrong_hostname', space='ADOPS', comment=None)

    #-------------------------------------------------------------------------------------------------------------------
    # url = 'https://cbcradiocanada.atlassian.net/wiki/rest/api/content/3628302929/child/attachment/att3640033455/data'
    # auth = HTTPBasicAuth("khalid.hafdi.idrissi@radio-canada.ca", "0PDh7Nk9p0jkR7geKd0999EA")
    # headers = {
    #     "Accept": "application/json"
    # }
    # response = req.request(
    #     "GET",
    #     url,
    #     headers=headers,
    #     auth=auth
    # )
    #
    # print(response.status_code)
    #-------------------------------------------------------------------------------------------------------------------

####################################################################
#                      Update_confluence_page
####################################################################
def update_confluencepage(data_wrong_hostname, data_wrong_switch, data_not_found, page_title):
    confluence = Confluence(
        url='https://cbcradiocanada.atlassian.net/',
        username='khalid.hafdi.idrissi@radio-canada.ca',
        password='0PDh7Nk9p0jkR7geKd0999EA',
        cloud=True)

    #print(confluence.get_page_by_id(3624239395, expand='body.storage'))

    html = '<p><strong>1- IP_Pres-outofband:</strong></p><p><u>Donnes trouvees avec un hostname different entre spreadsheet et pywire : '+ str(len(data_wrong_hostname)) +'</u></p>' \
           '<table data-layout="default" ac:local-id="95c3aa69-2d73-48e9-ad7d-fb3c28120c73"><colgroup><col style="width: 131.0px;" /><col style="width: 265.0px;" />' \
           '<col style="width: 135.0px;" /><col style="width: 48.0px;" /><col style="width: 93.0px;" /><col style="width: 88.0px;" /></colgroup>' \
           '<tbody><tr><th><p><strong>Hostname in Spreadsheet</strong></p></th><th><p><strong>Hostname in Pywire</strong></p></th><th><p><strong>Switch' \
           '</strong></p></th><th><p><strong>Port</strong></p></th><th><p><strong>Equipment Type</strong></p></th><th><p><strong>Schem</strong></p></th></tr>' \

    for elem in data_wrong_hostname:
        html += "<tr><td><p>" + elem['hostname in spreadsheet'] + "</p></td>"
        html += "<td><p>" + elem['alias'] + "</p></td>"
        html += "<td><p>" + elem['switch'] + "</p></td>"
        html += "<td><p>" + elem['port'] + "</p></td>"
        html += "<td><p>" + elem['equipment_type'] + "</p></td>"
        html += "<td><p>" + elem['schem'] + "</p></td></tr>"

    html += '</tbody></table><p><u>Donnes trouvees avec un switch different entre spreadsheet et pywire : ' + str(len(data_wrong_switch)) + '</u></p>' \
            '<table data-layout="default" ac:local-id="e4ece081-7f33-40b1-bd84-b8bf4066b2ab">' \
            '<colgroup><col style="width: 250.0px;" /><col style="width: 513.0px;" /><col style="width: 260.0px;" />' \
            '<col style="width: 96.0px;" /><col style="width: 182.0px;" /><col style="width: 157.0px;" /></colgroup>' \
            '<tbody><tr><th><p><strong>Hostname in Spreadsheet</strong></p></th><th><p><strong>Hostname_pywire</strong>' \
            '</p></th><th><p><strong>Switch</strong></p></th><th><p><strong>Port</strong></p></th><th><p>' \
            '<strong>Equipment Type</strong></p></th><th><p><strong>Schem</strong></p></th></tr>' \

    for elem in data_wrong_switch:
        html += "<tr><td><p>" + elem[0] + "</p></td>"
        html += "<td><p>" + elem[1] + "</p></td>"
        html += "<td><p>" + elem[3] + "</p></td>"
        html += "<td><p>" + elem[4] + "</p></td>"
        html += "<td><p>" + elem[6] + "</p></td>"
        html += "<td><p>" + elem[8] + "</p></td></tr>"

    html += '</tbody></table><p><u>Hostnames non trouves : ' + str(len(data_not_found)) + '</u></p><table data-layout="default" ac:local-id="e731b595-6a15-4316-9fa2-588212195f4e">' \
            '<colgroup><col style="width: 388.0px;" /><col style="width: 656.0px;" />' \
            '<col style="width: 417.0px;" /></colgroup><tbody><tr><th><p><strong>Hostname</strong></p></th>' \
            '<th><p><strong>Switch</strong></p></th><th><p><strong>Port</strong></p></th></tr>' \

    for elem in data_not_found:
        html += "<tr><td><p>" + elem['hostname'] + "</p></td>"
        html += "<td><p>" + elem['switch'] + "</p></td>"
        html += "<td><p>" + elem['port'] + "</p></td></tr>"


    html += '</tbody></table>'
    page_id = confluence.get_page_id('ADOPS', page_title)
    confluence.update_page(page_id, page_title,
                           html, parent_id=None, type='page',
                           representation='storage',
                           minor_edit=False, full_width=False)

####################################################################
#        Validate if a hostname respect lark-grammar
####################################################################
def validate_hostname(hostname):
    url = 'http://netbox-portal.cbc-rc.ca:8000/api/v1/network/hostname_validity/?hostnames='
    headers = {
        'Accept': 'application/json',
        'Authorization': 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJpZHJpc3NpayIsImV4cCI6MTY3NTI4Njk5MX0.Kege-8T5jnqqm2QO0LiDy-gc-PyXSAqKm1cKy-xNp9w'
    }
    response = req.request("GET", url + hostname, headers=headers)
    if response.status_code == 200:
        responseData = response.json()
        return responseData[hostname]
    else:
        return response.content

def generate_colors(number):
    list_colors = []
    for x in range(0, number):
        color = randomcolor.RandomColor().generate()[0].split('#')[1]
        list_colors.append(color)

    return list_colors

def create_device_role(role_name, role_slug, color, description, tag):

    nb = pynetbox.api(
        url='https://netbox-lab.cbc-rc.ca/',
        token='aeb8079c02cafe0f28d898dd97aeb02aff4529af'
    )
    nb.http_session.verify = False

    isRoleExist = nb.dcim.device_roles.get(name=role_name)

    if isRoleExist == None:
        role = nb.dcim.device_roles.create(
            name=role_name,
            slug=role_slug,
            color=color,
            vm_role=False,
            tags=[{'name': tag}],
            description=description
        )
        print(role.name + ' is created on Netbox')
    else :
        print('Error: ' + role_name + ' ==> device role with this name already exists')

def get_device_roles_from_spreadsheet():

    values = getDataFromSpreadsheet('1KYQXUJ9XEnislU8DZZCLusoPAbL3gmYGT2-JNsGdV0A', 'Broadcast endpoint devices')
    for role in values:
        role.append(role[1])

    values.pop(0)
    print(values)
    print(len(values))

    device_roles = []
    for role in values:
        if '/' in role[0]:
            name = role[0].split('/')[0]
        elif '-' in role[0]:
            name = role[0].split('-')[0]
        elif '(' in role[0]:
            name = role[0].split('(')[0]
        else:
            name = role[0]

        name = "".join(name.rstrip())
        slug = name.replace(' ', '_')
        description = role[0] + ' : ' + role[1]
        device_roles.append({'name': name, 'slug': slug, 'description': description})

    return device_roles

####################################################################
#        Get Roles acronymn from Broadcast endpoint device
####################################################################
def get_roles_from_spreadsheet():
    values = getDataFromSpreadsheet('1KYQXUJ9XEnislU8DZZCLusoPAbL3gmYGT2-JNsGdV0A', 'Broadcast endpoint devices')
    values.pop(0)
    roles_acronymn = []
    for elem in values:
        roles_acronymn.append(elem[1])
    return roles_acronymn

####################################################################
#                      Main Function
####################################################################
if __name__ == '__main__':

    # device_roles = get_device_roles_from_spreadsheet()
    # colors = generate_colors(len(device_roles))
    # i = 0
    # for role in device_roles:
    #     create_device_role(role['name'], role['slug'], colors[i], role['description'], 'Broadcast endpoint devices')
    #     i += 1

    # tagspreadsheet = nb.extras.tags.create(
    #     name='Broadcast endpoint devices',
    #     slug='Broadcast_endpoint_devices',
    #     color='a2cd5a',
    #     description='data imported from the spreadsheet Broadcast endpoint devices'
    # )
    roles = get_roles_from_spreadsheet()
    # #1- Ip_Pres_ outofband
    # main_traitment('1FlV5Bqc3wBSkWqMsreBkOyYPhjk3tlaUAuL6Akc9sD4', 'Ansible - Out Of Band control', roles)
    # #2- Ip_Pres_ inband
    # main_traitment('1FlV5Bqc3wBSkWqMsreBkOyYPhjk3tlaUAuL6Akc9sD4', 'Ansible - Out Of Band control', roles)
    # # 3- Ip_Prod_ outofband
    # main_traitment('1CkMFRH1CiPrw3wZUsEiBUg3tKhAd2CTJkNlwMjQJQ7I', 'Ansible - MPX Out Of Band control', roles)
    # # 4- Ip_Prod_ inband
    # main_traitment('1CkMFRH1CiPrw3wZUsEiBUg3tKhAd2CTJkNlwMjQJQ7I', 'Ansible - MPX In Band control', roles)


    # data_wrong_hostname = []
    # data_wrong_switch = []
    # data_not_found = []
    #
    # confluence = Confluence(
    #     url='https://cbcradiocanada.atlassian.net/',
    #     username='khalid.hafdi.idrissi@radio-canada.ca',
    #     password='0PDh7Nk9p0jkR7geKd0999EA',
    #     cloud=True)
    # title_tmp = 'IP_Pres Ansible - Out Of Band control'
    # update_confluencepage(data_wrong_hostname, data_wrong_switch, data_not_found, title_tmp)

    #print(confluence.get_page_by_id(3624239395, expand='body.storage'))
    #
    # page_id = confluence.get_page_id('ADOPS', 'IP_Pres Ansible - In Band control')
    # # confluence.update_page(page_id, 'IP_Pres Ansible - In Band control',
    # #                        html, parent_id=None, type='page',
    # #                        representation='storage',
    # #                        minor_edit=False, full_width=False)
    #
    # # print(confluence.get_page_id('ADOPS', "IP_Pres Ansible - Out Of Band control"))
    # # print(confluence.get_page_id('ADOPS', "IP_Pres Ansible - In Band control"))
    # # print(confluence.get_page_id('ADOPS', "IP_Pord Ansible - MPX In Band control"))
    # # print(confluence.get_page_id('ADOPS', "IP_Pord Ansible - MPX Out Of Band control"))

    print('-------------------------------------------------------------')
    # nb = pynetbox.api(
    #     url='https://netbox-lab.cbc-rc.ca/',
    #     token='aeb8079c02cafe0f28d898dd97aeb02aff4529af'
    # )
    # nb.http_session.verify = False
    # device = nb.dcim.devices.get(15)
    # print(dict(device))
    print('-------------------------------------------------------------')

    # data = getDataFromSpreadsheet('1OfQP7MMCBs6h-_s7Roh542DdE7EZAJu1UjqorTSOYzw', 'test')
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    try:
        service = build('sheets', 'v4', credentials=creds)
        # Call the Sheets API
        sheet = service.spreadsheets()
        result = sheet.values().get(spreadsheetId='1OfQP7MMCBs6h-_s7Roh542DdE7EZAJu1UjqorTSOYzw',range='test').execute()
        print(result)

    except:
        print('error')





