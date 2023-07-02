import sys
import pynetbox
import json
import re
import requests as req
import urllib3
from slugify import slugify
from atlassian import Confluence

urllib3.disable_warnings()

# Access environment variables
tnetbox = sys.argv[1]
tpywire = sys.argv[2]
atlassiantoken = sys.argv[3]

# tnetbox = '048bf3943797d831c88f95c4faef8ae3b3d9b084'
# tpywire = 'SWRyaXNzaUs6UVdBU3h1MDFleDUy'

#print parameters
print(tnetbox)
print(tpywire)

#pynetbox
nb = pynetbox.api(
            url='https://netbox.cbc-rc.ca/',
            token= tnetbox
        )
nb.http_session.verify = False


####################################################################
#                 Trace path by switch and port
####################################################################
def api_trace_path_byswitch_and_port(switch_port, token):

    port = switch_port['port']
    switch = switch_port['switch']

    if 'B' in switch_port['port']:
        matchport = re.search(r'B(\d+)P(\d+)', switch_port['port'])
        matchsplit = re.search(r'S(\d+)', switch_port['split'])
        if matchport:
            first_int = int(matchport.group(1))
            second_int = int(matchport.group(2))
            if matchsplit:
                third_int = int(matchsplit.group(1))
                port = str(first_int) + '/' + str(second_int) + '/' + str(third_int)
            else:
                return {}
        else:
            return {}

    if '*' in switch_port['port']:
        port = re.findall(r'\d+', switch_port['port'])[0]

    url = 'https://pywire-app.cbc-rc.ca/api/v2/tracedpathbyswitchandport/?switch=' + switch + '&port=' \
          + port + '&regex=true&selected_page=1&items_per_page=100'
    headers = {
        'Accept': 'application/json',
        'X-Access-Token': token
    }
    response = req.request("GET", url, headers=headers)
    if response.status_code == 200:
        responseData = response.json()
        if len(responseData) > 0:
                # and device['hostname'] in responseData[0]['path_ep2']['alias']:
            result = {
                'hostname_pywire': responseData[0]['path_ep2']['alias'].split('\n')[0],
                'device_type': responseData[0]['path_ep2']['equipment_name'].split('\n')[0],
                'rack': responseData[0]['path_ep2']['location'].split('\n')[0],
                'rack_elevation': responseData[0]['path_ep2']['rack_elevation'].split('\n')[0],
                'result': 'found'
            }
            return result
        else:
            return {}

    else:
        print(str(response.status_code) + ': ' + switch_port['switch'] + ' : ' + port)

####################################################################
#         api_template_data_from_device_with_auto_match
####################################################################
def api_template_data_from_device_with_auto_match(device_name, token):

    url = f"https://pywire-app.cbc-rc.ca/api/v2/template_data_from_device_with_auto_match/?device_name={device_name}"
    headers = {
        'Accept': 'application/json',
        'X-Access-Token': token
    }
    try:
        response = req.request("GET", url, headers=headers)
        response.raise_for_status()  # raise exception if status code is not 200
        response_data = response.json()
        if not response_data:
            # No match found
            return {}
        elif len(response_data.get('all_results', [])) >= 1 and device_name in response_data['result']:
            device_info = response_data['device_infos']
            template_info = response_data['template_infos']
            is_match = 'match' if len(response_data.get('all_results', [])) == 1 else 'not match'
            return {
                'hostname_pywire': response_data['result'],
                'device_name': device_name,
                'rack': device_info.get('location', 'none'),
                'rack_elevation': device_info.get('elevation', 'none'),
                'device_type': template_info.get('equipment_name', 'none'),
                'manufacturer': template_info.get('manufacturer', 'none'),
                'match': is_match
            }
        else:
            # the device name not match with API's propositions
            return {}
    except req.exceptions.HTTPError as e:
        raise Exception(f"HTTP Error {e.response.status_code}: {e.response.text}") from e
    except Exception as e:
        raise Exception(f"Error retrieving device data from Pywire API: {e}") from e


####################################################################
#                      get_device_data_from_pywire
####################################################################
def get_device_data_from_pywire(dev, token):

    result = api_template_data_from_device_with_auto_match(dev.name, token)

    if result != {}:
        return result
    else:
        device = nb.dcim.devices.get(name=dev.name)
        interfaces = nb.dcim.interfaces.filter(device_id=device.id)
        if len(interfaces) == 0:
            return {}
        else:
            for interface in interfaces:
                if interface.connected_endpoints is None:
                    result = {}
                else:
                    switch_and_port = {'switch': interface.connected_endpoints[0].device.name,
                                       'port': interface.connected_endpoints[0].name.split('Ethernet')[1]}

                    result = api_trace_path_byswitch_and_port(switch_and_port, token)
                    if result != {} and dev.name in result['hostname_pywire']:
                        result.update({'device_name': dev.name, "switch": switch_and_port['switch'], 'port': switch_and_port['port']})
                        return result

            return result
####################################################################
#                      Match device name
####################################################################
def find_switch(device_name, token):
    url = 'https://pywire-app.cbc-rc.ca/api/v2/template_data_from_device_with_auto_match/?device_name=' + device_name

    headers = {
        'Accept': 'application/json',
        'X-Access-Token': token
    }
    response = req.request("GET", url, headers=headers)
    if response.status_code == 200:
        responseData = response.json()
        print(responseData)
        if responseData['result'] == 'no match':
            return None
        else:
            if responseData['result'].split('-')[0] == device_name.split('-')[0] and responseData['result'].split('-')[
               2] == device_name.split('-')[2] and responseData['result'].split('-')[3] == device_name.split('-')[3]:
               
               print(responseData['result'])
               return responseData['result']
            else:
               return None

    else:
        print(str(response.status_code) + ' : ' + response.text + str(device_name))
####################################################################
#                      Get Token
####################################################################
def get_token(tokenpywire):

    url_prod = 'https://pywire-app.cbc-rc.ca/api/v2/get_token/'
    headers = {
        'Accept': 'application/json',
        'Authorization': 'Basic ' + tokenpywire
    }
    try:
        response = req.request("GET", url_prod, headers=headers)
        responseData = response.json()
        return responseData['token']

    except req.exceptions.HTTPError as err:
        raise SystemExit(err)

####################################################################
#                  Get hostname's role
####################################################################
def get_device_role(pattern, roles):

    role = None
    for elem in roles:
        accronym = elem.description.split(':')[1]
        accronym = "".join(accronym.split())
        if accronym in pattern:
            role = elem
            break
    return role
####################################################################
#                      Update device Netbox
####################################################################
def update_device_netbox(dev, result, accronym, roles):

    data_role_and_type_none = []
    data_no_role = []
    data_no_device_type = []
    data_updated = []
    data_found_not_match = []
    data_not_found = []
    data_alredy_updated = []
    data_type_or_role_none = []
    data_role_type_exists = []

    if result != {}:
        if dev.name in result['hostname_pywire']:  # the device name match with pywire
            role = get_device_role(accronym, roles)
            device_type = nb.dcim.device_types.get(slug=slugify(result['device_type']))
            if role is None and device_type is None:
                data_role_and_type_none.append(
                    {'device': dev.name, 'type': result['device_type'], 'tenant': dev.tenant.name})
            else:  # update the device in netbox
                data = {}
                data_type_or_role_none.append(dev.name)
                if role is not None and device_type is not None:
                    data_role_type_exists.append(dev.name)
                    role_id = nb.dcim.device_roles.get(name=role).id
                    if dev.device_role.id != role_id:
                        data.update({'device_role': role_id})
                        if dev.device_type.id != device_type.id:
                            data.update({'device_type': device_type.id})
                    if data != {}:
                        # tag = nb.extras.tags.get(name='yaml_update')
                        # new_tags = [tag] + dev.tags
                        # data.update({'tags': new_tags})
                        # dev.update(data)

                        # to be deleted
                        # tags = dev.tags
                        # tag_ids = []
                        # for tg in tags:
                        #     tag_ids.append(tg.id)
                        # tag_ids.append(tag)
                        # data.update({'tags': tag_ids})
                        # dev.update(data)
                        # data_updated.append(result)
                        # print(dev.name + ' is updated on Netbox')
                        # print('-' * 50)
                        data_updated.append(dev.name)
                    else:
                        # print(dev.name + 'is already update')
                        data_alredy_updated.append(dev.name)
                else:  # role or type is None
                    if role is None:
                        data_no_role.append({'device': dev.name, 'tenant': dev.tenant.name,
                                             'type': device_type})
                    elif device_type is None:
                        data_no_device_type.append(
                            {'device': dev.name, 'type': result['device_type'], 'tenant': dev.tenant.name,
                             'role': role})
        else:  # the device name doesn't match with pywire
            data_found_not_match.append(result)
    else:  # the device is not found
        data_not_found.append(dev)

    return data_role_and_type_none, data_no_role, data_no_device_type, data_updated, data_found_not_match, \
           data_not_found, data_alredy_updated, data_type_or_role_none, data_role_type_exists
           
####################################################################
#                      update generic devices
####################################################################
def update_generic_devices(token):

    roles_bed = list(nb.dcim.device_roles.filter(tag="broadcast-endpoint-devices"))
    roles_app = list(nb.dcim.device_roles.filter(tag="applications"))

    for role in roles_app:
        if ':' not in dict(role)['description']:
            roles_app.remove(role)

    data_role_and_type_none = []
    data_no_role = []
    data_no_device_type = []
    data_updated = []
    data_type_or_role_none = []
    data_role_type_exists = []
    data_alredy_updated = []
    data_found_not_match = []
    data_not_found = []
    data_no_respect_inames = []
    data_switches = []
    data_embrionix = []
    match1_total = []
    match2_total = []
    match3_total = []
    match4_total = []

    devices = nb.dcim.devices.filter(tag='yaml-migration')
    # devices = nb.dcim.devices.filter(name='MTLMPXCAM008')
    print(len(devices))
    regexApp1   = "^[A-Za-z]{3}[A-Za-z]{3}[PNL][PBVC][WLUCEO]([A-Za-z]{3})\d{2}$"  # APPS
    regexApp2   = "^[A-Za-z]{3}[A-Za-z]{3}[PNL][PBVC]([A-Za-z]{3})\d{3}$"  # APPS
    regexApp3   = "^[A-Za-z]{3}[A-Za-z]{3}[PNL][PBVC]([A-Za-z]{3})([A-Za-z-0-9]{4})"  # APPS
    regexBpd    = "^[A-Za-z]{3}[A-Za-z]{3}([A-Za-z]{3})\d{3,}$"  # broadcast endpoint devices
    regexEmb    = "^[A-Za-z-0-9]+[E|X]LF\d{3}-(\d{2})$"  # embrionix
    switchregex = r"MTL-\w{4}-[a-zA-Z]{3}-\w+"

    #token = get_token()
    for dev in devices:
        app1 = re.match(regexApp1, dev.name)
        app2 = re.match(regexApp2, dev.name)
        app3 = re.match(regexApp3, dev.name)
        bed = re.match(regexBpd, dev.name)
        emb = re.match(regexEmb, dev.name)
        swt = re.match(switchregex, dev.name)

        result = get_device_data_from_pywire(dev, token)
        # print(dev.name)
        # print(result)
        # print("*" * 50)
        if app1:  # Applications type 1
            match1_total.append(dev.name)
            data = update_device_netbox(dev, result, app1.group(1), roles_app)
            data_role_and_type_none.extend(data[0])
            data_no_role.extend(data[1])
            data_no_device_type.extend(data[2])
            data_updated.extend(data[3])
            data_found_not_match.extend(data[4])
            data_not_found.extend(data[5])
            data_alredy_updated.extend(data[6])
            data_type_or_role_none.extend(data[7])
            data_role_type_exists.extend(data[8])

        elif app2:  # Applications type 2
            match2_total.append(dev.name)
            data = update_device_netbox(dev, result, app2.group(1), roles_app)
            data_role_and_type_none.extend(data[0])
            data_no_role.extend(data[1])
            data_no_device_type.extend(data[2])
            data_updated.extend(data[3])
            data_found_not_match.extend(data[4])
            data_not_found.extend(data[5])
            data_alredy_updated.extend(data[6])
            data_type_or_role_none.extend(data[7])
            data_role_type_exists.extend(data[8])

        elif app3:  # Applications type 3
            match3_total.append(dev.name)
            data = update_device_netbox(dev, result, app3.group(1), roles_app)
            data_role_and_type_none.extend(data[0])
            data_no_role.extend(data[1])
            data_no_device_type.extend(data[2])
            data_updated.extend(data[3])
            data_found_not_match.extend(data[4])
            data_not_found.extend(data[5])
            data_alredy_updated.extend(data[6])
            data_type_or_role_none.extend(data[7])
            data_role_type_exists.extend(data[8])

        elif bed:  # Broadcast endpoint devices
            match4_total.append(dev.name)
            data = update_device_netbox(dev, result, bed.group(1), roles_bed)
            data_role_and_type_none.extend(data[0])
            data_no_role.extend(data[1])
            data_no_device_type.extend(data[2])
            data_updated.extend(data[3])
            data_found_not_match.extend(data[4])
            data_not_found.extend(data[5])
            data_alredy_updated.extend(data[6])
            data_type_or_role_none.extend(data[7])
            data_role_type_exists.extend(data[8])

        elif emb:  # Embrionix
            data_embrionix.append(dev)
        #     # update_tag = nb.extras.tags.get(name='yaml_update')
        #     # if update_tag not in dev.tags:
        #     #     new_tags = [update_tag] + dev.tags
        #     #     if int(dev.name.split('-')[1]) % 2 == 0:
        #     #         device_type = nb.dcim.device_types.get(slug='eb22hdrt-lm-0516')
        #     #     else:
        #     #         device_type = nb.dcim.device_types.get(slug='eb22hdrt-lm-0514')
        #     #     data = {
        #     #         'name': dev.name,
        #     #         'site': dev.site.id,
        #     #         'device_type': device_type.id,
        #     #         'device_role': nb.dcim.device_roles.get(name='Video Gateway').id,
        #     #         'tenant': dev.tenant.id,
        #     #         'tags': new_tags,
        #     #         'status': 'active'
        #     #     }
        #     #     dev.delete()
        #     #     new_device = nb.dcim.devices.create(data)
        #     #     if dev:
        #     #         print(f'{new_device.name} has been created')
        elif swt:
            data_switches.append(dev)
        else: # devices don't respect inames
            data_no_respect_inames.append(dev.name)
            data = update_device_netbox(dev, result, dev.name, roles_bed + roles_app)
            data_role_and_type_none.extend(data[0])
            data_no_role.extend(data[1])
            data_no_device_type.extend(data[2])
            data_updated.extend(data[3])
            data_found_not_match.extend(data[4])
            data_not_found.extend(data[5])
            data_alredy_updated.extend(data[6])
            data_type_or_role_none.extend(data[7])
            data_role_type_exists.extend(data[8])

    # write_to_csv_file(data_role_and_type_none, 'data_role_and_type_none', ['device','type', 'tenant'])
    # write_to_csv_file(data_no_device_type, 'data_no_device_type', ['device', 'tenant', 'type', 'role'])
    # write_to_csv_file(data_no_role, 'data_no_role', ['device', 'tenant', 'type'])

    print('------------------------------------------')
    print(f'match 1: {len(match1_total)}')
    print(match1_total)
    print('------------------------------------------')
    print(f'match 2: {len(match2_total)}')
    print(match2_total)
    print('------------------------------------------')
    print(f'match 3: {len(match3_total)}')
    print(match3_total)
    print('------------------------------------------')
    print(f'match 4: {len(match4_total)}')
    print(match4_total)
    print('------------------------------------------')
    print(f'data not found: {len(data_not_found)}')
    print(data_not_found)
    print('------------------------------------------')
    print(f'data_role_and_type_none: {len(data_role_and_type_none)}')
    print(data_role_and_type_none)
    print('------------------------------------------')
    print(f'data found not match: {len(data_found_not_match)}')
    print(data_found_not_match)
    print('------------------------------------------')
    print(f'data_updated: {len(data_updated)}')
    print(data_updated)
    print('------------------------------------------')
    print(f'data_no_respect_inames: {len(data_no_respect_inames)}')
    print(data_no_respect_inames)
    print('------------------------------------------')
    print(f'data switches {len(data_switches)}')
    print(data_switches)
    print('------------------------------------------')
    print(f'data_embrionix {len(data_embrionix)}')
    print(data_embrionix)
    print('------------------------------------------')
    print(f'data_no_device_type {len(data_no_device_type)}')
    print(data_no_device_type)
    print('------------------------------------------')
    print(f'data_no_role {len(data_no_role)}')
    print(data_no_role)
    print('------------------------------------------')
    print(f'data_alredy_updated {len(data_alredy_updated)}')
    print(data_alredy_updated)
    print('------------------------------------------')
    print(f'data_type_or_role_none {len(data_type_or_role_none)}')
    print(data_type_or_role_none)
    print('------------------------------------------')
    print(f'data_role_type_exists {len(data_role_type_exists)}')
    print(data_role_type_exists)
    print('------------------------------------------')

    type_counts = {}
    for item in data_no_device_type:
        device_type = item['type']
        if device_type in type_counts:
            type_counts[device_type] += 1
        else:
            type_counts[device_type] = 1

    type_counts_2 = {}
    for item in data_role_and_type_none:
        device_type = item['type']
        if device_type in type_counts_2:
            type_counts_2[device_type] += 1
        else:
            type_counts_2[device_type] = 1
    merged_dict = {**type_counts, **type_counts_2}
    sorted_items = sorted(merged_dict.items(), key=lambda x: x[1], reverse=True)
    top_10_items = sorted_items[:10]
    total_devices = len(devices)
    total_updated = nb.dcim.devices.filter(tag='yaml_update')
    ip_pres_updated = []
    ip_prod_updated = []
    for dev in total_updated:
        if dev.tenant.name == 'Presentation':
            ip_pres_updated.append(dev)
        elif dev.tenant.name == 'Media Production':
            ip_prod_updated.append(dev)
    total_applications = len(match1_total) + len(match2_total) + len(match3_total)
    update_conflence_page(total_devices, len(total_updated), len(data_embrionix), len(data_not_found), len(data_role_and_type_none), len(data_no_device_type), len(data_no_role), len(data_found_not_match),top_10_items, len(ip_pres_updated), len(ip_prod_updated), total_applications, len(data_switches), len(match4_total), len(data_updated), len(data_role_type_exists), len(data_no_respect_inames))

####################################################################
#                     Update Confluence page
####################################################################
def update_conflence_page(total_devices, total_devices_updated, total_embrionix, data_not_found, data_role_and_type_none, data_no_device_type, data_no_role, data_found_not_match, top_10_items, ip_pres_updated, ip_prod_updated, total_applications, total_switches, total_bed, data_updated, data_role_type_exists, data_no_respect_inames):
    username = 'khalid.hafdi.idrissi@radio-canada.ca'
    password = atlassiantoken
    confluence = Confluence(
        url='https://cbcradiocanada.atlassian.net/',
        username=username,
        password=password,
        cloud=True)
    auth = (username, password)
    base_url = 'https://cbcradiocanada.atlassian.net/wiki/'
    url = f'{base_url}/rest/api/content/3765764149?expand=body.storage'
    response = requests.get(url, auth=auth)
    # print(response.content)
    if response.status_code == 200:
        # Retrieve the content from the response
        content = response.json()['body']['storage']['value']
        print(content)
    else:
        print(f"Failed to retrieve page content. Status code: {response.status_code}")

    percentage = round(((total_devices_updated - total_switches) / total_devices) * 100, 2)
    html = '<p>Cette page donne des informations mis &agrave; jour sur l&rsquo;importation des &eacute;quipements dans Netbox</p><p><strong><span style="color: rgb(7,71,166);">Statistiques:</span></strong></p><table data-layout="default" ac:local-id="512623f8-e269-43d8-99c9-f5a4cfa2f0c4"><tbody><tr><th><p /></th><th><p><strong>Total des &eacute;quipements importes de Yaml vers Netbox</strong></p></th><th><p><strong>Total des &eacute;quipements mis &agrave; jour</strong></p></th><th><p><strong>Poucentage des &eacute;quipements mises &agrave; jour des </strong></p></th></tr><tr><td><p /></td><td data-highlight-colour="#ffffff"><p style="text-align: center;"><strong>' + str(total_devices) +'</strong></p></td><td><p style="text-align: center;"><strong>' +str(total_devices_updated) +'</strong></p></td><td><p style="text-align: center;"><strong>' + str(percentage) +'%</strong></p></td></tr></tbody></table><ac:adf-extension><ac:adf-node type="extension"><ac:adf-attribute key="extension-type">com.atlassian.chart</ac:adf-attribute><ac:adf-attribute key="extension-key">chart:default</ac:adf-attribute><ac:adf-attribute key="parameters"><ac:adf-parameter key="chart-type">BAR</ac:adf-parameter><ac:adf-parameter key="chart-group"><ac:adf-parameter key="data-tab"><ac:adf-parameter key="x-axis-idx-field">0</ac:adf-parameter><ac:adf-parameter key="y-axis-idx-field"><ac:adf-parameter-value>1</ac:adf-parameter-value><ac:adf-parameter-value>2</ac:adf-parameter-value></ac:adf-parameter><ac:adf-parameter key="aggregate-data" type="boolean">false</ac:adf-parameter></ac:adf-parameter><ac:adf-parameter key="customize-tab"><ac:adf-parameter key="style-field"><ac:adf-parameter key="height">350</ac:adf-parameter><ac:adf-parameter key="color-linear1">#0055CC</ac:adf-parameter><ac:adf-parameter key="color-linear2">#23A971</ac:adf-parameter><ac:adf-parameter key="show-points" type="boolean">false</ac:adf-parameter><ac:adf-parameter key="smooth" type="boolean">false</ac:adf-parameter><ac:adf-parameter key="orientation">vertical</ac:adf-parameter></ac:adf-parameter><ac:adf-parameter key="titles-field"><ac:adf-parameter key="chart-title">Progression des importations des &eacute;quipements</ac:adf-parameter><ac:adf-parameter key="y-label">Nombre &eacute;quipements</ac:adf-parameter><ac:adf-parameter key="x-label" /></ac:adf-parameter><ac:adf-parameter key="legend-field"><ac:adf-parameter key="show-legend" type="boolean">true</ac:adf-parameter><ac:adf-parameter key="legend-position">right</ac:adf-parameter></ac:adf-parameter></ac:adf-parameter></ac:adf-parameter><ac:adf-parameter key="extension-title">Chart</ac:adf-parameter></ac:adf-attribute><ac:adf-attribute key="layout">default</ac:adf-attribute><ac:adf-attribute key="local-id">1438095d-3728-40ce-ac7f-f6446929fe7b</ac:adf-attribute><ac:adf-mark key="data-consumer"><ac:adf-data-consumer-source>512623f8-e269-43d8-99c9-f5a4cfa2f0c4</ac:adf-data-consumer-source></ac:adf-mark></ac:adf-node><ac:adf-fallback><ac:adf-node type="extension"><ac:adf-attribute key="extension-type">com.atlassian.chart</ac:adf-attribute><ac:adf-attribute key="extension-key">chart:default</ac:adf-attribute><ac:adf-attribute key="parameters"><ac:adf-parameter key="chart-type">BAR</ac:adf-parameter><ac:adf-parameter key="chart-group"><ac:adf-parameter key="data-tab"><ac:adf-parameter key="x-axis-idx-field">0</ac:adf-parameter><ac:adf-parameter key="y-axis-idx-field"><ac:adf-parameter-value>1</ac:adf-parameter-value><ac:adf-parameter-value>2</ac:adf-parameter-value></ac:adf-parameter><ac:adf-parameter key="aggregate-data" type="boolean">false</ac:adf-parameter></ac:adf-parameter><ac:adf-parameter key="customize-tab"><ac:adf-parameter key="style-field"><ac:adf-parameter key="height">350</ac:adf-parameter><ac:adf-parameter key="color-linear1">#0055CC</ac:adf-parameter><ac:adf-parameter key="color-linear2">#23A971</ac:adf-parameter><ac:adf-parameter key="show-points" type="boolean">false</ac:adf-parameter><ac:adf-parameter key="smooth" type="boolean">false</ac:adf-parameter><ac:adf-parameter key="orientation">vertical</ac:adf-parameter></ac:adf-parameter><ac:adf-parameter key="titles-field"><ac:adf-parameter key="chart-title">Progression des importations des &eacute;quipements</ac:adf-parameter><ac:adf-parameter key="y-label">Nombre &eacute;quipements</ac:adf-parameter><ac:adf-parameter key="x-label" /></ac:adf-parameter><ac:adf-parameter key="legend-field"><ac:adf-parameter key="show-legend" type="boolean">true</ac:adf-parameter><ac:adf-parameter key="legend-position">right</ac:adf-parameter></ac:adf-parameter></ac:adf-parameter></ac:adf-parameter><ac:adf-parameter key="extension-title">Chart</ac:adf-parameter></ac:adf-attribute><ac:adf-attribute key="layout">default</ac:adf-attribute><ac:adf-attribute key="local-id">1438095d-3728-40ce-ac7f-f6446929fe7b</ac:adf-attribute><ac:adf-mark key="data-consumer"><ac:adf-data-consumer-source>512623f8-e269-43d8-99c9-f5a4cfa2f0c4</ac:adf-data-consumer-source></ac:adf-mark></ac:adf-node></ac:adf-fallback></ac:adf-extension><p><strong><span style="color: rgb(7,71,166);">Details:</span></strong></p><p>Nombre total des &eacute;quipements : <strong>' + str(total_devices) +'</strong></p><p>Nombre total des Embrionix: <strong>' + str(total_embrionix) +'</strong></p><p>Nombre total des Applications: <strong>' + str(total_applications) +'</strong></p><p>Nombre total des Broadcast Endpoint Devices: <strong>' + str(total_bed) +'</strong></p><p>Nombre des &eacute;quipements qui ne respectent pas Inames: <strong>' + str(data_no_respect_inames) +'</strong></p><p>Nombre total des Switches: <strong>' + str(total_switches) + '</strong></p><table data-layout="default" ac:local-id="0e1b9eca-46b6-4ce4-82e1-dfed7406b15b"><tbody><tr><th><p /></th><th><p style="text-align: center;"><strong>Embrionix</strong></p></th><th><p style="text-align: center;"><strong>Applications</strong></p></th><th><p style="text-align: center;"><strong>Broadcast Endpoint Devices</strong></p></th><th><p style="text-align: center;"><strong>Switches</strong></p></th></tr><tr><td><p /></td><td><p style="text-align: center;"><strong>' + str(total_embrionix) +'</strong></p></td><td><p style="text-align: center;"><strong>' + str(total_applications) +'</strong></p></td><td><p style="text-align: center;"><strong>' + str(total_bed) +'</strong></p></td><td><p style="text-align: center;"><strong>' + str(total_switches) +'</strong></p></td></tr></tbody></table><ac:adf-extension><ac:adf-node type="extension"><ac:adf-attribute key="extension-type">com.atlassian.chart</ac:adf-attribute><ac:adf-attribute key="extension-key">chart:default</ac:adf-attribute><ac:adf-attribute key="parameters"><ac:adf-parameter key="chart-type">BAR</ac:adf-parameter><ac:adf-parameter key="chart-group"><ac:adf-parameter key="data-tab"><ac:adf-parameter key="x-axis-idx-field">0</ac:adf-parameter><ac:adf-parameter key="y-axis-idx-field"><ac:adf-parameter-value>1</ac:adf-parameter-value><ac:adf-parameter-value>2</ac:adf-parameter-value><ac:adf-parameter-value>3</ac:adf-parameter-value><ac:adf-parameter-value>4</ac:adf-parameter-value></ac:adf-parameter><ac:adf-parameter key="aggregate-data" type="boolean">false</ac:adf-parameter></ac:adf-parameter><ac:adf-parameter key="customize-tab"><ac:adf-parameter key="style-field"><ac:adf-parameter key="height">350</ac:adf-parameter><ac:adf-parameter key="color-linear1">#0055CC</ac:adf-parameter><ac:adf-parameter key="color-linear2">#23A971</ac:adf-parameter><ac:adf-parameter key="color-linear3">#FF9D00</ac:adf-parameter><ac:adf-parameter key="color-linear4">#FC552C</ac:adf-parameter><ac:adf-parameter key="show-points" type="boolean">false</ac:adf-parameter><ac:adf-parameter key="smooth" type="boolean">false</ac:adf-parameter><ac:adf-parameter key="orientation">vertical</ac:adf-parameter></ac:adf-parameter><ac:adf-parameter key="titles-field"><ac:adf-parameter key="chart-title">Distribution des &eacute;quipements selon le type</ac:adf-parameter><ac:adf-parameter key="y-label">Nombre des &eacute;quipements</ac:adf-parameter><ac:adf-parameter key="x-label" /></ac:adf-parameter><ac:adf-parameter key="legend-field"><ac:adf-parameter key="show-legend" type="boolean">true</ac:adf-parameter><ac:adf-parameter key="legend-position">auto</ac:adf-parameter></ac:adf-parameter></ac:adf-parameter></ac:adf-parameter><ac:adf-parameter key="extension-title">Chart</ac:adf-parameter></ac:adf-attribute><ac:adf-attribute key="layout">default</ac:adf-attribute><ac:adf-attribute key="local-id">71e3a2d1-1b90-4eeb-b17e-f0a99e94b95a</ac:adf-attribute><ac:adf-mark key="data-consumer"><ac:adf-data-consumer-source>0e1b9eca-46b6-4ce4-82e1-dfed7406b15b</ac:adf-data-consumer-source></ac:adf-mark></ac:adf-node><ac:adf-fallback><ac:adf-node type="extension"><ac:adf-attribute key="extension-type">com.atlassian.chart</ac:adf-attribute><ac:adf-attribute key="extension-key">chart:default</ac:adf-attribute><ac:adf-attribute key="parameters"><ac:adf-parameter key="chart-type">BAR</ac:adf-parameter><ac:adf-parameter key="chart-group"><ac:adf-parameter key="data-tab"><ac:adf-parameter key="x-axis-idx-field">0</ac:adf-parameter><ac:adf-parameter key="y-axis-idx-field"><ac:adf-parameter-value>1</ac:adf-parameter-value><ac:adf-parameter-value>2</ac:adf-parameter-value><ac:adf-parameter-value>3</ac:adf-parameter-value><ac:adf-parameter-value>4</ac:adf-parameter-value></ac:adf-parameter><ac:adf-parameter key="aggregate-data" type="boolean">false</ac:adf-parameter></ac:adf-parameter><ac:adf-parameter key="customize-tab"><ac:adf-parameter key="style-field"><ac:adf-parameter key="height">350</ac:adf-parameter><ac:adf-parameter key="color-linear1">#0055CC</ac:adf-parameter><ac:adf-parameter key="color-linear2">#23A971</ac:adf-parameter><ac:adf-parameter key="color-linear3">#FF9D00</ac:adf-parameter><ac:adf-parameter key="color-linear4">#FC552C</ac:adf-parameter><ac:adf-parameter key="show-points" type="boolean">false</ac:adf-parameter><ac:adf-parameter key="smooth" type="boolean">false</ac:adf-parameter><ac:adf-parameter key="orientation">vertical</ac:adf-parameter></ac:adf-parameter><ac:adf-parameter key="titles-field"><ac:adf-parameter key="chart-title">Distribution des &eacute;quipements selon le type</ac:adf-parameter><ac:adf-parameter key="y-label">Nombre des &eacute;quipements</ac:adf-parameter><ac:adf-parameter key="x-label" /></ac:adf-parameter><ac:adf-parameter key="legend-field"><ac:adf-parameter key="show-legend" type="boolean">true</ac:adf-parameter><ac:adf-parameter key="legend-position">auto</ac:adf-parameter></ac:adf-parameter></ac:adf-parameter></ac:adf-parameter><ac:adf-parameter key="extension-title">Chart</ac:adf-parameter></ac:adf-attribute><ac:adf-attribute key="layout">default</ac:adf-attribute><ac:adf-attribute key="local-id">71e3a2d1-1b90-4eeb-b17e-f0a99e94b95a</ac:adf-attribute><ac:adf-mark key="data-consumer"><ac:adf-data-consumer-source>0e1b9eca-46b6-4ce4-82e1-dfed7406b15b</ac:adf-data-consumer-source></ac:adf-mark></ac:adf-node></ac:adf-fallback></ac:adf-extension><p /><p>Nombre des &eacute;quipements sans les embrionix ni les switches : <strong>' + str(total_devices - total_embrionix - total_embrionix) +'</strong></p><p>Nombre total des &eacute;quipements n''ayant pas des informations dans Pywire : <strong>' + str(data_not_found) +'</strong></p><p>Nombre total des &eacute;quipements ayant des infos dans Pywire : <strong>' + str(total_devices - total_embrionix - total_embrionix - data_not_found) + '</strong></p><p>Nombre des &eacute;quipements trouves dans Pywire avec un nom diff&eacute;rent du fichier Yaml : <strong>' + str(data_found_not_match) + '</strong></p><p>Nombre des &eacute;quipements trouves dans Pywire avec le m&ecirc;me nom du fichier Yaml  : <strong>' + str(total_devices - total_embrionix - total_embrionix - data_not_found - data_found_not_match) + '</strong></p><p>Nombre des &eacute;quipements trouves dans Pywire mais n&rsquo;ont pas de type ni de r&ocirc;le : <strong>' + str(data_role_and_type_none) + '</strong></p><p>Nombre des &eacute;quipements trouves dans Pywire mais n&rsquo;ont pas de type : <strong>' + str(data_no_device_type) + '</strong></p><p>Nombre des &eacute;quipements trouves dans Pywire mais n&rsquo;ont pas de r&ocirc;le : <strong>' + str(data_no_role) + '</strong></p><p>Nombre des &eacute;quipements trouves dans Pywire qui ont un r&ocirc;le et un type : <strong>' + str(data_role_type_exists) + '</strong></p><p>Les top 10 des types &agrave; ajouter dans Netbox :<strong>  ' + str(top_10_items) + '</strong></p><p><strong><span style="color: rgb(7,71,166);">Progression des importations selon le Tenant:</span></strong></p><table data-layout="default" ac:local-id="b486e750-28a6-41ce-aae6-28f591aae227"><tbody><tr><th><p /></th><th><p><strong>Nombre des &eacute;quipements</strong></p></th><th><p><strong>Taux d&rsquo;importation</strong></p></th></tr><tr><td><p><strong>Pr&eacute;sentation</strong></p></td><td><p style="text-align: center;"><strong>' + str(ip_pres_updated) +'</strong></p></td><td><p style="text-align: center;"><strong>' + str(round((ip_pres_updated / total_devices) * 100, 2)) + '%</strong></p></td></tr><tr><td><p><strong>Production</strong></p></td><td><p style="text-align: center;"><strong>' + str(ip_prod_updated) +'</strong></p></td><td><p style="text-align: center;"><strong>' + str(round((ip_prod_updated / total_devices) * 100, 2)) + '%</strong></p></td></tr></tbody></table><ac:adf-extension><ac:adf-node type="extension"><ac:adf-attribute key="extension-type">com.atlassian.chart</ac:adf-attribute><ac:adf-attribute key="extension-key">chart:default</ac:adf-attribute><ac:adf-attribute key="parameters"><ac:adf-parameter key="chart-type">PIE</ac:adf-parameter><ac:adf-parameter key="chart-group"><ac:adf-parameter key="data-tab"><ac:adf-parameter key="x-axis-idx-field">0</ac:adf-parameter><ac:adf-parameter key="y-axis-idx-field"><ac:adf-parameter-value>1</ac:adf-parameter-value></ac:adf-parameter><ac:adf-parameter key="aggregate-data" type="boolean">false</ac:adf-parameter></ac:adf-parameter><ac:adf-parameter key="customize-tab"><ac:adf-parameter key="style-field"><ac:adf-parameter key="height">350</ac:adf-parameter><ac:adf-parameter key="color-pie0">#0055CC</ac:adf-parameter><ac:adf-parameter key="color-pie1">#23A971</ac:adf-parameter><ac:adf-parameter key="show-points" type="boolean">false</ac:adf-parameter><ac:adf-parameter key="smooth" type="boolean">false</ac:adf-parameter><ac:adf-parameter key="orientation">vertical</ac:adf-parameter></ac:adf-parameter><ac:adf-parameter key="titles-field"><ac:adf-parameter key="chart-title">Progressions des importation selon le Tenant:</ac:adf-parameter><ac:adf-parameter key="y-label">Untitled axis</ac:adf-parameter><ac:adf-parameter key="x-label" /></ac:adf-parameter><ac:adf-parameter key="legend-field"><ac:adf-parameter key="show-legend" type="boolean">true</ac:adf-parameter><ac:adf-parameter key="legend-position">auto</ac:adf-parameter></ac:adf-parameter></ac:adf-parameter></ac:adf-parameter><ac:adf-parameter key="extension-title">Chart</ac:adf-parameter></ac:adf-attribute><ac:adf-attribute key="layout">default</ac:adf-attribute><ac:adf-attribute key="local-id">bef839fa-9c07-4e61-be19-eb39fa0c3ae3</ac:adf-attribute><ac:adf-mark key="data-consumer"><ac:adf-data-consumer-source>b486e750-28a6-41ce-aae6-28f591aae227</ac:adf-data-consumer-source></ac:adf-mark></ac:adf-node><ac:adf-fallback><ac:adf-node type="extension"><ac:adf-attribute key="extension-type">com.atlassian.chart</ac:adf-attribute><ac:adf-attribute key="extension-key">chart:default</ac:adf-attribute><ac:adf-attribute key="parameters"><ac:adf-parameter key="chart-type">PIE</ac:adf-parameter><ac:adf-parameter key="chart-group"><ac:adf-parameter key="data-tab"><ac:adf-parameter key="x-axis-idx-field">0</ac:adf-parameter><ac:adf-parameter key="y-axis-idx-field"><ac:adf-parameter-value>1</ac:adf-parameter-value></ac:adf-parameter><ac:adf-parameter key="aggregate-data" type="boolean">false</ac:adf-parameter></ac:adf-parameter><ac:adf-parameter key="customize-tab"><ac:adf-parameter key="style-field"><ac:adf-parameter key="height">350</ac:adf-parameter><ac:adf-parameter key="color-pie0">#0055CC</ac:adf-parameter><ac:adf-parameter key="color-pie1">#23A971</ac:adf-parameter><ac:adf-parameter key="show-points" type="boolean">false</ac:adf-parameter><ac:adf-parameter key="smooth" type="boolean">false</ac:adf-parameter><ac:adf-parameter key="orientation">vertical</ac:adf-parameter></ac:adf-parameter><ac:adf-parameter key="titles-field"><ac:adf-parameter key="chart-title">Progression des importation selon le Tenant:</ac:adf-parameter><ac:adf-parameter key="y-label">Untitled axis</ac:adf-parameter><ac:adf-parameter key="x-label" /></ac:adf-parameter><ac:adf-parameter key="legend-field"><ac:adf-parameter key="show-legend" type="boolean">true</ac:adf-parameter><ac:adf-parameter key="legend-position">auto</ac:adf-parameter></ac:adf-parameter></ac:adf-parameter></ac:adf-parameter><ac:adf-parameter key="extension-title">Chart</ac:adf-parameter></ac:adf-attribute><ac:adf-attribute key="layout">default</ac:adf-attribute><ac:adf-attribute key="local-id">bef839fa-9c07-4e61-be19-eb39fa0c3ae3</ac:adf-attribute><ac:adf-mark key="data-consumer"><ac:adf-data-consumer-source>b486e750-28a6-41ce-aae6-28f591aae227</ac:adf-data-consumer-source></ac:adf-mark></ac:adf-node></ac:adf-fallback></ac:adf-extension><p /><p /><p /><p />'
    confluence.update_page('3765764149', 'Importation des equipements vers Netbox',
                           html, parent_id=None, type='page',
                           representation='storage',
                           minor_edit=False, full_width=False)


####################################################################
#                     Main
####################################################################

if __name__ == '__main__':

    token_result = get_token(tpywire)
    update_generic_devices(token_result)
   

    
    
    