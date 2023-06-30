import sys

# Access environment variables
param1 = sys.argv[1]
param2 = sys.argv[2]

#print parameters
print(tokenpywire)
print(netbixtoken)


####################################################################
#                      Get Token
####################################################################
def get_token():

    url_prod = 'https://pywire-app.cbc-rc.ca/api/v2/get_token/'
    headers = {
        'Accept': 'application/json',
        'Authorization': 'Basic tokenpywire'
    }
    try:
        response = req.request("GET", url_prod, headers=headers)
        responseData = response.json()
        return responseData['token']

    except req.exceptions.HTTPError as err:
        raise SystemExit(err)

def update_generic_devices():

    roles_bed = list(nb.dcim.device_roles.filter(tag="broadcast-endpoint-devices"))
    roles_app = list(nb.dcim.device_roles.filter(tag="applications"))

    for role in roles_app:
        if ':' not in dict(role)['description']:
            roles_app.remove(role)
     print(roles_bed)
    print(roles_app)
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

    token = get_token()
    print(token)
    
####################################################################
#                      Main Function
####################################################################
if __name__ == '__main__':

    # roles_applications = get_device_roles_from_spreadsheet('1KYQXUJ9XEnislU8DZZCLusoPAbL3gmYGT2-JNsGdV0A', 'Applications')
    # print(roles_applications)
    # migrate_device_roles_application(roles_applications)

    # #### Import devices #######
    # #1- Ip_Pres_ outofband
    # main_treatment('IP_Présentation-MTL.xlsx', 'Ansible - Out Of Band control', roles)
    # #2- Ip_Pres_ inband
    # main_treatment('IP_Présentation-MTL.xlsx', 'Ansible - In Band Control', roles)
    # # 3- Ip_Prod_ outofband
    # main_treatment('IP_Production-MTL.xlsx', 'Ansible - MPX Out Of Band Control', roles)
    # # # 4- Ip_Prod_ inband
    # main_treatment('IP_Production-MTL.xlsx', 'Ansible - MPX In Band Control', roles)

    # ==============================================================================
    
    update_generic_devices()
   