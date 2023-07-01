import sys
import pynetbox
import json
import requests as req

# Access environment variables
tnetbox = sys.argv[1]
tpywire = sys.argv[2]
token = sys.argv[3]

#print parameters
print(tnetbox)
print(tpywire)
print(token)

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
    print('Basic' + tokenpywire)
    try:
        response = req.request("GET", url_prod, headers=headers)
        responseData = response.json()
        print(responseData)
        return responseData['token']

    except req.exceptions.HTTPError as err:
        raise SystemExit(err)

####################################################################
#                     Main
####################################################################

if __name__ == '__main__':

    nb = pynetbox.api(
            url='https://netbox.cbc-rc.ca/',
            token= tnetbox
        )
    nb.http_session.verify = False
    device = nb.dcim.devices.get(name='MTLMPXITC2004')
    print(device.id)
    print('end of the programm')
    
    token_result = get_token(tpywire)
    result = find_switch("MTLPREPPIMAW003", token_result)
    print(result)
    
    