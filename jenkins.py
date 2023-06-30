import os


####################################################################
#                      Get Token
####################################################################
def get_token(tokenpywire):

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
####################################################################
#                      update devices
####################################################################
def update_generic_devices(netboxtoken, tokenpywire):
    nb = pynetbox.api(
        url='https://netbox.cbc-rc.ca/',
        token='netboxtoken'
    )
    nb.http_session.verify = False
    
    roles_bed = list(nb.dcim.device_roles.filter(tag="broadcast-endpoint-devices"))
    roles_app = list(nb.dcim.device_roles.filter(tag="applications"))
    devices = nb.dcim.devices.filter(tag='yaml-migration')
    print(len(devices))
    token = get_token(tokenpywire)
    print(token)
    
####################################################################
#                      Main Function
####################################################################
if __name__ == '__main__':
    
    # Access environment variables
    netboxtoken = os.environ.get('netboxtoken')
    tokenpywire = os.environ.get('tokenpywire')

    # Print values of variables
    print("netboxtoken:", netboxtoken)
    print("tokenpywire:", tokenpywire)
    update_generic_devices(netboxtoken, tokenpywire)
   
