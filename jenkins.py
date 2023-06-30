import sys
import pynetbox
import requests as req


# Access environment variables
tnetbox = sys.argv[1]
tpywire = sys.argv[2]

#print parameters
print(tnetbox)

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


nb = pynetbox.api(
        url='https://netbox.cbc-rc.ca/',
        token= tnetbox
    )
nb.http_session.verify = False
device = nb.dcim.devices.get(name='MTLMPXITC2004')
print(device.id)
print('end of the programm')

tokenp = get_token(tpywire)
print(tokenp)