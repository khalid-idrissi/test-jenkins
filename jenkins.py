import sys
import pynetbox
# Access environment variables
param = sys.argv[1]
#print parameters
print(param1)
print(param2)
print(param3)
nb = pynetbox.api(
        url='https://netbox.cbc-rc.ca/',
        token= param
    )
nb.http_session.verify = False
device = nb.dcim.devices.get(name='MTLMPXITC2004')
print(device.id)
print('end of the programm')