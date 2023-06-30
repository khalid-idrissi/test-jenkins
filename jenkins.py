import sys
import pynetbox
# Access environment variables
param1 = sys.argv[1]
param2 = sys.argv[2]
param3 = sys.argv[3]
#print parameters
print(param1)
print(param2)
print(param3)
nb = pynetbox.api(
        url='https://netbox.cbc-rc.ca/',
        token= param3
    )
nb.http_session.verify = False
device = nb.dcim.devices.get(name='MTLMPXITC2004')
print(device.id)
print('end of the programm')