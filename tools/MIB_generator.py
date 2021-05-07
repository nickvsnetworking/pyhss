#This generates OIDs for all the Redis values to be presented as SNMP
#It outputs a file of OIDs and their meaning and generates code that can be copied into snmp_service.py to update it

import sys
import re
import os

import yaml
import sys
with open(os.path.dirname(__file__) + '/../config.yaml') as stream:
    yaml_config = (yaml.safe_load(stream))

global generic_counter
global oid_dict

generic_counter = 0
oid_dict = {}

def ParsePython(filename):
    print("parsing " + str(filename))
    sauce = open(os.path.dirname(__file__) + '/../' + str(filename), 'r')

    global generic_counter
    global oid_dict

    for lines in sauce:
        lines = lines.rstrip()
        if "logtool.RedisIncrimenter('" in lines:
            print(lines)
            lines = lines.split("'")
            redis_name = lines[1]
            print(redis_name)
            regex = r"_(\d*)_(\d*)"
            pattern = re.compile(regex, re.UNICODE)

            if "Answer" in redis_name:
                for match in pattern.finditer(redis_name):
                    try:
                        vendor_id = match.group(1)
                    except:
                        pass
                    
                    try:
                        if len(match.group(2)) == 0:
                            vendor_id = 0
                            command_code = match.group(1)
                        else:
                            command_code = match.group(2)


                        if "attempt" in redis_name:
                            oid = "0." + str(vendor_id) + "." + str(command_code) + ".0"
                            oid_dict[oid] = redis_name
                        if "success" in redis_name:
                            oid = "0." + str(vendor_id) + "." + str(command_code) + ".1"
                            oid_dict[oid] = redis_name

                    except:
                        print("ERROR WITH " + str(redis_name))
                        sys.exit()

            else:
                
                generic_counter = generic_counter + 1
                oid = str(generic_counter) + ".0.0.0"
                print(oid)
                oid_dict[oid] = redis_name

    return oid_dict

files = os.listdir(os.path.dirname(__file__) + '/../')
for filename in files:
    print("Searching for Redis update objects in " + str(filename))
    if '.py' in filename:
        print(filename)
        ParsePython(filename)

print(oid_dict)

for oid in oid_dict:
    print("""
###OID """ + str(oid) + """
class """ + str(oid_dict[oid]) + """(MibScalarInstance):
    def getValue(self, name, idx):
        try:
            return self.getSyntax().clone(redis_store.get('""" + str(oid_dict[oid]) + """'))
        except:
            return self.getSyntax().clone(0)
    """)

print("\n\n\n\n")

for oid in oid_dict:
    oid_split = oid.split('.')
    
    print("\t" + str(oid_dict[oid]) + "((1, 3, 6, 1, 2, 1, 1, 1), (" + str(oid_split[0]) + ", " + str(oid_split[1]) + ", " + str(oid_split[2]) + ", " + str(oid_split[3]) + "), v2c.Integer32()),")
