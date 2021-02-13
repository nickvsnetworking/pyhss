#This generates OIDs for all the Redis values to be presented as SNMP
#It outputs a file of OIDs and their meaning and generates code that can be copied into snmp_service.py to update it

import sys
import re
sauce = open(sys.path[0] + '/../diameter.py', 'r')
generic_counter = 0
oid_dict = {}
for lines in sauce:
    lines = lines.rstrip()
    if "self.redis_store.incr('" in lines:
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
                        oid = str(vendor_id) + "." + str(command_code) + ".0"
                        oid_dict[oid] = redis_name
                    if "success" in redis_name:
                        oid = str(vendor_id) + "." + str(command_code) + ".1"
                        oid_dict[oid] = redis_name

                except:
                    print("ERROR WITH " + str(redis_name))
                    sys.exit()

        else:
            generic_counter = generic_counter + 1
            oid = str(generic_counter)
            oid_dict[oid] = redis_name

        print(oid)

print(oid_dict)