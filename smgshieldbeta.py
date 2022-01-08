from pcapParser import getUrlDict

from apiCallFrame import apicall 

from secretsParser import getKey

import sys

#pull file from command line
vtkey= getKey("virustotal")

with open(sys.argv[1], 'r') as pcapfile:
    urlrepo= getUrlDict(pcapfile)
    
    print("Imported, getting to work")
#pcapParse hand to call frame

    apirepo= apicall(vtkey, urlrepo)
    print(apirepo)

    #print("done")




