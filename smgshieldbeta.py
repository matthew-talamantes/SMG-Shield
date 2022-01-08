from pcapParser import getUrlDict

from apiCallFrame import apicall 

from secretsParser import getKey

import sys


def sortThreats(inputDict):
    sortedList = [] # sortedList = [['urlValue', {result}], ...]

    for key, value in inputDict.items():
        sortedList.append([key, value])

    sortedList.sort(reverse=True, key=lambda item: item[1]['malicious'])            
                
    return sortedList

def printResults(type, printList):
    print(f'{type : ^54}')
    print("-" * 54)
    for item in printList:
        print(f'{item[0]:_<27}{item[1]["malicious"]:_>27}')


def main():
    #pull file from command line
    vtkey= getKey("virustotal")

    with open(sys.argv[1], 'r') as pcapfile:
        urlrepo= getUrlDict(pcapfile)
        
        print("Imported, getting to work")
    #pcapParse hand to call frame

    apirepo= apicall(vtkey, urlrepo)
    sortedUrls = sortThreats(apirepo['urls'])
    printResults('urls', sortedUrls)


if __name__ == '__main__':
    main()



