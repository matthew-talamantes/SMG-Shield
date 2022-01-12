from pcapParser import getUrlDict, getIpDict

from apiCallFrame import apicall 

from secretsParser import getKey

import sys


def sortThreats(inputDict):
    sortedList = [] # sortedList = [['urlValue', {result}], ...]

    for key, value in inputDict.items():
        total = value['harmless'] + value['malicious'] + value['suspicious'] +\
            value['undetected'] + value['timeout']
        percentGood = (value['harmless'] / total) * 100
        sortedList.append([key, value, percentGood])

    sortedList.sort(key=lambda item: item[2])            
                
    return sortedList

def printResults(type, inputList):
    print(f'{type : <40}{"% harmless": >40}')
    print("-" * 80)
    printList = sortThreats(inputList)
    for item in printList:
        print(f'{item[0]:_<60}{item[2]:_>20.2f}%')
    print()


def main():
    #pull file from command line
    vtKey= getKey("virustotal")

    with open(sys.argv[1], 'r') as pcapfile:
        urlrepo= getUrlDict(pcapfile)
        ipRepo = getIpDict(pcapfile)
        
        print("Imported, getting to work")
    #pcapParse hand to call frame

    apirepo= apicall(vtKey, urlrepo, ipRepo)
    # sortedUrls = sortThreats(apirepo['urls'])
    printResults('urls', apirepo['urls'])
    printResults('IPs', apirepo['ips'])


if __name__ == '__main__':
    main()



