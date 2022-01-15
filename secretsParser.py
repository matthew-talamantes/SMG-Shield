#used to get api key from secrets.txt
def getKeyValue(item):
    item = item.strip()
    itemList = item.split(':')
    return itemList

def getKey(keyName):
    with open('./secrets.txt', 'r') as file:
        secretsDict = {}
        for line in file.readlines():
            lineList = getKeyValue(line)
            secretsDict[lineList[0]] = lineList[1]
    
    return secretsDict[keyName]



if __name__ == '__main__':
    print(getKey('virustotal'))