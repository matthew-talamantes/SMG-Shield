import vt
from datetime import datetime, timedelta
import time
import requests
import json

from fileReader import read_value

def ipApi(ip, vtKey):
    # Returns the last_analysis_stats of the given IP.
    # TO-DO: handle non 200 responses
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    response = requests.get(url, headers={'x-apikey': vtKey})
    resDict = json.loads(response.text)
    resStats = resDict['data']['attributes']['last_analysis_stats']
    return resStats

def scanUrls(client, url, results):
    analysis = client.scan_url(url)
    notCompleted = True
    while notCompleted:
        analysis = client.get_object('/analyses/{}', analysis.id)
        if analysis.status == 'completed':
            print()
            notCompleted = False
        else:
            time.sleep(30)
    # results.append(analysis.stats)
    results['urls'][url] = analysis.stats



def apicall(vtkey, urlDict, ipList=None):
    apiCalls = 0
    apiMaxCalls = 250
    urllist = []
    results= {'urls': {}, 'ips': {}}
    for key in urlDict.keys():
        urllist.append(key)
    
    client = vt.Client(vtkey)

    urls = urllist
    currentTime = datetime.now()
    cachedUrls = read_value('results.csv', 'urls')
    unscannedUrls = []

    for url in urls:
        if url not in cachedUrls:
            if apiCalls <= apiMaxCalls:
                url_id = vt.url_id(url)
                try:
                    urlResult = client.get_object("/urls/{}", url_id) 
                except:
                    print(f'No record for: {url} found. Continuing...')
                
                
                if urlResult.last_analysis_date <= (currentTime - timedelta(days = 7)):
                    print('Unscanned addresses found. Scanning Now...')
                    unscannedUrls.append(url)
                else:
                    # print(f'{url}: harmless: {urlResult.last_analysis_stats["harmless"]}, malicious: {urlResult.last_analysis_stats["malicious"]}')
                    results['urls'][url] = urlResult.last_analysis_stats
                apiCalls += 1
            else:
                print('ERROR: Max API calls reached!')
        else:
            results['urls'][url] = cachedUrls[url]
        
    startScan = input(f'There are {len(unscannedUrls)}, would you like to scan them? ("yes" or "no"): ')
    if startScan.lower() == 'yes':
        for url in unscannedUrls:
            if apiCalls <= apiMaxCalls:
                scanUrls(client, url, results)
                apiCalls += 1
            else:
                print('ERROR: Max API calls reached!')

    # Get IP scores
    cachedIps = read_value('results.csv', 'ips')
    for ip in ipList:
        if ip not in cachedIps:
            if apiCalls <= apiMaxCalls:
                ipStats = ipApi(ip, vtkey)
                results['ips'][ip] = ipStats
                apiCalls += 1
            else:
                print('ERROR: Max API calls reached!')
        else:
            results['ips'][ip] = cachedIps[ip]
        
    client.close()
    print(f'{apiCalls} API calls made.')
    
    return results
