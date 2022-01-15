import vt
from datetime import datetime, timedelta
import time
import requests
import json

def ipApi(ip, vtKey):
    # Returns the last_analysis_stats of the given IP.
    # TO-DO: handle non 200 responses
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    response = requests.get(url, headers={'x-apikey': vtKey})
    resDict = json.loads(response.text)
    resStats = resDict['data']['attributes']['last_analysis_stats']
    return resStats

def apicall(vtkey, urlDict, ipList=None):
    urllist = []
    results= {'urls': {}, 'ips': {}}
    for key in urlDict.keys():
        urllist.append(key)
    
    client = vt.Client(vtkey)

    urls = urllist
    currentTime = datetime.now()

    for url in urls:
        url_id = vt.url_id(url)
        try:
            urlResult = client.get_object("/urls/{}", url_id) 
        except:
            print(f'No record for: {url} found. Continuing...')
        
        else:
            if urlResult.last_analysis_date <= (currentTime - timedelta(days = 7)):
                print('Unscanned addresses found. Scanning Now...')
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
            else:
                # print(f'{url}: harmless: {urlResult.last_analysis_stats["harmless"]}, malicious: {urlResult.last_analysis_stats["malicious"]}')
                results['urls'][url] = urlResult.last_analysis_stats

    # Get IP scores
    for ip in ipList:
        ipStats = ipApi(ip, vtkey)
        results['ips'][ip] = ipStats
        
    client.close()
    
    return results
