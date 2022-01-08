import vt
from datetime import datetime, timedelta
import time

def apicall(vtkey, urlDict, ipList=None):
    urllist = []
    results= {}
    for key in urlDict.keys():
        urllist.append(key)
    
    client = vt.Client(vtkey)

    urls = urllist
    currentTime = datetime.now()

    for url in urls:
        url_id = vt.url_id(url)
        urlResult = client.get_object("/urls/{}", url_id)
        if urlResult.last_analysis_date <= (currentTime - timedelta(days = 7)):
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
            print(analysis.stats)
        else:
            print(f'{url}: harmless: {urlResult.last_analysis_stats["harmless"]}, malicious: {urlResult.last_analysis_stats["malicious"]}')
    client.close()
    print('Done')

#urldict = {'ocsp.digicert.com': 17, 'www.amazon.com': 1, 'ocsp.sca1b.amazontrust.com': 7, 'ocsp.pki.goog': 11, 'ocsp.godaddy.com': 2, 'status.rapidssl.com': 1, 'ocsp.sectigo.com': 2, 'status.geotrust.com': 2, 'ocsp.globalsign.com': 1}

#apicall(urldict)