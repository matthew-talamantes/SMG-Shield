import vt
from datetime import datetime, timedelta
import time

client = vt.Client("<API_KEY>")

urls = ['www.google.com', 'www.facebook.com', 'www.twitter.com', 'www.amazon.com']
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
        print(analysis.stats)
    else:
        print(f'{url}: harmless: {urlResult.last_analysis_stats["harmless"]}, malicious: {urlResult.last_analysis_stats["malicious"]}')
client.close()
print('Done')