import pyshark

def getUrlDict(pcapFile: str):
    # The "display_filter" parameter allows you to use the same display filters as wireshark to filter the search.
    # Pull URLs
    cap = pyshark.FileCapture(pcapFile, display_filter="http")

    urlDict = {}
    for packet in cap:
        # Check for host so as not to double count by seeing the responses
        if hasattr(packet.http, 'host'):
            if packet.http.host in urlDict:
                urlDict[packet.http.host] += 1
            else:
                urlDict[packet.http.host] = 1

    cap.close()
    return urlDict


urlDict = getUrlDict('testPcap.pcap')
print(urlDict)