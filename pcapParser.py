import pyshark
import re

#Regex pattern for private IP addresses
def regexsearch(searchstring): 
    regex10 = re.compile("(10)(\.([2]([0-5][0-5]|[01234][6-9])|[1][0-9][0-9]|[1-9][0-9]|[0-9])){3}") 
    regex127 = re.compile("(127)(\.([2]([0-5][0-5]|[01234][6-9])|[1][0-9][0-9]|[1-9][0-9]|[0-9])){3}")
    regex172 =re.compile("(172)\.(1[6-9]|2[0-9]|3[0-1])(\.(2[0-4][0-9]|25[0-5]|[1][0-9][0-9]|[1-9][0-9]|[0-9])){2}")
    regex192 = re.compile("(192)\.(168)(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])){2}")
    if re.search(regex10, searchstring) != None or re.search(regex127, searchstring) != None or re.search(regex172, searchstring) != None or re.search(regex192, searchstring) != None:
        return True
    else:
        return False

#Parsing pcap to make url dictionary for api intake
def getUrlDict(pcapFile: str):
    # The "display_filter" parameter allows you to use the same display filters as wireshark to filter the search.
    # Pull URLs
    cap = pyshark.FileCapture(pcapFile, display_filter="http")
    urlDict = {}
    for packet in cap:
        # Check for host so as not to double count by seeing the responses
        if hasattr(packet.http, 'host'):
            if regexsearch(packet.http.request_full_uri):
                continue

            if packet.http.request_full_uri in urlDict:
                urlDict[packet.http.request_full_uri] += 1
            else:
                urlDict[packet.http.request_full_uri] = 1

    cap.close()
    return urlDict

#Compile dictionary of nonprivate IP adresses for api intake
def getIpDict(pcapFile: str):
    # Get the dictionary with the ip addresses
    
    ipList = []
    arpCount = 0
    tcpStreamList = []
    udpStreamList = []
    with pyshark.FileCapture(pcapFile) as cap:
        for packet in cap:
            if hasattr(packet, 'tcp') and hasattr(packet, 'ip'):
                if regexsearch(packet.ip.dst):
                    continue
                if packet.tcp.stream not in tcpStreamList:
                    if packet.ip.dst not in ipList:
                        ipList.append(packet.ip.dst)
                    tcpStreamList.append(packet.tcp.stream)
            else:
                if hasattr(packet, 'ip'):
                    if regexsearch(packet.ip.addr):
                        continue
                    if hasattr(packet, 'udp'):
                        if packet.udp.stream not in udpStreamList:
                            if packet.ip.addr not in ipList:
                                ipList.append(packet.ip.addr)
                            
                            if packet.ip.dst not in ipList:
                                ipList.append(packet.ip.dst)

                            udpStreamList.append(packet.udp.stream)
                    elif hasattr(packet, 'icmp'):
                        if packet.ip.dst not in ipList:
                            ipList.append(packet.ip.dst)
                    else:
                        print('Proto not found')
                elif packet.highest_layer == 'ARP':
                    arpCount += 1
    
    return ipList

