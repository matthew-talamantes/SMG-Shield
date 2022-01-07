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

def getIpDict(pcapFile: str):
    # Get the dictionary with the ip addresses
    
    ipList = []
    arpCount = 0
    tcpStreamList = []
    udpStreamList = []
    with pyshark.FileCapture(pcapFile) as cap:
        for packet in cap:
            if hasattr(packet, 'tcp'):
                if packet.tcp.stream not in tcpStreamList:
                    if packet.ip.dst not in ipList:
                        ipList.append(packet.ip.dst)
                    tcpStreamList.append(packet.tcp.stream)
            else:
                if hasattr(packet, 'ip'):
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
                        print()
                elif packet.highest_layer == 'ARP':
                    arpCount += 1
    
    return ipList

    # ackList = []
    # streamNum = 0
    # stillPackets = True

    # while stillPackets and streamNum < 100:
    #     cap = pyshark.FileCapture(pcapFile, display_filter=f'tcp.stream eq {streamNum}')
    #     for packet in cap:
    #         if packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '0':
    #             print(f'{streamNum}: {packet.ip.dst}')
        
    #     cap.close()
    #     streamNum += 1


urlDict = getUrlDict('testPcap.pcap')
ipList = getIpDict('testPcap.pcap')
