import pyshark

cap = pyshark.FileCapture('testPcap.pcap')
for packet in cap:
    if hasattr(packet, 'ip'):
        print(packet.ip.dst)
cap.close()