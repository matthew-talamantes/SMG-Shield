import pyshark

# The "display_filter" parameter allows you to use the same display filters as wireshark to filter the search.
cap = pyshark.FileCapture('testPcap.pcap', display_filter="http")
for packet in cap:
    print(packet.number)
cap.close()