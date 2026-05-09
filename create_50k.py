from scapy.all import PcapReader, PcapWriter

count = 0
with PcapReader('Tuesday-WorkingHours-converted.pcap') as reader, \
     PcapWriter('Tuesday-WorkingHours-original-50k.pcap', sync=True) as writer:
    for pkt in reader:
        writer.write(pkt)
        count += 1
        if count >= 50000:
            break
print(f' {count} paquets écrits')
