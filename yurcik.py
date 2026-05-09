#!/usr/bin/env python3
"""
ANONYMISATION SCRUB-TCPDUMP DE YURCIK
======================================

5 combinaisons pour voir l'impact sur les ports :

C1 : Black Marker       → IPs=0.0.0.0  + Ports=0
C2 : CryptoPAn only     → IPs=CryptoPAn + Ports=INTACT
C3 : Keyed IPs only     → IPs=aléatoire + Ports=INTACT
C4 : CryptoPAn + Keyed  → IPs=CryptoPAn + Ports=aléatoire
C5 : Keyed all          → IPs=aléatoire + Ports=aléatoire
"""

from scapy.all import PcapReader, PcapWriter, IP, TCP, UDP
from yacryptopan import CryptoPAn
import random
import os

BATCH_SIZE    = 5000
MAX_BATCHES   = 10  # 10 × 5000 = 50,000 paquets
CRYPTOPAN_KEY = b"a" * 32

# ============================================
# FONCTIONS D'ANONYMISATION
# ============================================

# -- IPs --

ip_mapping_keyed = {}

def black_marker_ip(ip):
    return "0.0.0.0"

def keyed_random_ip(ip):
    global ip_mapping_keyed
    if ip not in ip_mapping_keyed:
        ip_mapping_keyed[ip] = (
            f"{random.randint(0,255)}."
            f"{random.randint(0,255)}."
            f"{random.randint(0,255)}."
            f"{random.randint(0,255)}"
        )
    return ip_mapping_keyed[ip]

cp = CryptoPAn(CRYPTOPAN_KEY)

def cryptopan_ip(ip):
    try:
        return cp.anonymize(ip)
    except:
        return ip

# -- Ports --

port_mapping_keyed = {}

def black_marker_port(port):
    return 0

def keyed_random_port(port):
    global port_mapping_keyed
    if port not in port_mapping_keyed:
        port_mapping_keyed[port] = random.randint(1024, 65535)
    return port_mapping_keyed[port]

def apply_ports(pkt, port_func):
    """Applique une fonction aux ports TCP/UDP"""
    if TCP in pkt:
        pkt[TCP].sport = port_func(pkt[TCP].sport)
        pkt[TCP].dport = port_func(pkt[TCP].dport)
    elif UDP in pkt:
        pkt[UDP].sport = port_func(pkt[UDP].sport)
        pkt[UDP].dport = port_func(pkt[UDP].dport)

# ============================================
# COMBINAISONS
# ============================================

def anonymize_C1(packets):
    """C1 : Black Marker → IPs=0.0.0.0 + Ports=0"""
    for pkt in packets:
        if IP in pkt:
            pkt[IP].src = "0.0.0.0"
            pkt[IP].dst = "0.0.0.0"
            apply_ports(pkt, black_marker_port)
    return packets

def anonymize_C2(packets):
    """C2 : CryptoPAn only → IPs=CryptoPAn + Ports=INTACT"""
    for pkt in packets:
        if IP in pkt:
            pkt[IP].src = cryptopan_ip(pkt[IP].src)
            pkt[IP].dst = cryptopan_ip(pkt[IP].dst)
            # Ports NON modifiés !
    return packets

def anonymize_C3(packets):
    """C3 : Keyed IPs only → IPs=aléatoire cohérent + Ports=INTACT"""
    for pkt in packets:
        if IP in pkt:
            pkt[IP].src = keyed_random_ip(pkt[IP].src)
            pkt[IP].dst = keyed_random_ip(pkt[IP].dst)
            # Ports NON modifiés !
    return packets

def anonymize_C4(packets):
    """C4 : CryptoPAn + Keyed ports → IPs=CryptoPAn + Ports=aléatoire"""
    for pkt in packets:
        if IP in pkt:
            pkt[IP].src = cryptopan_ip(pkt[IP].src)
            pkt[IP].dst = cryptopan_ip(pkt[IP].dst)
            apply_ports(pkt, keyed_random_port)
    return packets

def anonymize_C5(packets):
    """C5 : Keyed all → IPs=aléatoire + Ports=aléatoire"""
    for pkt in packets:
        if IP in pkt:
            pkt[IP].src = keyed_random_ip(pkt[IP].src)
            pkt[IP].dst = keyed_random_ip(pkt[IP].dst)
            apply_ports(pkt, keyed_random_port)
    return packets

# ============================================
# TRAITEMENT PAR BATCH
# ============================================

def process_file(input_file, output_file, anonymize_func, name):
    """Traite un fichier par batch."""

    # Reset mappings pour chaque technique
    global ip_mapping_keyed, port_mapping_keyed
    ip_mapping_keyed   = {}
    port_mapping_keyed = {}

    print(f"\n{name}")
    print("-" * 70)

    try:
        total     = 0
        batch_num = 0

        with PcapReader(input_file) as reader, \
             PcapWriter(output_file, sync=True) as writer:

            batch = []
            for pkt in reader:
                batch.append(pkt)
                if len(batch) >= BATCH_SIZE:
                    batch_num += 1
                    batch = anonymize_func(batch)
                    for p in batch:
                        writer.write(p)
                    total += len(batch)
                    print(f"   Batch {batch_num} → {total} paquets traités")
                    batch = []
                    if batch_num >= MAX_BATCHES:
                        break

            if batch and batch_num < MAX_BATCHES:
                batch = anonymize_func(batch)
                for p in batch:
                    writer.write(p)
                total += len(batch)

        print(f"✓ {output_file} ({total} paquets)\n")
        return True

    except Exception as e:
        print(f"❌ Erreur : {e}\n")
        return False

# ============================================
# MAIN
# ============================================

if __name__ == "__main__":

    print("="*70)
    print("ANONYMISATION YURCIK - 5 COMBINAISONS")
    print(f"({MAX_BATCHES} × {BATCH_SIZE} = {MAX_BATCHES*BATCH_SIZE} paquets)")
    print("="*70)

    INPUT = "Tuesday-WorkingHours-converted.pcap"

    if not os.path.exists(INPUT):
        print(f"❌ Fichier {INPUT} non trouvé !")
        exit(1)

    process_file(INPUT, "Tuesday-WorkingHours-C1-BlackMarker.pcap",
                 anonymize_C1, "C1 : Black Marker (IPs=0 + Ports=0)")

    process_file(INPUT, "Tuesday-WorkingHours-C2-CryptoPAn.pcap",
                 anonymize_C2, "C2 : CryptoPAn only (IPs=CP + Ports=INTACT)")

    process_file(INPUT, "Tuesday-WorkingHours-C3-KeyedIPs.pcap",
                 anonymize_C3, "C3 : Keyed IPs only (IPs=aléatoire + Ports=INTACT)")

    process_file(INPUT, "Tuesday-WorkingHours-C4-CryptoPAn-KeyedPorts.pcap",
                 anonymize_C4, "C4 : CryptoPAn + Keyed ports")

    process_file(INPUT, "Tuesday-WorkingHours-C5-KeyedAll.pcap",
                 anonymize_C5, "C5 : Keyed all (IPs=aléatoire + Ports=aléatoire)")

    print("="*70)
    print("TERMINÉ ✓")
    print("="*70)
    print()
    print("Fichiers créés :")
    print("  ✓ C1-BlackMarker.pcap          (IPs=0,    Ports=0)")
    print("  ✓ C2-CryptoPAn.pcap            (IPs=CP,   Ports=intact)")
    print("  ✓ C3-KeyedIPs.pcap             (IPs=rand, Ports=intact)")
    print("  ✓ C4-CryptoPAn-KeyedPorts.pcap (IPs=CP,   Ports=rand)")
    print("  ✓ C5-KeyedAll.pcap             (IPs=rand, Ports=rand)")