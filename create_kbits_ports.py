#!/usr/bin/env python3
"""
K BITS IPs + TRANSFORMATION PORTS
===================================

Crée 3 séries de fichiers PCAP :
1. k bits IPs + ports INTACTS     (déjà fait)
2. k bits IPs + ports BLACK MARKER (→ 0)
3. k bits IPs + ports KEYED RANDOM (→ aléatoire cohérent)

k = [0, 4, 8, 12, 16, 20, 24, 28, 32]
"""

from scapy.all import PcapReader, PcapWriter, IP, TCP, UDP
import random
import os

INPUT_FILE  = "Tuesday-WorkingHours-converted.pcap"
K_VALUES    = [0, 4, 8, 12, 16, 20, 24, 28, 32]
BATCH_SIZE  = 5000
MAX_BATCHES = 10  # 50,000 paquets

# ============================================
# ANONYMISATION IPs
# ============================================

def anonymize_k_bits(ip, k, ip_mapping):
    if k == 0:
        return ip
    if ip in ip_mapping:
        return ip_mapping[ip]
    parts = [int(x) for x in ip.split('.')]
    ip_int = (parts[0]<<24)|(parts[1]<<16)|(parts[2]<<8)|parts[3]
    mask = (1 << k) - 1
    new_ip_int = (ip_int & ~mask) | random.randint(0, mask)
    new_ip = (
        f"{(new_ip_int>>24)&0xFF}."
        f"{(new_ip_int>>16)&0xFF}."
        f"{(new_ip_int>>8)&0xFF}."
        f"{new_ip_int&0xFF}"
    )
    ip_mapping[ip] = new_ip
    return new_ip

# ============================================
# TRANSFORMATION PORTS
# ============================================

def apply_black_marker_ports(pkt):
    """Ports → 0"""
    if TCP in pkt:
        pkt[TCP].sport = 0
        pkt[TCP].dport = 0
    elif UDP in pkt:
        pkt[UDP].sport = 0
        pkt[UDP].dport = 0

def apply_keyed_ports(pkt, port_mapping):
    """Ports → aléatoire cohérent"""
    if TCP in pkt:
        for attr in ['sport', 'dport']:
            p = getattr(pkt[TCP], attr)
            if p not in port_mapping:
                port_mapping[p] = random.randint(1024, 65535)
            setattr(pkt[TCP], attr, port_mapping[p])
    elif UDP in pkt:
        for attr in ['sport', 'dport']:
            p = getattr(pkt[UDP], attr)
            if p not in port_mapping:
                port_mapping[p] = random.randint(1024, 65535)
            setattr(pkt[UDP], attr, port_mapping[p])

def create_file(output_file, k, port_transform):
    """Crée un fichier PCAP avec k bits IPs + transformation ports."""
    ip_mapping   = {}
    port_mapping = {}
    total        = 0
    batch_num    = 0

    try:
        with PcapReader(INPUT_FILE) as reader, \
             PcapWriter(output_file, sync=True) as writer:
            batch = []
            for pkt in reader:
                batch.append(pkt)
                if len(batch) >= BATCH_SIZE:
                    for p in batch:
                        if IP in p:
                            p[IP].src = anonymize_k_bits(p[IP].src, k, ip_mapping)
                            p[IP].dst = anonymize_k_bits(p[IP].dst, k, ip_mapping)
                        port_transform(p, port_mapping)
                        writer.write(p)
                    total += len(batch)
                    batch = []
                    batch_num += 1
                    if batch_num >= MAX_BATCHES:
                        break
            if batch and batch_num < MAX_BATCHES:
                for p in batch:
                    if IP in p:
                        p[IP].src = anonymize_k_bits(p[IP].src, k, ip_mapping)
                        p[IP].dst = anonymize_k_bits(p[IP].dst, k, ip_mapping)
                    port_transform(p, port_mapping)
                    writer.write(p)
                total += len(batch)
        print(f"    {output_file} ({total} paquets)")
    except Exception as e:
        print(f"    Erreur : {e}")

# ============================================
# MAIN
# ============================================

if __name__ == "__main__":

    print("="*60)
    print("CRÉATION FICHIERS K BITS IPs + TRANSFORMATION PORTS")
    print(f"({MAX_BATCHES} × {BATCH_SIZE} = {MAX_BATCHES*BATCH_SIZE} paquets)")
    print("="*60 + "\n")

    if not os.path.exists(INPUT_FILE):
        print(f" {INPUT_FILE} non trouvé !")
        exit(1)

    # Série 2 : k bits IPs + ports BLACK MARKER
    print("--- Série 2 : k bits IPs + ports BLACK MARKER ---")
    for k in K_VALUES:
        output = f"kbits_BM_ports_k{k}.pcap"
        print(f"k={k}...", end=' ')
        create_file(
            output, k,
            lambda p, pm: apply_black_marker_ports(p)
        )

    # Série 3 : k bits IPs + ports KEYED RANDOM
    print("\n--- Série 3 : k bits IPs + ports KEYED RANDOM ---")
    for k in K_VALUES:
        output = f"kbits_keyed_ports_k{k}.pcap"
        print(f"k={k}...", end=' ')
        create_file(output, k, apply_keyed_ports)

    print("\n TERMINÉ !")
    print("Fichiers créés :")
    for k in K_VALUES:
        print(f"  kbits_BM_ports_k{k}.pcap")
        print(f"  kbits_keyed_ports_k{k}.pcap")
