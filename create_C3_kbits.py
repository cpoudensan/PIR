#!/usr/bin/env python3
"""
ANONYMISATION C3 (KEYED IPs) + K BITS
=======================================
Ports INTACTS - IPs modifiées par k bits
"""

from scapy.all import PcapReader, PcapWriter, IP
import random
import os

INPUT_FILE  = "Tuesday-WorkingHours-converted.pcap"
K_VALUES    = [0, 4, 8, 12, 16, 20, 24, 28, 32]
BATCH_SIZE  = 5000
MAX_BATCHES = 10  # 50,000 paquets

def anonymize_k_bits(ip, k, ip_mapping):
    """Modifie les k derniers bits d'une IP de façon cohérente."""
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

def create_file(output_file, k):
    """Crée un fichier PCAP avec k bits modifiés sur les IPs."""
    ip_mapping = {}
    total = 0
    batch_num = 0

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
                    writer.write(p)
                total += len(batch)
        print(f"   ✓ {output_file} ({total} paquets)")
    except Exception as e:
        print(f"   ❌ Erreur : {e}")

if __name__ == "__main__":

    print("="*60)
    print("CRÉATION FICHIERS C3 + K BITS")
    print(f"({MAX_BATCHES} × {BATCH_SIZE} = {MAX_BATCHES*BATCH_SIZE} paquets)")
    print("="*60 + "\n")

    if not os.path.exists(INPUT_FILE):
        print(f"❌ {INPUT_FILE} non trouvé !")
        exit(1)

    for k in K_VALUES:
        output = f"C3_keyed_k{k}.pcap"
        print(f"k={k}...", end=' ')
        create_file(output, k)

    print("\n✓ TERMINÉ !")
    print("Fichiers créés :")
    for k in K_VALUES:
        print(f"  C3_keyed_k{k}.pcap")