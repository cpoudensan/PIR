#!/usr/bin/env python3
"""
ÉVALUATION PRIVACY - 3 NIVEAUX D'ATTAQUANT
============================================

NIVEAU 0 : Attaquant naïf (k-anonymat)
NIVEAU 1 : Connaît le DNS (192.168.10.3)
NIVEAU 2 : Connaît toutes les IPs internes
"""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from scapy.all import PcapReader, IP, TCP, UDP
from collections import Counter, defaultdict

ORIGINAL  = "Tuesday-WorkingHours-original-50k.pcap"
FILES = {
    'C1 Black Marker'    : 'Tuesday-WorkingHours-C1-BlackMarker.pcap',
    'C2 CryptoPAn'       : 'Tuesday-WorkingHours-C2-CryptoPAn.pcap',
    'C3 Keyed IPs'       : 'Tuesday-WorkingHours-C3-KeyedIPs.pcap',
    'C4 CryptoPAn+Keyed' : 'Tuesday-WorkingHours-C4-CryptoPAn-KeyedPorts.pcap',
    'C5 Keyed all'       : 'Tuesday-WorkingHours-C5-KeyedAll.pcap',
}
KNOWN_DNS = "192.168.10.3"
KNOWN_IPS = {
    "192.168.10.1",  "192.168.10.3",  "192.168.10.5",
    "192.168.10.8",  "192.168.10.9",  "192.168.10.12",
    "192.168.10.14", "192.168.10.15", "192.168.10.17",
    "192.168.10.19", "192.168.10.50", "192.168.10.51",
}
MAX_PAQUETS = 50000

def extract_data(filepath):
    ip_packets  = Counter()
    ip_ports    = defaultdict(set)
    ip_subnet24 = {}
    count = 0
    with PcapReader(filepath) as r:
        for pkt in r:
            if IP in pkt:
                src = pkt[IP].src
                ip_packets[src] += 1
                ip_subnet24[src] = '.'.join(src.split('.')[:3])
                if TCP in pkt:
                    ip_ports[src].add(pkt[TCP].dport)
                elif UDP in pkt:
                    ip_ports[src].add(pkt[UDP].dport)
            count += 1
            if count >= MAX_PAQUETS:
                break
    return ip_packets, ip_ports, ip_subnet24

def privacy_level0(orig_data, anon_data):
    n_orig = len(orig_data[0])
    n_anon = len(anon_data[0])
    if n_orig == 0:
        return 0
    if n_anon <= 1:
        return 100.0
    return max(0, (1 - n_anon / n_orig)) * 100

def privacy_level1(orig_data, anon_data, known_ip):
    orig_packets  = orig_data[0]
    anon_packets  = anon_data[0]
    anon_subnet24 = anon_data[2]
    if len(set(anon_packets.keys())) <= 1:
        return 100.0
    if known_ip not in orig_packets:
        return 50
    known_pkts = orig_packets[known_ip]
    best_match = min(anon_packets.keys(),
                     key=lambda ip: abs(anon_packets[ip] - known_pkts))
    anon_subnet     = anon_subnet24.get(best_match, "")
    ips_same_subnet = sum(1 for ip, s in anon_subnet24.items()
                          if s == anon_subnet)
    total = len(anon_packets)
    if total == 0:
        return 0
    return max(0, min(100, (1 - ips_same_subnet / total) * 100))

def privacy_level2(orig_data, anon_data, known_ips):
    orig_packets = orig_data[0]
    orig_ports   = orig_data[1]
    anon_packets = anon_data[0]
    anon_ports   = anon_data[1]
    if len(set(anon_packets.keys())) <= 1:
        return 100.0
    reidentified = 0
    total_known  = 0
    for known_ip in known_ips:
        if known_ip not in orig_packets:
            continue
        total_known += 1
        orig_pkts = orig_packets[known_ip]
        orig_p    = orig_ports[known_ip]
        if orig_pkts == 0:
            continue
        best_sim = 0
        for anon_ip in anon_packets:
            anon_pkts = anon_packets[anon_ip]
            anon_p    = anon_ports[anon_ip]
            pkt_sim   = max(0, 1 - abs(orig_pkts - anon_pkts) / orig_pkts)
            union     = orig_p | anon_p
            port_sim  = len(orig_p & anon_p) / len(union) if union else 0
            sim       = 0.5 * pkt_sim + 0.5 * port_sim
            if sim > best_sim:
                best_sim = sim
        if best_sim > 0.8:
            reidentified += 1
    if total_known == 0:
        return 0
    return max(0, min(100, (1 - reidentified / total_known) * 100))

if __name__ == "__main__":

    print("="*70)
    print("ÉVALUATION PRIVACY - 3 NIVEAUX D'ATTAQUANT")
    print("="*70 + "\n")

    print("Extraction données originales...")
    orig_data = extract_data(ORIGINAL)
    print(f"✓ {len(orig_data[0])} IPs analysées\n")

    results = {}

    for name, filepath in FILES.items():
        print(f" {name}...")
        try:
            anon_data = extract_data(filepath)
        except Exception as e:
            print(f"    Erreur : {e}\n")
            continue

        p0 = privacy_level0(orig_data, anon_data)
        p1 = privacy_level1(orig_data, anon_data, KNOWN_DNS)
        p2 = privacy_level2(orig_data, anon_data, KNOWN_IPS)

        results[name] = {'level0': p0, 'level1': p1, 'level2': p2}

        print(f"   Niveau 0 (k-anonymat)  : Privacy = {p0:.1f}%")
        print(f"   Niveau 1 (DNS connu)   : Privacy = {p1:.1f}%")
        print(f"   Niveau 2 (tout connu)  : Privacy = {p2:.1f}%\n")

    names  = list(results.keys())
    level0 = [results[n]['level0'] for n in names]
    level1 = [results[n]['level1'] for n in names]
    level2 = [results[n]['level2'] for n in names]

    x      = np.arange(len(names))
    width  = 0.25
    colors = ['#2ecc71', '#f39c12', '#e74c3c']

    fig, ax = plt.subplots(figsize=(14, 7))

    bars0 = ax.bar(x - width, level0, width,
                   label='Niveau 0 : k-anonymat',
                   color=colors[0], edgecolor='black', linewidth=0.5)
    bars1 = ax.bar(x, level1, width,
                   label=f'Niveau 1 : Connaît DNS ({KNOWN_DNS})',
                   color=colors[1], edgecolor='black', linewidth=0.5)
    bars2 = ax.bar(x + width, level2, width,
                   label='Niveau 2 : Connaît toutes les IPs',
                   color=colors[2], edgecolor='black', linewidth=0.5)

    for bars in [bars0, bars1, bars2]:
        for bar in bars:
            val = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width()/2,
                val + 1,
                f'{val:.0f}%',
                ha='center', va='bottom',
                fontsize=9, fontweight='bold'
            )

    ax.set_xlabel('Technique d\'anonymisation', fontsize=12)
    ax.set_ylabel('Privacy (%)', fontsize=12)
    ax.set_title(
        'Privacy selon le niveau de connaissance de l\'attaquant\n'
        'Vert = k-anonymat | Orange = connaît DNS | Rouge = connaît tout\n'
        'Dataset : CIC-IDS 2017 Tuesday | Basé sur Yurcik et al. (2008)',
        fontsize=12, fontweight='bold'
    )
    ax.set_xticks(x)
    ax.set_xticklabels(names, fontsize=10, rotation=10)
    ax.set_ylim(0, 120)
    ax.axhline(y=50, color='gray', linestyle='--', alpha=0.3)
    ax.grid(axis='y', alpha=0.3)
    ax.legend(fontsize=9, loc='upper right')

    plt.tight_layout()
    plt.savefig('graph_privacy_levels.png', dpi=150)
    print("✓ Graphique sauvegardé : graph_privacy_levels.png\n")

    print("="*70)
    print("RÉSULTATS FINAUX")
    print("="*70 + "\n")
    print(f"{'Technique':<22} | {'Niveau 0':>8} | {'Niveau 1':>8} | {'Niveau 2':>8}")
    print("-"*58)
    for n in names:
        r = results[n]
        print(f"{n:<22} | {r['level0']:>7.1f}% | {r['level1']:>7.1f}% | {r['level2']:>7.1f}%")
