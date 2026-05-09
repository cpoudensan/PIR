#!/usr/bin/env python3
"""

Crée un fichier PCAP avec :
- IPs ORIGINALES (pas anonymisées)
- Ports → catégories (comme les fichiers anonymisés)

Utilisé comme baseline pour comparer avec kbits_category_ports_k*.pcap

Catégories :
1 = Web (80, 443)
2 = Kerberos (88)
3 = LDAP (389)
4 = SMB (445)
5 = RPC (135)
0 = Autres
"""

from scapy.all import PcapReader, PcapWriter, IP, TCP, UDP
import os

INPUT_FILE  = "Tuesday-WorkingHours-original-50k.pcap"
OUTPUT_FILE = "original_category_ports.pcap"
BATCH_SIZE  = 5000

PORT_CATEGORIES = {
    80: 1, 443: 1,
    88: 2,
    389: 3,
    445: 4,
    135: 5,
}

def apply_category_ports(pkt):
    if TCP in pkt:
        pkt[TCP].sport = PORT_CATEGORIES.get(pkt[TCP].sport, 0)
        pkt[TCP].dport = PORT_CATEGORIES.get(pkt[TCP].dport, 0)
    elif UDP in pkt:
        pkt[UDP].sport = PORT_CATEGORIES.get(pkt[UDP].sport, 0)
        pkt[UDP].dport = PORT_CATEGORIES.get(pkt[UDP].dport, 0)

if __name__ == "__main__":

    print("="*60)
    print("CRÉATION BASELINE CATÉGORIE PORTS")
    print("IPs originales + ports catégorisés")
    print("="*60 + "\n")

    if not os.path.exists(INPUT_FILE):
        print(f" {INPUT_FILE} non trouvé !")
        exit(1)

    total = 0
    try:
        with PcapReader(INPUT_FILE) as reader, \
             PcapWriter(OUTPUT_FILE, sync=True) as writer:
            batch = []
            for pkt in reader:
                batch.append(pkt)
                if len(batch) >= BATCH_SIZE:
                    for p in batch:
                        apply_category_ports(p)
                        writer.write(p)
                    total += len(batch)
                    print(f"   {total} paquets traités...")
                    batch = []
            if batch:
                for p in batch:
                    apply_category_ports(p)
                    writer.write(p)
                total += len(batch)

        print(f"\n✓ {OUTPUT_FILE} ({total} paquets)")
        print("Lance maintenant :")
        print(f"  mkdir -p alerts_orig_category")
        print(f"  sudo snort -r {OUTPUT_FILE} -c /etc/snort/snort.conf -A full -l ./alerts_orig_category/ -k none")

    except Exception as e:
        print(f" Erreur : {e}")
