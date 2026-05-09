# Anonymisation de Traces Réseau - Compromis Privacy/Utilité
## Basé sur Yurcik et al. (2008) - SCRUB-tcpdump

Ce projet implémente et évalue des techniques d'anonymisation de traces réseau sur le dataset CIC-IDS 2017 Tuesday, en mesurant le compromis entre privacy et utilité via Snort IDS.

---

## Prérequis

```bash
pip install scapy yacryptopan matplotlib numpy
```

- Python 3.8+
- Snort 2.9.x
- Dataset CIC-IDS 2017 Tuesday (converti en .pcap)

---

## Dataset

Télécharger le dataset CIC-IDS 2017 :
https://www.unb.ca/cic/datasets/ids-2017.html

Convertir le fichier pcapng en pcap :
```bash
tcpdump -r Tuesday-WorkingHours.pcapng -w Tuesday-WorkingHours-converted.pcap
```

---

## Note importante

Toujours utiliser `-k none` avec Snort lors de l'analyse des fichiers PCAP anonymisés. L'anonymisation des IPs invalide les checksums IP, ce qui amène Snort à ignorer les paquets par défaut.

---

## Figure 1 : F-score des techniques Yurcik (graph_snort_fscore.png)

### Règles Snort (basées sur les ports)
```
alert tcp any any -> any 80  (msg:"HTTP Traffic";  classtype:misc-activity; sid:2000001; rev:1;)
alert tcp any any -> any 443 (msg:"HTTPS Traffic"; classtype:misc-activity; sid:2000002; rev:1;)
alert tcp any any -> any 22  (msg:"SSH Traffic";   classtype:misc-activity; sid:2000003; rev:1;)
alert tcp any any -> any 21  (msg:"FTP Traffic";   classtype:misc-activity; sid:2000004; rev:1;)
```

### Étapes
```bash
python3 yurcik.py
python3 create_50k.py

mkdir -p alerts_orig alerts_C1 alerts_C2 alerts_C3 alerts_C4 alerts_C5

sudo snort -r Tuesday-WorkingHours-original-50k.pcap          -c /etc/snort/snort.conf -A full -l ./alerts_orig/ -k none
sudo snort -r Tuesday-WorkingHours-C1-BlackMarker.pcap         -c /etc/snort/snort.conf -A full -l ./alerts_C1/  -k none
sudo snort -r Tuesday-WorkingHours-C2-CryptoPAn.pcap           -c /etc/snort/snort.conf -A full -l ./alerts_C2/  -k none
sudo snort -r Tuesday-WorkingHours-C3-KeyedIPs.pcap            -c /etc/snort/snort.conf -A full -l ./alerts_C3/  -k none
sudo snort -r Tuesday-WorkingHours-C4-CryptoPAn-KeyedPorts.pcap -c /etc/snort/snort.conf -A full -l ./alerts_C4/ -k none
sudo snort -r Tuesday-WorkingHours-C5-KeyedAll.pcap            -c /etc/snort/snort.conf -A full -l ./alerts_C5/  -k none

python3 run_metrics.py
```

---

## Figure 2 : F-score en fonction de k bits (graph_C3_kbits_fscore.png)

### Règles Snort (basées sur les IPs)
```
alert tcp 192.168.10.0/24 any -> any any (msg:"Internal Network Traffic"; classtype:misc-activity; sid:3000001; rev:1;)
alert tcp any any -> 192.168.10.0/24 any (msg:"To Internal Network";      classtype:misc-activity; sid:3000002; rev:1;)
alert tcp 205.174.165.73 any -> any any  (msg:"Attacker Kali Traffic";    classtype:misc-activity; sid:3000003; rev:1;)
alert tcp any any -> 205.174.165.68 any  (msg:"To Victim Server";         classtype:misc-activity; sid:3000004; rev:1;)
```

### Étapes
```bash
python3 create_C3_kbits.py

mkdir -p alerts_orig_ip alerts_C3_k0 alerts_C3_k4 alerts_C3_k8 alerts_C3_k12 alerts_C3_k16 alerts_C3_k20 alerts_C3_k24 alerts_C3_k28 alerts_C3_k32

sudo snort -r Tuesday-WorkingHours-original-50k.pcap -c /etc/snort/snort.conf -A full -l ./alerts_orig_ip/ -k none
sudo snort -r C3_keyed_k0.pcap  -c /etc/snort/snort.conf -A full -l ./alerts_C3_k0/  -k none
sudo snort -r C3_keyed_k4.pcap  -c /etc/snort/snort.conf -A full -l ./alerts_C3_k4/  -k none
sudo snort -r C3_keyed_k8.pcap  -c /etc/snort/snort.conf -A full -l ./alerts_C3_k8/  -k none
sudo snort -r C3_keyed_k12.pcap -c /etc/snort/snort.conf -A full -l ./alerts_C3_k12/ -k none
sudo snort -r C3_keyed_k16.pcap -c /etc/snort/snort.conf -A full -l ./alerts_C3_k16/ -k none
sudo snort -r C3_keyed_k20.pcap -c /etc/snort/snort.conf -A full -l ./alerts_C3_k20/ -k none
sudo snort -r C3_keyed_k24.pcap -c /etc/snort/snort.conf -A full -l ./alerts_C3_k24/ -k none
sudo snort -r C3_keyed_k28.pcap -c /etc/snort/snort.conf -A full -l ./alerts_C3_k28/ -k none
sudo snort -r C3_keyed_k32.pcap -c /etc/snort/snort.conf -A full -l ./alerts_C3_k32/ -k none

python3 run_metrics_C3_kbits.py
```

---

## Figure 3 : F-score k bits + transformation ports (graph_kbits_3courbes.png)

### Règles Snort : mêmes que Figure 2 (basées sur les IPs)

### Étapes
```bash
python3 create_kbits_ports.py

mkdir -p alerts_BM_ports_k0 alerts_BM_ports_k4 alerts_BM_ports_k8 alerts_BM_ports_k12 alerts_BM_ports_k16 alerts_BM_ports_k20 alerts_BM_ports_k24 alerts_BM_ports_k28 alerts_BM_ports_k32
mkdir -p alerts_keyed_ports_k0 alerts_keyed_ports_k4 alerts_keyed_ports_k8 alerts_keyed_ports_k12 alerts_keyed_ports_k16 alerts_keyed_ports_k20 alerts_keyed_ports_k24 alerts_keyed_ports_k28 alerts_keyed_ports_k32

sudo snort -r kbits_BM_ports_k0.pcap     -c /etc/snort/snort.conf -A full -l ./alerts_BM_ports_k0/     -k none
sudo snort -r kbits_BM_ports_k4.pcap     -c /etc/snort/snort.conf -A full -l ./alerts_BM_ports_k4/     -k none
sudo snort -r kbits_BM_ports_k8.pcap     -c /etc/snort/snort.conf -A full -l ./alerts_BM_ports_k8/     -k none
sudo snort -r kbits_BM_ports_k12.pcap    -c /etc/snort/snort.conf -A full -l ./alerts_BM_ports_k12/    -k none
sudo snort -r kbits_BM_ports_k16.pcap    -c /etc/snort/snort.conf -A full -l ./alerts_BM_ports_k16/    -k none
sudo snort -r kbits_BM_ports_k20.pcap    -c /etc/snort/snort.conf -A full -l ./alerts_BM_ports_k20/    -k none
sudo snort -r kbits_BM_ports_k24.pcap    -c /etc/snort/snort.conf -A full -l ./alerts_BM_ports_k24/    -k none
sudo snort -r kbits_BM_ports_k28.pcap    -c /etc/snort/snort.conf -A full -l ./alerts_BM_ports_k28/    -k none
sudo snort -r kbits_BM_ports_k32.pcap    -c /etc/snort/snort.conf -A full -l ./alerts_BM_ports_k32/    -k none
sudo snort -r kbits_keyed_ports_k0.pcap  -c /etc/snort/snort.conf -A full -l ./alerts_keyed_ports_k0/  -k none
sudo snort -r kbits_keyed_ports_k4.pcap  -c /etc/snort/snort.conf -A full -l ./alerts_keyed_ports_k4/  -k none
sudo snort -r kbits_keyed_ports_k8.pcap  -c /etc/snort/snort.conf -A full -l ./alerts_keyed_ports_k8/  -k none
sudo snort -r kbits_keyed_ports_k12.pcap -c /etc/snort/snort.conf -A full -l ./alerts_keyed_ports_k12/ -k none
sudo snort -r kbits_keyed_ports_k16.pcap -c /etc/snort/snort.conf -A full -l ./alerts_keyed_ports_k16/ -k none
sudo snort -r kbits_keyed_ports_k20.pcap -c /etc/snort/snort.conf -A full -l ./alerts_keyed_ports_k20/ -k none
sudo snort -r kbits_keyed_ports_k24.pcap -c /etc/snort/snort.conf -A full -l ./alerts_keyed_ports_k24/ -k none
sudo snort -r kbits_keyed_ports_k28.pcap -c /etc/snort/snort.conf -A full -l ./alerts_keyed_ports_k28/ -k none
sudo snort -r kbits_keyed_ports_k32.pcap -c /etc/snort/snort.conf -A full -l ./alerts_keyed_ports_k32/ -k none

python3 graph_kbits_3courbes.py
```

---

## Figure 4 : F-score k bits + catégorie protocoles (graph_kbits_category.png)

### Règles Snort (basées sur les catégories)
```
alert tcp any any -> any 1 (msg:"Catégorie Web";      classtype:misc-activity; sid:4000001; rev:1;)
alert tcp any any -> any 2 (msg:"Catégorie Kerberos"; classtype:misc-activity; sid:4000002; rev:1;)
alert tcp any any -> any 3 (msg:"Catégorie LDAP";     classtype:misc-activity; sid:4000003; rev:1;)
alert tcp any any -> any 4 (msg:"Catégorie SMB";      classtype:misc-activity; sid:4000004; rev:1;)
alert tcp any any -> any 5 (msg:"Catégorie RPC";      classtype:misc-activity; sid:4000005; rev:1;)
```

### Étapes
```bash
python3 create_category_ports.py
python3 create_original_category.py

mkdir -p alerts_orig_category alerts_category_ports_k0 alerts_category_ports_k4 alerts_category_ports_k8 alerts_category_ports_k12 alerts_category_ports_k16 alerts_category_ports_k20 alerts_category_ports_k24 alerts_category_ports_k28 alerts_category_ports_k32

sudo snort -r original_category_ports.pcap   -c /etc/snort/snort.conf -A full -l ./alerts_orig_category/      -k none
sudo snort -r kbits_category_ports_k0.pcap   -c /etc/snort/snort.conf -A full -l ./alerts_category_ports_k0/  -k none
sudo snort -r kbits_category_ports_k4.pcap   -c /etc/snort/snort.conf -A full -l ./alerts_category_ports_k4/  -k none
sudo snort -r kbits_category_ports_k8.pcap   -c /etc/snort/snort.conf -A full -l ./alerts_category_ports_k8/  -k none
sudo snort -r kbits_category_ports_k12.pcap  -c /etc/snort/snort.conf -A full -l ./alerts_category_ports_k12/ -k none
sudo snort -r kbits_category_ports_k16.pcap  -c /etc/snort/snort.conf -A full -l ./alerts_category_ports_k16/ -k none
sudo snort -r kbits_category_ports_k20.pcap  -c /etc/snort/snort.conf -A full -l ./alerts_category_ports_k20/ -k none
sudo snort -r kbits_category_ports_k24.pcap  -c /etc/snort/snort.conf -A full -l ./alerts_category_ports_k24/ -k none
sudo snort -r kbits_category_ports_k28.pcap  -c /etc/snort/snort.conf -A full -l ./alerts_category_ports_k28/ -k none
sudo snort -r kbits_category_ports_k32.pcap  -c /etc/snort/snort.conf -A full -l ./alerts_category_ports_k32/ -k none

python3 graph_kbits_category.py
```

---

## Informations réseau (CIC-IDS 2017)

```
Attaquant      : Kali Linux 205.174.165.73
DNS            : 192.168.10.3
Réseau interne : 192.168.10.0/24

Attaques (Mardi 4 juillet 2017) :
- FTP Brute Force : 09h20 - 10h20
- SSH Brute Force : 14h00 - 15h00
```

---

## Références

- Yurcik et al. (2008) - SCRUB-tcpdump
- Lakkaraju et al. (2004) - NVisionIP
- Koukis et al. (2006) - Modèle adversarial
- Sharafaldin et al. (2018) - Dataset CIC-IDS 2017
