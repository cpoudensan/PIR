#!/usr/bin/env python3
"""
GRAPHIQUE F-SCORE VS K BITS - CATÉGORIE PORTS
===============================================

Baseline : alerts_orig_category (règles catégories ports)
Technique : k bits IPs + ports catégorie protocole
"""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from snort_metrics import compute_ids_metrics

K_VALUES     = [0, 4, 8, 12, 16, 20, 24, 28, 32]
BASELINE_DIR = "./alerts_orig_category"

print("="*60)
print("F-SCORE VS K BITS - CATÉGORIE PORTS")
print("="*60 + "\n")

fmeasures  = []
precisions = []
recalls    = []

for k in K_VALUES:
    alert_dir = f"./alerts_category_ports_k{k}"
    metrics   = compute_ids_metrics(BASELINE_DIR, alert_dir)

    fmeasures.append(metrics['F-measure'])
    precisions.append(metrics['Precision'])
    recalls.append(metrics['Recall'])

    print(
        f"k={k:2d} | "
        f"TP={metrics['TP']} FP={metrics['FP']} FN={metrics['FN']} | "
        f"F-measure={metrics['F-measure']:.3f}"
    )

fig, ax = plt.subplots(figsize=(12, 7))

color = '#f39c12'

ax.plot(K_VALUES, fmeasures, 'D-',
        color=color, linewidth=2.5, markersize=9,
        label='F-measure')
ax.plot(K_VALUES, precisions, 's--',
        color=color, linewidth=1.5, markersize=7,
        alpha=0.6, label='Precision')
ax.plot(K_VALUES, recalls, '^--',
        color=color, linewidth=1.5, markersize=7,
        alpha=0.4, label='Recall')

for k, f in zip(K_VALUES, fmeasures):
    ax.annotate(f'{f:.3f}', (k, f),
                textcoords="offset points",
                xytext=(0, 12), ha='center',
                fontsize=9, fontweight='bold', color=color)

ax.set_xlabel('k = nombre de bits modifiés dans l\'adresse IP', fontsize=12)
ax.set_ylabel('Score', fontsize=12)
ax.set_title(
    'F-score Snort en fonction de k bits modifiés\n'
    'Technique : k bits IPs + Catégorie protocole (ports)\n'
    'Catégories : Web(1) | FTP(2) | Email(3) | SSH(4) | SNMP(5)\n'
    'Dataset : CIC-IDS 2017 Tuesday | Basé sur Yurcik et al. (2008)',
    fontsize=11, fontweight='bold'
)
ax.set_xticks(K_VALUES)
ax.set_xticklabels([f'k={k}' for k in K_VALUES], fontsize=10)
ax.set_ylim(0, 1.15)
ax.axhline(y=1.0, color='gray', linestyle='--',
           alpha=0.5, label='F-measure = 1.0')
ax.grid(True, alpha=0.3)
ax.legend(fontsize=11)

plt.tight_layout()
plt.savefig('graph_kbits_category.png', dpi=150)
print("\n✓ Graphique sauvegardé : graph_kbits_category.png")
