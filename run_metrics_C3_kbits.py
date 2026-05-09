#!/usr/bin/env python3
"""
F-SCORE VS K BITS - TECHNIQUE C3 (KEYED IPs)
=============================================

Calcule le F-score Snort pour chaque valeur de k
et génère le graphique.
"""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from snort_metrics import compute_ids_metrics

K_VALUES     = [0, 4, 8, 12, 16, 20, 24, 28, 32]
BASELINE_DIR = "./alerts_orig_ip"

# ============================================
# CALCUL F-SCORE
# ============================================

print("="*60)
print("F-SCORE VS K BITS - C3 KEYED IPs (ports intacts)")
print("="*60 + "\n")

fmeasures  = []
precisions = []
recalls    = []

for k in K_VALUES:
    alert_dir = f"./alerts_C3_k{k}"
    metrics   = compute_ids_metrics(BASELINE_DIR, alert_dir)

    fmeasures.append(metrics['F-measure'])
    precisions.append(metrics['Precision'])
    recalls.append(metrics['Recall'])

    print(
        f"k={k:2d} | "
        f"TP={metrics['TP']} "
        f"FP={metrics['FP']} "
        f"FN={metrics['FN']} | "
        f"F-measure={metrics['F-measure']:.3f}"
    )

fig, ax = plt.subplots(figsize=(12, 7))

color = '#27ae60'

ax.plot(K_VALUES, fmeasures, 'o-',
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
    'Technique C3 : Keyed Random IPs (ports intacts)\n'
    'Dataset : CIC-IDS 2017 Tuesday | Basé sur Yurcik et al. (2008)',
    fontsize=12, fontweight='bold'
)
ax.set_xticks(K_VALUES)
ax.set_xticklabels([
    f'k={k}\n({k//8} octet{"s" if k//8>1 else ""})'
    if k > 0 else 'k=0\n(original)'
    for k in K_VALUES
], fontsize=9)
ax.set_ylim(0, 1.15)
ax.axhline(y=1.0, color='gray', linestyle='--',
           alpha=0.5, label='F-measure = 1.0')
ax.grid(True, alpha=0.3)
ax.legend(fontsize=11)

plt.tight_layout()
plt.savefig('graph_C3_kbits_fscore.png', dpi=150)
print("\n✓ Graphique sauvegardé : graph_C3_kbits_fscore.png")
