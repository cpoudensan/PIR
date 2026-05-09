#!/usr/bin/env python3
"""
Calcule le F-score basé sur les alertes Snort
En utilisant la méthode de Yurcik (2008)
"""
from snort_metrics import evaluate_all
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

BASELINE_DIR = "./alerts_orig"

ALGO_DIRS = {
    "C1 Black Marker"      : "./alerts_C1",
    "C2 CryptoPAn only"    : "./alerts_C2",
    "C3 Keyed IPs only"    : "./alerts_C3",
    "C4 CryptoPAn+Keyed"   : "./alerts_C4",
    "C5 Keyed all"         : "./alerts_C5",
}

# Calcule les métriques
results = evaluate_all(BASELINE_DIR, ALGO_DIRS)

# Graphique
names     = list(results.keys())
fmeasures = [results[n]['F-measure'] * 100 for n in names]
tps       = [results[n]['TP'] for n in names]
fps       = [results[n]['FP'] for n in names]
fns       = [results[n]['FN'] for n in names]

colors = ['#e74c3c', '#f39c12', '#2ecc71', '#3498db']

fig, ax = plt.subplots(figsize=(12, 7))
bars = ax.bar(names, fmeasures, color=colors,
              width=0.5, edgecolor='black', linewidth=0.5)

for bar, val, tp, fp, fn in zip(bars, fmeasures, tps, fps, fns):
    ax.text(
        bar.get_x() + bar.get_width()/2,
        bar.get_height() + 1,
        f'{val:.1f}%\nTP={tp} FP={fp} FN={fn}',
        ha='center', va='bottom',
        fontsize=9, fontweight='bold'
    )

ax.set_xlabel('Technique d\'anonymisation', fontsize=12)
ax.set_ylabel('F-measure (%)', fontsize=12)
ax.set_title(
    'F-measure basé sur les alertes Snort\n'
    'Méthodologie Yurcik et al. (2008) - Lakkaraju Section 3.2\n'
    'Dataset : CIC-IDS 2017 Tuesday',
    fontsize=12, fontweight='bold'
)
ax.set_ylim(0, 120)
ax.axhline(y=50, color='gray', linestyle='--', alpha=0.5, label='Seuil 50%')
ax.grid(axis='y', alpha=0.3)
ax.legend(fontsize=11)

plt.tight_layout()
plt.savefig('graph_snort_fscore.png', dpi=150)
print("\n✓ Graphique sauvegardé : graph_snort_fscore.png")