#!/usr/bin/env python3
"""
GRAPHIQUE 3 COURBES : K BITS IPs + TRANSFORMATION PORTS
=========================================================


Courbe 1 (verte)  : k bits IPs + ports INTACTS
Courbe 2 (rouge)  : k bits IPs + ports BLACK MARKER
Courbe 3 (bleue)  : k bits IPs + ports KEYED RANDOM
"""


import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from snort_metrics import compute_ids_metrics


K_VALUES     = [0, 4, 8, 12, 16, 20, 24, 28, 32]
BASELINE_DIR = "./alerts_orig_ip"


def get_fmeasures(alert_prefix, label):
    """Calcule le F-score pour chaque k."""
    print(f"\n--- {label} ---")
    fmeasures = []
    for k in K_VALUES:
        alert_dir = f"./{alert_prefix}_k{k}"
        metrics   = compute_ids_metrics(BASELINE_DIR, alert_dir)
        fmeasures.append(metrics['F-measure'])
        print(f"  k={k:2d} | TP={metrics['TP']} FP={metrics['FP']} FN={metrics['FN']} | F-measure={metrics['F-measure']:.3f}")
    return fmeasures


print("="*60)
print("CALCUL F-SCORE - 3 COURBES")
print("="*60)


# Courbe 1 : ports intacts 
fm_intact = get_fmeasures("alerts_C3", "k bits IPs + ports INTACTS")


# Courbe 2 : ports Black Marker
fm_bm = get_fmeasures("alerts_BM_ports", "k bits IPs + ports BLACK MARKER")


# Courbe 3 : ports Keyed Random
fm_keyed = get_fmeasures("alerts_keyed_ports", "k bits IPs + ports KEYED RANDOM")


# ============================================
# GRAPHIQUE
# ============================================


fig, ax = plt.subplots(figsize=(13, 7))


ax.plot(K_VALUES, fm_intact, 'o-',
        color='#27ae60', linewidth=2.5, markersize=9,
        label='k bits IPs + ports intacts')


ax.plot(K_VALUES, fm_bm, 's-',
        color='#e74c3c', linewidth=2.5, markersize=9,
        label='k bits IPs + ports Black Marker (→0)')


ax.plot(K_VALUES, fm_keyed, '^-',
        color='#2980b9', linewidth=2.5, markersize=9,
        label='k bits IPs + ports Keyed Random')


for k, f in zip(K_VALUES, fm_intact):
    ax.annotate(f'{f:.2f}', (k, f),
                textcoords="offset points",
                xytext=(-12, 8), ha='center',
                fontsize=8, color='#27ae60')


for k, f in zip(K_VALUES, fm_bm):
    ax.annotate(f'{f:.2f}', (k, f),
                textcoords="offset points",
                xytext=(0, -16), ha='center',
                fontsize=8, color='#e74c3c')


for k, f in zip(K_VALUES, fm_keyed):
    ax.annotate(f'{f:.2f}', (k, f),
                textcoords="offset points",
                xytext=(12, 8), ha='center',
                fontsize=8, color='#2980b9')


ax.set_xlabel('k = nombre de bits modifiés dans l\'adresse IP', fontsize=12)
ax.set_ylabel('F-measure', fontsize=12)
ax.set_title(
    'F-score Snort : Impact combiné k bits IPs + transformation ports\n'
    'Vert = ports intacts | Rouge = ports Black Marker | Bleu = ports Keyed Random\n'
    'Dataset : CIC-IDS 2017 Tuesday | Basé sur Yurcik et al. (2008)',
    fontsize=12, fontweight='bold'
)
ax.set_xticks(K_VALUES)
ax.set_xticklabels([f'k={k}' for k in K_VALUES], fontsize=10)
ax.set_ylim(0, 1.15)
ax.axhline(y=1.0, color='gray', linestyle='--', alpha=0.5)
ax.grid(True, alpha=0.3)
ax.legend(fontsize=11, loc='upper right')


plt.tight_layout()
plt.savefig('graph_kbits_3courbes.png', dpi=150)
print("\n✓ Graphique sauvegardé : graph_kbits_3courbes.png")
