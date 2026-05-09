# snort_metrics.py
import re
from pathlib import Path


def parse_snort_alerts(log_dir):
    """
    Parse le fichier d'alertes Snort.
    Snort 3 → alert_full.txt
    """
    log_path = Path(log_dir)

    for filename in ["alert_full.txt", "alert"]:
        alert_file = log_path / filename
        if alert_file.exists():
            break
    else:
        if log_path.exists():
            files = list(log_path.iterdir())
            print(f"  Dossier {log_dir} contient : {files}")
        else:
            print(f"  Dossier {log_dir} n'existe pas")
        return set()

    alerts = set()
    with open(alert_file, 'r', errors='ignore') as f:
        content = f.read()

    pattern = r'\[\*\*\]\s*\[(\d+:\d+:\d+)\]\s*"?(.*?)"?\s*\[\*\*\]'
    matches = re.findall(pattern, content)

    for sid, msg in matches:
        alerts.add((sid, msg.strip()))

    print(f"  {len(alerts)} types d'alertes — {log_dir}")
    return alerts


def compute_ids_metrics(baseline_dir, anonymized_dir):
    """
    Calcule TP, FP, FN entre baseline et anonymisé.
    Méthodologie exacte de Lakkaraju Section 3.2.
    """
    baseline   = parse_snort_alerts(baseline_dir)
    anonymized = parse_snort_alerts(anonymized_dir)

    tp = len(baseline & anonymized)
    fp = len(anonymized - baseline)
    fn = len(baseline - anonymized)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f_measure = (2 * precision * recall /
                 (precision + recall)
                 if (precision + recall) > 0 else 0)

    return {
        'TP': tp, 'FP': fp, 'FN': fn,
        'Precision': precision,
        'Recall':    recall,
        'F-measure': f_measure,
    }


def evaluate_all(baseline_dir, algo_log_dirs):
    """
    Évalue tous les algorithmes par rapport à la baseline.
    """
    print(f"\n{'='*65}")
    print(f"{'Algorithme':<30} {'TP':>4} {'FP':>6} "
          f"{'FN':>4} {'F-measure':>10}")
    print(f"{'='*65}")

    results = {}
    for algo, log_dir in algo_log_dirs.items():
        m = compute_ids_metrics(baseline_dir, log_dir)
        results[algo] = m
        print(f"{algo:<30} {m['TP']:>4} {m['FP']:>6} "
              f"{m['FN']:>4} {m['F-measure']:>10.3f}")

    return results