"""
train.py — Phase 2: Training
==============================
Loads normal_traces.pkl, runs the full ML pipeline, saves model.pkl.

Usage:
  python train.py normal_traces.pkl model.pkl
  python train.py normal_traces.pkl model.pkl --z 2.5 --holdout 0.2
  python train.py normal_traces.pkl model.pkl --inspect   # show learned grammar

What gets saved in model.pkl:
  {
    "detector":   AnomalyDetector instance  (has .predict(), .threshold),
    "threshold":  float,
    "grammar":    dict  (human-readable rules for the dashboard),
    "stats":      dict  (training stats for display),
    "created":    str   (ISO timestamp),
  }

The detector object contains:
  .pcfg     — PCFG (rule probabilities)
  .cnf      — CNFConverter (Chomsky Normal Form rules)
  .inside   — InsideAlgorithm (pre-indexed for fast CYK)
  .threshold — float (μ + z·σ from holdout calibration)
"""

from __future__ import annotations
import sys
import os
import pickle
import argparse
import datetime
import math
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcfg_inside import AnomalyDetector, PCFG, CNFConverter, InsideAlgorithm
from sequitur import SequiturSimple


# ═════════════════════════════════════════════════════════════════════════════
# LOAD
# ═════════════════════════════════════════════════════════════════════════════

def load_traces(path: str) -> tuple[list[list[str]], dict]:
    """Load traces pkl. Returns (traces, metadata)."""
    with open(path, "rb") as f:
        payload = pickle.load(f)

    if isinstance(payload, dict):
        traces = payload["traces"]
        meta   = {k: v for k, v in payload.items() if k != "traces"}
    else:
        traces = payload   # legacy plain list
        meta   = {}

    return traces, meta


# ═════════════════════════════════════════════════════════════════════════════
# TRAINING PIPELINE
# ═════════════════════════════════════════════════════════════════════════════

def train(traces: list[list[str]],
          holdout_fraction: float = 0.2,
          z_threshold: float = 2.5,
          verbose: bool = True) -> AnomalyDetector:
    """
    Full pipeline:
      traces → SEQUITUR per trace → PCFG → CNF → InsideAlgorithm → threshold

    Returns a trained AnomalyDetector ready to call .predict() on.
    """
    if verbose:
        print(f"\n[Train] {len(traces)} traces loaded")
        lengths = [len(t) for t in traces]
        print(f"[Train] Trace lengths — "
              f"min={min(lengths)}, max={max(lengths)}, "
              f"mean={sum(lengths)/len(lengths):.1f}")

    detector = AnomalyDetector(z_threshold=z_threshold)
    detector.train(traces, holdout_fraction=holdout_fraction)
    return detector


# ═════════════════════════════════════════════════════════════════════════════
# GRAMMAR EXPORT (for the dashboard's Grammar Inspector panel)
# ═════════════════════════════════════════════════════════════════════════════

def export_grammar(detector: AnomalyDetector) -> dict:
    """
    Export the learned grammar as a plain dict for the frontend.
    Excludes CNF auxiliary rules (X1, X2, T_open, ...) — shows only
    the human-meaningful SEQUITUR rules.

    Returns:
      {
        "S":   [{"body": ["R1","open","R2"], "prob": 0.45}, ...],
        "R1":  [{"body": ["open","read"],    "prob": 1.0 }],
        ...
      }
    """
    if not detector.pcfg:
        return {}

    grammar = {}
    for lhs, productions in detector.pcfg.rules.items():
        grammar[lhs] = [
            {"body": body, "prob": round(prob, 4)}
            for body, prob in productions
        ]
    return grammar


# ═════════════════════════════════════════════════════════════════════════════
# TRAINING STATISTICS
# ═════════════════════════════════════════════════════════════════════════════

def compute_stats(traces: list[list[str]],
                  detector: AnomalyDetector) -> dict:
    """
    Score all training traces and compute distribution statistics.
    Used by the dashboard's stats cards.
    """
    scores = detector.score_batch(traces)
    finite = [s for s in scores if s < 999.0]

    if not finite:
        return {"error": "All training traces scored as unparseable."}

    mean = sum(finite) / len(finite)
    variance = sum((s - mean)**2 for s in finite) / len(finite)
    std  = math.sqrt(variance)

    return {
        "n_traces":      len(traces),
        "score_mean":    round(mean, 4),
        "score_std":     round(std, 4),
        "score_min":     round(min(finite), 4),
        "score_max":     round(max(finite), 4),
        "threshold":     round(detector.threshold, 4),
        "z_threshold":   detector.z_threshold,
        "n_rules":       sum(len(v) for v in detector.pcfg.rules.values()),
        "n_terminals":   len(detector.pcfg.terminals),
        "n_nonterminals": len(detector.pcfg.non_terminals),
        "vocabulary":    sorted(detector.pcfg.terminals),
    }


# ═════════════════════════════════════════════════════════════════════════════
# SAVE MODEL
# ═════════════════════════════════════════════════════════════════════════════

def save_model(detector: AnomalyDetector,
               grammar:  dict,
               stats:    dict,
               output_path: str) -> None:
    payload = {
        "detector":  detector,
        "threshold": detector.threshold,
        "grammar":   grammar,
        "stats":     stats,
        "created":   datetime.datetime.now().isoformat(timespec="seconds"),
        "version":   "1.0",
    }
    with open(output_path, "wb") as f:
        pickle.dump(payload, f)
    size_kb = os.path.getsize(output_path) / 1024
    print(f"\n[Train] Model saved → {output_path}  ({size_kb:.1f} KB)")


def load_model(path: str) -> dict:
    """Load model.pkl. Returns the full payload dict."""
    with open(path, "rb") as f:
        return pickle.load(f)


# ═════════════════════════════════════════════════════════════════════════════
# INSPECTION HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def inspect_model(payload: dict) -> None:
    """Print a human-readable summary of a saved model."""
    print(f"\n{'═'*55}")
    print(f"  MODEL INSPECTION")
    print(f"{'═'*55}")
    print(f"  Created   : {payload.get('created', 'unknown')}")
    print(f"  Threshold : {payload['threshold']:.4f}")

    s = payload.get("stats", {})
    if s:
        print(f"\n  Training stats:")
        print(f"    Traces      : {s.get('n_traces', '?')}")
        print(f"    Score mean  : {s.get('score_mean', '?')}")
        print(f"    Score std   : {s.get('score_std', '?')}")
        print(f"    Vocabulary  : {s.get('n_terminals', '?')} syscalls")
        print(f"    Grammar rules: {s.get('n_rules', '?')}")

    g = payload.get("grammar", {})
    if g:
        print(f"\n  Learned Grammar (PCFG rules):")
        print(f"  {'─'*50}")
        for lhs in sorted(g.keys()):
            for entry in g[lhs]:
                body_str = " ".join(entry["body"])
                print(f"    {lhs:<6} →  {body_str:<35} [{entry['prob']:.4f}]")

    vocab = s.get("vocabulary", [])
    if vocab:
        print(f"\n  Known syscalls ({len(vocab)}):")
        print(f"    {', '.join(vocab)}")
    print(f"{'═'*55}")


# ═════════════════════════════════════════════════════════════════════════════
# VALIDATION (quick sanity check after training)
# ═════════════════════════════════════════════════════════════════════════════

def validate(detector: AnomalyDetector,
             traces:   list[list[str]],
             verbose:  bool = True) -> None:
    """
    Score a sample of training traces and print the distribution.
    A well-trained model should score training traces LOW (below threshold).
    If many training traces score above threshold, z_threshold is too low.
    """
    sample = traces[:20]
    scores = detector.score_batch(sample)
    above  = sum(1 for s in scores if s > detector.threshold)

    if verbose:
        print(f"\n[Validate] Scoring {len(sample)} training traces:")
        for i, (trace, score) in enumerate(zip(sample, scores)):
            flag = "⚠" if score > detector.threshold else "✓"
            preview = " ".join(trace[:5]) + ("..." if len(trace) > 5 else "")
            score_str = f"{score:.3f}" if score < 999 else "∞"
            print(f"  {flag} [{score_str:>8}]  {preview}")

        if above > 0:
            pct = above / len(sample) * 100
            print(f"\n  ⚠ {above}/{len(sample)} training traces ({pct:.0f}%) "
                  f"scored above threshold.")
            print(f"  Consider increasing --z (currently {detector.z_threshold})")
        else:
            print(f"\n  ✓ All training traces score below threshold — model looks healthy.")


# ═════════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════════

def main():
    p = argparse.ArgumentParser(
        description="Train CFG-IDS model from collected normal traces.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("input",  type=str, help="Path to normal_traces.pkl")
    p.add_argument("output", type=str, help="Path to save model.pkl")
    p.add_argument("--z",       type=float, default=2.5,
                   help="Z-score threshold (default 2.5). Higher = fewer false positives.")
    p.add_argument("--holdout", type=float, default=0.2,
                   help="Fraction of traces held out for threshold calibration (default 0.2)")
    p.add_argument("--inspect", action="store_true",
                   help="After training, print full model inspection")
    p.add_argument("--validate", action="store_true",
                   help="Score training traces to verify model health")
    args = p.parse_args()

    print(f"\n{'═'*55}")
    print(f"  CFG-IDS TRAINING PIPELINE")
    print(f"{'═'*55}")
    print(f"  Input    : {args.input}")
    print(f"  Output   : {args.output}")
    print(f"  Z        : {args.z}")
    print(f"  Holdout  : {args.holdout*100:.0f}%")

    # ── Phase 2a: Load ────────────────────────────────────────────────────────
    print(f"\n[1/4] Loading traces from {args.input}...")
    traces, meta = load_traces(args.input)
    if meta:
        print(f"      Original collection: PID={meta.get('pid','?')}, "
              f"duration={meta.get('duration','?')}s")

    # ── Phase 2b: Train ───────────────────────────────────────────────────────
    print(f"\n[2/4] Running SEQUITUR → PCFG → CNF → Inside...")
    detector = train(traces, holdout_fraction=args.holdout,
                     z_threshold=args.z, verbose=True)

    # ── Phase 2c: Validate ────────────────────────────────────────────────────
    print(f"\n[3/4] Validating...")
    validate(detector, traces, verbose=args.validate)

    # ── Phase 2d: Save ────────────────────────────────────────────────────────
    print(f"\n[4/4] Saving model...")
    grammar = export_grammar(detector)
    stats   = compute_stats(traces, detector)
    save_model(detector, grammar, stats, args.output)

    if args.inspect:
        payload = load_model(args.output)
        inspect_model(payload)

    print(f"\n  ✓ Training complete.")
    print(f"  Next step:  python cyclic_monitor.py --pid <PID> --model {args.output}")


if __name__ == "__main__":
    main()