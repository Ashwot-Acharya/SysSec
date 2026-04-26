"""
pcfg_inside.py  — Fixed Version
=================================
WHAT CHANGED AND WHY:

  OLD scoring (broken):
    CYK Inside tries to parse the FULL sequence under start symbol S.
    Grammar only has bigram/trigram rules — NO recursive S → S S rule.
    So any sequence longer than 3 syscalls scores 0 → anomaly = ∞.
    One unknown bigram → entire sequence fails → 100% false positive rate.

  NEW scoring (fixed):
    NGramScorer: score each consecutive bigram in the sequence independently.
    anomaly_score = mean( -log P(wi+1 | wi) ) across all bigrams in sequence.
    Unknown bigrams get Laplace-smoothed probability → NEVER returns ∞.
    Works on sequences of ANY length. Robust to unseen transitions.

  CYK InsideAlgorithm is KEPT but only for explain_with_parse_tree() —
  the visual parse tree on the frontend. It no longer drives detection.

  Threshold calibration fixed:
    OLD: μ + z·σ — collapses when σ is tiny (uniform training data).
    NEW: max( μ + z·σ,  P95 of holdout scores,  floor=1.5*μ )

  Pickle compatibility:
    Old PCFG objects (saved before vocab/bigram_counts were added) are
    patched on first access via __getattr__ so that loading a legacy
    model.pkl never raises AttributeError.
"""

from __future__ import annotations
import math
import re
from collections import defaultdict
from typing import Optional
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from sequitur import SequiturSimple
except ImportError:
    raise ImportError("sequitur.py not found. Place both files in the same directory.")


# ─────────────────────────────────────────────────────────────────────────────
def _default_int_dd():
    return defaultdict(int)


# ═════════════════════════════════════════════════════════════════════════════
# PART 1 — PCFG
# ═════════════════════════════════════════════════════════════════════════════

class PCFG:
    """
    Probabilistic CFG learned from normal syscall traces.

    Stores raw bigram/trigram counts for NGramScorer + a display grammar
    (the old S → bigram/trigram rules) for the dashboard Grammar Inspector.

    Pickle compatibility
    --------------------
    Old pickled PCFG objects may be missing vocab, bigram_counts, or
    unigram_counts.  __getattr__ reconstructs them from whatever IS present
    (terminals set, rules dict) so that loaded legacy models never raise
    AttributeError at runtime.
    """

    def __init__(self):
        # Primary: raw counts for NGramScorer
        self.bigram_counts:  dict[str, dict[str, int]]    = defaultdict(_default_int_dd)
        self.unigram_counts: dict[str, int]                = defaultdict(int)
        self.vocab:          set[str]                      = set()
        self.total_bigrams   = 0

        # Secondary: display grammar (S → bigram/trigram rules, for dashboard)
        self._raw_counts     = defaultdict(_default_int_dd)
        self.rules           = {}
        self.terminals:      set[str] = set()
        self.non_terminals:  set[str] = set()

    # ── Pickle compatibility shim ─────────────────────────────────────────────
    def __getattr__(self, name: str):
        """
        Called only when normal attribute lookup fails — i.e. the attribute
        is genuinely missing from a legacy pickle.  Reconstruct sensible
        defaults so the scorer can still run.
        """
        if name == 'vocab':
            # Rebuild from terminals (present in old pickles) or rules
            v = set()
            if hasattr(self, 'terminals') and self.terminals:
                v = set(self.terminals)
            elif hasattr(self, 'rules'):
                for prods in self.rules.values():
                    for body, _ in prods:
                        for sym in body:
                            if not sym.startswith('R') and not sym.startswith('X'):
                                v.add(sym)
            # Cache it so __getattr__ isn't called again
            object.__setattr__(self, 'vocab', v)
            return v

        if name == 'bigram_counts':
            bc = defaultdict(_default_int_dd)
            object.__setattr__(self, 'bigram_counts', bc)
            return bc

        if name == 'unigram_counts':
            uc = defaultdict(int)
            object.__setattr__(self, 'unigram_counts', uc)
            return uc

        if name == 'total_bigrams':
            object.__setattr__(self, 'total_bigrams', 0)
            return 0

        if name == '_raw_counts':
            rc = defaultdict(_default_int_dd)
            object.__setattr__(self, '_raw_counts', rc)
            return rc

        raise AttributeError(f"'PCFG' object has no attribute '{name}'")

    # ── Training ──────────────────────────────────────────────────────────────

    def train(self, traces: list[list[str]]) -> None:
        print(f"\n[PCFG] Training on {len(traces)} traces...")

        for trace in traces:
            # Unigram / bigram counts from RAW trace (no expansion needed)
            for sym in trace:
                self.unigram_counts[sym] += 1
                self.vocab.add(sym)

            for i in range(len(trace) - 1):
                a, b = trace[i], trace[i + 1]
                self.bigram_counts[a][b] += 1
                self.total_bigrams += 1

            # Display grammar via SEQUITUR expansion
            sq      = SequiturSimple()
            grammar = sq.learn(trace)
            self._count_rules_display(grammar)

        self._normalize_display()
        self._collect_symbols()

        print(f"[PCFG] Vocabulary    : {len(self.vocab)} syscalls")
        print(f"[PCFG] Unique bigrams: {sum(len(v) for v in self.bigram_counts.values())}")
        print(f"[PCFG] Total bigrams : {self.total_bigrams}")

    def _count_rules_display(self, grammar: dict) -> None:
        def expand(sym: str, depth: int = 0) -> list[str]:
            if depth > 50 or sym not in grammar:
                return [sym]
            result = []
            for s in grammar[sym]:
                result.extend(expand(s, depth + 1))
            return result

        expanded = expand("S")
        n = len(expanded)
        for i in range(n - 1):
            self._raw_counts["S"][tuple(expanded[i:i + 2])] += 1
        for i in range(n - 2):
            self._raw_counts["S"][tuple(expanded[i:i + 3])] += 1

    def _normalize_display(self) -> None:
        self.rules = {}
        for lhs, rhs_counts in self._raw_counts.items():
            total = sum(rhs_counts.values())
            prods = [(list(rhs), cnt / total) for rhs, cnt in rhs_counts.items()]
            prods.sort(key=lambda x: x[1], reverse=True)
            self.rules[lhs] = prods

    def _collect_symbols(self) -> None:
        self.non_terminals = set(self.rules.keys())
        self.terminals      = set(self.vocab)

    def bigram_prob_smoothed(self, a: str, b: str, alpha: float = 0.1) -> float:
        """
        Laplace-smoothed P(b | a).
        P(b|a) = (count(a,b) + α) / (count(a,*) + α * |V|)
        NEVER returns 0 — unknown transitions get α / (α * |V|) = 1/|V|.
        """
        V     = max(len(self.vocab), 1)
        count = self.bigram_counts[a].get(b, 0)
        total = sum(self.bigram_counts[a].values()) if a in self.bigram_counts else 0
        return (count + alpha) / (total + alpha * V)

    def print_grammar(self) -> None:
        print("\n" + "═" * 55)
        print("  PROBABILISTIC CFG  (top bigrams/trigrams)")
        print("═" * 55)
        top = sorted(self.rules.get("S", []), key=lambda x: x[1], reverse=True)[:20]
        for body, prob in top:
            print(f"  S  →  {' '.join(body):<30}  [{prob:.4f}]")
        print("═" * 55)


# ═════════════════════════════════════════════════════════════════════════════
# PART 1b — N-GRAM SCORER  (primary anomaly scorer — replaces CYK)
# ═════════════════════════════════════════════════════════════════════════════

class NGramScorer:
    """
    Bigram language model scorer with Laplace smoothing.

    anomaly_score(seq) = mean( -log P(wi+1 | wi) ) + unknown_penalty per OOV syscall

    Why this fixes the ∞-score problem:
      - Laplace smoothing: P never = 0, so -log P never = ∞
      - No full-sequence parse needed: works on any length
      - Unknown syscalls get a fixed penalty (not ∞)
      - Decomposes cleanly: find the most anomalous bigram transition

    Pickle compatibility
    --------------------
    Old pickled NGramScorer objects may be missing smoothing or
    unknown_penalty.  __getattr__ supplies safe defaults.
    """

    def __init__(self, pcfg: PCFG,
                 smoothing: float = 0.1,
                 unknown_penalty: float = 5.0):
        self.pcfg            = pcfg
        self.smoothing       = smoothing
        self.unknown_penalty = unknown_penalty

    # ── Pickle compatibility shim ─────────────────────────────────────────────
    def __getattr__(self, name: str):
        if name == 'smoothing':
            object.__setattr__(self, 'smoothing', 0.1)
            return 0.1
        if name == 'unknown_penalty':
            object.__setattr__(self, 'unknown_penalty', 5.0)
            return 5.0
        raise AttributeError(f"'NGramScorer' object has no attribute '{name}'")

    # ── Scoring ───────────────────────────────────────────────────────────────

    def anomaly_score(self, sequence: list[str]) -> float:
        if not sequence:
            return 0.0

        # OOV penalty per unknown syscall
        oov_penalty = self.unknown_penalty * sum(
            1 for s in sequence if s not in self.pcfg.vocab
        )

        if len(sequence) == 1:
            base = 0.0 if sequence[0] in self.pcfg.vocab else self.unknown_penalty
            return base

        bigram_scores = [
            -math.log(self.pcfg.bigram_prob_smoothed(sequence[i], sequence[i + 1], self.smoothing))
            for i in range(len(sequence) - 1)
        ]

        return sum(bigram_scores) / len(bigram_scores) + oov_penalty

    def explain(self, sequence: list[str]) -> dict:
        n       = len(sequence)
        unknown = [s for s in sequence if s not in self.pcfg.vocab]

        token_scores = [0.0]   # first token has no predecessor
        for i in range(1, n):
            s = -math.log(
                self.pcfg.bigram_prob_smoothed(sequence[i-1], sequence[i], self.smoothing)
            )
            token_scores.append(s)

        # Most anomalous transition
        max_idx   = max(range(1, n), key=lambda i: token_scores[i]) if n > 1 else 0
        breakdown = {
            "position":    max_idx,
            "syscall":     sequence[max_idx],
            "reason": (
                f"Transition '{sequence[max_idx-1]} → {sequence[max_idx]}' "
                f"is unusual (score={token_scores[max_idx]:.2f}). "
                + ("Syscall never seen in training." if sequence[max_idx] not in self.pcfg.vocab
                   else "Unusual transition order under normal grammar.")
            ),
            "bigram_score": token_scores[max_idx],
        } if n > 1 else None

        total_score = self.anomaly_score(sequence)

        if unknown:
            verdict = f"UNKNOWN SYSCALLS: {unknown} — never seen in training."
        elif breakdown and breakdown["bigram_score"] > 8.0:
            verdict = (
                f"Suspicious transition at position {breakdown['position']}: "
                f"'{breakdown['syscall']}'. {breakdown['reason']}"
            )
        else:
            verdict = f"Unusual syscall ordering. Mean bigram score={total_score:.2f}."

        token_parseable = [s in self.pcfg.vocab for s in sequence]
        parse_spans = [
            [i, i+1]
            for i in range(n - 1)
            if sequence[i] in self.pcfg.vocab and sequence[i+1] in self.pcfg.vocab
        ]

        return {
            "sequence":          sequence,
            "length":            n,
            "token_parseable":   token_parseable,
            "token_scores":      [round(s, 3) for s in token_scores],
            "parse_spans":       parse_spans,
            "breakdown":         breakdown,
            "unknown_syscalls":  unknown,
            "full_parse_prob":   math.exp(-total_score) if total_score < 700 else 0.0,
            "verdict":           verdict,
        }


# ═════════════════════════════════════════════════════════════════════════════
# PART 2 — CNF CONVERTER  (for dashboard visualization only)
# ═════════════════════════════════════════════════════════════════════════════

class CNFConverter:
    def __init__(self):
        self.rules:         dict[str, list[tuple[list[str], float]]] = {}
        self.terminals:     set[str] = set()
        self.non_terminals: set[str] = set()
        self._aux_counter   = 0
        self._term_map:     dict[str, str] = {}

    def convert(self, pcfg: PCFG) -> "CNFConverter":
        self.rules = {
            lhs: [(list(body), prob) for body, prob in prods]
            for lhs, prods in pcfg.rules.items()
        }
        print("\n[CNF] Starting conversion...")
        self._step1_new_start()
        self._step2_term()
        self._step3_bin()
        self._step5_unit()
        self._collect_symbols()
        total = sum(len(v) for v in self.rules.values())
        print(f"[CNF] Done. {len(self.non_terminals)} NTs, "
              f"{len(self.terminals)} terminals, {total} rules.")
        return self

    def _step1_new_start(self):
        if "S" in self.rules:
            self.rules["S0"] = [(["S"], 1.0)]

    def _step2_term(self):
        new_rules = {}
        for lhs, productions in self.rules.items():
            new_prods = []
            for body, prob in productions:
                if len(body) >= 2:
                    new_body = [
                        self._terminal_nt(sym) if sym not in self.rules else sym
                        for sym in body
                    ]
                    new_prods.append((new_body, prob))
                else:
                    new_prods.append((body, prob))
            new_rules[lhs] = new_prods
        for terminal, t_name in self._term_map.items():
            new_rules[t_name] = [([terminal], 1.0)]
        self.rules = new_rules

    def _terminal_nt(self, terminal: str) -> str:
        if terminal not in self._term_map:
            safe = re.sub(r'[^A-Za-z0-9_]', '_', terminal)
            self._term_map[terminal] = f"T_{safe}"
        return self._term_map[terminal]

    def _step3_bin(self):
        changed = True
        while changed:
            changed   = False
            new_rules = {}
            for lhs, productions in self.rules.items():
                new_prods = []
                for body, prob in productions:
                    if len(body) > 2:
                        self._aux_counter += 1
                        aux = f"X{self._aux_counter}"
                        new_prods.append(([body[0], aux], prob))
                        new_rules[aux] = [(body[1:], 1.0)]
                        changed = True
                    else:
                        new_prods.append((body, prob))
                new_rules[lhs] = new_prods
            self.rules = new_rules

    def _step5_unit(self):
        changed = True
        while changed:
            changed   = False
            new_rules = {}
            for lhs, productions in self.rules.items():
                expanded = []
                for body, prob in productions:
                    if len(body) == 1 and body[0] in self.rules and body[0] != lhs:
                        for t_body, t_prob in self.rules[body[0]]:
                            expanded.append((t_body, prob * t_prob))
                        changed = True
                    else:
                        expanded.append((body, prob))
                new_rules[lhs] = expanded
            self.rules = new_rules

    def _collect_symbols(self):
        self.non_terminals = set(self.rules.keys())
        for lhs, productions in self.rules.items():
            for body, _ in productions:
                for sym in body:
                    if sym not in self.non_terminals:
                        self.terminals.add(sym)

    def verify_cnf(self) -> bool:
        ok = True
        for lhs, productions in self.rules.items():
            for body, _ in productions:
                if len(body) == 1:
                    if body[0] in self.non_terminals:
                        print(f"  ✗ UNIT: {lhs} → {body[0]}")
                        ok = False
                elif len(body) == 2:
                    for sym in body:
                        if sym not in self.non_terminals:
                            print(f"  ✗ TERM: {lhs} → {' '.join(body)} ({sym} is terminal)")
                            ok = False
                else:
                    print(f"  ✗ LEN:  {lhs} → {' '.join(body)}")
                    ok = False
        return ok


# ═════════════════════════════════════════════════════════════════════════════
# PART 3 — INSIDE ALGORITHM  (visualization only — not used for scoring)
# ═════════════════════════════════════════════════════════════════════════════

class InsideAlgorithm:
    """CYK Inside — kept for dashboard parse-tree visualization only."""

    def __init__(self, cnf: CNFConverter):
        self.cnf   = cnf
        self.start = "S0" if "S0" in cnf.rules else "S"
        self._terminal_rules: dict[str, list[tuple[str, float]]] = defaultdict(list)
        self._binary_rules:   dict[tuple, list[tuple[str, float]]] = defaultdict(list)
        self._index_rules()

    def _index_rules(self):
        for lhs, productions in self.cnf.rules.items():
            for body, prob in productions:
                if len(body) == 1:
                    self._terminal_rules[body[0]].append((lhs, prob))
                elif len(body) == 2:
                    self._binary_rules[(body[0], body[1])].append((lhs, prob))

    def inside(self, sequence: list[str]) -> dict:
        n     = len(sequence)
        table: dict[tuple, float] = defaultdict(float)
        for i, word in enumerate(sequence):
            for lhs, prob in self._terminal_rules.get(word, []):
                table[(i, i, lhs)] = table.get((i, i, lhs), 0.0) + prob
        for span in range(2, n + 1):
            for i in range(n - span + 1):
                j = i + span - 1
                for k in range(i, j):
                    for (B, C), lhs_list in self._binary_rules.items():
                        left  = table.get((i, k, B), 0.0)
                        right = table.get((k + 1, j, C), 0.0)
                        if left > 0.0 and right > 0.0:
                            for lhs, prob in lhs_list:
                                key = (i, j, lhs)
                                table[key] = table.get(key, 0.0) + prob * left * right
        return table

    def explain_with_parse_tree(self, sequence: list[str]) -> dict:
        table   = self.inside(sequence)
        n       = len(sequence)
        unknown = [w for w in sequence if w not in self.cnf.terminals]

        token_parseable = []
        for i in range(n):
            covered = any(table.get((i, i, nt), 0) > 0
                          for nt in self.cnf.non_terminals)
            token_parseable.append(covered)

        parse_map = {}
        parse_spans = []
        for i in range(n):
            for j in range(i, n):
                covered = any(table.get((i, j, nt), 0) > 0
                              for nt in self.cnf.non_terminals)
                parse_map[(i, j)] = covered
                
                # Generate visual spans for valid sequences of length > 1
                if covered and j > i and (j - i) <= 4:
                    label = " → ".join(sequence[i:j+1])
                    if len(label) > 40:
                        label = label[:37] + "..."
                    parse_spans.append({
                        "start": i,
                        "end": j,
                        "label": label,
                        "valid": True
                    })

        breakdown_idx  = None
        breakdown_info = None

        for i in range(n):
            if not token_parseable[i]:
                breakdown_idx = i
                breakdown_info = {
                    "position": i,
                    "syscall":  sequence[i],
                    "reason": (
                        f"'{sequence[i]}' was never seen in training"
                        if sequence[i] in unknown
                        else f"'{sequence[i]}' cannot follow "
                             f"'{sequence[i-1] if i > 0 else 'START'}' "
                             f"in any learned rule"
                    )
                }
                break

        if breakdown_idx is None and table.get((0, n-1, self.start), 0) == 0:
            for end in range(n-1, -1, -1):
                if parse_map.get((0, end)):
                    breakdown_idx = end + 1
                    breakdown_info = {
                        "position": end + 1,
                        "syscall":  sequence[end + 1] if end + 1 < n else "END",
                        "reason": (
                            f"Grammar parsed 0–{end} "
                            f"({' '.join(sequence[:end+1])}), "
                            f"but failed at '{sequence[end+1] if end+1 < n else 'END'}'"
                        )
                    }
                    break

        p = table.get((0, n-1, self.start), 0)
        if unknown:
            verdict = f"UNKNOWN SYSCALLS: {unknown} — never seen in training."
        elif p == 0:
            verdict = (f"PARSE FAILURE at position {breakdown_idx} "
                       f"('{breakdown_info['syscall']}'). {breakdown_info['reason']}")
        else:
            verdict = (f"Low probability sequence. P={p:.2e}, "
                       f"score={-math.log(p):.2f}. Unusual ordering.")

        return {
            "sequence":         sequence,
            "length":           n,
            "token_parseable":  token_parseable,
            "parse_map":        {f"{i},{j}": v for (i, j), v in parse_map.items()},
            "parse_spans":      parse_spans,
            "breakdown":        breakdown_info,
            "unknown_syscalls": unknown,
            "full_parse_prob":  table.get((0, n-1, self.start), 0.0),
            "verdict":          "CYK visualization — anomaly score from NGramScorer.",
        }


# ═════════════════════════════════════════════════════════════════════════════
# PART 4 — ANOMALY DETECTOR
# ═════════════════════════════════════════════════════════════════════════════

class AnomalyDetector:
    """
    Full pipeline:
      train(traces) → PCFG → NGramScorer → threshold
      predict(seq)  → (is_anomaly, score, explanation)

    NGramScorer is the primary scorer.
    InsideAlgorithm is built for dashboard visualization only.

    Pickle compatibility
    --------------------
    predict() reconstructs .scorer from .pcfg if the loaded object is
    missing it (legacy pickle saved before NGramScorer was introduced).
    """

    def __init__(self, z_threshold: float = 3.0,
                 smoothing: float = 0.1,
                 unknown_penalty: float = 5.0):
        self.z_threshold     = z_threshold
        self.smoothing       = smoothing
        self.unknown_penalty = unknown_penalty
        self.pcfg:   Optional[PCFG]            = None
        self.cnf:    Optional[CNFConverter]     = None
        self.inside: Optional[InsideAlgorithm] = None
        self.scorer: Optional[NGramScorer]     = None
        self._threshold_mean = 0.0
        self._threshold_std  = 1.0
        self.threshold       = 0.0

    def train(self, normal_traces: list[list[str]],
              holdout_fraction: float = 0.2) -> None:
        split          = int(len(normal_traces) * (1 - holdout_fraction))
        train_traces   = normal_traces[:split]
        holdout_traces = normal_traces[split:]

        print(f"\n[Detector] Training traces : {len(train_traces)}")
        print(f"[Detector] Holdout  traces : {len(holdout_traces)}")

        self.pcfg   = PCFG()
        self.pcfg.train(train_traces)

        self.scorer = NGramScorer(self.pcfg, self.smoothing, self.unknown_penalty)
        self.cnf    = CNFConverter().convert(self.pcfg)
        self.inside = InsideAlgorithm(self.cnf)

        self._calibrate(holdout_traces, n_train=len(train_traces))

    def _calibrate(self, holdout_traces: list[list[str]], n_train: int = 0) -> None:
        """
        Fixed threshold:  max( μ + z·σ,  P95 of holdout,  floor=1.5*μ )
        """
        if not holdout_traces:
            self.threshold = 10.0
            return

        scores = sorted(self.scorer.anomaly_score(t) for t in holdout_traces if t)
        if not scores:
            self.threshold = 10.0
            return

        n    = len(scores)
        mean = sum(scores) / n
        var  = sum((s - mean) ** 2 for s in scores) / n
        std  = math.sqrt(var) if var > 0 else 1.0

        self._threshold_mean = mean
        self._threshold_std  = std

        # Dynamic z boost for small corpora
        z = self.z_threshold
        if n_train < 10:
            z += 2.0
        elif n_train < 30:
            z += 1.0

        mean_z = mean + z * std

        # 95th percentile
        p95 = scores[min(int(0.95 * n), n - 1)]

        # Floor: never below 1.5× training mean (prevents over-sensitivity)
        floor = max(mean * 1.5, 1.0)

        self.threshold = max(mean_z, p95, floor)

        print(f"\n[Calibrate] μ={mean:.4f}  σ={std:.4f}  "
              f"P95={p95:.4f}  z={z:.1f}")
        print(f"[Calibrate] threshold = max({mean_z:.4f}, {p95:.4f}, {floor:.4f})"
              f" = {self.threshold:.4f}")

    def _ensure_scorer(self) -> None:
        """
        Reconstruct NGramScorer if missing (legacy pickle compatibility).
        Also ensures the PCFG inside the scorer has all required attributes.
        """
        if not hasattr(self, 'scorer') or self.scorer is None:
            if self.pcfg is None:
                raise RuntimeError(
                    "Model has no PCFG — cannot recover. "
                    "Retrain:  python train.py normal_traces.pkl model.pkl"
                )
            smoothing       = getattr(self, 'smoothing',       0.1)
            unknown_penalty = getattr(self, 'unknown_penalty', 5.0)
            self.scorer = NGramScorer(self.pcfg, smoothing, unknown_penalty)
            print("[Compat] Reconstructed NGramScorer from legacy PCFG.")

    def predict(self, sequence: list[str]) -> tuple[bool, float, dict]:
        self._ensure_scorer()
        score       = self.scorer.anomaly_score(sequence)
        is_anomaly  = score > self.threshold
        explanation = self.scorer.explain(sequence) if is_anomaly else {}
        return is_anomaly, score, explanation

    def score_batch(self, sequences: list[list[str]]) -> list[float]:
        self._ensure_scorer()
        return [self.scorer.anomaly_score(s) for s in sequences]


# ═════════════════════════════════════════════════════════════════════════════
# SELF-TEST
# ═════════════════════════════════════════════════════════════════════════════

def _sep(t):
    print("\n" + "━"*55)
    print(f"  {t}")
    print("━"*55)


def test_no_infinite():
    _sep("TEST 1 — Smoothing prevents ∞ scores")

    traces = [
        ['open','read','close'],
        ['open','read','read','close'],
        ['statx','openat','read','close'],
        ['statx','statx','openat','read','close'],
        ['open','write','close'],
    ] * 5

    det = AnomalyDetector(z_threshold=2.5)
    det.train(traces, holdout_fraction=0.2)

    for trace in traces[:10]:
        score = det.scorer.anomaly_score(trace)
        assert score < 999, f"Training trace scored ∞: {trace}"

    print(f"  ✓ All training traces score < 999. Smoothing works.")
    print(f"  Threshold: {det.threshold:.4f}")


def test_pipeline():
    _sep("TEST 2 — Full detection pipeline")

    normal = [
        ['open','read','close'],
        ['statx','openat','read','close'],
        ['statx','statx','openat','read','read','close'],
        ['open','write','close'],
        ['open','read','write','close'],
    ] * 8

    det = AnomalyDetector(z_threshold=2.5, smoothing=0.1, unknown_penalty=5.0)
    det.train(normal, holdout_fraction=0.2)

    print(f"\n  Threshold : {det.threshold:.4f}")
    print(f"\n  {'Sequence':<45} {'Score':>8}  Flag")
    print(f"  {'─'*45} {'─'*8}  ────")

    cases = [
        (['open','read','close'],                           "normal"),
        (['statx','openat','read','close'],                 "normal"),
        (['statx','statx','statx','openat','read','close'], "normal variant"),
        (['access','socket','bind','listen'],               "ATTACK — unknown"),
        (['open','mmap','execve','connect'],                "ATTACK — shellcode"),
        (['close','read','open'],                           "reversed"),
    ]
    for seq, label in cases:
        is_a, score, expl = det.predict(seq)
        flag = "⚠ ANOM" if is_a else "✓ ok  "
        print(f"  {' '.join(seq):<45} {score:>8.3f}  {flag}  ({label})")


def test_legacy_compat():
    _sep("TEST 3 — Legacy pickle compatibility (simulated)")
    import pickle, io

    # Train a fresh detector
    normal = [
        ['open','read','close'],
        ['openat','read','write','close'],
        ['statx','openat','read','close'],
    ] * 10

    det = AnomalyDetector(z_threshold=2.5)
    det.train(normal, holdout_fraction=0.2)

    # Simulate a legacy pickle: delete scorer and vocab from pcfg
    del det.scorer
    del det.pcfg.vocab
    del det.pcfg.bigram_counts

    # Re-pickle and reload
    buf = io.BytesIO()
    pickle.dump(det, buf)
    buf.seek(0)
    det2 = pickle.load(buf)

    # Should work without AttributeError
    is_a, score, _ = det2.predict(['open', 'read', 'close'])
    print(f"  ✓ Legacy pickle loaded and predicted without error.")
    print(f"    Score for ['open','read','close']: {score:.4f}  anomaly={is_a}")


if __name__ == "__main__":
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║   pcfg_inside — Fixed NGramScorer Verification      ║")
    print("╚══════════════════════════════════════════════════════╝")
    test_no_infinite()
    test_pipeline()
    test_legacy_compat()
    print("\n\nAll tests complete. No ∞ scores on normal sequences.")