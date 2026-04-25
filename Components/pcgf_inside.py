"""
PCFG → CNF → CYK Inside Algorithm
====================================
Anomaly scoring for the CFG-Based IDS project.

Pipeline (this file):
  1. PCFG     — take SequiturSimple grammar, count rule frequencies across
                 training traces, normalize to probabilities
  2. CNF      — convert the PCFG into Chomsky Normal Form so CYK can run
  3. Inside   — CYK dynamic-programming table gives P(sequence | grammar)
  4. Scoring  — anomaly_score = -log P(sequence | grammar)
  5. Threshold — fit on held-out normal data, flag anything above μ + 3σ

How to run:
  python pcfg_inside.py

Depends on:
  sequitur.py  (SequiturSimple must be importable)
"""

from __future__ import annotations
import math
import re
from collections import defaultdict
from typing import Optional
import sys
import os

# ── import SequiturSimple from sequitur.py ───────────────────────────────────
# Adjust path if sequitur.py lives elsewhere
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from sequitur import SequiturSimple
except ImportError:
    raise ImportError("sequitur.py not found. Place both files in the same directory.")


# ═════════════════════════════════════════════════════════════════════════════
# PART 1 — PCFG
# Learn probabilities for each grammar rule by counting across training traces.
# ═════════════════════════════════════════════════════════════════════════════

class PCFG:
    """
    Probabilistic Context-Free Grammar.

    Attributes
    ----------
    rules : dict[str, list[tuple[list[str], float]]]
        { "S": [( ["R1","R2"], 0.6 ), ( ["R1","open"], 0.4 )], ... }
        Each non-terminal maps to a list of (production_body, probability).

    terminals : set[str]
        All terminal symbols seen during training.

    non_terminals : set[str]
        All non-terminal symbols (rule heads).
    """

    def __init__(self):
        # raw_counts[lhs][(rhs_tuple)] = count
        self._raw_counts: dict[str, dict[tuple, int]] = defaultdict(lambda: defaultdict(int))
        self.rules:        dict[str, list[tuple[list[str], float]]] = {}
        self.terminals:    set[str] = set()
        self.non_terminals: set[str] = set()

    # ── Training ──────────────────────────────────────────────────────────────

    def train(self, traces: list[list[str]]) -> None:
        """
        Given a list of normal syscall traces, run SEQUITUR on each,
        then count how often every grammar rule fires.

        After training, self.rules holds the normalized probabilities.
        """
        print(f"\n[PCFG] Training on {len(traces)} traces...")

        for i, trace in enumerate(traces):
            sq = SequiturSimple()
            grammar = sq.learn(trace)
            self._count_rules(grammar, trace)

        self._normalize()
        self._collect_symbols()

        print(f"[PCFG] Non-terminals : {len(self.non_terminals)}")
        print(f"[PCFG] Terminals     : {len(self.terminals)}")
        total_rules = sum(len(v) for v in self.rules.values())
        print(f"[PCFG] Total rules   : {total_rules}")

    def _count_rules(self, grammar: dict, original_trace: list[str]) -> None:
        """
        Walk the grammar dict from SequiturSimple and increment raw counts.

        grammar format:  { "S": ["R1","open","R2"],  "R1": ["open","read"], ... }
        We treat each body as one production and count it once per trace.
        """
        for lhs, body in grammar.items():
            rhs = tuple(body)
            self._raw_counts[lhs][rhs] += 1

    def _normalize(self) -> None:
        """
        Convert raw counts to probabilities.
        P(A → α) = count(A → α) / Σ_β count(A → β)
        """
        self.rules = {}
        for lhs, rhs_counts in self._raw_counts.items():
            total = sum(rhs_counts.values())
            productions = []
            for rhs, count in rhs_counts.items():
                prob = count / total
                productions.append((list(rhs), prob))
            # Sort by descending probability for readability
            productions.sort(key=lambda x: x[1], reverse=True)
            self.rules[lhs] = productions

    def _collect_symbols(self) -> None:
        self.non_terminals = set(self.rules.keys())
        for lhs, productions in self.rules.items():
            for body, _ in productions:
                for sym in body:
                    if sym not in self.non_terminals:
                        self.terminals.add(sym)

    # ── Output ────────────────────────────────────────────────────────────────

    def print_grammar(self) -> None:
        print("\n" + "═"*55)
        print("  PROBABILISTIC CFG")
        print("═"*55)
        for lhs in sorted(self.rules.keys()):
            for body, prob in self.rules[lhs]:
                body_str = " ".join(body)
                print(f"  {lhs:<6} →  {body_str:<35}  [{prob:.4f}]")
        print("═"*55)


# ═════════════════════════════════════════════════════════════════════════════
# PART 2 — CNF CONVERSION
# CYK requires the grammar to be in Chomsky Normal Form.
# Every production must be EITHER:
#   A → B C       (exactly two non-terminals)
#   A → a         (exactly one terminal)
# ═════════════════════════════════════════════════════════════════════════════

class CNFConverter:
    """
    Converts a PCFG into Chomsky Normal Form (CNF).

    Steps (standard algorithm):
      1. START   — new start symbol S0 → S  (so S never appears on a rhs)
      2. TERM    — wrap every terminal inside a long rhs in its own unit rule
                   e.g.  A → B open C  becomes  A → B T_open C
                                                 T_open → open
      3. BIN     — binarize long rhs (length > 2) by introducing new rules
                   e.g.  A → B C D  becomes  A → B X1,  X1 → C D
      4. DEL     — remove ε-productions  (not needed here; syscall seqs are non-empty)
      5. UNIT    — inline unit productions  A → B  (fold probability in)

    Probabilities are propagated at each step so the CNF grammar still
    assigns the same probability to every terminal string.
    """

    def __init__(self):
        # CNF grammar:  { lhs: [ ([sym, sym], prob), ... ] }
        self.rules:        dict[str, list[tuple[list[str], float]]] = {}
        self.terminals:    set[str] = set()
        self.non_terminals: set[str] = set()
        self._aux_counter  = 0       # for naming auxiliary symbols X1, X2, ...
        self._term_map:    dict[str, str] = {}  # terminal → T_<terminal>

    # ── Public ────────────────────────────────────────────────────────────────

    def convert(self, pcfg: PCFG) -> "CNFConverter":
        """
        Convert pcfg into CNF.  Returns self so you can chain:
            cnf = CNFConverter().convert(pcfg)
        """
        # Deep-copy rules so we don't mutate the original PCFG
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
        print(f"[CNF] Done. {len(self.non_terminals)} non-terminals, "
              f"{len(self.terminals)} terminals, {total} rules.")
        return self

    # ── Step 1: New start symbol ───────────────────────────────────────────────

    def _step1_new_start(self) -> None:
        """Add S0 → S with probability 1.0 so S never appears on any rhs."""
        if "S" in self.rules:
            self.rules["S0"] = [(["S"], 1.0)]

    # ── Step 2: TERM — replace terminals in mixed/long bodies ─────────────────

    def _step2_term(self) -> None:
        """
        For any production  A → α  where |α| ≥ 2 and α contains a terminal t,
        replace t with a fresh non-terminal T_t and add rule  T_t → t  [1.0].
        """
        new_rules: dict[str, list[tuple[list[str], float]]] = {}

        for lhs, productions in self.rules.items():
            new_prods = []
            for body, prob in productions:
                if len(body) >= 2:
                    new_body = []
                    for sym in body:
                        if sym not in self.rules:
                            # It's a terminal — wrap it
                            t_name = self._terminal_nt(sym)
                            new_body.append(t_name)
                        else:
                            new_body.append(sym)
                    new_prods.append((new_body, prob))
                else:
                    new_prods.append((body, prob))
            new_rules[lhs] = new_prods

        # Add all T_t → t rules
        for terminal, t_name in self._term_map.items():
            new_rules[t_name] = [([terminal], 1.0)]

        self.rules = new_rules

    def _terminal_nt(self, terminal: str) -> str:
        """Return (and register) the non-terminal wrapper for a terminal."""
        if terminal not in self._term_map:
            # Sanitize terminal name for use as a non-terminal identifier
            safe = re.sub(r'[^A-Za-z0-9_]', '_', terminal)
            self._term_map[terminal] = f"T_{safe}"
        return self._term_map[terminal]

    # ── Step 3: BIN — binarize long productions ───────────────────────────────

    def _step3_bin(self) -> None:
        """
        Replace any production  A → B C D ...  (length > 2) with:
            A  → B X1       [prob]
            X1 → C D ...    [1.0]
        Recurse until all productions have at most 2 symbols.
        Probabilities: the original prob stays on the first split;
        all auxiliary rules get probability 1.0 (deterministic).
        """
        changed = True
        while changed:
            changed = False
            new_rules: dict[str, list[tuple[list[str], float]]] = {}

            for lhs, productions in self.rules.items():
                new_prods = []
                for body, prob in productions:
                    if len(body) > 2:
                        # Split off the last n-1 symbols into a fresh NT
                        self._aux_counter += 1
                        aux_name = f"X{self._aux_counter}"
                        # A → B aux  with original prob
                        new_prods.append(([body[0], aux_name], prob))
                        # aux → rest  with prob 1.0
                        new_rules[aux_name] = [(body[1:], 1.0)]
                        changed = True
                    else:
                        new_prods.append((body, prob))
                new_rules[lhs] = new_prods

            self.rules = new_rules

    # ── Step 5: UNIT — eliminate unit productions A → B ───────────────────────

    def _step5_unit(self) -> None:
        """
        Inline unit productions (productions of the form A → B where B is a NT).
        A → B [p]  and  B → α [q]  becomes  A → α [p*q].

        Iterate until no unit productions remain.
        We skip  T_x → x  since x is a terminal (that's fine CNF).
        """
        changed = True
        while changed:
            changed = False
            new_rules: dict[str, list[tuple[list[str], float]]] = {}

            for lhs, productions in self.rules.items():
                expanded = []
                for body, prob in productions:
                    if (len(body) == 1 and
                            body[0] in self.rules and
                            body[0] != lhs):   # unit production A → B
                        # Inline: replace with all of B's productions
                        target = body[0]
                        for t_body, t_prob in self.rules[target]:
                            expanded.append((t_body, prob * t_prob))
                        changed = True
                    else:
                        expanded.append((body, prob))
                new_rules[lhs] = expanded

            self.rules = new_rules

    # ── Symbol collection ─────────────────────────────────────────────────────

    def _collect_symbols(self) -> None:
        self.non_terminals = set(self.rules.keys())
        for lhs, productions in self.rules.items():
            for body, _ in productions:
                for sym in body:
                    if sym not in self.non_terminals:
                        self.terminals.add(sym)

    # ── Output ────────────────────────────────────────────────────────────────

    def print_grammar(self) -> None:
        print("\n" + "═"*60)
        print("  CNF GRAMMAR")
        print("═"*60)
        for lhs in sorted(self.rules.keys()):
            for body, prob in self.rules[lhs]:
                body_str = " ".join(body)
                print(f"  {lhs:<10} →  {body_str:<30}  [{prob:.4f}]")
        print("═"*60)

    def verify_cnf(self) -> bool:
        """
        Check every production is valid CNF.
        Returns True if valid, prints violations and returns False otherwise.
        """
        ok = True
        for lhs, productions in self.rules.items():
            for body, _ in productions:
                if len(body) == 1:
                    # Must be a terminal
                    if body[0] in self.non_terminals:
                        print(f"  ✗ UNIT VIOLATION: {lhs} → {body[0]}  (non-terminal)")
                        ok = False
                elif len(body) == 2:
                    # Both must be non-terminals
                    for sym in body:
                        if sym not in self.non_terminals:
                            print(f"  ✗ TERM VIOLATION: {lhs} → {' '.join(body)}  ({sym} is terminal)")
                            ok = False
                else:
                    print(f"  ✗ LENGTH VIOLATION: {lhs} → {' '.join(body)}  (len={len(body)})")
                    ok = False
        return ok


# ═════════════════════════════════════════════════════════════════════════════
# PART 3 — INSIDE (CYK) ALGORITHM
# Compute P(w | grammar) for a sequence w using the CNF grammar.
# ═════════════════════════════════════════════════════════════════════════════

class InsideAlgorithm:
    """
    CYK Inside Algorithm for PCFGs in CNF.

    For a sequence w = w_1 w_2 ... w_n, computes a table:

        inside[i][j][A] = P(A  ⟹*  w_i ... w_j)

    i.e., the probability that non-terminal A can generate the substring
    from position i to position j (inclusive, 0-indexed).

    The probability of the full sequence is:
        P(w | G) = inside[0][n-1]["S0"]   (or "S" if no S0)

    Anomaly score:
        score(w) = -log( P(w | G) + ε )

    High score = low probability = anomalous.
    """

    def __init__(self, cnf: CNFConverter):
        self.cnf    = cnf
        self.start  = "S0" if "S0" in cnf.rules else "S"

        # Pre-index rules for fast lookup during CYK
        # terminal_rules[terminal] = [(lhs, prob), ...]
        # binary_rules[(B, C)]     = [(lhs, prob), ...]
        self._terminal_rules: dict[str, list[tuple[str, float]]] = defaultdict(list)
        self._binary_rules:   dict[tuple, list[tuple[str, float]]] = defaultdict(list)
        self._index_rules()

    def _index_rules(self) -> None:
        """Pre-build lookup tables for O(1) access during CYK."""
        for lhs, productions in self.cnf.rules.items():
            for body, prob in productions:
                if len(body) == 1:
                    self._terminal_rules[body[0]].append((lhs, prob))
                elif len(body) == 2:
                    self._binary_rules[(body[0], body[1])].append((lhs, prob))

    # ── Core CYK ──────────────────────────────────────────────────────────────

    def inside(self, sequence: list[str]) -> dict:
        """
        Run the Inside algorithm on `sequence`.

        Returns the full inside table as a dict:
            { (i, j, lhs): probability }

        Also returns the sequence probability directly as:
            table[(0, n-1, self.start)]
        """
        n = len(sequence)
        # table[(i, j, A)] = inside probability
        table: dict[tuple, float] = defaultdict(float)

        # ── Base case: single terminals  (i == j) ────────────────────────────
        for i, word in enumerate(sequence):
            # Direct terminal rules: A → word
            for lhs, prob in self._terminal_rules.get(word, []):
                table[(i, i, lhs)] = table.get((i, i, lhs), 0.0) + prob

        # ── Recursive case: span length 2 to n ───────────────────────────────
        for span in range(2, n + 1):          # span length
            for i in range(n - span + 1):      # start of span
                j = i + span - 1               # end of span

                for k in range(i, j):          # split point
                    # For every binary rule A → B C
                    for (B, C), lhs_list in self._binary_rules.items():
                        left  = table.get((i, k, B), 0.0)
                        right = table.get((k+1, j, C), 0.0)
                        if left > 0.0 and right > 0.0:
                            for lhs, prob in lhs_list:
                                key = (i, j, lhs)
                                table[key] = table.get(key, 0.0) + prob * left * right

        return table

    def sequence_probability(self, sequence: list[str]) -> float:
        """Return P(sequence | grammar). Returns 0.0 if unparseable."""
        table = self.inside(sequence)
        return table.get((0, len(sequence)-1, self.start), 0.0)

    def anomaly_score(self, sequence: list[str]) -> float:
        """
        Anomaly score = -log P(sequence | grammar).

        Range:
          0.0 → perfectly normal (probability 1.0, impossible in practice)
          10–30 → mildly unusual
          > 50 → highly anomalous / unparseable
          inf → completely unknown sequence (probability 0)

        We cap at 1000.0 to avoid inf in charts.
        """
        p = self.sequence_probability(sequence)
        if p <= 0.0:
            return 1000.0   # unparseable = maximally anomalous
        return -math.log(p)

    def explain(self, sequence: list[str]) -> str:
        """
        Return a plain-English explanation of WHY a sequence is anomalous.
        Checks for:
          - Unknown terminals (never seen in training)
          - Partial parse failure (which span breaks down)
        """
        table = self.inside(sequence)
        n = len(sequence)

        # Check for unknown terminals
        unknown = [w for w in sequence if w not in self.cnf.terminals
                   and self._terminal_rules.get(w) is None]
        if unknown:
            return (f"Unknown syscalls detected: {unknown}. "
                    f"These never appeared during training — strong anomaly signal.")

        # Find the largest span that CAN be parsed
        parseable_spans = []
        for i in range(n):
            for j in range(i, n):
                nt_set = {k[2] for k in table if k[0] == i and k[1] == j}
                if nt_set:
                    parseable_spans.append((j - i + 1, i, j, nt_set))

        if not parseable_spans:
            return "No span of the sequence matches any grammar rule. Complete parse failure."

        parseable_spans.sort(reverse=True)
        best_len, bi, bj, bnts = parseable_spans[0]
        if best_len < n:
            gap_start = bj + 1
            gap_sym   = sequence[gap_start] if gap_start < n else "?"
            return (f"Parse succeeded for positions {bi}–{bj} "
                    f"({' '.join(sequence[bi:bj+1])}), "
                    f"but failed starting at position {gap_start} "
                    f"('{gap_sym}'). "
                    f"Possible illegal transition after '{sequence[bj]}'.")

        return "Sequence is parseable but has very low probability under the grammar."


# ═════════════════════════════════════════════════════════════════════════════
# PART 4 — ANOMALY DETECTOR (puts it all together)
# ═════════════════════════════════════════════════════════════════════════════

class AnomalyDetector:
    """
    Full pipeline:
        train(normal_traces)
            → SEQUITUR per trace
            → PCFG (count + normalize)
            → CNF conversion
            → InsideAlgorithm
            → threshold calibration on held-out normal scores

        predict(sequence)  →  (is_anomaly: bool, score: float, explanation: str)
    """

    def __init__(self, z_threshold: float = 3.0):
        """
        z_threshold : how many standard deviations above the mean
                      a score must be to count as anomalous.
                      3.0 ≈ top 0.13% of normal scores flagged.
        """
        self.z_threshold = z_threshold
        self.pcfg:    Optional[PCFG]           = None
        self.cnf:     Optional[CNFConverter]   = None
        self.inside:  Optional[InsideAlgorithm] = None
        self._threshold_mean: float = 0.0
        self._threshold_std:  float = 1.0
        self.threshold: float = 0.0

    # ── Training ──────────────────────────────────────────────────────────────

    def train(self, normal_traces: list[list[str]],
              holdout_fraction: float = 0.2) -> None:
        """
        Train on normal_traces.

        1. Split into train (80%) and holdout (20%).
        2. Build PCFG on train split.
        3. Convert to CNF.
        4. Score holdout to calibrate threshold.
        """
        split = int(len(normal_traces) * (1 - holdout_fraction))
        train_traces   = normal_traces[:split]
        holdout_traces = normal_traces[split:]

        print(f"\n[Detector] Training traces : {len(train_traces)}")
        print(f"[Detector] Holdout  traces : {len(holdout_traces)}")

        # Step 1: PCFG
        self.pcfg = PCFG()
        self.pcfg.train(train_traces)

        # Step 2: CNF
        self.cnf = CNFConverter().convert(self.pcfg)

        # Step 3: Inside algorithm
        self.inside = InsideAlgorithm(self.cnf)

        # Step 4: Calibrate threshold on holdout
        self._calibrate(holdout_traces)

    def _calibrate(self, holdout_traces: list[list[str]]) -> None:
        """Score all holdout traces, set threshold = mean + z*std."""
        if not holdout_traces:
            self.threshold = 50.0  # sensible default
            return

        scores = [self.inside.anomaly_score(t) for t in holdout_traces
                  if len(t) > 0]
        # Filter out the 1000.0 cap values from calibration
        finite = [s for s in scores if s < 999.0]
        if not finite:
            self.threshold = 50.0
            return

        self._threshold_mean = sum(finite) / len(finite)
        variance = sum((s - self._threshold_mean)**2 for s in finite) / len(finite)
        self._threshold_std  = math.sqrt(variance) if variance > 0 else 1.0
        self.threshold = self._threshold_mean + self.z_threshold * self._threshold_std

        print(f"\n[Detector] Score stats on holdout:")
        print(f"           mean  = {self._threshold_mean:.4f}")
        print(f"           std   = {self._threshold_std:.4f}")
        print(f"           threshold (μ + {self.z_threshold}σ) = {self.threshold:.4f}")

    # ── Prediction ────────────────────────────────────────────────────────────

    def predict(self, sequence: list[str]) -> tuple[bool, float, str]:
        """
        Returns (is_anomaly, score, explanation).
        """
        if self.inside is None:
            raise RuntimeError("Call train() before predict().")

        score       = self.inside.anomaly_score(sequence)
        is_anomaly  = score > self.threshold
        explanation = ""

        if is_anomaly:
            explanation = self.inside.explain(sequence)

        return is_anomaly, score, explanation

    def score_batch(self, sequences: list[list[str]]) -> list[float]:
        return [self.inside.anomaly_score(s) for s in sequences]

def _separator(title: str) -> None:
    print("\n" + "━"*55)
    print(f"  {title}")
    print("━"*55)


def test_pcfg_basic():
    _separator("TEST 1 — PCFG: rule probability extraction")

    traces = [
        ['open','read','close'],
        ['open','read','read','close'],
        ['open','write','close'],
        ['open','read','write','close'],
        ['open','read','close'],
    ]

    pcfg = PCFG()
    pcfg.train(traces)
    pcfg.print_grammar()

    # Sanity: probabilities for each lhs should sum to 1.0
    for lhs, prods in pcfg.rules.items():
        total = sum(p for _, p in prods)
        ok = abs(total - 1.0) < 1e-6
        print(f"  P-sum for {lhs}: {total:.6f}  {'✓' if ok else '✗ BAD'}")


def test_cnf_conversion():
    _separator("TEST 2 — CNF conversion + validity check")

    traces = [
        ['open','read','close'],
        ['open','read','read','close'],
        ['open','write','close'],
        ['open','read','write','close'],
        ['open','read','close'],
    ]

    pcfg = PCFG()
    pcfg.train(traces)

    cnf = CNFConverter().convert(pcfg)
    cnf.print_grammar()

    print("\n  Verifying CNF constraints:")
    valid = cnf.verify_cnf()
    print(f"  CNF valid: {'✓ YES' if valid else '✗ NO'}")


def test_inside_toy():
    _separator("TEST 3 — Inside algorithm on toy grammar")

    cnf = CNFConverter()
    cnf.rules = {
        "S":  [(["A", "B"], 1.0)],
        "A":  [(["open"],   1.0)],
        "B":  [(["close"],  1.0)],
    }
    cnf.terminals     = {"open", "close"}
    cnf.non_terminals = {"S", "A", "B"}

    engine = InsideAlgorithm(cnf)

    p1 = engine.sequence_probability(["open", "close"])
    p2 = engine.sequence_probability(["open", "open"])
    p3 = engine.sequence_probability(["close"])

    print(f"  P(open close)  = {p1:.6f}  (expected 1.0)")
    print(f"  P(open open)   = {p2:.6f}  (expected 0.0)")
    print(f"  P(close)       = {p3:.6f}  (expected 0.0)")

    s1 = engine.anomaly_score(["open", "close"])
    s2 = engine.anomaly_score(["open", "open"])
    print(f"\n  score(open close) = {s1:.4f}  (expected ~0)")
    print(f"  score(open open)  = {s2:.4f}  (expected 1000 = cap)")


def test_full_pipeline():
    _separator("TEST 4 — Full pipeline: train → threshold → predict")

    # Simulate a small ADFA-like dataset
    # Normal: file operations (open, read, write, close)
    normal_traces = [
        ['open','read','close'],
        ['open','read','read','close'],
        ['open','write','close'],
        ['open','read','write','close'],
        ['open','read','close'],
        ['open','write','write','close'],
        ['open','read','write','close'],
        ['open','read','read','write','close'],
        ['open','read','close'],
        ['open','write','close'],
    ] * 3   # 30 traces total for stable statistics

    detector = AnomalyDetector(z_threshold=2.0)
    detector.train(normal_traces, holdout_fraction=0.3)

    # Test sequences
    test_cases = [
        (['open','read','close'],                    "normal — file read"),
        (['open','write','close'],                   "normal — file write"),
        (['open','read','write','close'],            "normal — read then write"),
        (['open','mmap','execve','connect','send'],  "ATTACK — shellcode pattern"),
        (['connect','send','recv'],                  "ATTACK — network without open"),
        (['open','read','read','read',
          'read','read','read','read',
          'read','close'],                           "suspicious — very long read loop"),
        (['close','read','open'],                    "suspicious — reversed order"),
    ]

    print(f"\n  {'Sequence':<45} {'Score':>8}  {'Flag':<8}  Explanation")
    print(f"  {'─'*45} {'─'*8}  {'─'*8}  {'─'*30}")

    for seq, label in test_cases:
        is_anom, score, expl = detector.predict(seq)
        flag   = "⚠️ ANOM" if is_anom else "✓ OK"
        score_str = f"{score:.2f}" if score < 999 else "∞"
        seq_str   = ' '.join(seq)[:42] + ("..." if len(' '.join(seq)) > 42 else "")
        print(f"  {seq_str:<45} {score_str:>8}  {flag:<8}")
        if is_anom and expl:
            print(f"  {'':>45}   └─ {expl[:80]}")

    print(f"\n  Decision threshold: {detector.threshold:.4f}")


def test_expressiveness():
    _separator("TEST 5 — Context-free expressiveness vs regular")

    print("""
  The language L = {{ open^n close^n | n ≥ 1 }} is provably NOT regular
  (Pumping Lemma for Regular Languages).
  
  DeepLog (LSTM ≈ regular) will fail on deep nesting.
  Our PCFG captures the hierarchical structure natively.

  Generating open^n close^n for n = 1..5 and scoring:
""")

    normal_traces = []
    for _ in range(20):
        for n in range(1, 4):
            normal_traces.append(['open']*n + ['close']*n)

    detector = AnomalyDetector(z_threshold=2.0)
    detector.train(normal_traces)

    print(f"  {'Sequence':<35} {'Score':>8}  Flag")
    print(f"  {'─'*35} {'─'*8}  {'─'*8}")

    test_cases = [
        (['open','close'],                        "n=1 (trained)"),
        (['open','open','close','close'],          "n=2 (trained)"),
        (['open','open','open','close','close',
          'close'],                               "n=3 (trained)"),
        (['open','open','open','open','close',
          'close','close','close'],               "n=4 (unseen depth)"),
        (['open','close','open','close'],          "flat (different structure)"),
        (['open','open','close'],                  "MISMATCH: 2 opens 1 close"),
        (['close','open'],                         "REVERSED: close before open"),
    ]

    for seq, label in test_cases:
        is_anom, score, expl = detector.predict(seq)
        flag = "⚠️ ANOM" if is_anom else "✓ OK"
        score_str = f"{score:.2f}" if score < 999 else "∞"
        seq_str = ' '.join(seq)
        print(f"  {seq_str:<35} {score_str:>8}  {flag}  ({label})")


# ═════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print()
    print("╔══════════════════════════════════════════════════╗")
    print("║  PCFG → CNF → CYK Inside — Verification Suite  ║")
    print("╚══════════════════════════════════════════════════╝")

    test_pcfg_basic()
    test_cnf_conversion()
    test_inside_toy()
    test_full_pipeline()
    test_expressiveness()

    print("\n\nAll tests complete.")
    print("Next step: backend.py — Flask/WebSocket API wrapping AnomalyDetector.")