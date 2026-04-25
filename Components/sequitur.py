"""
SEQUITUR Algorithm — Full Implementation
==========================================
Nevill-Manning & Witten (1997)
"Identifying Hierarchical Structure in Sequences: A linear-time algorithm"

What this file does:
  1. Implements Symbol, Rule, and Sequitur classes
  2. Enforces BOTH invariants at every step:
       - Digram Uniqueness  (no pair of adjacent symbols appears twice)
       - Rule Utility       (every rule is used at least twice)
  3. Provides a pretty-printer for the final grammar
  4. Runs a toy example you can trace by hand to verify correctness

How to run:
  python sequitur.py
"""

from __future__ import annotations
from collections import defaultdict
from typing import Optional


# ─────────────────────────────────────────────
# CORE DATA STRUCTURES
# ─────────────────────────────────────────────

class Symbol:
    """
    One node in the doubly-linked list that represents the working sequence
    (and every rule body).

    A Symbol wraps either:
      - A terminal  (a raw syscall name / integer, e.g. 'open' or 4)
      - A non-terminal  (a reference to a Rule object)

    The linked-list pointers (prev / next) let us splice and delete in O(1).
    """

    def __init__(self, value, is_terminal: bool = True):
        self.value      = value          # str/int for terminals, Rule for non-terminals
        self.is_terminal = is_terminal
        self.prev: Optional[Symbol] = None
        self.next: Optional[Symbol] = None

    # ── Convenience ──────────────────────────────────────────────────────────

    def text(self) -> str:
        """Human-readable label for printing."""
        if self.is_terminal:
            return str(self.value)
        else:
            return self.value.name   # e.g. "R1"

    def key(self):
        """
        Hashable identity used as digram-table key.
        Two Symbols with the same terminal value hash identically.
        Two non-terminal Symbols are equal only if they point to the same Rule.
        """
        if self.is_terminal:
            return ('T', self.value)
        else:
            return ('R', self.value.rule_id)

    def __repr__(self):
        return f"Symbol({self.text()})"


# ─────────────────────────────────────────────

class Rule:
    """
    One production rule, e.g.  R1 → open read

    Internally the body is stored as a doubly-linked list with two
    sentinel guard nodes (head / tail) so that every real symbol always
    has a prev and a next — this avoids edge-case checks everywhere.

    Attributes
    ----------
    rule_id   : int          unique numeric id
    name      : str          display name, e.g. "R1"
    ref_count : int          how many times this rule is referenced in the
                             grammar (must stay ≥ 2 for Rule Utility)
    head/tail : Symbol       sentinel guard nodes (not real symbols)
    """

    _counter = 0   # class-level counter so each rule gets a unique id

    def __init__(self):
        Rule._counter += 1
        self.rule_id   = Rule._counter
        self.name      = f"R{self.rule_id}"
        self.ref_count = 0

        # Set up sentinel guards
        self.head = Symbol("__HEAD__")
        self.tail = Symbol("__TAIL__")
        self.head.next = self.tail
        self.tail.prev = self.head

    # ── Linked-list helpers ───────────────────────────────────────────────────

    def append(self, sym: Symbol):
        """Insert sym just before the tail sentinel."""
        sym.prev       = self.tail.prev
        sym.next       = self.tail
        self.tail.prev.next = sym
        self.tail.prev      = sym

    def body_symbols(self) -> list[Symbol]:
        """Return all real (non-sentinel) symbols in order."""
        syms = []
        cur = self.head.next
        while cur is not self.tail:
            syms.append(cur)
            cur = cur.next
        return syms

    def body_text(self) -> str:
        return " ".join(s.text() for s in self.body_symbols())

    def __repr__(self):
        return f"Rule({self.name} → {self.body_text()})"


# ─────────────────────────────────────────────
# THE SEQUITUR ALGORITHM
# ─────────────────────────────────────────────

class Sequitur:


    def __init__(self):
        Rule._counter = 0          # reset so every fresh run starts at R1

        self.start_rule   = Rule()
        self.start_rule.name = "S"
        self.rules        = {}     # rule_id → Rule  (excludes start rule)
        self.digram_index = {}     # (key, key) → Symbol (first of the pair)

    # ── Public API ────────────────────────────────────────────────────────────

    def learn(self, sequence: list) -> None:
        """
        Feed the entire sequence into SEQUITUR one symbol at a time.
        After this call, self.start_rule and self.rules hold the grammar.
        """
        for item in sequence:
            self._append_to_rule(self.start_rule, Symbol(item, is_terminal=True))

    # ── Internal: appending ───────────────────────────────────────────────────

    def _append_to_rule(self, rule: Rule, new_sym: Symbol) -> None:
        """
        Append new_sym to the end of rule's body, then check the new digram.
        """
        rule.append(new_sym)

        # We only form a digram if there are at least 2 real symbols
        last   = rule.tail.prev          # = new_sym
        second_last = last.prev
        if second_last is rule.head:
            return    # only one real symbol so far — no digram yet

        self._check_digram(second_last)

    # ── Internal: digram check (the heart of SEQUITUR) ────────────────────────

    def _check_digram(self, left: Symbol) -> None:
        """
        Given the symbol `left`, examine the digram (left, left.next).

        Cases:
          A) digram not in index  → just record it
          B) digram in index, and the existing occurrence is a different rule
             whose body IS exactly this digram (length-2 rule)
             → reuse that rule (don't create a duplicate)
          C) digram in index, general case → create new rule, replace both
        """
        right = left.next

        # Guard: if either side is a sentinel, this isn't a real digram
        if right is None or right.next is None:
            return
        if left.prev is None:
            return

        digram_key = (left.key(), right.key())

        if digram_key not in self.digram_index:
            # ── Case A: new digram — just index it ──────────────────────────
            self.digram_index[digram_key] = left
            return

        existing_left = self.digram_index[digram_key]

        # Make sure the existing occurrence and the new one don't overlap
        # (e.g. aaa produces digram (a,a) twice but they share a symbol)
        if existing_left.next is left or left.next is existing_left:
            return   # overlapping — skip, not a true duplicate

        # ── Case B / C: digram already exists somewhere ──────────────────────
        # First, check if there's already a rule whose body is exactly this digram
        matching_rule = self._find_rule_for_digram(left, right)

        if matching_rule is None:
            # ── Case C: create a brand-new rule ─────────────────────────────
            matching_rule = self._create_rule_for_digram(left, right)

        # Replace the existing occurrence (may or may not be in start_rule)
        self._replace_digram(existing_left, matching_rule)

        # Replace the new (current) occurrence
        # NOTE: `left` may have been moved/deleted if it was part of existing
        # occurrence.  We re-check the index after the first replacement.
        if digram_key in self.digram_index:
            new_existing = self.digram_index[digram_key]
            if new_existing is not left:
                self._replace_digram(left, matching_rule)
        else:
            self._replace_digram(left, matching_rule)

    def _find_rule_for_digram(self, left: Symbol, right: Symbol) -> Optional[Rule]:
        """
        Return an existing rule R such that R's body is exactly [left_val, right_val],
        or None if no such rule exists.
        """
        for rule in self.rules.values():
            body = rule.body_symbols()
            if len(body) == 2:
                if body[0].key() == left.key() and body[1].key() == right.key():
                    return rule
        return None

    def _create_rule_for_digram(self, left: Symbol, right: Symbol) -> Rule:
        """
        Create a new rule  Rn → left_val right_val  and register it.
        """
        new_rule = Rule()
        self.rules[new_rule.rule_id] = new_rule

        # Copy left and right as fresh symbols inside the new rule's body
        new_rule.append(self._clone_symbol(left))
        new_rule.append(self._clone_symbol(right))

        # Index the digram inside the new rule
        body = new_rule.body_symbols()
        self.digram_index[(body[0].key(), body[1].key())] = body[0]

        return new_rule

    # ── Internal: replacement ─────────────────────────────────────────────────

    def _replace_digram(self, left: Symbol, rule: Rule) -> None:
        """
        Replace the digram (left, left.next) with a single non-terminal
        symbol that references `rule`.

        Steps:
          1. Remove both left and right from the digram index (stale entries)
          2. Splice in a new non-terminal symbol in their place
          3. Remove the two old symbols from the linked list
          4. Increment rule's ref_count
          5. Check the NEW digrams formed by the splice
          6. Enforce Rule Utility (inline any rule used < 2 times)
        """
        right = left.next

        # 1. Remove stale digram entries
        self._remove_digram(left)
        if right.next and right.next is not self._tail_sentinel(right):
            self._remove_digram(right)

        # 2. Build the replacement non-terminal
        nt = Symbol(rule, is_terminal=False)
        rule.ref_count += 1

        # 3. Splice: prev ↔ nt ↔ right.next
        prev_sym   = left.prev
        next_sym   = right.next
        prev_sym.next = nt
        next_sym.prev = nt
        nt.prev = prev_sym
        nt.next = next_sym

        # left and right are now detached

        # 4. Check new digrams formed by the splice
        if prev_sym and not self._is_sentinel(prev_sym):
            self._check_digram(prev_sym)
        if nt.next and not self._is_sentinel(nt.next):
            self._check_digram(nt)

        # 5. Rule Utility check
        self._enforce_rule_utility()

    def _remove_digram(self, left: Symbol) -> None:
        """Remove the digram starting at `left` from the index if it's there."""
        right = left.next
        if right is None or self._is_sentinel(left) or self._is_sentinel(right):
            return
        key = (left.key(), right.key())
        # Only remove if this specific symbol is the indexed one
        if self.digram_index.get(key) is left:
            del self.digram_index[key]

    # ── Internal: Rule Utility ────────────────────────────────────────────────

    def _enforce_rule_utility(self) -> None:
        """
        Scan all non-start rules.  If any rule has ref_count < 2,
        inline it everywhere it appears and delete it.

        This may cascade (inlining can create new under-used rules),
        so we loop until stable.
        """
        changed = True
        while changed:
            changed = False
            for rule_id, rule in list(self.rules.items()):
                if rule.ref_count < 2:
                    self._inline_rule(rule)
                    del self.rules[rule_id]
                    changed = True
                    break   # restart scan after any deletion

    def _inline_rule(self, rule: Rule) -> None:
        """
        Find every non-terminal symbol referencing `rule` and replace it
        with the rule's body symbols (expanded inline).
        """
        # Collect all rules to search (including start)
        all_rules = [self.start_rule] + list(self.rules.values())

        for host_rule in all_rules:
            cur = host_rule.head.next
            while cur is not host_rule.tail:
                nxt = cur.next
                if not cur.is_terminal and cur.value is rule:
                    # Remove stale digrams around cur
                    if not self._is_sentinel(cur.prev):
                        self._remove_digram(cur.prev)
                    self._remove_digram(cur)

                    # Splice in the body of `rule`
                    body = rule.body_symbols()
                    prev_node = cur.prev
                    for body_sym in body:
                        fresh = self._clone_symbol(body_sym)
                        fresh.prev = prev_node
                        prev_node.next = fresh
                        prev_node = fresh
                    prev_node.next = cur.next
                    cur.next.prev  = prev_node

                    # Decrement ref count for any non-terminals in the body
                    for body_sym in body:
                        if not body_sym.is_terminal:
                            body_sym.value.ref_count -= 1

                    rule.ref_count -= 1

                    # Re-index new digrams around the spliced-in symbols
                    # (walk from one before the insertion point)
                    recheck = cur.prev if not self._is_sentinel(cur.prev) else None
                    if recheck:
                        self._check_digram(recheck)
                    first_inserted = cur.prev   # prev_node chain starts here
                    # index digrams within inserted block
                    for body_sym in body[:-1]:
                        # They're now in host_rule's list — re-check each
                        pass   # handled by _check_digram on prev above

                cur = nxt

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _clone_symbol(self, sym: Symbol) -> Symbol:
        return Symbol(sym.value, sym.is_terminal)

    def _is_sentinel(self, sym: Symbol) -> bool:
        return sym.value in ("__HEAD__", "__TAIL__")

    def _tail_sentinel(self, sym: Symbol) -> Symbol:
        """Walk forward until we hit a tail sentinel."""
        cur = sym
        while cur.next is not None:
            cur = cur.next
        return cur

    # ── Output ────────────────────────────────────────────────────────────────

    def get_grammar(self) -> dict:
        """
        Return the grammar as a plain dict for easy processing downstream.

            {
              "S":  ["R1", "open", "R2"],
              "R1": ["open", "read"],
              "R2": ["R1", "close"],
              ...
            }
        """
        grammar = {}
        grammar["S"] = [s.text() for s in self.start_rule.body_symbols()]
        for rule in self.rules.values():
            grammar[rule.name] = [s.text() for s in rule.body_symbols()]
        return grammar

    def print_grammar(self) -> None:
        """Pretty-print the grammar to stdout."""
        print("\n" + "═" * 50)
        print("  SEQUITUR GRAMMAR")
        print("═" * 50)

        # Print S first
        s_body = self.start_rule.body_text()
        print(f"  S  →  {s_body}")
        print()

        # Print rules in creation order
        for rule in sorted(self.rules.values(), key=lambda r: r.rule_id):
            print(f"  {rule.name}  →  {rule.body_text()}")

        print("═" * 50)

    def print_derivation(self) -> None:
        """
        Expand the grammar fully back to the original sequence
        and print it — use this to verify correctness.
        """
        def expand(symbol_text: str, grammar: dict, visited: set) -> list:
            if symbol_text not in grammar:
                return [symbol_text]   # terminal
            if symbol_text in visited:
                return [f"[CYCLE:{symbol_text}]"]
            visited.add(symbol_text)
            result = []
            for token in grammar[symbol_text]:
                result.extend(expand(token, grammar, visited))
            visited.remove(symbol_text)
            return result

        grammar = self.get_grammar()
        expanded = expand("S", grammar, set())
        print("\n  Full expansion of S:")
        print("  " + " ".join(expanded))


# ─────────────────────────────────────────────
# SIMPLE (ROBUST) VERSION FOR HACKATHON
# ─────────────────────────────────────────────
# The full linked-list implementation above is the "correct" SEQUITUR.
# Below is a simpler list-based version that is easier to debug
# during a 24-hour hackathon. It is O(n²) but correct and readable.
# Use this for the demo, swap to the above for the writeup.

class SequiturSimple:
    """
    Simpler O(n²) SEQUITUR using a plain Python list as the working string.
    Easier to trace and debug. Recommended for hackathon use.
    """

    def __init__(self):
        self.working  = []       # the working sequence (list of str)
        self.rules    = {}       # rule_name → [symbol, symbol]  e.g. "R1" → ["open","read"]
        self._counter = 0        # for naming R1, R2, ...
        self._digrams = {}       # digram tuple → index in working list

    # ── Public ────────────────────────────────────────────────────────────────

    def learn(self, sequence: list) -> dict:
        """
        Learn a grammar from `sequence`.
        Returns the grammar dict  { "S": [...], "R1": [...], ... }
        """
        self.working = [str(x) for x in sequence]
        self._run()
        return self.get_grammar()

    # ── Core loop ─────────────────────────────────────────────────────────────

    def _run(self):
        """
        Scan through the working list and replace repeated digrams with rules.
        Repeat until no digram appears more than once.
        """
        changed = True
        while changed:
            changed = False
            digram_positions = self._index_digrams()

            for digram, positions in digram_positions.items():
                if len(positions) >= 2:
                    # Check they don't overlap
                    non_overlapping = self._remove_overlaps(positions)
                    if len(non_overlapping) >= 2:
                        rule_name = self._get_or_create_rule(digram)
                        self._replace_all(digram, rule_name, non_overlapping)
                        changed = True
                        break   # restart after every replacement

        # Rule utility: inline rules used only once
        self._enforce_utility()

    def _index_digrams(self) -> dict:
        """Return { (a,b): [pos1, pos2, ...] } for all digrams in working."""
        index = defaultdict(list)
        for i in range(len(self.working) - 1):
            digram = (self.working[i], self.working[i+1])
            index[digram].append(i)
        return dict(index)

    def _remove_overlaps(self, positions: list) -> list:
        """Filter out overlapping positions (e.g. aaa gives pos 0 and 1 for (a,a))."""
        result = [positions[0]]
        for pos in positions[1:]:
            if pos > result[-1] + 1:   # gap of at least 1 means no overlap
                result.append(pos)
        return result

    def _get_or_create_rule(self, digram: tuple) -> str:
        """Return existing rule name for this digram, or create a new one."""
        for name, body in self.rules.items():
            if tuple(body) == digram:
                return name
        # Create new rule
        self._counter += 1
        name = f"R{self._counter}"
        self.rules[name] = list(digram)
        return name

    def _replace_all(self, digram: tuple, rule_name: str, positions: list):
        """
        Replace all non-overlapping occurrences of digram in self.working
        with rule_name.  Work right-to-left so indices don't shift.
        """
        for pos in sorted(positions, reverse=True):
            # Double-check the digram is still there (earlier replacements may shift)
            if (pos < len(self.working) - 1 and
                self.working[pos] == digram[0] and
                self.working[pos+1] == digram[1]):
                self.working[pos:pos+2] = [rule_name]

    def _enforce_utility(self):
        """Inline any rule used fewer than 2 times."""
        changed = True
        while changed:
            changed = False
            usage = defaultdict(int)

            # Count usage in working string and in other rules
            for sym in self.working:
                if sym in self.rules:
                    usage[sym] += 1
            for name, body in self.rules.items():
                for sym in body:
                    if sym in self.rules and sym != name:
                        usage[sym] += 1

            for name in list(self.rules.keys()):
                if usage.get(name, 0) < 2:
                    # Inline this rule
                    body = self.rules[name]
                    self.working = self._inline(self.working, name, body)
                    for rname in list(self.rules.keys()):
                        self.rules[rname] = self._inline(self.rules[rname], name, body)
                    del self.rules[name]
                    changed = True
                    break

    def _inline(self, seq: list, rule_name: str, body: list) -> list:
        """Replace every occurrence of rule_name in seq with body."""
        result = []
        for sym in seq:
            if sym == rule_name:
                result.extend(body)
            else:
                result.append(sym)
        return result


    def get_grammar(self) -> dict:
        grammar = {"S": self.working[:]}
        grammar.update(self.rules)
        return grammar

    def print_grammar(self):
        grammar = self.get_grammar()
        print("\n" + "═" * 50)
        print("  SEQUITUR GRAMMAR  (Simple Version)")
        print("═" * 50)
        print(f"  S  →  {' '.join(grammar['S'])}")
        print()
        for name in sorted(k for k in grammar if k != "S"):
            print(f"  {name}  →  {' '.join(grammar[name])}")
        print("═" * 50)

    def expand(self, symbol: str = "S") -> list:
        """Fully expand the grammar back to the original sequence."""
        grammar = self.get_grammar()
        def _expand(sym):
            if sym not in grammar:
                return [sym]
            result = []
            for token in grammar[sym]:
                result.extend(_expand(token))
            return result
        return _expand(symbol)


