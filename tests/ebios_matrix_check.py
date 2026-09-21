#!/usr/bin/env python3
"""
Check that every EBIOS risk matrix in doc/security/ agrees with the risk sheets
it summarises (#213, #214).

Why this exists: the matrices were maintained by hand, next to the sheets they
summarise, and drifted from them in at least thirteen places -- a risk shown one
column to the left, a residual impact that no sheet states, a consolidated table
missing eleven analysed risks and carrying two that had no sheet at all. An
evaluator reads the matrix, not the sheets, so a matrix that disagrees with its
own study is worse than no matrix.

The rule enforced here is simple: a matrix cell is not a claim of its own. Every
placement must be derivable from the (Probabilite, Impact) written in the
corresponding sheet, and every analysed risk must appear exactly once.

Run:  python3 tests/ebios_matrix_check.py
"""

import re
import sys
from pathlib import Path

DOC = Path(__file__).resolve().parent.parent / "doc" / "security"

ENROLLMENT = DOC / "01-enrollment.rst"
SSH = DOC / "02-ssh-connection.rst"
PORTAL = DOC / "09-portail-llng.rst"
CONSOLIDATED = DOC / "99-risk-reduce.rst"
WORKSHOP1 = DOC / "04-atelier1-cadrage-socle.rst"

RISK_ID = r"R-?(?:SA|S|P)?\d+"

# The study is reStructuredText: a heading is a title line underlined with a
# run of one punctuation character, and its level is the position of that
# character in the order the file first uses them (docutils' own rule).
UNDERLINE = set("=-~^\"'`:.+*#_")

# A score row, in either shape pandoc emits: the simple table
# "**Probabilite**  2" and the grid table "| **Probabilite** | 2 (...) |".
PROB_ROW = re.compile(r"^\|?\s*\*\*Probabilit[ée]\*\*\s*\|?\s*([0-9])", re.M)
IMPACT_ROW = re.compile(r"^\|?\s*\*\*Impact\*\*\s*\|?\s*([0-9])", re.M)

SEPARATOR = re.compile(r"^\s*\+[-=+]+\+\s*$")


def headings(lines):
    """[(line index, level, title)] for every reST section in `lines`."""
    order, found = [], []
    for i in range(len(lines) - 1):
        title, under = lines[i].rstrip(), lines[i + 1].rstrip()
        if not title.strip() or title[0].isspace() or not under:
            continue
        if len(set(under)) != 1 or under[0] not in UNDERLINE:
            continue
        if len(under) < len(title):
            continue
        if under[0] not in order:
            order.append(under[0])
        found.append((i, order.index(under[0]) + 1, title.strip()))
    return found


def grid_rows(lines, start=0, stop_after_first=True):
    """Logical rows of the grid tables in `lines`, from `start`.

    A grid cell can span several physical lines, and the separator lines that
    delimit the rows do not start with "|" -- reading the table line by line
    drops every continuation and stops at the first separator, which is how a
    matrix cell listing six risks would come back holding two.
    """
    rows, current, seen = [], None, False

    def flush():
        nonlocal current
        if current:
            rows.append([" ".join(c.split()) for c in current])
            current = None

    for line in lines[start:]:
        if SEPARATOR.match(line):
            flush()
            seen = True
            continue
        if line.lstrip().startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if current is None:
                current = cells
            else:
                for n, cell in enumerate(cells[:len(current)]):
                    current[n] = (current[n] + " " + cell).strip()
            continue
        flush()
        if seen and stop_after_first:
            break                       # the table has ended
    flush()
    return rows


def sheets(path):
    """Return {risk_id: {"initial": (P, I), "residual": (P, I), "level": n, "line": n}}.

    A sheet runs from its own heading to the next heading of the same or a
    higher level: stopping only at the next *risk* heading would make the last
    sheet in a file swallow the matrices that follow it.
    """
    lines = path.read_text(encoding="utf-8").split("\n")
    found = headings(lines)
    level_of = {i: level for i, level, _ in found}

    starts = [(i, level, m.group(1))
              for i, level, title in found if 3 <= level <= 4
              for m in [re.match(rf"^({RISK_ID})\s*[-\u2013\u2014]\s", title)] if m]

    result = {}
    for i, level, rid in starts:
        end = len(lines)
        for j in range(i + 1, len(lines)):
            if level_of.get(j, 0) and level_of[j] <= level:
                end = j
                break
        body = "\n".join(lines[i:end])
        probs = PROB_ROW.findall(body)
        impacts = IMPACT_ROW.findall(body)
        if len(probs) < 2 or len(impacts) < 2:
            continue  # not a scored sheet (or an unscored backlog heading)
        result[rid] = {
            "initial": (int(probs[0]), int(impacts[0])),
            "residual": (int(probs[-1]), int(impacts[-1])),
            "level": level,
            "line": i + 1,
        }
    return result


def matrix(path, heading_path):
    """Parse the risk matrix under the headings named by `heading_path`.

    `heading_path` is read outside-in ("4. Matrice des Risques", then
    "Avant remediation"): the same sub-heading appears under several parents.
    Returns {risk_id: (P, I)} and the line the matrix starts on.
    """
    lines = path.read_text(encoding="utf-8").split("\n")
    found = headings(lines)

    start, depth = 0, 0
    for name in heading_path:
        for i, level, title in found:
            if i >= start and title == name and level > depth:
                start, depth = i + 2, level
                break
        else:
            raise ValueError(name)

    placed = {}
    for cells in grid_rows(lines, start):
        m = re.match(r"^\*\*([0-9])\s*[-\u2013\u2014]", cells[0])
        if not m:
            continue                    # header row, or a row of another shape
        impact = int(m.group(1))
        for col, cell in enumerate(cells[1:], start=1):
            for rid in re.findall(rf"\b{RISK_ID}\b", cell):
                placed[rid] = (col, impact)
    return placed, start


def compare(label, expected, placed, kind, errors):
    """`expected` is {rid: (P, I)}; `placed` is what the matrix says."""
    for rid, want in sorted(expected.items()):
        got = placed.get(rid)
        if got is None:
            errors.append(f"{label}: {rid} is analysed ({kind} P={want[0]}, I={want[1]}) "
                          f"but absent from the matrix")
        elif got != want:
            errors.append(f"{label}: {rid} placed at P={got[0]}, I={got[1]} "
                          f"but its sheet says P={want[0]}, I={want[1]}")
    for rid in sorted(placed):
        if rid not in expected:
            errors.append(f"{label}: {rid} appears in the matrix but has no scored sheet")


def main():
    errors = []

    enrol = sheets(ENROLLMENT)
    ssh = sheets(SSH)
    portal = sheets(PORTAL) if PORTAL.exists() else {}

    if len(enrol) < 14:
        errors.append(f"01-enrollment.md: only {len(enrol)} scored sheets parsed, expected 14")
    if len(ssh) < 23:
        errors.append(f"02-ssh-connection.md: only {len(ssh)} scored sheets parsed, expected 23+")
    # Same floor for the portal study, so a parser that silently stops seeing
    # sheets cannot pass the run by comparing an empty set to an empty matrix.
    #
    # Gated on the file existing, NOT on `portal` being truthy. Keying it on the
    # parse result made the floor vacuous in precisely the case it was written
    # for: a parser that returns nothing leaves `portal` falsy, so the floor
    # never fires AND the slice below drops the portal comparisons -- a third of
    # the study stops being checked and the run still prints OK and exits 0.
    if PORTAL.exists() and len(portal) < 8:
        errors.append(f"09-portail-llng.rst: only {len(portal)} scored sheets parsed, "
                      f"expected 8+ (the file is there, so this is a parser failure, "
                      f"not an absent study)")

    checks = [
        ("01-enrollment avant", ENROLLMENT, ("3. Matrice des Risques", "Avant remédiation"),
         {k: v["initial"] for k, v in enrol.items()}, "initial"),
        ("01-enrollment après", ENROLLMENT, ("3. Matrice des Risques", "Après remédiation"),
         {k: v["residual"] for k, v in enrol.items()}, "residual"),
        ("02-ssh avant", SSH, ("4. Matrice des Risques", "Avant remédiation"),
         {k: v["initial"] for k, v in ssh.items()}, "initial"),
        ("02-ssh après", SSH, ("4. Matrice des Risques", "Après remédiation complète"),
         {k: v["residual"] for k, v in ssh.items()}, "residual"),
        ("09-portail avant", PORTAL, ("Matrice des risques du portail", "Avant remédiation"),
         {k: v["initial"] for k, v in portal.items()}, "initial"),
        ("09-portail après", PORTAL, ("Matrice des risques du portail", "Après remédiation"),
         {k: v["residual"] for k, v in portal.items()}, "residual"),
    ]
    # Drop the portal comparisons only when the study itself is absent. When the
    # file exists the checks stay in, so a parse that came back empty is caught
    # by the floor above and by every R-P missing from the matrices below.
    if not PORTAL.exists():
        checks = checks[:4]

    for label, path, heading, expected, kind in checks:
        try:
            placed, _ = matrix(path, heading)
        except ValueError as exc:
            errors.append(f"{label}: matrix heading not found ({exc})")
            continue
        compare(label, expected, placed, kind, errors)

    # The consolidated matrix must cover EVERY analysed risk from both studies.
    all_residual = {}
    all_residual.update({k: v["residual"] for k, v in enrol.items()})
    all_residual.update({k: v["residual"] for k, v in ssh.items()})
    all_residual.update({k: v["residual"] for k, v in portal.items()})
    try:
        placed, _ = matrix(CONSOLIDATED, ("Matrice des Risques Résiduels (Mode E)",))
    except ValueError:
        placed = None
        errors.append("99-risk-reduce.rst: consolidated matrix heading not found")
    if placed is not None:
        compare("99-risk-reduce consolidée", all_residual, placed, "residual", errors)

    # 99-risk-reduce.md repeats each score in its own section headings
    # ("### R5 _(P=1, I=4)_ - ..."). Those must agree with the sheets too: the
    # file used to state three different values for R-S18 on three lines.
    text = CONSOLIDATED.read_text(encoding="utf-8")
    for m in re.finditer(rf"^#{{2,4}}\s+({RISK_ID})\s+_\(P=([0-9]+)[^)]*?I=([0-9]+)", text, re.M):
        rid, p, i = m.group(1), int(m.group(2)), int(m.group(3))
        want = all_residual.get(rid)
        if want is None:
            errors.append(f"99-risk-reduce heading: {rid} has no scored sheet")
        elif (p, i) != want:
            line = text[:m.start()].count("\n") + 1
            errors.append(f"99-risk-reduce heading (line {line}): {rid} says P={p}, I={i} "
                          f"but its sheet says P={want[0]}, I={want[1]}")

    # Atelier 1 attaches every risk sheet to exactly one feared event. That table
    # is the bridge between the workshops and the sheets: if a sheet is added and
    # not attached, the study silently stops covering it.
    if WORKSHOP1.exists():
        w1 = WORKSHOP1.read_text(encoding="utf-8").split("\n")
        attached = {}
        for cells in grid_rows(w1, stop_after_first=False):
            m = re.match(r"^\*{0,2}(ER[0-9]+)\*{0,2}$", cells[0])
            if not m or len(cells) < 2:
                continue
            er = m.group(1)
            for rid in re.findall(rf"\b{RISK_ID}\b", cells[1]):
                if rid in attached:
                    errors.append(f"04-atelier1: {rid} is attached to both "
                                  f"{attached[rid]} and {er}")
                attached[rid] = er
        if not attached:
            errors.append("04-atelier1: no feared-event/risk-sheet mapping found")
        else:
            for rid in sorted(all_residual):
                if rid not in attached:
                    errors.append(f"04-atelier1: {rid} has a risk sheet but is attached "
                                  f"to no feared event")
            for rid in sorted(attached):
                if rid not in all_residual:
                    errors.append(f"04-atelier1: {rid} is attached to {attached[rid]} "
                                  f"but has no risk sheet")

    # The zone listing in 99-risk-reduce.md must follow from the same scores.
    # It used to list R-S6 and R-SA1 as "jaune" while stating score = P x I,
    # which puts them at 6.
    zones = {"rouge": (9, 99), "orange": (6, 8), "jaune": (4, 5), "verte": (0, 3)}
    computed = {z: set() for z in zones}
    for rid, (p, i) in all_residual.items():
        score = p * i
        for z, (lo, hi) in zones.items():
            if lo <= score <= hi:
                computed[z].add(rid)
    text = CONSOLIDATED.read_text(encoding="utf-8")
    for z in ("rouge", "orange", "jaune"):
        m = re.search(rf"^- \*\*{z.capitalize()}\*\* \(score[^)]*\)\s*:(.*)$", text, re.M)
        if not m:
            errors.append(f"99-risk-reduce: no '{z}' zone listing found")
            continue
        listed = set(re.findall(rf"\b{RISK_ID}\b", m.group(1)))
        if listed != computed[z]:
            missing = sorted(computed[z] - listed)
            extra = sorted(listed - computed[z])
            errors.append(f"99-risk-reduce zone {z}: "
                          f"missing {missing or '-'}, unexpected {extra or '-'}")

    if errors:
        print(f"{len(errors)} matrix/sheet disagreement(s):\n")
        for e in errors:
            print(f"  - {e}")
        return 1

    total = len(all_residual)
    print(f"OK: {total} risk sheets, every matrix cell derivable from its sheet")
    return 0


if __name__ == "__main__":
    sys.exit(main())
