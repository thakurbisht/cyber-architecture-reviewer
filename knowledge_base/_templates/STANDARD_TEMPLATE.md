# <Standard Name> Standard

Owner: <team that owns this standard>
Applies to: <which designs are in scope — be specific enough that a reviewer can decide>
Version: <x.y> | Last reviewed: <YYYY-MM-DD>
Domain folder: place this file under knowledge_base/{network|application|security|cloud_data}/

## 1.1 Purpose

<Two or three sentences. What risk does this standard exist to control? A
reviewer reads this to decide whether a clause applies to an edge case.>

## 1.2 Scope

<When does this standard apply, and when does it not? Explicit exclusions
prevent findings being raised against designs the standard was never meant to
cover.>

## 1.3 Severity definitions

CRITICAL: <observable condition specific to this domain>
HIGH: <observable condition>
MEDIUM: <observable condition>
LOW: <observable condition>

<Define these in terms a reviewer can test against a document, not in terms of
abstract risk. "A single failure causes total loss of service for a site" is
testable. "High business impact" is not.>

---

## 2.1 <First requirement — short imperative title>

Requirement: <One MUST/SHOULD statement. One requirement per clause. If you
need the word "and" twice, it is two clauses.>

FINDING TRIGGER: If <observable condition in the design document>, flag as <SEVERITY>.
FINDING TRIGGER: If <second observable condition>, flag as <SEVERITY>, and state <what the finding should say>.

Compliant pattern:
    <A short concrete example, in the format a real design document uses —
    a config snippet, a table row, a topology line, a sentence.>

Non-compliant pattern (flag as <SEVERITY>):
    <The near-miss. This is the highest-value line in the clause: the case
    that looks compliant on a quick read but is not. Annotate WHY.>

Recommendation text to use: "<The remediation sentence you want to appear in
the report. Writing it here makes recommendations consistent between runs and
between reviewers.>"

---

## 2.2 <Second requirement>

Requirement: <...>

FINDING TRIGGER: If <...>, flag as <SEVERITY>.

---

## 3.1 <Next group>

Requirement: <...>

FINDING TRIGGER: If <...>, flag as <SEVERITY>.

---

## Exceptions

<How is an exception to this standard recorded and approved? Findings should
reference this so the architect knows the route to "accepted risk" rather than
"must change". If your organisation has an exception register, name it here.>

## Lessons encoded

<Optional but valuable. Past incidents this standard exists because of. Written
as trigger sentences, an outage becomes a control the organisation cannot
forget.>

FINDING TRIGGER: If <the condition that caused the 20XX incident>, flag as <SEVERITY>, and note that this pattern caused <brief description> in <year>.

---

Control mapping: <NIST SP 800-53 controls, ISO/IEC 27001:2022 Annex A controls,
CIS benchmark items, OWASP ASVS sections, MITRE ATT&CK techniques. These
populate the control mapping column in the report and are what auditors ask
for.>

---
<!--
CHECKLIST BEFORE COMMITTING THIS FILE
[ ] Every clause is numbered (## 2.1 style) so findings can cite it.
[ ] Every clause is under ~250 words.
[ ] Every clause has at least one FINDING TRIGGER.
[ ] At least one clause has a non-compliant pattern that looks compliant.
[ ] Severity words match the definitions in §1.3.
[ ] No clause contradicts a clause in another seeded standard.
[ ] A sample design violating this standard exists in samples/ for regression.
[ ] Re-seeded and chunk count confirmed non-zero:
        python scripts/seed_kb.py --domain <domain>
-->
