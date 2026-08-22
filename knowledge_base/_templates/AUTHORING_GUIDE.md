# How to Write a Knowledge Base Standard That Actually Produces Findings

This is the single highest-leverage document in the repository. The model is a
commodity — you can swap it for a bigger one and the reviews improve slightly.
The knowledge base is the moat. Improve it and the reviews improve
dramatically.

Everything below exists because of one observation: **the specificity of your
knowledge base directly determines the specificity of your findings.**

---

## 1. The finding trigger sentence

This is the most important structural element in any knowledge base document.

A trigger sentence tells the reviewer, in the imperative, exactly what pattern
to match and exactly what to do about it.

**Useless (produces nothing):**
> Ensure redundant uplinks are provided.

**Useful (produces a citable CRITICAL finding):**
> FINDING TRIGGER: If two uplinks from the same device terminate on the same
> upstream device, flag as CRITICAL even though two uplinks exist. State
> explicitly that quantity is satisfied but diversity is not.

The second version gives a pattern to match, a severity to apply, and the exact
reasoning to reproduce. The first gives an aspiration.

Write trigger sentences in this shape:

```
FINDING TRIGGER: If <observable condition in the design document>,
flag as <SEVERITY>[, <what to state in the finding>].
```

Aim for at least one trigger per clause. A clause with no trigger is
documentation, not an enforceable standard.

---

## 2. Compliant and non-compliant patterns

The model pattern-matches. Give it both poles.

```
Compliant pattern:
    Access-SW-01 --uplink-1--> Dist-SW-A
    Access-SW-01 --uplink-2--> Dist-SW-B

Non-compliant pattern (flag as CRITICAL even though 2 uplinks exist):
    Access-SW-01 --uplink-1--> Dist-SW-A (port Gi1/0/1)
    Access-SW-01 --uplink-2--> Dist-SW-A (port Gi1/0/2)
```

The non-compliant example is the more valuable of the two, and the annotation
in the parentheses is what stops the model from being fooled by "two uplinks
are present, therefore compliant".

---

## 3. Clause numbering

Number every clause: `## 3.2 Uplink Diversity`. The chunker splits on clause
boundaries and stamps the clause number into the chunk, so findings can cite
`Three-Tier LAN Standard §3.2` rather than gesturing at a document. Reviewers
act on citations they can look up. They argue with citations they cannot.

Keep each clause under about 250 words. One clause, one requirement, one
retrievable idea. A 2,000-word clause produces chunks that mean nothing in
particular and retrieve for everything.

---

## 4. Severity mapping

State your severity definitions once, near the top, in observable terms:

> CRITICAL: a single component failure causes total loss of service for a user
> population, or an unauthenticated path exists into a protected zone.

Then use those words consistently in triggers. Without a shared definition the
model applies its own, and its own drifts toward CRITICAL because most training
data about security is written to alarm.

---

## 5. What to seed, in priority order

1. **Your own reference architectures and HLD/LLD templates.** Highest value in
   the entire knowledge base. Nothing else encodes how *your* organisation
   builds things.
2. **Your design standards, rewritten with trigger sentences.** Most
   organisations already have the standards; they are written as prose for
   humans. Rewriting them in this format is a day of work with a large payoff.
3. **Post-incident findings from past reviews and outages.** "In 2024 we lost
   the Dubai site because both circuits entered through the same duct" becomes
   a trigger sentence, and the organisation stops relearning it.
4. **Public frameworks** — NIST SP 800-207, SP 800-53, CIS Benchmarks, OWASP
   ASVS, ISO 27001 Annex A. Useful for control mapping and for language the
   auditors recognise. Seed these *last* and in abridged form: they are large,
   they embed slowly on CPU, and the model already knows most of their content
   from training. Their value here is citation, not knowledge.

---

## 6. Sizing and seeding order

Seed small documents first, verify the chunk count, then add larger ones.

Embedding a large corpus on a CPU-only machine is slow and the embedding call
can time out mid-batch, leaving a corrupted index that fails at query time with
errors that look nothing like the actual cause. `scripts/seed_kb.py` batches
and retries, and prints a chunk count per domain afterwards.

**If the count is zero after seeding, the seed failed silently and every review
in that domain will run on the model's parametric memory alone** — producing
generic, uncitable findings that look plausible. Always check the count.

---

## 7. Never mix embedding models

The same embedding model must be used for seeding and for querying. Vectors
from different models occupy incompatible geometric spaces where similarity
scores are meaningless, and the failure is silent — you get results, they are
just noise.

The collection records the model it was seeded with and the retriever refuses
to proceed on a mismatch. If you change `models.embedding` in `config.yaml`,
re-seed everything:

```bash
python scripts/seed_kb.py --reset
```

---

## 8. Anti-patterns

| Anti-pattern | Why it fails |
|---|---|
| "Follow industry best practice" | Nothing to match, nothing to cite. |
| A 5,000-word clause | Chunks lose meaning; retrieves for everything, informs nothing. |
| No clause numbers | Findings cite a document, not a requirement. Nobody can verify. |
| Only public standards seeded | Findings are indistinguishable from a generic model's output. |
| Contradictory clauses across documents | The model picks one arbitrarily; findings become non-reproducible. |
| Severity words with no definitions | Severity inflation; everything becomes CRITICAL and nothing gets fixed. |

---

## 9. Testing a new standard

After adding a document:

1. Re-seed and confirm the chunk count rose.
2. Write a small sample design that deliberately violates the new clause.
3. Run the review. The finding should appear, cite your clause number, and use
   your severity.
4. If it does not appear, the trigger sentence is too vague. Make the condition
   more observable, not the language more emphatic.

Keep those sample designs. They are your regression suite — see
`samples/` for the ones shipped with this repository.
