"""Report components for the Streamlit UI."""
from __future__ import annotations
from typing import Dict, Iterable, Mapping, Sequence, Tuple

SEV_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
SEV_VAR = {"CRITICAL": "var(--car-critical)", "HIGH": "var(--car-high)", "MEDIUM": "var(--car-medium)", "LOW": "var(--car-low)"}
_MIN_LABEL_PCT = 6.0

def severity_bar(counts: Mapping[str, int]) -> str:
    total = sum(int(counts.get(s, 0)) for s in SEV_ORDER)
    if total <= 0:
        return '<div class="car-card" style="color:var(--car-ink-3);font-size:.85rem">No findings recorded.</div>'
    bands, keys = [], []
    for sev in SEV_ORDER:
        n = int(counts.get(sev, 0))
        if n:
            pct = n / total * 100
            label = str(n) if pct >= _MIN_LABEL_PCT else ""
            bands.append(f'<i style="background:{SEV_VAR[sev]};flex:0 0 {pct:.2f}%">{label}</i>')
        keys.append(f'<div><span class="car-chip" style="background:{SEV_VAR[sev]}"></span>{sev.title()} <b>{n}</b></div>')
    aria = ", ".join(f"{int(counts.get(s, 0))} {s.lower()}" for s in SEV_ORDER)
    return f'<div class="car-sevbar" role="img" aria-label="{aria}">{"".join(bands)}</div><div class="car-key">{"".join(keys)}</div>'

def risk_gauge(score: float, rag: str, size: int = 168) -> str:
    colour = {"RED": "var(--car-critical)", "AMBER": "var(--car-high)", "GREEN": "var(--car-green)"}.get(str(rag).upper(), "var(--car-ink-3)")
    clamped = max(0.0, min(float(score), 100.0))
    r = size / 2 - 14
    circ = 2 * 3.141592653589793 * r
    offset = circ * (1 - clamped / 100)
    return f'<div style="position:relative;width:{size}px;height:{size}px;flex:none"><svg width="{size}" height="{size}" style="transform:rotate(-90deg);overflow:visible"><circle cx="{size/2}" cy="{size/2}" r="{r}" fill="none" stroke="var(--car-surface-3)" stroke-width="11"></circle><circle cx="{size/2}" cy="{size/2}" r="{r}" fill="none" stroke="{colour}" stroke-width="11" stroke-linecap="round" stroke-dasharray="{circ:.1f}" stroke-dashoffset="{offset:.1f}" style="filter:drop-shadow(0 0 8px color-mix(in srgb,{colour} 40%,transparent))"></circle></svg><div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:1px"><span style="font-size:3rem;font-weight:700;letter-spacing:-.045em;line-height:1;font-variant-numeric:tabular-nums;color:var(--car-ink)">{clamped:.1f}</span><span style="font-family:\'IBM Plex Mono\',monospace;font-size:.69rem;letter-spacing:.13em;text-transform:uppercase;color:var(--car-ink-3)">Risk score</span></div></div>'

def rag_badge(rag: str) -> str:
    tone = {"RED": ("var(--car-critical-bg)", "var(--car-critical)", "do not approve"), "AMBER": ("var(--car-high-bg)", "var(--car-high)", "approve with conditions"), "GREEN": ("var(--car-low-bg)", "var(--car-green)", "no blocking defects")}.get(str(rag).upper())
    if tone is None:
        return f'<span class="car-rag" style="background:var(--car-surface-2);color:var(--car-ink-3)"><span class="bead"></span>{rag}</span>'
    bg, fg, words = tone
    return f'<span class="car-rag" style="background:{bg};color:{fg}"><span class="bead"></span>{str(rag).upper()} — {words}</span>'

def counters(items: Sequence[Tuple[object, str]]) -> str:
    cells = "".join(f'<div class="car-counter"><b>{v}</b><span>{label}</span></div>' for v, label in items)
    return f'<div class="car-counters">{cells}</div>'

def domain_rows(by_domain: Mapping[str, Mapping[str, int]]) -> str:
    rows = []
    for name, counts in by_domain.items():
        total = sum(int(v) for v in counts.values())
        if total <= 0:
            continue
        segs = "".join(f'<i style="background:{SEV_VAR[s]};flex:0 0 {int(counts.get(s, 0)) / total * 100:.2f}%"></i>' for s in SEV_ORDER if int(counts.get(s, 0)))
        rows.append(f'<div class="car-dom"><span style="font-size:.79rem;color:var(--car-ink-2)">{name}</span><span class="car-dom-t">{segs}</span><span class="car-dom-c">{total}</span></div>')
    if not rows:
        return ""
    return '<div class="car-card" style="display:flex;flex-direction:column;gap:14px">' + "".join(rows) + '</div>'

def clause(reference: str) -> str:
    return f'<span class="car-clause"><svg width="12" height="12" viewBox="0 0 16 16" fill="none"><path d="M4 2h5l3 3v9H4V2Z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"></path><path d="M9 2v3h3" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"></path></svg>{reference}</span>'

def evidence(text: str, limit: int = 400) -> str:
    body = (text or "").strip().replace("<", "&lt;").replace(">", "&gt;")
    if len(body) > limit:
        body = body[:limit].rstrip() + "…"
    return f'<pre class="car-ev">{body}</pre>'

def controls(mappings: Iterable[str]) -> str:
    tags = "".join(f'<span class="car-ctrl">{m}</span>' for m in mappings)
    return f"<div>{tags}</div>" if tags else ""

def stage(inner_html: str) -> str:
    return f'<div class="car-stage">{inner_html}</div>'
