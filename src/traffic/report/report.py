"""
Report generation (JSON + Markdown) for the Source-to-Traffic analysis.

Each candidate feature carries the six items required by the specification:
feature content, source, derivation, trigger conditions, observable
location and confidence. LLM output, when present, is shown separately and
labelled as unverified.
"""
import json
import os
from typing import Dict, List

KIND_SCORE = {"sequence": 6, "fixed": 5, "range": 5, "affine": 2, "input-dependent": 1, "symbolic": 0}


def score_feature(f: dict) -> float:
    s = KIND_SCORE.get(f.get("unit_kind"), 0)
    conf = f.get("confidence", "")
    if conf.startswith("static-derived"):
        s += 2
        if "unresolved" not in conf and "domain" not in conf:
            s += 1
    if f.get("sink_class") == "net":
        s += 2
    elif f.get("sink_class") == "stream":
        s += 1
    if f.get("crypto_on_path"):
        s += 1
    if f.get("layer_constructed_by_project"):
        s += 1.5
    elif f.get("layer_used_by_project"):
        s += 0.5
    if f.get("sequence") and f["sequence"][0].get("exact"):
        s += 1
    if f.get("sequence"):
        single = sum(1 for x in f["sequence"] if len(x.get("values", [])) == 1)
        s += 1.5 * single / len(f["sequence"])
    rel = f.get("network_relevance")
    if rel == "generic":
        s -= 6
    elif rel == "network":
        s += 1
    if f.get("values") and len(f["values"]) == 1:
        s += 0.5
    return s


def first_values(f: dict) -> str:
    if f.get("sequence"):
        parts = []
        for x in f["sequence"][:6]:
            v = x["values"]
            parts.append(str(v[0]) if len(v) == 1 else "{" + ",".join(map(str, v[:6])) + ("…" if len(v) > 6 else "") + "}")
        more = "" if len(f["sequence"]) <= 6 else f", … ({len(f['sequence'])} units)"
        return "sequence k=0..: " + ", ".join(parts) + more
    if f.get("values"):
        vs = f["values"]
        if "overhead_bytes" in vs[0]:
            return "unit = input + {" + ",".join(str(v["overhead_bytes"]) for v in vs[:8]) + "} bytes"
        if "min" in vs[0]:
            return f"range [{vs[0]['min']}, {vs[0]['max']}]"
        return "{" + ",".join(str(v.get("value")) for v in vs[:10]) + "}"
    return f.get("formula", "")[:120]


CLASS_ORDER = ["protocol_state", "configuration", "other", "connection_state", "input_size"]


def _cond_list(f: dict, max_len: int = 110) -> List[str]:
    """Conditions ordered by how informative they are for a reader (protocol/config first)."""
    out = []
    groups = f.get("conditions", {}).get("all_of", {})
    for cls in CLASS_ORDER + [c for c in groups if c not in CLASS_ORDER]:
        for item in groups.get(cls, []):
            out.append(item if len(item) <= max_len else item[: max_len - 1] + "…")
    return out


def is_strong(f: dict) -> bool:
    """Input-independent unit with at least one positive size (zero-length writes are degenerate)."""
    if f.get("unit_kind") not in ("sequence", "fixed", "range"):
        return False
    if f.get("unit_kind") == "fixed":
        vals = [v.get("value") for v in f.get("values", [])]
        if vals and all(isinstance(v, int) and v <= 0 for v in vals):
            return False
    return True


def families(features: List[dict]) -> List[List[dict]]:
    groups: Dict[tuple, List[dict]] = {}
    order = []
    for f in features:
        key = (f["layer"], f["entry"], f["emission_site"]["file"], f["emission_site"]["line"])
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)
    fams = [sorted(groups[k], key=lambda f: -f.get("score", 0)) for k in order]
    fams.sort(key=lambda fam: -max(f.get("score", 0) for f in fam))
    return fams


def _short(path: str, roots: List[str]) -> str:
    for r in roots:
        if r and path.startswith(r):
            return os.path.relpath(path, r)
    return path


def write_reports(result: dict, out_dir: str, top_n: int = 30) -> Dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    feats = result.get("features", [])
    for f in feats:
        f["score"] = round(score_feature(f), 2)
    feats.sort(key=lambda f: (-f["score"], f.get("layer", ""), f.get("emission_site", {}).get("line", 0)))
    json_path = os.path.join(out_dir, "traffic_report.json")
    with open(json_path, "w") as fp:
        json.dump(result, fp, indent=2, ensure_ascii=False, default=str)
    md_path = os.path.join(out_dir, "traffic_report.md")
    with open(md_path, "w") as fp:
        fp.write(render_markdown(result, top_n))
    return {"json": json_path, "markdown": md_path}


def render_markdown(result: dict, top_n: int = 30) -> str:
    deps = result.get("dependencies", {})
    roots = [result.get("project_root", ""), deps.get("goroot_src") or ""]
    cache = result.get("cache_dir", "")
    if cache:
        roots.append(os.path.join(cache, "gomod"))
    L: List[str] = []
    L.append(f"# LLMSCAN Source-to-Traffic report: {result.get('project_name', '')}\n")
    L.append("> Every value below was derived by static symbolic analysis of the source code and its pinned "
             "dependencies. **Nothing here has been confirmed by a packet capture unless the confidence "
             "says so.** LLM interpretations are labelled and never change derived values.\n")
    L.append("## Run\n")
    L.append(f"- Project: `{result.get('project_root')}`")
    L.append(f"- Language frontend: {result.get('language')}; build context: `{json.dumps(result.get('build_context', {}).get('goos'))}/{result.get('build_context', {}).get('goarch')}`")
    L.append(f"- Go toolchain sources: go{deps.get('go_version')} ({deps.get('go_version_source')})")
    fetched = [k for k, v in (deps.get("modules_fetched") or {}).items() if v]
    L.append(f"- Dependency modules analysed: {len(fetched)}; failures: {len(deps.get('failures') or {})}")
    st = result.get("stats", {})
    L.append(f"- Packages loaded: {st.get('packages_loaded')}; functions summarised: {st.get('functions_summarised')}; "
             f"time: {st.get('seconds')} s; timeouts: {len(st.get('timeouts', []))}; errors: {len(st.get('errors', []))}")
    if result.get("llm"):
        L.append(f"- LLM: {result['llm'].get('model')} ({result['llm'].get('calls')} calls, "
                 f"{result['llm'].get('failures')} failed/unparsed)")
    L.append("")

    layers = result.get("layers", [])
    L.append("## Layers that wrap a connection (traffic construction stages)\n")
    L.append("| Layer | Relevance | Provenance | Used by project | Entry points | Sink(s) | Features |")
    L.append("|---|---|---|---|---|---|---|")
    rel_order = {"network": 0, "project": 1, "generic": 2}
    for ly in sorted(layers, key=lambda x: (rel_order.get(x.get("network_relevance"), 3), -x.get("feature_count", 0), x["layer"])):
        u = ly.get("usage", {})
        used = "defined in project" if ly["provenance"] == "project source" else (
            "constructs" if u.get("constructs_layer") else ("imports" if u.get("used_by_project") else "no"))
        sinks = ", ".join(sorted({f"{s['call'].split('(')[0]} [{s['target_type']}]" for s in ly.get("sink_sites", [])}))[:120]
        L.append(f"| `{ly['layer']}` | {ly.get('network_relevance')} | {ly['provenance']} | {used} | "
                 f"{', '.join(e['function'] for e in ly.get('entries', []))[:80]} | {sinks} | {ly.get('feature_count', 0)} |")
    L.append("")
    if result.get("llm_stack"):
        L.append("### Plausible encapsulation stacks (LLM hypothesis, unverified)\n")
        L.append("```json\n" + json.dumps(result["llm_stack"].get("response"), indent=2, ensure_ascii=False)[:4000] + "\n```\n")

    feats = result.get("features", [])
    strong_all = [f for f in feats if is_strong(f)]
    strong = [f for f in strong_all if f.get("network_relevance") != "generic"]
    generic = [f for f in strong_all if f.get("network_relevance") == "generic"]
    fams = families(strong)
    L.append(f"## Candidate externally observable features\n")
    L.append(f"{len(strong)} input-independent unit models in {len(fams)} families (one family = one emission site "
             f"reached from one entry point; variants = protocol/configuration paths). {len(feats)} emission models in total.\n")
    L.append("| # | Layer / entry | Emission site | Variants | Representative feature (特征内容) | Confidence (可信程度) |")
    L.append("|---|---|---|---|---|---|")
    for i, fam in enumerate(fams[:top_n]):
        f = fam[0]
        L.append(f"| {i + 1} | `{f['layer']}` {f['entry']} | `{_short(f['emission_site']['file'], roots)}:"
                 f"{f['emission_site']['line']}` `{f['sink']}` | {len(fam)} | {first_values(f)} | {f['confidence']} |")
    L.append("")
    for i, fam in enumerate(fams[:top_n]):
        f = fam[0]
        L.append(f"### Family {i + 1}: `{f['layer']}` {f['entry']} → `{f['sink']}`\n")
        L.append(f"- **Source (来源)**: layer `{f['layer']}` ({f.get('provenance')}); entry `{f['entry']}` at "
                 f"`{_short(f['entry_location']['file'], roots)}:{f['entry_location']['line']}`; unit emitted at "
                 f"`{_short(f['emission_site']['file'], roots)}:{f['emission_site']['line']}`")
        flow = f.get("flow", [])
        if flow:
            L.append("- **Construction path**: " + " → ".join(
                f"{x['function']} @{os.path.basename(x['call_site_file'])}:{x['call_site_line']}" for x in flow[:16]))
        ob = f.get("observability", {})
        L.append(f"- **Observable location (可观测位置)**: {ob.get('observable_as')}. {ob.get('mapping')}")
        for ev in ob.get("evidence", []):
            L.append(f"  - evidence: {ev.get('fact')} (`{_short(ev.get('file', ''), roots)}:{ev.get('line')}`)")
        for lim in ob.get("limitations", [])[:6]:
            L.append(f"  - limitation: {lim}")
        common = None
        for g in fam:
            cs = set(_cond_list(g))
            common = cs if common is None else (common & cs)
        common = common or set()
        L.append("- **Trigger conditions shared by all variants (触发条件)**: " +
                 ("; ".join(f"`{c}`" for c in sorted(common)[:14]) or "none"))
        L.append("")
        L.append("| Variant | Feature (特征内容) | Distinguishing conditions | Confidence |")
        L.append("|---|---|---|---|")
        for j, g in enumerate(fam[:12]):
            dist = [c for c in _cond_list(g) if c not in common]
            L.append(f"| {i + 1}.{j + 1} | {first_values(g)} | {'; '.join(f'`{c}`' for c in dist[:9]) or '-'} | {g['confidence']} |")
        if len(fam) > 12:
            L.append(f"| … | {len(fam) - 12} more variants in JSON | | |")
        L.append("")
        for j, g in enumerate(fam[:3]):
            L.append(f"#### Variant {i + 1}.{j + 1} — derivation (推导过程)\n")
            L.append(f"- formula: `{g['formula']}`")
            for k, dv in (g.get("domains") or {}).items():
                vals = sorted({d["value"] for d in dv if d["value"] is not None})
                unres = sum(1 for d in dv if d["value"] is None)
                srcs = sorted({e["function"].split("/")[-1] for d in dv if d["value"] is not None for e in d["evidence"][-1:]})
                L.append(f"  - `{k}` ∈ {vals} from {', '.join(srcs[:6])}"
                         f"{' (+%d unresolved implementation(s))' % unres if unres else ''}")
            consts = g.get("constants", [])
            if consts:
                L.append("- constants: " + "; ".join(f"`{c['definition']}` ({_short(c['file'], roots)}:{c['line']})" for c in consts[:14]))
            for note in g.get("notes", []):
                L.append(f"- {note}")
            for cls, items in g["conditions"].get("all_of", {}).items():
                L.append(f"- condition [{cls}]: " + "; ".join(f"`{x}`" for x in items[:10]))
            if g.get("assumptions"):
                L.append("- assumptions: " + "; ".join(g.get("assumptions")[:4]))
            L.append(f"- confidence: {g['confidence']} — derived statically; not validated against captured traffic")
            L.append("")
        if f.get("llm"):
            resp = f["llm"].get("response", {})
            L.append(f"*LLM interpretation (unverified, {f['llm'].get('model')})*: unit = **{resp.get('unit_name', '?')}**. "
                     f"{str(resp.get('mechanism', ''))[:700]}")
            if resp.get("external_visibility"):
                L.append(f"  - visibility (LLM): {str(resp.get('external_visibility'))[:400]}")
            if resp.get("caveats"):
                L.append(f"  - caveats (LLM): " + "; ".join(map(str, resp.get("caveats")[:5])))
            if f["llm"].get("numbers_not_statically_derived"):
                L.append(f"  - numbers mentioned by the LLM that were NOT derived statically: "
                         f"{f['llm']['numbers_not_statically_derived']}")
            L.append("")
    if generic:
        gl = sorted({f["layer"] for f in generic})
        L.append(f"## Excluded: generic byte-stream transforms ({len(generic)} unit models)\n")
        L.append("Layers that neither write to a network connection nor implement one and are not part of the "
                 "project (e.g. encoders); kept in the JSON report only: " + ", ".join(f"`{x}`" for x in gl[:20]) + "\n")
    affine = [f for f in feats if f.get("unit_kind") == "affine" and f.get("network_relevance") != "generic"]
    if affine:
        L.append("## Size-preserving units (unit = application bytes + constant overhead)\n")
        L.append("These leak the plaintext length (plus a fixed overhead) rather than a fixed size.\n")
        L.append("| Layer / entry | Sink | Overhead | Confidence |")
        L.append("|---|---|---|---|")
        seen = set()
        for f in affine:
            key = (f["layer"], f["entry"], f["sink"], first_values(f))
            if key in seen:
                continue
            seen.add(key)
            L.append(f"| `{f['layer'].split('/')[-1]}` {f['entry']} | `{f['sink']}` | {first_values(f)} (`{f.get('overhead')}`) | {f['confidence']} |")
        L.append("")
    unresolved = [f for f in feats if f.get("unit_kind") in ("symbolic", "input-dependent")]
    L.append("## Unresolved / uncertain results\n")
    L.append(f"- {len(unresolved)} emission model(s) could not be reduced to concrete lengths (symbolic or input-dependent "
             f"in a non-affine way). They are listed in the JSON report and are **not** claimed as features.")
    for e in st.get("timeouts", [])[:20]:
        L.append(f"- timeout: `{e}`")
    for e in st.get("errors", [])[:20]:
        L.append(f"- error: `{e}`")
    L.append("")
    L.append("## Method and limitations\n")
    L.append("- Lengths are derived by path-sensitive symbolic execution over tree-sitter ASTs with interprocedural "
             "summaries; constants are evaluated from their declarations in the analysed sources and pinned dependencies.")
    L.append("- Opaque calls through interfaces are resolved by searching implementations that are constructed in code "
             "reachable from the layer's package (rapid type analysis) and that implement the receiver interface; this "
             "is an over-approximation and is labelled as such.")
    L.append("- Error paths (`err != nil` branches) are not explored; loops are summarised by one symbolic iteration.")
    L.append("- A unit is a byte string handed to a sink in one call. Its relation to packets depends on the transport; "
             "see the per-feature limitations.")
    return "\n".join(L) + "\n"
