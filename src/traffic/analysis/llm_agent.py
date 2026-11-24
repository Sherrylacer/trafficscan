"""
LLM-assisted interpretation for the traffic analysis.

The LLM is used only to *interpret* statically derived results (name the
protocol unit, explain the mechanism, point out caveats) and to propose
hypotheses for things the static engine could not resolve. It never sets
or changes a derived value. Every LLM statement is stored separately and
labelled "LLM interpretation (unverified)"; numbers the LLM mentions that
were not derived statically are listed explicitly as unverified.

Reuses LLMSCAN's original model wrapper (model/llm.py).
"""
import json
import re
from typing import Dict, List, Optional


def extract_json(text: str) -> Optional[dict]:
    if not text:
        return None
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    cand = m.group(1) if m else None
    if cand is None:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            cand = text[start:end + 1]
    if cand is None:
        return None
    try:
        return json.loads(cand)
    except Exception:
        return None


FEATURE_PROMPT = """You are assisting a static analyser that recovers how a network program builds the bytes it sends.
The analyser has ALREADY DERIVED the following facts from source code by symbolic execution. Treat the numbers
as authoritative; do not recompute or invent other values.

Layer (type wrapping a connection): {layer}
Provenance: {provenance}
Entry point: {entry}
Unit = the byte string passed in one call to: {sink} (type {sink_type})
Unit kind: {unit_kind}
Length formula (symbols are source expressions): {formula}
Derived values: {values}
Derived sequence (index k -> length): {sequence}
Trigger conditions (path conditions): {conditions}
Functions on the construction path (in order): {flow}

Relevant source excerpts:
{code}

Answer in JSON only, with keys:
  "unit_name": short name of the protocol unit this length describes (e.g. "TLS record", "WebSocket frame", "AEAD chunk"),
  "construction_stages": list of short strings, the stages from application data to this unit (encapsulation, encryption, framing, fragmentation, buffering),
  "mechanism": 2-4 sentences explaining WHY the derived length arises, referencing the formula,
  "external_visibility": 1-3 sentences on how a passive observer (no keys) could see it and what can blur it,
  "caveats": list of short strings (configurations or code paths that would change or remove the feature),
  "follow_up_checks": list of short strings (what a human or a controlled experiment should verify).
"""

STACK_PROMPT = """You are assisting a static analyser of a network program ({project}).
It found these connection-wrapping layers (type, package, provenance, whether the project imports/constructs it)
and their statically derived candidate traffic features:
{layers}

Using only this information, answer in JSON with keys:
  "likely_stacks": list of objects {{"description": str, "layers_outer_to_inner": [layer names from the list]}} describing plausible
     encapsulation stacks from application data to the wire (mark each as a hypothesis),
  "notes": list of short strings.
Do not invent layers that are not in the list.
"""


class TrafficLLMAgent:
    def __init__(self, model, max_calls: int = 12, log=print) -> None:
        self.model = model
        self.max_calls = max_calls
        self.calls = 0
        self.log = log
        self.failures = 0

    def _ask(self, prompt: str) -> Optional[dict]:
        if self.calls >= self.max_calls:
            return None
        self.calls += 1
        try:
            out, _, _ = self.model.infer(prompt, False)
        except Exception as exc:  # network / API errors must not break the static analysis
            self.failures += 1
            self.log(f"[llm] call failed: {exc}")
            return None
        data = extract_json(out)
        if data is None:
            self.failures += 1
            return {"raw_response": (out or "")[:2000], "parse_error": True}
        return data

    @staticmethod
    def _numbers(obj) -> List[int]:
        text = json.dumps(obj, ensure_ascii=False)
        return [int(x) for x in re.findall(r"(?<![\w.])(\d{2,6})(?![\w.])", text)]

    def annotate_feature(self, feature: dict, code: str) -> Optional[dict]:
        derived = set()
        for v in feature.get("values", []):
            for x in v.values():
                if isinstance(x, int):
                    derived.add(x)
        for s in feature.get("sequence", []):
            for x in s.get("values", []):
                derived.add(int(x))
        for c in feature.get("constants", []):
            m = re.search(r"=\s*(-?\d+)", c.get("definition", ""))
            if m:
                derived.add(int(m.group(1)))
        seq_txt = ", ".join(f"{s['index']}->{s['values']}" for s in feature.get("sequence", [])[:8])
        prompt = FEATURE_PROMPT.format(
            layer=feature["layer"], provenance=feature.get("provenance", ""), entry=feature["entry"],
            sink=feature["sink"], sink_type=feature["sink_type"], unit_kind=feature["unit_kind"],
            formula=feature["formula"], values=feature.get("values"), sequence=seq_txt or "-",
            conditions=json.dumps(feature["conditions"].get("all_of", {}), ensure_ascii=False)[:2500],
            flow=" -> ".join(x["function"] for x in feature.get("flow", []))[:1500], code=code[:9000],
        )
        data = self._ask(prompt)
        if data is None:
            return None
        nums = self._numbers(data)
        unverified = sorted({n for n in nums if n not in derived and n > 64})
        return {
            "label": "LLM interpretation (unverified; does not change derived values)",
            "model": getattr(self.model, "online_model_name", "?"),
            "response": data,
            "numbers_not_statically_derived": unverified,
        }

    def summarize_stacks(self, project: str, layer_lines: List[str]) -> Optional[dict]:
        prompt = STACK_PROMPT.format(project=project, layers="\n".join(layer_lines)[:12000])
        data = self._ask(prompt)
        if data is None:
            return None
        return {"label": "LLM hypothesis (unverified)", "model": getattr(self.model, "online_model_name", "?"),
                "response": data}
