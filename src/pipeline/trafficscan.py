import os
import re
from pathlib import Path

from traffic.analysis.llm_agent import TrafficLLMAgent
from traffic.report.report import first_values, is_strong, score_feature, write_reports

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


class TrafficScanPipeline:
    """
    Source-to-Traffic analysis: recovers how a network program builds the
    bytes it sends (encapsulation, encryption, framing, fragmentation,
    buffering) from its source and pinned dependencies, and derives
    candidate externally observable traffic features with evidence.
    """

    def __init__(self, project_name, project_path, language, inference_model_name, inference_key_str,
                 temperature, options=None, log=print):
        self.project_name = project_name
        self.project_path = project_path
        self.language = language
        self.inference_model_name = inference_model_name
        self.inference_key_str = inference_key_str
        self.temperature = temperature
        self.opts = options or {}
        self.log = log

    def detect_language(self) -> str:
        if self.language:
            return self.language
        if (Path(self.project_path) / "go.mod").exists():
            return "Go"
        raise ValueError("could not detect language; pass --language")

    def frontend(self, language: str):
        if language == "Go":
            from traffic.lang.go_frontend import GoTrafficFrontend
            return GoTrafficFrontend(
                self.project_path,
                self.opts.get("cache_dir") or str(REPO_ROOT / "cache"),
                go_version=self.opts.get("go_version"),
                goos=self.opts.get("goos", "linux"),
                goarch=self.opts.get("goarch", "amd64"),
                tags=self.opts.get("build_tags"),
                offline=self.opts.get("offline", False),
                entry_timeout=self.opts.get("entry_timeout", 60),
                package_filter=self.opts.get("package_filter"),
                log=self.log,
            )
        raise NotImplementedError(
            f"trafficscan frontend for {language} is not implemented yet (available: Go). "
            "The analysis core (traffic/analysis) is language independent; a frontend must provide "
            "program loading, layer discovery and a symbolic executor producing Emission objects.")

    def annotate_with_llm(self, result: dict) -> None:
        from model.llm import LLM

        model = LLM(self.inference_model_name, self.inference_key_str, self.temperature)
        agent = TrafficLLMAgent(model, max_calls=self.opts.get("llm_max_calls", 12), log=self.log)
        feats = sorted(result["features"], key=lambda f: -score_feature(f))
        strong = [f for f in feats if is_strong(f) and f.get("network_relevance") != "generic"]
        # one annotation per (layer, entry, emission site): variants of the same unit share the explanation
        done = set()
        top = []
        for f in strong:
            key = (f["layer"], f["entry"], f["emission_site"]["file"], f["emission_site"]["line"])
            if key in done:
                continue
            done.add(key)
            top.append(f)
            if len(top) >= self.opts.get("llm_features", 8):
                break
        for f in top:
            code = self._code_for(f)
            ann = agent.annotate_feature(f, code)
            if ann is not None:
                for g in strong:
                    if (g["layer"], g["entry"], g["emission_site"]["file"], g["emission_site"]["line"]) == \
                            (f["layer"], f["entry"], f["emission_site"]["file"], f["emission_site"]["line"]):
                        g["llm"] = ann
            self.log(f"[llm] annotated {f['layer']} {f['entry']} -> "
                     f"{(ann or {}).get('response', {}).get('unit_name', 'n/a') if ann else 'n/a'}")
        layer_lines = []
        for ly in result["layers"]:
            fs = [f for f in result["features"] if f["layer"] == ly["layer"] and
                  f.get("unit_kind") in ("sequence", "fixed", "range")]
            fs.sort(key=lambda f: -score_feature(f))
            u = ly.get("usage", {})
            layer_lines.append(
                f"- {ly['layer']} ({ly['provenance']}; project uses: {u.get('used_by_project')}, constructs: "
                f"{u.get('constructs_layer', ly['provenance'] == 'project source')}): "
                + "; ".join(first_values(f) for f in fs[:2]))
        result["llm_stack"] = agent.summarize_stacks(self.project_name, layer_lines)
        result["llm"] = {"model": self.inference_model_name, "calls": agent.calls, "failures": agent.failures}

    @staticmethod
    def _code_for(f: dict, budget: int = 9000) -> str:
        """Source excerpts of the functions on the construction path (entry, callees, emission site)."""
        chunks = []
        files = {}
        spots = [(f["entry_location"]["file"], f["entry_location"]["line"])]
        for s in f.get("derivation", []):
            if s["kind"] in ("call", "emit") or (s["kind"] == "const"):
                spots.append((s["file"], s["line"]))
        seen = set()
        used = 0
        for path, line in spots:
            if (path, line) in seen or not path or not os.path.exists(path):
                continue
            seen.add((path, line))
            if path not in files:
                files[path] = open(path, encoding="utf-8", errors="replace").read().splitlines()
            lines = files[path]
            lo, hi = max(0, line - 4), min(len(lines), line + 6)
            snippet = "\n".join(lines[lo:hi])
            chunk = f"// {os.path.basename(path)}:{lo + 1}-{hi}\n{snippet}\n"
            if used + len(chunk) > budget:
                break
            chunks.append(chunk)
            used += len(chunk)
        return "\n".join(chunks)

    def start_scan(self) -> dict:
        language = self.detect_language()
        log_dir = REPO_ROOT / "log" / "trafficscan" / self.project_name
        fe = self.frontend(language)
        result = fe.run()
        result["project_name"] = self.project_name
        result["project_root"] = str(Path(self.project_path).resolve())
        result["cache_dir"] = self.opts.get("cache_dir") or str(REPO_ROOT / "cache")
        if self.opts.get("use_llm"):
            try:
                self.annotate_with_llm(result)
            except Exception as exc:
                self.log(f"[llm] annotation skipped: {exc}")
                result["llm"] = {"model": self.inference_model_name, "error": str(exc)}
        paths = write_reports(result, str(log_dir), top_n=self.opts.get("top_n", 30))
        self.log(f"[trafficscan] reports: {paths['markdown']} , {paths['json']}")
        result["report_paths"] = paths
        return result
