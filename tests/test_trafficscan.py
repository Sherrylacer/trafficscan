"""
Tests for the Source-to-Traffic analysis (trafficscan).

Run from the repository root:
    .venv/bin/python -m unittest discover -s tests -v

Tests that need the Go standard library / Xray dependency sources use the
dependency cache (cache/) and are skipped when it is not populated (run the
trafficscan once online to populate it).
"""
import os
import re
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from traffic.deps.go_resolver import parse_go_mod, escape_module_path  # noqa: E402
from traffic.lang.go_program import BuildContext, GoProgram  # noqa: E402
from traffic.lang.go_symexec import GoSymExec  # noqa: E402

FIX = REPO / "tests" / "fixtures"
CACHE = REPO / "cache"
GO_STD = CACHE / "go" / "go1.27.3" / "go" / "src"
XRAY = REPO / "xray-source" / "Xray-core"


def load_fixture(rel: str, ip: str):
    prog = GoProgram(None, BuildContext())
    pkg = prog.load_directory(FIX / rel, ip, "project")
    return prog, pkg


class TestBuildAndConstants(unittest.TestCase):
    def test_file_name_constraints(self):
        b = BuildContext("linux", "arm64", 27)
        self.assertTrue(b.file_name_ok("conn.go"))
        self.assertTrue(b.file_name_ok("sock_linux.go"))
        self.assertFalse(b.file_name_ok("sock_windows.go"))
        self.assertFalse(b.file_name_ok("asm_amd64.go"))
        self.assertTrue(b.file_name_ok("asm_arm64.go"))
        self.assertFalse(b.file_name_ok("conn_test.go"))

    def test_go_build_expressions(self):
        b = BuildContext("linux", "arm64", 27)
        self.assertTrue(b.constraint_ok("//go:build linux && !windows\n\npackage x\n"))
        self.assertFalse(b.constraint_ok("//go:build windows || darwin\n\npackage x\n"))
        self.assertTrue(b.constraint_ok("//go:build go1.21 && (arm64 || amd64)\n\npackage x\n"))
        self.assertFalse(b.constraint_ok("//go:build go1.30\n\npackage x\n"))

    def test_constant_evaluation_iota_and_expressions(self):
        prog, pkg = load_fixture("go_synthtunnel/tunnel", "example.com/synthtunnel/tunnel")
        self.assertEqual(prog.const_value(pkg, "linkMTU"), 1420)
        self.assertEqual(prog.const_value(pkg, "frameData"), 1)
        self.assertEqual(prog.const_value(pkg, "frameKeepalive"), 2)
        self.assertEqual(prog.const_value(pkg, "frameProbe"), 3)
        self.assertEqual(prog.const_value(pkg, "probeSize"), 6 + 24 + 16)

    def test_go_mod_parsing(self):
        gm = parse_go_mod(XRAY / "go.mod") if XRAY.exists() else None
        if gm is None:
            self.skipTest("xray-source not present")
        self.assertEqual(gm.module, "github.com/xtls/xray-core")
        self.assertIn("github.com/refraction-networking/utls", gm.requires)
        self.assertEqual(escape_module_path("github.com/BurntSushi/toml"), "github.com/!burnt!sushi/toml")


class TestSymbolicLengths(unittest.TestCase):
    def test_interprocedural_slice_lengths_no_placeholder_clash(self):
        prog, pkg = load_fixture("go_lenflow/lenflow", "example.com/lenflow/lenflow")
        ex = GoSymExec(prog)
        s = ex.summarize(pkg.funcs["twice"])
        lengths = sorted(str(p.returns[0].length) for p in s.paths)
        self.assertEqual(lengths, ["$p2 + len($p0) + len($p1) + 3", "len($p0) + len($p1) + 3"])

    def test_capacity_branch_merged(self):
        prog, pkg = load_fixture("go_lenflow/lenflow", "example.com/lenflow/lenflow")
        ex = GoSymExec(prog)
        s = ex.summarize(pkg.funcs["sliceForAppend"])
        self.assertEqual(len(s.paths), 1, "branches that do not affect lengths must be merged")


class TestSyntheticTunnel(unittest.TestCase):
    """Generality: a made-up protocol with different constants and mechanisms."""

    @classmethod
    def setUpClass(cls):
        from traffic.lang.go_frontend import GoTrafficFrontend
        fe = GoTrafficFrontend(str(FIX / "go_synthtunnel"), str(CACHE), go_version="1.27.3",
                               offline=True, log=lambda *a: None)
        cls.result = fe.run()
        cls.features = cls.result["features"]

    def _by_entry(self, entry):
        return [f for f in self.features if f["entry"].endswith(entry)]

    def test_layers_found(self):
        names = {l["layer"] for l in self.result["layers"]}
        # project layers must be found; layers of imported packages (e.g. crypto/cipher.StreamWriter) may also be
        self.assertTrue({"example.com/synthtunnel/tunnel.Prober", "example.com/synthtunnel/tunnel.Tunnel"} <= names)

    def test_full_frame_size_derived(self):
        fixed = [f for f in self._by_entry(".Write") if f["unit_kind"] == "fixed"]
        vals = {v["value"] for f in fixed for v in f["values"]}
        self.assertIn(1392, vals)
        f = [f for f in fixed if any(v["value"] == 1392 for v in f["values"])][0]
        self.assertTrue(f["confidence"].startswith("static-derived"))
        self.assertNotIn("unresolved", f["confidence"])
        self.assertTrue(any("len(b)" in c for c in f["conditions"]["all_of"].get("input_size", [])))

    def test_tail_frame_is_affine(self):
        aff = [f for f in self._by_entry(".Write") if f["unit_kind"] == "affine"]
        self.assertTrue(aff)
        self.assertIn("4", aff[0]["overhead"])

    def test_keepalive_random_range(self):
        rng = [f for f in self._by_entry("WriteKeepalive") if f["unit_kind"] == "range"]
        self.assertTrue(rng)
        self.assertEqual(rng[0]["values"][0], {"min": 12, "max": 75})

    def test_udp_probe_fixed(self):
        pr = [f for f in self._by_entry("SendProbe") if f["unit_kind"] == "fixed"]
        self.assertTrue(pr)
        self.assertEqual(pr[0]["values"], [{"value": 46}])
        self.assertIn("UDP", pr[0]["observability"]["observable_as"])


@unittest.skipUnless(GO_STD.exists() and XRAY.exists(), "Go 1.27.3 stdlib cache or xray-source missing")
class TestGoTLSDynamicRecordSizing(unittest.TestCase):
    """Phase-1 acceptance: derive the Go TLS dynamic record sizing feature from source."""

    @classmethod
    def setUpClass(cls):
        from traffic.lang.go_frontend import GoTrafficFrontend
        fe = GoTrafficFrontend(str(XRAY), str(CACHE), go_version="1.27.3", goarch="arm64", offline=True,
                               package_filter=["crypto/tls"], log=lambda *a: None)
        cls.result = fe.run()
        cls.features = [f for f in cls.result["features"] if f["layer"] == "crypto/tls.Conn"]

    def test_first_full_record_is_derived(self):
        seqs = [f for f in self.features if f["unit_kind"] == "sequence"]
        firsts = [f for f in seqs if f["sequence"] and f["sequence"][0]["values"] == [1208] and f["sequence"][0]["exact"]]
        self.assertTrue(firsts, "expected an exactly derived first full record length")
        # the TLS 1.3 + AEAD variant must have the complete growth sequence
        tls13 = [f for f in seqs if any("c.vers == VersionTLS13" in c for c in
                                        f["conditions"]["all_of"].get("protocol_state", []))
                 and any("aead" in c for c in f["conditions"]["all_of"].get("protocol_state", []))
                 and "0 >= c.out.explicitNonceLen()" in " ".join(f["conditions"]["all_of"].get("connection_state", []))]
        self.assertTrue(tls13)
        vals = [s["values"] for s in tls13[0]["sequence"][:3]]
        self.assertEqual(vals, [[1208], [2394], [3580]])

    def test_trigger_conditions_and_evidence(self):
        f = [f for f in self.features if f["unit_kind"] == "sequence" and f["sequence"][0]["values"] == [1208]][0]
        conds = " ".join(x for v in f["conditions"]["all_of"].values() for x in v)
        self.assertIn("DynamicRecordSizingDisabled", conds)
        self.assertIn("bytesSent < 131072", conds)
        defs = " ".join(c["definition"] for c in f["constants"])
        self.assertIn("tcpMSSEstimate = 1208", defs)
        self.assertIn("recordHeaderLen = 5", defs)
        self.assertTrue(f["emission_site"]["file"].endswith("crypto/tls/conn.go"))

    def test_used_by_project(self):
        ly = [l for l in self.result["layers"] if l["layer"] == "crypto/tls.Conn"][0]
        self.assertTrue(ly["usage"]["constructs_layer"])


class TestNoHardcodedTarget(unittest.TestCase):
    """The production analysis code must not contain the acceptance value."""

    def test_no_1208_in_production_code(self):
        offenders = []
        for p in list((REPO / "src" / "traffic").rglob("*.py")) + [REPO / "src" / "pipeline" / "trafficscan.py"]:
            if re.search(r"(?<!\d)1208(?!\d)", p.read_text()):
                offenders.append(str(p))
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
