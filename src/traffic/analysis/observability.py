"""
Observability model: from an emission unit to what a passive observer sees.

The symbolic analysis yields *units*: byte strings handed in one call to a
sink (e.g. one net.Conn.Write). This module states, with evidence, how such
a unit maps onto externally observable objects (TLS record / TCP payload /
UDP datagram ...) and which mechanisms can blur the mapping. Generic
transport semantics are encoded here; language/runtime-specific evidence
(e.g. whether the runtime enables TCP_NODELAY by default) is collected by
the language frontend from the runtime's own source.
"""
from typing import Dict, List, Optional


def transport_semantics(sink_class: str, sink_type: str, runtime_evidence: Dict[str, dict]) -> dict:
    """Describe how a unit written to `sink_type` becomes observable on the wire."""
    nodelay = runtime_evidence.get("tcp_nodelay_default")
    if sink_class == "net":
        is_packet = any(k in sink_type for k in ("PacketConn", "UDPConn"))
        if is_packet:
            return {
                "observable_as": "UDP datagram payload (one datagram per unit) when the connection is UDP",
                "mapping": "exact: each unit is one datagram; IP fragmentation only if unit exceeds path MTU",
                "limitations": [
                    "the connection may be wrapped by another layer (e.g. QUIC/KCP/DTLS) before reaching UDP",
                ],
                "evidence": [],
            }
        lim = [
            "TCP is a byte stream: unit boundaries are not marked on the wire",
            "a unit larger than the path MSS is split into several segments; only the total is preserved",
            "units can be coalesced with other queued data when the congestion window or receive window is "
            "full, or when another write is pending (e.g. concurrent writers, buffering layers)",
            "TSO/GSO/GRO on the capturing host may merge or split segments in captures",
            "middleboxes (CDN, reverse proxies, TCP-splitting VPNs) re-segment the stream",
            "the net.Conn may be another layer (TLS-in-WebSocket, mux, ...); then this unit is the payload of "
            "that outer layer and its observable size changes accordingly",
        ]
        ev = []
        mapping = ("each unit is passed to the kernel in one write(); if unit <= MSS and nothing else is queued, "
                   "it is typically sent as one TCP segment whose payload length equals the unit length")
        if nodelay:
            mapping += " (Nagle disabled by default, so no delay-based coalescing)"
            ev.append(nodelay)
        else:
            lim.append("Nagle's algorithm may coalesce small units (TCP_NODELAY default not established)")
        return {"observable_as": "TCP payload (stream bytes) when the connection is TCP",
                "mapping": mapping, "limitations": lim, "evidence": ev}
    if sink_class == "stream":
        return {
            "observable_as": "input to the next layer (io.Writer); not directly the wire",
            "mapping": "the unit becomes the payload of whatever writer it is handed to; its wire form depends "
                       "on the outer layers (often TLS records or a TCP stream)",
            "limitations": ["observable only after the outer layers' transformations"],
            "evidence": [],
        }
    return {"observable_as": "buffered", "mapping": "coalesced in a buffer before reaching the sink",
            "limitations": ["unit boundaries are lost by buffering"], "evidence": []}


def go_runtime_evidence(program) -> Dict[str, dict]:
    """Collect runtime facts from the Go standard library source (not assumed)."""
    out: Dict[str, dict] = {}
    net = program.load("net", "stdlib")
    if net is None:
        return out
    for fn in net.all_functions():
        if fn.body is None:
            continue
        text = fn.file.text(fn.body)
        idx = text.find("setNoDelay(")
        if idx >= 0 and "true" in text[idx: idx + 60]:
            line = fn.start_line + text[:idx].count("\n")
            out["tcp_nodelay_default"] = {
                "fact": "Go's net package enables TCP_NODELAY on new TCP connections",
                "function": fn.qualname, "file": str(fn.file.path), "line": line,
                "code": text[idx: idx + 60].split("\n")[0],
            }
            break
    return out
