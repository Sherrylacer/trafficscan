"""
Go API knowledge used by the traffic analysis.

This is *semantic API knowledge* (what a standard library call does to byte
lengths, which interfaces represent network connections, which calls draw
random numbers). It deliberately contains no protocol-specific constants or
expected traffic features: all sizes are derived from the analysed source.
"""

# Interfaces / concrete types that represent a network transport endpoint.
# A Write on a value of one of these types hands bytes to the next layer
# toward the wire.
NET_CONN_TYPES = {
    ("net", "Conn"), ("net", "PacketConn"), ("net", "TCPConn"), ("net", "UDPConn"),
    ("net", "UnixConn"), ("net", "IPConn"),
}
# Generic byte sinks. A Write on these goes to an unknown destination which
# is frequently the next layer's connection.
STREAM_WRITER_TYPES = {
    ("io", "Writer"), ("io", "WriteCloser"), ("io", "ReadWriter"), ("io", "ReadWriteCloser"),
}
# Buffering writers: data written here is coalesced before reaching the sink.
BUFFER_TYPES = {("bufio", "Writer"), ("bytes", "Buffer")}

# Methods that move bytes into a sink.
SINK_METHODS = {"Write", "WriteTo", "WriteToUDP", "WriteMsgUDP", "WriteToUDPAddrPort",
                "WriteMsgUDPAddrPort", "WriteBuffers"}

# AEAD.Seal(dst, nonce, plaintext, additionalData) appends
# len(plaintext) + Overhead() bytes to dst (crypto/cipher.AEAD contract).
AEAD_SEAL = {"method": "Seal", "nargs": 4, "dst": 0, "plaintext": 2, "overhead_method": "Overhead"}

# hash.Hash.Sum(b) appends Size() bytes to b (hash.Hash contract).
HASH_SUM = {"method": "Sum", "nargs": 1, "size_method": "Size", "types": {("hash", "Hash")}}

# In-place transforms: no change in length.
IN_PLACE_CRYPTO = {"XORKeyStream", "CryptBlocks"}

# Arbitrary-precision helpers whose numeric value passes through unchanged.
NUMERIC_PASSTHROUGH_FUNCS = {("math/big", "NewInt"): 0}
NUMERIC_PASSTHROUGH_METHODS = {"Int64", "Uint64", "IsInt64"}

# Random primitives with a bound argument other than the first:
# (import path, function) -> (bound argument index, low, high_offset, result is (value, err) tuple)
RANDOM_FUNCS_EXT = {
    ("crypto/rand", "Int"): (1, 0, -1, True),
}

# Random number primitives: (import path, function) -> (low, high_offset) where the
# result is in [low, arg0 + high_offset].
RANDOM_FUNCS = {
    ("math/rand", "Intn"): (0, -1), ("math/rand", "Int31n"): (0, -1), ("math/rand", "Int63n"): (0, -1),
    ("math/rand/v2", "IntN"): (0, -1), ("math/rand/v2", "Int32N"): (0, -1),
    ("math/rand/v2", "Int64N"): (0, -1), ("math/rand/v2", "UintN"): (0, -1),
    ("math/rand/v2", "Uint32N"): (0, -1), ("math/rand/v2", "Uint64N"): (0, -1),
    ("math/rand/v2", "N"): (0, -1),
}

# Calls whose (single) error result signals failure; branches testing
# `err != nil` are treated as error paths and not explored for emissions.
ERROR_NAME_PATTERN = r"^(err|e|[A-Za-z_]*[eE]rr[A-Za-z_]*)$"

INT_TYPE_NAMES = {
    "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64",
    "uintptr", "byte", "rune",
}
