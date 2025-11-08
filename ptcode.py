# app.py
import os
import sys
import json
import math
import argparse
from typing import Dict, List, Tuple, Any
from web3 import Web3

DEFAULT_RPC = os.environ.get("RPC_URL", "https://mainnet.infura.io/v3/YOUR_INFURA_KEY")

# Minimal mnemonic map for key opcodes; unknowns will be labeled as OP_0xXX
MNEMONICS: Dict[int, str] = {
    0x00: "STOP",
    0x01: "ADD",
    0x02: "MUL",
    0x03: "SUB",
    0x10: "LT",
    0x11: "GT",
    0x14: "EQ",
    0x15: "ISZERO",
    0x33: "CALLER",
    0x34: "CALLVALUE",
    0x35: "CALLDATALOAD",
    0x36: "CALLDATASIZE",
    0x37: "CALLDATACOPY",
    0x39: "CODECOPY",
    0x3b: "EXTCODESIZE",
    0x3c: "EXTCODECOPY",
    0x3d: "RETURNDATASIZE",
    0x3e: "RETURNDATACOPY",
    0x3f: "EXTCODEHASH",
    0x44: "GASPRICE",
    0x45: "BLOCKHASH",
    0x46: "COINBASE",
    0x47: "TIMESTAMP",
    0x48: "NUMBER",
    0x49: "DIFFICULTY",
    0x4a: "GASLIMIT",
    0x50: "POP",
    0x51: "MLOAD",
    0x52: "MSTORE",
    0x53: "MSTORE8",
    0x54: "SLOAD",
    0x55: "SSTORE",
    0x56: "JUMP",
    0x57: "JUMPI",
    0x5b: "JUMPDEST",
    0xf0: "CREATE",
    0xf1: "CALL",
    0xf2: "CALLCODE",
    0xf3: "RETURN",
    0xf4: "DELEGATECALL",
    0xf5: "CREATE2",
    0xfa: "STATICCALL",
    0xfd: "REVERT",
    0xfe: "INVALID",
    0xff: "SELFDESTRUCT",
}

DANGEROUS_OPCODES = {
    0xf4: "DELEGATECALL",
    0xf2: "CALLCODE",
    0xff: "SELFDESTRUCT",
}
RISKY_OPCODES = {
    0xf0: "CREATE",
    0xf5: "CREATE2",
    0xf1: "CALL",
}

def mnemonic(op: int) -> str:
    if 0x60 <= op <= 0x7f:
        return f"PUSH{op - 0x5f}"
    return MNEMONICS.get(op, f"OP_0x{op:02x}")

def disassemble_and_count(bytecode: bytes) -> Dict[str, int]:
    i = 0
    counts: Dict[str, int] = {}
    n = len(bytecode)
    while i < n:
        op = bytecode[i]
        i += 1
        name = mnemonic(op)
        counts[name] = counts.get(name, 0) + 1
        if 0x60 <= op <= 0x7f:
            skip = op - 0x5f
            i += min(skip, max(0, n - i))
    return counts

def byte_entropy(bytecode: bytes) -> float:
    if not bytecode:
        return 0.0
    freq = [0] * 256
    for b in bytecode:
        freq[b] += 1
    ent = 0.0
    n = len(bytecode)
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 4)

def analyze_contract(w3: Web3, address: str, block: str) -> Dict[str, Any]:
    addr = Web3.to_checksum_address(address)
    code = w3.eth.get_code(addr, block_identifier=block)
    code_hash = Web3.keccak(code).hex() if code else None
    counts = disassemble_and_count(code)
    entropy = byte_entropy(code)
    dangerous = {name: counts.get(name, 0) for name in DANGEROUS_OPCODES.values()}
    risky = {name: counts.get(name, 0) for name in RISKY_OPCODES.values()}
    return {
        "address": addr,
        "size_bytes": len(code),
        "bytecode_hash": code_hash,
        "entropy": entropy,
        "op_histogram": counts,
        "dangerous": dangerous,
        "risky": risky,
    }

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="zk-opcode-soundness — fetch on-chain bytecode and flag potentially unsound patterns (DELEGATECALL, SELFDESTRUCT, etc.). Useful for Aztec/Zama bridges, verifiers, and general Web3 audits."
    )
    p.add_argument("--rpc", default=DEFAULT_RPC, help="EVM RPC URL (default from RPC_URL)")
    p.add_argument("--address", action="append", required=True, help="Contract address (repeatable: --address A --address B)")
    p.add_argument("--block", default="latest", help="Block tag/number (default: latest)")
    p.add_argument("--timeout", type=int, default=30, help="RPC timeout seconds (default: 30)")
    p.add_argument("--json", action="store_true", help="Output JSON")
    p.add_argument("--fail-on-dangerous", action="store_true", help="Exit non-zero if any dangerous opcode is found")
    return p.parse_args()

def main() -> None:
    args = parse_args()

    if not args.rpc.startswith(("http://", "https://")):
        print("❌ Invalid RPC URL format. Must start with http(s).")
        sys.exit(1)

    # Validate addresses early
    targets: List[str] = []
    for a in args.address:
        if not Web3.is_address(a):
            print(f"❌ Invalid address: {a}")
            sys.exit(1)
        targets.append(Web3.to_checksum_address(a))

    w3 = Web3(Web3.HTTPProvider(args.rpc, request_kwargs={"timeout": args.timeout}))
    if not w3.is_connected():
        print("❌ RPC connection failed. Check RPC_URL or --rpc.")
        sys.exit(1)

    print("🔧 zk-opcode-soundness")
    try:
        print(f"🧭 Chain ID: {w3.eth.chain_id}")
    except Exception:
        pass
    print(f"🔗 RPC: {args.rpc}")
    print(f"🧱 Block: {args.block}")
    print(f"🎯 Targets: {len(targets)} address(es)")

    overall_ok = True
    results: List[Dict[str, Any]] = []

    for i, addr in enumerate(targets, start=1):
        print(f"\n— [{i}/{len(targets)}] Analyzing {addr} ...")
        try:
            res = analyze_contract(w3, addr, args.block)
            results.append(res)
        except Exception as e:
            print(f"❌ Analysis failed for {addr}: {e}")
            overall_ok = False
            continue

        print(f"📦 Size: {res['size_bytes']} bytes")
        print(f"🔑 Code hash: {res['bytecode_hash']}")
        print(f"🎛️ Entropy: {res['entropy']}")
        if sum(res["dangerous"].values()) > 0:
            overall_ok = False if args.fail_on-dangerous else overall_ok  # type: ignore
        # Display dangerous/risky summaries
        if any(res["dangerous"].values()):
            print("🚨 Dangerous opcodes detected:")
            for k, v in res["dangerous"].items():
                if v:
                    print(f"   • {k}: {v}")
        else:
            print("✅ No dangerous opcodes detected.")
        if any(res["risky"].values()):
            print("⚠️  Risky opcodes observed:")
            for k, v in res["risky"].items():
                if v:
                    print(f"   • {k}: {v}")

        # Top 8 opcodes by frequency
        top = sorted(res["op_histogram"].items(), key=lambda x: x[1], reverse=True)[:8]
        pretty = ", ".join([f"{k}:{v}" for k, v in top])
        print(f"📊 Top opcodes: {pretty}")

        # ✅ New: Print summary of contracts with dangerous opcodes
    dangerous_contracts = sum(1 for r in results if sum(r["dangerous"].values()) > 0)
    print(f"\n📈 Summary: {dangerous_contracts}/{len(results)} contract(s) contain dangerous opcodes.")


    if args.json:
        out = {
            "rpc": args.rpc,
            "chain_id": None,
            "block": args.block,
            "results": results,
        }
        try:
            out["chain_id"] = w3.eth.chain_id  # type: ignore[index]
        except Exception:
            pass
        print(json.dumps(out, ensure_ascii=False, indent=2))

    # Exit code policy
    if args.fail_on-dangerous and any(sum(r["dangerous"].values()) > 0 for r in results):
        print("\n❌ Soundness failed: dangerous opcodes present.")
        sys.exit(2)
    if not overall_ok:
        sys.exit(2)

    print("\n🎯 Soundness check completed.")
    sys.exit(0)

if __name__ == "__main__":
    main()
