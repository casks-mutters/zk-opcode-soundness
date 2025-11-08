# zk-opcode-soundness

##Overview
A lightweight CLI that fetches on-chain bytecode for one or more addresses and scans for opcode patterns that can undermine soundness, such as DELEGATECALL or SELFDESTRUCT. This is useful for audits of bridges, verifiers, and agents in zk ecosystems like Aztec or Zama, and for general Web3 security checks.

##What it checks
1) Retrieves runtime bytecode and computes its keccak256 hash.  
2) Disassembles by walking opcodes and skipping PUSH data.  
3) Builds an opcode histogram and reports entropy.  
4) Flags dangerous opcodes (DELEGATECALL, CALLCODE, SELFDESTRUCT) and risky ones (CREATE, CREATE2, CALL).  
5) Provides a concise top-opcodes summary to spot unusual dispatch or proxy patterns.

##Installation
1) Python 3.9+  
2) Install dependency:
   pip install web3
3) Set or pass your RPC endpoint:
   export RPC_URL=https://mainnet.infura.io/v3/YOUR_KEY

#Usage
Analyze a single contract at the latest block:
   python app.py --address 0xYourContract

Analyze multiple contracts:
   python app.py --address 0xA --address 0xB --address 0xC

Specify a block/tag (e.g., finalized on L2s):
   python app.py --address 0xYourContract --block latest
   python app.py --address 0xYourContract --block 21000000

Fail the run if dangerous opcodes are found:
   python app.py --address 0xYourContract --fail-on-dangerous

Emit JSON for CI dashboards:
   python app.py --address 0xYourContract --json

Use a custom RPC and higher timeout:
   python app.py --rpc https://arb1.arbitrum.io/rpc --address 0xYourContract --timeout 60

##Expected output
- Prints chain ID, RPC, block, and a per-address summary.  
- Shows bytecode size, hash, entropy, dangerous/risky opcode counts, and top-opcode frequencies.  
- If --fail-on-dangerous is set and any dangerous opcode is found, exits with status 2.  
- JSON mode emits per-address results with histogram, entropy, and flags.

##Example (human output)
🔧 zk-opcode-soundness  
🧭 Chain ID: 1  
🔗 RPC: https://mainnet.infura.io/v3/YOUR_KEY  
🧱 Block: latest  
🎯 Targets: 1 address(es)

— [1/1] Analyzing 0x00000000219ab540356cBB839Cbe05303d7705Fa ...
📦 Size: 5234 bytes
🔑 Code hash: 0x4d0e2df5b23f8b8ddcc9a4329fa4e21c0a6fbd12530a3a8e25a3d6579f0ed1b5
🎛️ Entropy: 7.89
✅ No dangerous opcodes detected.
⚠️  Risky opcodes observed:
   • CALL: 12
📊 Top opcodes: PUSH4:36, JUMPDEST:28, CALL:12, SSTORE:10, SLOAD:10, RETURN:6, DUP2:6, SWAP1:5

🎯 Soundness check completed.

##Notes
- Entropy is a heuristic; very high entropy may indicate unstructured or packed data/metadata.  
- Proxies: scanning the proxy address will include delegate patterns; DELEGATECALL is normal for proxies but still flagged for awareness.  
- Libraries: CREATE/CREATE2 may be legitimate for factories but are risky in governance-critical contracts.  
- Archive access: some RPCs can’t return historical bytecode; use latest-only or an archive node for older blocks.  
- ZK relevance: soundness checks help ensure rollup verifiers/bridges stay immutable (or strictly governed), improving proof integrity and auditability.

##Exit codes
0 → Completed without detected dangerous opcodes (or --fail-on-dangerous not set)  
2 → Dangerous opcode found with --fail-on-dangerous, analysis failure, or partial errors across targets
