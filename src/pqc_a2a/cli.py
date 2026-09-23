from __future__ import annotations

import argparse
import getpass
import json
from pathlib import Path

from .protocol import AgentIdentity, available_algorithms


def main() -> int:
    parser = argparse.ArgumentParser(prog="pqc-a2a", description="PQC-A2A identity and environment tools")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("identity-create", help="create an encrypted agent identity")
    create.add_argument("agent_id")
    create.add_argument("output", type=Path)
    create.add_argument("--password", help="password; omit to enter it without echo")
    sub.add_parser("doctor", help="check liboqs mechanisms available to this installation")
    args = parser.parse_args()
    if args.command == "doctor":
        algorithms = available_algorithms()
        result = {"status": "ok", "kem_ml_kem_768": "ML-KEM-768" in algorithms["kem"], "signature_ml_dsa_65": "ML-DSA-65" in algorithms["signature"], "signature_slh_dsa": "SLH_DSA_PURE_SHA2_128S" in algorithms["signature"], "kem_count": len(algorithms["kem"]), "signature_count": len(algorithms["signature"])}
        print(json.dumps(result, indent=2))
        return 0 if result["kem_ml_kem_768"] and result["signature_ml_dsa_65"] else 1
    password = args.password or getpass.getpass("Identity password (minimum 12 characters): ")
    identity = AgentIdentity(args.agent_id)
    identity.save(args.output, password)
    print(f"Encrypted identity written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
