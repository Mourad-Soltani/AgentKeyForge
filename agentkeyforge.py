#!/usr/bin/env python3
# AgentKeyForge — Offline CLI for forging strong secrets and scanning agent configs
# Built by Mourad.Soltani
"""AgentKeyForge: forge cryptographically strong keys/passphrases and scan for secret leakage patterns.
Pure Python stdlib. Ideal for AI agent builders.
"""

import argparse
import json
import math
import os
import re
import secrets
import string
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

VERSION = "1.0.0"
SIGNATURE = "Built by Mourad.Soltani"

# Character sets
CHARSETS = {
    "mixed": string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?",
    "alphanum": string.ascii_letters + string.digits,
    "hex": "0123456789abcdef",
    "base64url": string.ascii_letters + string.digits + "-_",
}

# Basic secret patterns for scanning (illustrative, not exhaustive)
SECRET_PATTERNS = [
    (re.compile(r'(?i)(api[_-]?key|secret|token|password|passwd)\s*[:=]\s*[\'"]?([A-Za-z0-9_\-]{16,})[\'"]?'), "generic_secret"),
    (re.compile(r'\b(sk-[A-Za-z0-9]{20,}|sk_live_[A-Za-z0-9]{20,}|sk_test_[A-Za-z0-9]{20,})\b'), "openai_or_stripe_key"),
    (re.compile(r'\b(AKIA[0-9A-Z]{16})\b'), "aws_access_key"),
    (re.compile(r'\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,})\b'), "github_token"),
    (re.compile(r'\b(xox[baprs]-[A-Za-z0-9-]{10,})\b'), "slack_token"),
]


def shannon_entropy(s: str) -> float:
    """Approximate Shannon entropy in bits for the string."""
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy * length  # total bits


def generate_key(length: int = 32, charset: str = "mixed", prefix: Optional[str] = None) -> Tuple[str, float]:
    """Generate a cryptographically secure key using secrets module."""
    if charset not in CHARSETS:
        raise ValueError(f"Unknown charset: {charset}. Choose from {list(CHARSETS.keys())}")
    alphabet = CHARSETS[charset]
    body = "".join(secrets.choice(alphabet) for _ in range(length))
    key = f"{prefix}{body}" if prefix else body
    entropy = shannon_entropy(key)
    return key, entropy


def score_key(key: str) -> Dict:
    """Score a key's entropy and give a qualitative rating."""
    bits = shannon_entropy(key)
    if bits < 40:
        rating = "weak"
    elif bits < 60:
        rating = "moderate"
    elif bits < 80:
        rating = "strong"
    else:
        rating = "very_strong"
    return {
        "key_length": len(key),
        "entropy_bits": round(bits, 2),
        "rating": rating,
        "signature": SIGNATURE,
    }


def scan_file(path: Path) -> List[Dict]:
    """Scan a single text file for secret patterns. Returns list of findings."""
    findings = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings
    for pattern, kind in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            findings.append({
                "file": str(path),
                "kind": kind,
                "line_hint": text[:match.start()].count("\n") + 1,
                "snippet": match.group(0)[:80],
            })
    return findings


def scan_path(target: Path) -> List[Dict]:
    """Scan file or directory recursively for secrets."""
    findings = []
    if target.is_file():
        findings.extend(scan_file(target))
    elif target.is_dir():
        for root, _, files in os.walk(target):
            for f in files:
                if f.endswith((".md", ".txt", ".py", ".js", ".ts", ".json", ".yml", ".yaml", ".env", ".toml")):
                    findings.extend(scan_file(Path(root) / f))
    return findings


def cmd_generate(args):
    key, bits = generate_key(args.length, args.charset, args.prefix)
    result = {
        "key": key,
        "entropy_bits": round(bits, 2),
        "length": len(key),
        "charset": args.charset,
        "version": VERSION,
        "signature": SIGNATURE,
    }
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Generated key: {key}")
        print(f"Entropy: {result['entropy_bits']} bits")
        print(f"{SIGNATURE}")


def cmd_score(args):
    result = score_key(args.key)
    result["version"] = VERSION
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Length: {result['key_length']}")
        print(f"Entropy: {result['entropy_bits']} bits")
        print(f"Rating: {result['rating']}")
        print(f"{SIGNATURE}")


def cmd_scan(args):
    target = Path(args.target)
    if not target.exists():
        print(f"Error: {target} does not exist", file=sys.stderr)
        sys.exit(1)
    findings = scan_path(target)
    result = {
        "target": str(target),
        "findings_count": len(findings),
        "findings": findings,
        "version": VERSION,
        "signature": SIGNATURE,
    }
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Scanned: {target}")
        print(f"Findings: {len(findings)}")
        for f in findings[:10]:  # limit display
            print(f"  [{f['kind']}] {f['file']}:{f['line_hint']} → {f['snippet']}")
        if len(findings) > 10:
            print(f"  ... and {len(findings)-10} more (use --json for full)")
        print(f"{SIGNATURE}")


def main():
    parser = argparse.ArgumentParser(
        description=f"AgentKeyForge v{VERSION} — Forge strong secrets & scan agent configs. {SIGNATURE}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_gen = sub.add_parser("generate", help="Generate a cryptographically strong key")
    p_gen.add_argument("--length", type=int, default=32, help="Body length (default 32)")
    p_gen.add_argument("--charset", choices=list(CHARSETS.keys()), default="mixed")
    p_gen.add_argument("--prefix", default=None, help="Optional prefix e.g. sk-")
    p_gen.add_argument("--json", action="store_true")
    p_gen.set_defaults(func=cmd_generate)

    p_score = sub.add_parser("score", help="Score entropy of an existing key")
    p_score.add_argument("key", help="The key/string to score")
    p_score.add_argument("--json", action="store_true")
    p_score.set_defaults(func=cmd_score)

    p_scan = sub.add_parser("scan", help="Scan file or directory for secret patterns")
    p_scan.add_argument("target", help="File or directory to scan")
    p_scan.add_argument("--json", action="store_true")
    p_scan.set_defaults(func=cmd_scan)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
