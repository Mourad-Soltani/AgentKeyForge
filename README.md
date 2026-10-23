# AgentKeyForge

**Offline CLI for forging cryptographically strong secrets and scanning AI agent configs for leakage.**

Built by Mourad.Soltani

## What you get
- Pure Python 3.8+ stdlib CLI (no dependencies)
- `generate` — cryptographically secure keys/passphrases with entropy score
- `score` — entropy rating for existing secrets
- `scan` — basic pattern detection for common secret leaks in skill/config files
- JSON output for scripting
- Health tests included

## How to run in 30 seconds
```bash
# Generate a 32-char mixed key
python agentkeyforge.py generate

# With prefix and JSON
python agentkeyforge.py generate --length 40 --charset hex --prefix sk- --json

# Score an existing key
python agentkeyforge.py score "my-weak-password"

# Scan a directory
python agentkeyforge.py scan ./my-agent-skills --json
```

## Requirements
- Python 3.8 or newer
- No external packages

## License
MIT — see LICENSE

Built by Mourad.Soltani
