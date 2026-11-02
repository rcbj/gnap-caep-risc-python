# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

"""Write a P-256 private key and self-signed certificate at the file: paths in a configuration."""

import json
import os
import sys
from pathlib import Path

from .x509gen import create_self_signed_key_pair


def _usage() -> str:
    return """Usage: gnap-caep-risc generate-key --config gnap.json [--cn name] [--days 1095] [--force]

Writes a P-256 private key and a self-signed certificate at the file: paths in the configuration
(privateKey and certificate). A path that already exists is left alone unless --force is given."""


def _destination(raw, base: Path, what: str):
    if not raw:
        return None
    if str(raw).startswith("env:"):
        raise SystemExit(f"{what} is {raw}; this command only writes file: paths")
    if "-----BEGIN" in str(raw):
        raise SystemExit(f"{what} is inline PEM; this command only writes file: paths")
    path = str(raw)[5:] if str(raw).startswith("file:") else str(raw)
    return Path(path) if Path(path).is_absolute() else base / path


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] != "generate-key":
        print(_usage())
        if argv:
            sys.exit(1)
        return
    config = ""
    cn = ""
    days = 1095
    force = False
    index = 1
    while index < len(argv):
        arg = argv[index]
        def value():
            nonlocal index
            index += 1
            if index >= len(argv):
                raise SystemExit(f"{arg} needs a value")
            return argv[index]
        if arg == "--config":
            config = value()
        elif arg == "--cn":
            cn = value()
        elif arg == "--days":
            days = float(value())
        elif arg == "--force":
            force = True
        elif arg in ("--help", "-h"):
            print(_usage())
            return
        else:
            raise SystemExit(f"Unknown argument {arg}\n{_usage()}")
        index += 1
    if not config:
        raise SystemExit(f"--config is required\n{_usage()}")
    if days < 1:
        raise SystemExit("--days must be a positive number")
    full = Path(config).resolve()
    raw = json.loads(full.read_text(encoding="utf-8"))
    base = full.parent
    key_path = _destination(raw.get("privateKey"), base, "privateKey")
    cert_path = _destination(raw.get("certificate"), base, "certificate")
    if key_path is None:
        raise SystemExit("the configuration has no privateKey path to write")
    if not force and key_path.exists() and (cert_path is None or cert_path.exists()):
        print(f"Key already at {key_path}. Pass --force to replace it.")
        return
    name = cn or ((raw.get("display") or {}).get("name")) or raw.get("application") or "gnap-client"
    pair = create_self_signed_key_pair(name, days=int(days))
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(pair.private_key_pem, encoding="utf-8")
    os.chmod(key_path, 0o600)
    if cert_path:
        cert_path.parent.mkdir(parents=True, exist_ok=True)
        cert_path.write_text(pair.certificate_pem, encoding="utf-8")
    print(f"Wrote {key_path}")
    if cert_path:
        print(f"Wrote {cert_path}")
    print(f"sha256 {pair.fingerprint256}")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as err:
        print(str(err), file=sys.stderr)
        sys.exit(1)
