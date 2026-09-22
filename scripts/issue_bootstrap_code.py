"""Create the first device's short-lived pairing code from the server host."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.storage import Storage


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=os.getenv("SESSION_NOTIFY_DB", "runtime/session_notify.db"))
    parser.add_argument("--json", action="store_true", help="Print the pairing result as JSON")
    args = parser.parse_args()
    storage = Storage(args.db)
    try:
        code, expires_at = storage.issue_bootstrap_code()
        if args.json:
            print(json.dumps({"code": code, "expires_at": expires_at.isoformat()}))
            return 0
        print(f"Pairing code: {code}")
        print(f"Expires: {expires_at.isoformat()}")
        print("Use this code with the client's Pair device action. Keep it private.")
        return 0
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 1
    finally:
        storage.close()


if __name__ == "__main__":
    raise SystemExit(main())
