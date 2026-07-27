#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com
"""
Kronagent — Analyst Console Web Server Runner.

Launches the FastAPI web server to host the incident approval queue,
audit explorer, and allowlist governance web dashboard.
"""

from __future__ import annotations

import argparse
import sys
import uvicorn


def main() -> int:
    parser = argparse.ArgumentParser(description="Start the Kronagent Analyst Console Web Server.")
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Bind address. Defaults to '127.0.0.1' (localhost)."
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to listen on. Defaults to 8000."
    )
    
    args = parser.parse_args()
    
    print(f"[*] Starting Kronagent Analyst Console on http://{args.host}:{args.port}")
    print("[*] Access the web UI dashboard directly in your browser.")
    
    try:
        uvicorn.run(
            "kronagent.web:app",
            host=args.host,
            port=args.port,
            log_level="info",
            reload=False
        )
    except KeyboardInterrupt:
        print("\n[*] Stopping Kronagent Analyst Console.")
    except Exception as exc:
        print(f"[-] Failed to start web console: {exc}", file=sys.stderr)
        return 1
        
    return 0


if __name__ == "__main__":
    sys.exit(main())
