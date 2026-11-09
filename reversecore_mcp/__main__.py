"""Module entrypoint for python -m reversecore_mcp."""

import sys

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("setup", "--setup"):
        from reversecore_mcp.setup import main as setup_main

        sys.exit(setup_main(sys.argv[2:]))

    from reversecore_mcp.server import main

    main()
