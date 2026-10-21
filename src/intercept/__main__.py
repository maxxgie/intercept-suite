"""Allow the package to be executed with ``python -m intercept``."""

from intercept.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
