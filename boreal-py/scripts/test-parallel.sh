#!/usr/bin/env sh

set -eux

export BOREAL_PY_TESTS_NO_YARA=1

uv run -p 3.14+freethreaded pytest -v --parallel-threads=10 --iterations=10 -m "not global_config"
uv run -p 3.14+freethreaded pytest -v --parallel-threads=10 --iterations=10 -m "global_config(yara_compat_mode=True)"
uv run -p 3.14+freethreaded pytest -v --parallel-threads=10 --iterations=10 -m "global_config and not global_config(yara_compat_mode=True)"
