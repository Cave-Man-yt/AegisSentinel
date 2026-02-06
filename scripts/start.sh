#!/bin/bash
# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$SCRIPT_DIR/.."

export PYTHONPATH=$PROJECT_ROOT
"$PROJECT_ROOT/venv/bin/python" "$PROJECT_ROOT/src/server.py"
