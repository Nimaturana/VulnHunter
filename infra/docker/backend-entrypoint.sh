#!/bin/sh
set -eu

python -m vulnhunter.database.init_db
exec "$@"
