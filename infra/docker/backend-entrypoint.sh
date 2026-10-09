#!/bin/sh
set -eu

if [ "${RUN_DB_MIGRATIONS:-true}" = "true" ]; then
    python -m vulnhunter.database.init_db
fi
exec "$@"
