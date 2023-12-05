#!/usr/bin/env bash
set -euo pipefail
FROM=$(echo -n $1 | xxd -p)
cat delete.sql | sed "s/###/$FROM/g" | psql merkle
rm -r "db/lev$FROM"
