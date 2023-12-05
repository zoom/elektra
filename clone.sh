#!/usr/bin/env bash
set -euo pipefail
FROM=$(echo -n $1 | xxd -p)
TO=$(echo -n $2 | xxd -p)
cat clone.sql | sed "s/@@@/$TO/g" | sed "s/###/$FROM/g" | psql merkle
cp -r "db/lev$FROM" "db/lev$TO"
