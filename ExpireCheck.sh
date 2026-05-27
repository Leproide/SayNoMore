#!/bin/bash

DIR="${1:-/var/www/saynomore/data}"

NOW=$(date +%s)
LIMIT=$((NOW + 86400))

# COLORI CORRETTI
PURPLE='\033[0;35m'   # OK
ORANGE='\033[0;33m'   # EXPIRING
RED='\033[0;31m'      # EXPIRED
YELLOW='\033[1;33m'   # NO EXPIRES
NC='\033[0m'

echo "Scan dir: $DIR"
echo "Now: $(date -d @$NOW)"
echo "----------------------------------------"

ok=0
warn=0
expired=0
noexp=0

for f in "$DIR"/*; do
  [ -f "$f" ] || continue

  name=$(basename "$f")

  # skip file con estensione
  if [[ "$name" == *.* ]]; then
    continue
  fi

  expires=$(grep -o '"expires":[0-9]*' "$f" | cut -d: -f2)

  if [ -z "$expires" ]; then
    echo -e "${YELLOW}[NO EXPIRES] $f${NC}"
    ((noexp++))
    continue
  fi

  human=$(date -d "@$expires" '+%Y-%m-%d %H:%M:%S')

  if [ "$expires" -lt "$NOW" ]; then
    color=$RED
    status="EXPIRED"
    ((expired++))

  elif [ "$expires" -le "$LIMIT" ]; then
    color=$ORANGE
    status="EXPIRING <24h"
    ((warn++))

  else
    color=$PURPLE
    status="OK"
    ((ok++))
  fi

  echo -e "${color}$status $f -> $human${NC}"
done

echo "----------------------------------------"
echo "OK: $ok | WARN: $warn | EXPIRED: $expired | NO EXPIRES: $noexp"
