#!/usr/bin/env bash
set -euo pipefail
mkdir -p outputs
{
  echo "== Docker =="; docker ps --format 'table {{.Names}}	{{.Image}}	{{.Status}}	{{.Ports}}'
  echo -e "\n== Nginx =="; docker logs lr3-threat-pack-nginx-1 2>/dev/null | tail -n 20 || true
  echo -e "\n== API =="; curl -s http://localhost:8080/health || true
} | tee outputs/env_report.txt
