#!/bin/sh
# Entrypoint for the self-contained image.
#
# SEED_SAMPLE=true writes the synthetic demo days so `docker run` lands on a populated app
# instead of an empty "no datasets yet" screen. It is opt-in and never overwrites an existing
# dataset: on a real /data volume this is a no-op, so it can't clobber a downloaded day.
# Datasets are namespaced by WAF type: DATA_DIR/<waf_type>/<date>/merged.json.
set -e

if [ "${SEED_SAMPLE:-false}" = "true" ]; then
  data_dir="${DATA_DIR:-/data}"
  # Front Door, two days: the 24th has the false positive firing, the 25th has it fixed — that
  # pair is what makes the before/after diff show something. See docs/walkthrough.md.
  if [ ! -f "$data_dir/frontdoor/2026-06-24/merged.json" ]; then
    python -m lawless_waf.sample "$data_dir/frontdoor/2026-06-24/merged.json"
  fi
  if [ ! -f "$data_dir/frontdoor/2026-06-25/merged.json" ]; then
    python -m lawless_waf.sample "$data_dir/frontdoor/2026-06-25/merged.json" --resolved
  fi
  # Application Gateway, one day — the same scenarios in the AppGw log schema, so the demo shows
  # both WAF types working.
  if [ ! -f "$data_dir/appgw/2026-06-24/merged.json" ]; then
    python -m lawless_waf.sample "$data_dir/appgw/2026-06-24/merged.json" --appgw
  fi
fi

exec "$@"
