# Attack statistics export

CSV snapshots exported from the running platform with
[`export_stats.py`](../export_stats.py):

```bash
python3 export_stats.py                               # production
python3 export_stats.py --url http://localhost:8000   # local instance
```

Each run overwrites these files. [`EXPORT.txt`](EXPORT.txt) records the source host,
export timestamp, server mode and the running totals at that moment.

> **Mode matters.** When `EXPORT.txt` says `mode: simulation`, the rows come from the
> built-in attack generator, not from real FTTH traffic — demo data, not incident data.
> A capture taken while the server runs with `--live` contains only ingested events.

## Files

| File | Grain | Columns |
|---|---|---|
| [`attacks_timeseries.csv`](attacks_timeseries.csv) | one row per bucket per range | `range` (day/month/year), `bucket` (hour `14h`, day `09-21`, month `2026-09`), `attacks` |
| [`attacks_by_zone.csv`](attacks_by_zone.csv) | top 10 zones per range, both directions | `range`, `direction` (`target` = attacked, `origin` = attacked from), `zone`, `attacks` |
| [`zone_status.csv`](zone_status.csv) | one row per province, live snapshot | `zone_id`, `zone`, `risk` (0–1), `onts`, `compromised`, `suspicious`, `severity`, `attack_origin`, `alert_since` |
| [`attacker_sources.csv`](attacker_sources.csv) | top attacker IPs, 5-minute window | `ip`, `hits` |

`range` buckets are fixed windows: `day` = 24 hourly buckets, `month` = 30 daily,
`year` = 12 monthly. Buckets with no attacks are kept as zero rows so the series is
complete and plots without gaps.

`zone_status.csv` is a point-in-time snapshot — the `severity`, `attack_origin` and
`alert_since` columns are empty for any zone without an active alert at export time.
