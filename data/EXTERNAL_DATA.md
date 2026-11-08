# External data adapters

Third-party datasets are kept as local ignored inputs and are not source
artifacts. Obtain each source directly and check its current terms before use or
redistribution.

## Schonlau masquerade data

The official page describes 50 files with 15,000 command lines each: the first
5,000 are clean baseline data, followed by 100 blocks of 100 commands. The
separate contamination matrix is 100 rows by 50 columns. Files named `User1`
through `User50` are ordered numerically to match matrix columns. It creates
one baseline training record and 100 labeled test
records per user. These blocks are benchmark units from a continuous trace, not
independent real SSH sessions.

```powershell
python data/load_schonlau.py .\datasets\schonlau\commands .\datasets\schonlau\locations.txt --output data\schonlau_sessions.jsonl
```

Source and format: [Schonlau masquerading-user data](https://schonlau.net/intrusion.html).
The source page provides downloads but does not state a clear reuse license;
confirm permission before redistribution or publication.

## Cowrie JSONL

Supply Cowrie JSON output (`cowrie.json`, one JSON event object per line). The
adapter groups `cowrie.command.input` events by session, orders them by
timestamp, excludes events with `realm` (interactive program input), ignores
all other events (including authentication records), then splits whole
sessions into train/validation/test. Collection-specific privacy, consent, and
license terms remain the operator's responsibility.

```powershell
python data/load_cowrie.py .\datasets\cowrie\cowrie.json --output data\cowrie_sessions.jsonl
```

Cowrie's event schema documents shared `session`, `timestamp`, and `eventid`
fields and the `input`/optional `realm` fields for `cowrie.command.input`:
[Cowrie output event reference](https://docs.cowrie.org/en/stable/OUTPUT.html).

## COW160 Cowrie corpus

The project includes a range downloader for one daily event log from the
[COW160x4 Zenodo record](https://zenodo.org/records/21260400), whose API
metadata reports CC BY 4.0. The full `data_all.zip` is about 19.4 GB; the
script requests only one dated member and refuses to continue if the server
does not honor byte ranges. It downloads event logs only, not the separate
archive containing transferred file payloads.

```powershell
python data/fetch_cow160_day.py --day 2025-06-27
python data/load_cowrie.py data/external_raw/cowrie/cow160_2025-06-27.json.gz --output data/cowrie_sessions.jsonl
```

The gateway reads `CZTS_ATTACKER_SESSIONS` and trains its attacker transition
profile only from records marked `split=train`. Validation and test sessions
remain excluded. Re-start the gateway after regenerating the converted file.
Attribute the data to “Deployment of 160 Cowrie SSH honeypot instances across
four distinct configurations,” Zenodo record 21260400, CC BY 4.0.

For the temporal multi-day experiment, fetch at least six days (the existing
2025-06-27 day plus five later days) with:

```powershell
python data/fetch_cow160_days.py 2025-06-28 2025-06-29 2025-06-30 2025-07-01 2025-07-02 --workers 4
python eval/scripts/evaluate_cowrie_multiday.py
```

The experiment builds an expanding temporal split: each held-out day is scored
against an attacker profile trained only on earlier days. It calibrates a
profile-match threshold using separate synthetic benign validation sessions
and reports held-out synthetic benign false positives separately from Cowrie
detection. The generated `data/cowrie_multiday_sessions.jsonl` marks the first
four days `train` and the final two `test`; the gateway consumes only rows with
`split=train`. Raw daily downloads and generated JSONL remain ignored local
data. This is a honeypot sequence validation, not live gateway accuracy.

These adapters only normalize data. They do not assert that honeypot traffic is
representative of attackers against an authenticated production gateway.
