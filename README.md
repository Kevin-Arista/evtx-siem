# etw-Based SIEM

> A lightweight SIEM in Python that ingests Windows `.evtx` logs, normalizes them into a common schema, and runs detections and correlations across files, with an AI layer that explains alerts instead of deciding them. I've divided this project into two parts: "Fundamental" and "AI-integration" Phases.


> Currently in the Fundamental Phase of the project. 

```
ingest → normalize → store → detect → correlate → explain
```
---

## Why this project

Security analysts often get a pile of `.evtx` files (Security, System, Sysmon, PowerShell) and need answers to questions that span all of them:

- *Did those failed logons end in a successful one?*
- *What did that user do after logging in?*
- *Which process spawned this PowerShell, and what did it touch next?*
- *What process injected DLL into temp process?*
- *What happened 5mins before and after the event occured?*


Once Fundamental SIEM is built, We can employ ML:
- *What is a normal parent-child process, how can we use AI to detect anomalies? (isolated forest)*


It's built to learn how a SIEM works internally and to practice Windows log analysis and detection engineering.

---

## Architecture

```
            ┌─────────────────────────────┐
            │  evtx/: collect .evtx logs  │ all inside same single folder
            └────────────┬────────────────┘
                         ▼
      ┌──────────────────────────────────────────┐
      │  ingest.py: Schema on Write/read Hybrid  │
      └──────────────────┬───────────────────────┘
                         ▼
            ┌─────────────────────────────────┐
            │  siem.duckdb: 'events' table    │  one table, shared columns + JSON column
            └────────────┬────────────────────┘
          ┌──────────────┼───────────────────┐
          ▼              ▼                   ▼
   ┌────────────┐  ┌──────────────────┐   ┌──────────────┐
   │ Detections │  │   Correlation    │   │  Outputs     │
   │ YAML+SQL / │─▶│  process tree   │──▶│  CLI report  │
   │ Sigma      │  │  triage + speed  │   │  Elastic     │
   └────────────┘  │ session tracking │   └──────────────┘
                   └────────┬─────────┘
                            ▼
                     ┌──────────────┐
                     │  AI layer    │  summaries, triage, NL→SQL, reports
                     └──────────────┘
```

### Design principles

Fundamental Phase

1. **One all-encompassing events table** All .evtx logs will have System.* keys, which will zone out data extremely fast with column partitionining.
2. **Detections are yaml files found inside 'detections/'** Adding a detection means adding a Sigma file.
3. **Schema on Write/Read Hybrid**


AI Integration Phase:


1. **Rules detect, AI explains.** The LLM never creates or dismisses an alert on its own.
2. **Every claim is traceable.** Alerts and AI output reference the original event record IDs.

---

## Tech stack

| Layer | Tool |
|---|---|
| Language | Python 3.11+ |
| `.evtx` parsing | [evtxParser](https://pypi.org/project/python-evtx/)
| Storage and queries | [DuckDB](https://duckdb.org/) (embedded, SQL, no server) |
| Detection rules | YAML + SQL, [Sigma](https://github.com/SigmaHQ/sigma) via [`pySigma`](https://github.com/SigmaHQ/pySigma) |

---

## Schema Hybrid

```sql
CREATE OR REPLACE TABLE events (
    provider        VARCHAR        NOT NULL,
    event_id        UBIGINT        NOT NULL,
    timestamp       TIMESTAMP      NOT NULL,
    record_id       UBIGINT        NOT NULL,
    channel         VARCHAR        NOT NULL,
    computer        VARCHAR        NOT NULL,
    event_data      JSON           DEFAULT NULL,
    user_data       JSON           DEFAULT NULL
);
```

---

## Usage
commands: ingest, run, timeline
```bash
# Ingest a file/folder of .evtx files into DuckDB, it will auto append or create a new database file if one does not exist
python siem.py ingest --log <log-path> --db <db-path>
python siem.py ingest --log <logs-paths> --db <db-path>

# Run a saved query or all queries and generate alerts table, eventually export parquet files
python siem.py run --rule <detection-path> --db <db-path>
python siem.py run --rule <detections-path> --db <db-path>

# Timeline for one host, anchoring to a specific alertID or eventRecordID, must provide User GUID
python siem.py timeline --host <hostname> --from <timestamp> --to <timestamp>
python siem.py timeline --host <hostname> --recordID <eventRecordID>

# use AI to explain an alert and reduce alert fatigue
python siem.py explain --alert 42
```

## Directory Structure

```
.
├── logs/              # Windows Event Log files (.evtx)
├── db/                # DuckDB database files (.duckdb)
├── rules/             # Sigma detection rules (.yml)
├── modules/
│   ├── ingest.py      # Loads .evtx files into DuckDB (creates or appends)
│   ├── run.py         # Runs Sigma rules and writes matches to an alerts table
│   └── timeline.py    # Builds a per-host event timeline by time range or record ID
└── siem.py            # CLI entry point (ingest, run, timeline)
```


---
## Lessons
Schema on Read v Schema on Write :
- Schema on Write means you parse and force a schema on logs before storing in them in the SIEM database
- Schema on Read means you store logs as is in the database, so you delay parsing them until you query them 

Modern SIEM will use a hybrid model. They use Schema on Write, when dealing with high priority logs that should be able to be zoned easily when quering-- such as security events. Schema on Read, is delayed parsing, so you store the raw data log as is, and only parse it when you want to read it, you parse however you like.
- Schema on Write Example: parsing Windows Sysmon Events using Envelope + Payload approach, using System.* keys as columns, and storing the rest of the json in "event_data" column, where it is a JSON string, not just a raw string of data.
- Schema on Read Example: data that is classified as noisy such as DNS queries, you don't really have to run all sorts of complex queries on them. 

Parsing EVTX NDJSON objects:
- When normalizing our object with the read_json(), it converts the ndjson obj into STRUCT implicilty, so we explicity define to read as JSON using 'columns = {Event: 'JSON'}'. This is beacause column names are case-insensitive and ProcessGUID and ProcessGuid are interpreted as the same. 
- Additionally, if an event, doesn't a specified key, the object will not be skipped and istead just fill in that column as NULL.

## TODO

Ensure we watch out for duplicates. Make sure, we make a primary key-- called hash. And we hash not only the "event_data", but the whole ndjson log-- or at least the columns we are choosing to abstract and the eventData or userData.
---

## Testing and validation

- **Count parity:** event counts per file/ID must match `Get-WinEvent`.
- **Detection tests:** each rule has a positive and a negative sample.
- **Reference tools:** compare findings with [Chainsaw](https://github.com/WithSecureLabs/chainsaw) and [Hayabusa](https://github.com/Yamato-Security/hayabusa).
- **Attack data:** generate telemetry with [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) in an isolated Windows VM.

---

## Data and safety

- Only analyze logs you own or that are published for research.
- Never commit real logs containing personal data. `logs/` and `*.duckdb` are git-ignored.
- Run attack simulations only in isolated lab VMs.

---

## References

- [Microsoft: Windows Security audit events](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [SigmaHQ](https://github.com/SigmaHQ/sigma)

---

## License

MIT (to be added).
