# Linux Endpoint Agent

A lightweight malware-scanning agent for Fedora and RHEL-family hosts. It runs a
scheduled ClamAV scan, adds file metadata to each detection, and forwards events to
Splunk over HTTP Event Collector (HEC). It is deployed with Ansible.

Nothing stays resident except a small forwarder (~17 MB). ClamAV signatures load
only while a scan is running, instead of a `clamd` daemon holding 1–1.5 GB of RAM
all day. The trade-off is that detection is **not real-time**: a file is found at
the next scheduled scan, up to about 26 hours later with the default schedule.

## How it works

```
endpoint-scan.timer ──► endpoint-scan.service ──► var/spool/*.json ──► endpoint-agent.service ──► Splunk HEC
  (daily, 02:00          (clamscan, oneshot,         (one file           (always running: queues
   + random delay)        then exits)                 per event)          in SQLite, retries, heartbeats)
```

- **Scan** (`endpoint_agent.py scan`): runs `clamscan` over `scan_paths`, writes one
  `malware_detection` event per hit (with SHA-256, owner, mode and timestamps) and a
  `scan_summary` event, then exits. It runs at low CPU and IO priority, in a
  read-only systemd sandbox.
- **Worker** (`endpoint_agent.py worker`): every 5 s, moves spool files into a
  SQLite queue and sends batches of up to 25 events to HEC. Failed sends are
  retried with exponential backoff, capped at 1 hour. Every hour it also sends an
  `agent_health` heartbeat.

### Events

All events share the `linux:security:telemetry` sourcetype and carry host metadata
(hostname, machine ID, OS).

| `event_type`        | When                                                            |
|---------------------|-----------------------------------------------------------------|
| `malware_detection` | One per infected file found by a scan (capped at 1000 per scan) |
| `scan_summary`      | Once per scan: status, file counts, duration, signature version |
| `agent_health`      | Hourly and at worker start: queue depth, last HEC success, last scan |
| `agent_error`       | The scan could not run `clamscan` at all                        |
| `agent_test`        | Written by `endpoint_agent.py test`                             |

In Splunk, alert when `agent_health` stops arriving from a host, or when
`health.last_scan.age_hours` exceeds 26.

If HEC is unreachable for a long time, the queue is capped at 50 000 events. When
it is full, the oldest non-detection events are dropped first.

## Requirements

- Fedora or a RHEL-family distribution (RHEL, Rocky, Alma) with systemd
- Python 3.6+ on the target (standard library only)
- ClamAV packages (`clamav`, `clamav-update`). On RHEL these come from EPEL or an
  internal repository.
- `ansible-core` on the control machine

## Install

1. Set the HEC connection in
   [`ansible/roles/linux_security_agent/defaults/main.yml`](ansible/roles/linux_security_agent/defaults/main.yml):

   ```yaml
   hec_url: "http://localhost:8088"   # http:// or https://
   hec_token: "dev-token-12345"
   hec_index: security
   hec_ca_file: ""                    # CA bundle for https; empty = system trust store
   ```

   Role defaults have the lowest precedence in Ansible, so inventory variables or
   `-e` override them. The defaults file stores the token in plain text, so don't
   commit a production token to it.

2. Deploy:

   ```bash
   ansible-playbook ansible/deploy.yml
   ```

   `deploy.yml` targets `localhost`. Change `hosts:` to deploy to an inventory.

The playbook installs ClamAV, seeds the signature database if it is empty, enables
`clamav-freshclam`, deploys the agent and its systemd units, and starts the worker
and the timer. If a host still has the older on-access setup (`clamonacc` and a
clamd `VirusEvent` hook), the playbook disables it.

## File layout

Everything lives under `agent_home` (`/opt/linux-security-agent`):

```
/opt/linux-security-agent/
├── bin/endpoint_agent.py
├── etc/
│   ├── agent.env        HEC settings and tuning (mode 0600)
│   └── scan.json        scan paths, exclusions, limits
└── var/
    ├── spool/           events waiting for the worker
    ├── lib/             events.db (queue), last_scan.json, tmp/
    └── log/             worker.log, scan.log (rotated at 10 MB, 5 kept)
```

Logs also go to the journal (`journalctl -u endpoint-agent -u endpoint-scan`). The
agent's own directory is always excluded from scans.

## Configuration

All settings are role variables in `defaults/main.yml`. The ones you're most
likely to change:

| Variable                  | Default                               | Purpose                                   |
|---------------------------|---------------------------------------|-------------------------------------------|
| `scan_paths`              | `/tmp /var/tmp /opt /usr/local`       | Directories to scan                       |
| `scan_exclude_dirs`       | `/proc /sys /dev /run /home /mnt`     | Regexes passed to `--exclude-dir`         |
| `scan_skip_fstypes`       | NFS, CIFS, SSHFS, Ceph, …             | Network filesystems are never scanned     |
| `scan_on_calendar`        | `*-*-* 02:00:00`                      | systemd `OnCalendar` for the timer        |
| `scan_randomized_delay`   | `2h`                                  | Spreads scans across a fleet              |
| `scan_cpu_quota` / `scan_memory_max` | `50%` / `2G`               | Limits for the scan service               |
| `scan_protect_home`       | `"true"`                              | Hide `/home`, `/root` and `/run/user` from the scan |
| `scan_run_on_deploy`      | `false`                               | Start a scan as soon as the playbook finishes |
| `agent_heartbeat_interval`| `3600`                                | Seconds between `agent_health` events     |
| `agent_max_queue_events`  | `50000`                               | Queue cap while HEC is unreachable        |

The playbook fails if a path in `scan_paths` is on a network filesystem.

## Operating

```bash
# Run a scan now instead of waiting for the timer
sudo systemctl start endpoint-scan.service

# Next scheduled run
systemctl list-timers endpoint-scan.timer

# Follow the forwarder / last scan
tail -f /opt/linux-security-agent/var/log/worker.log
sudo cat /opt/linux-security-agent/var/lib/last_scan.json

# Push a synthetic event through the pipeline
sudo bash -c 'set -a; . /opt/linux-security-agent/etc/agent.env; \
  python3 /opt/linux-security-agent/bin/endpoint_agent.py test'
```

The `scan` mode exits with 0 when a scan completes, whether or not it finds
anything, and with 1 when the scan fails or there is nothing to scan.

## Uninstall

```bash
ansible-playbook ansible/deploy.yml -e agent_uninstall=true
```

This stops and removes the units and deletes `/opt/linux-security-agent`. Before
deleting anything, it tries once to send queued events to HEC. Events that can't
be delivered are deleted, and the playbook prints a warning. Related variables:

| Variable                   | Default | Effect                                        |
|----------------------------|---------|-----------------------------------------------|
| `agent_uninstall_flush`    | `true`  | Try to send queued events before removing the agent |
| `agent_uninstall_packages` | `false` | Also remove ClamAV and stop `clamav-freshclam` |

ClamAV is kept by default because other software on the host may use it.

## Local testing with the mock HEC server

`splunk_server.py` is a minimal HTTP (no TLS) HEC endpoint for development. It
accepts `/services/collector/event`, prints each request and event to the console,
and appends events to `hec_events.jsonl`.

```bash
HEC_TOKEN=dev-token-12345 python3 splunk_server.py
```

| Variable          | Default              |                                         |
|-------------------|----------------------|-----------------------------------------|
| `HEC_TOKEN`       | (required)           | Must match `hec_token`                  |
| `HEC_HOST` / `HEC_PORT` | `127.0.0.1` / `8088` |                                   |
| `HEC_DATA_FILE`   | `./hec_events.jsonl` |                                         |
| `HEC_SHOW_EVENTS` | `1`                  | `0` prints only one-line summaries      |

`GET /health` returns the server status. `GET /events` (with the token) returns
the last 100 stored events.

To test an end-to-end detection, put the harmless
[EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) in a
scanned directory, run a scan, and watch for a `malware_detection` event in the
mock server's output.
