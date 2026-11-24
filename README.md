# ecpp — Exim & Mail Log Forensics / Outbound Spam Analyzer (`v2.0.0`)

![ecpp cover](ecpp-cover.webp)

A modern, standalone Bash + Python 3 CLI for **Exim mail log forensics, outbound spam triage, PHP `cwd=` script-origin tracking, IMAP/POP3 auth IP correlation, and bounce analysis** — replacing legacy 2009–2013 Perl `ecpp_2.pl` with pure Python 3 stdlib and `table` / `json` / `csv` outputs.

## Historical Modernization

Inspired by **`ecpp_2.pl` (version `20130416`, 2009–2013)** authored by **Michael Karr** (`© 2012 — HostGator.com, LLC`, with contributions by `jcarter`).

In `v2.0.0`, the 1,490-line legacy Perl script was reimplemented in **Bash + Python 3.6+ (stdlib)**:
- **Eliminated Legacy Perl Modules**: Removed `IO::Uncompress::Gunzip`, `FileHandle`, `Time::Local`, and `File::stat` in favor of native Python `gzip`, `datetime`, and `collections.Counter`.
- **Removed Dead Links & Fragile Splits**: Removed `git.toolbox.hostgator.com`, `gatorwiki.hostgator.com`, and `bugs.hostgator.com` references, and hardened Exim `A=`, `H=[]`, `cwd=`, `T="..."`, and bounce (`**`) parsing.
- **Structured Outputs**: Added `json` and `csv` alongside the forensic terminal report, plus `--exim-log` / `--mail-log` / `--no-time-filter` for offline incident analysis.

## Usage

```bash
./ecpp.sh <user|domain|root> [OPTIONS]
```

## Real Output Example

```text
$ ./ecpp.sh percio --exim-log /tmp/ecpp-e2e/exim_mainlog --no-time-filter --no-color
=== ecpp.sh v2.0.0 | Mail Log Forensics Report ===
  Target:     percio
  Window:     2026-11-22 01:05:00 -> 2026-11-24 01:05:00
  Summary:    Sent: 3 | Delivered: 2 | Bounces: 1 | Unique Recips: 2

--- Top Senders / Auth ---
      2  mailer@example.com
      1  percio@host.example.com

--- Top Source IPs ---
      2  198.51.100.42

--- Top Script CWDs ---
      1  /home/percio/public_html/wp-content/uploads
```

## License

Apache-2.0 — see [LICENSE](LICENSE).
