# ecpp — Análisis Forense de Logs Exim y Correo Saliente (`v2.0.0`)

![ecpp cover](ecpp-cover.webp)

Una CLI moderna e independiente en Bash + Python 3 para **análisis forense de logs Exim, triaje de spam saliente, rastreo de scripts PHP (`cwd=`), correlación de IPs IMAP/POP3 y conteo de rebotes** — reemplazando el legado en Perl `ecpp_2.pl` (2009–2013) con Python 3 stdlib y salidas `table` / `json` / `csv`.

## Modernización Histórica

Inspirado en **`ecpp_2.pl` (versión `20130416`, 2009–2013)** desarrollado por **Michael Karr** (`© 2012 — HostGator.com, LLC`, con aportes de `jcarter`).

En `v2.0.0`, el script Perl original de 1.490 líneas fue reescrito en **Bash + Python 3.6+ (stdlib)** eliminando módulos Perl obsoletos, enlaces muertos de HostGator y añadiendo salidas `json`/`csv` y modo forense offline (`--exim-log`, `--mail-log`).

## Ejemplo de Salida Real

```text
$ ./ecpp.sh percio --exim-log /tmp/ecpp-e2e/exim_mainlog --no-time-filter --no-color
=== ecpp.sh v2.0.0 | Mail Log Forensics Report ===
  Target:     percio
  Window:     2026-11-22 01:05:00 -> 2026-11-24 01:05:00
  Summary:    Sent: 3 | Delivered: 2 | Bounces: 1 | Unique Recips: 2
```

## Licencia

Apache-2.0 — ver [LICENSE](LICENSE).
