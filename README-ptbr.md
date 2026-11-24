# ecpp — Análise Forense de Logs Exim e Combate a Spam (`v2.0.0`)

Uma CLI moderna e independente em Bash + Python 3 para **análise forense de logs do Exim, triagem de spam de saída, rastreio de scripts PHP (`cwd=`), correlação de IPs IMAP/POP3 e contagem de bounces** — substituindo o legado em Perl `ecpp_2.pl` (2009–2013) por Python 3 stdlib com saídas `table` / `json` / `csv`.

## Modernização Histórica

Inspirado no **`ecpp_2.pl` (versão `20130416`, 2009–2013)** criado por **Michael Karr** (`© 2012 — HostGator.com, LLC`, com contribuições de `jcarter`).

Na versão `v2.0.0`, o script Perl legado de 1.490 linhas foi reescrito em **Bash + Python 3.6+ (stdlib)**:
- **Remoção de Módulos Perl Antigos**: Elimina `IO::Uncompress::Gunzip`, `FileHandle`, `Time::Local` e `File::stat`, utilizando `gzip`, `datetime` e `collections.Counter` nativos.
- **Fim de URLs Mortas e Splits Frágeis**: Remove referências internas da HostGator e endurece o parsing de `A=`, `H=[]`, `cwd=`, `T="..."` e bounces (`**`).
- **Saídas Estruturadas**: Adiciona exportação `json` e `csv` e flags `--exim-log` / `--mail-log` / `--no-time-filter` para forense offline.

## Exemplo de Saída Real

```text
$ ./ecpp.sh percio --exim-log /tmp/ecpp-e2e/exim_mainlog --no-time-filter --no-color
=== ecpp.sh v2.0.0 | Mail Log Forensics Report ===
  Target:     percio
  Window:     2026-11-22 01:05:00 -> 2026-11-24 01:05:00
  Summary:    Sent: 3 | Delivered: 2 | Bounces: 1 | Unique Recips: 2
```

## Licença

Apache-2.0 — veja [LICENSE](LICENSE).
