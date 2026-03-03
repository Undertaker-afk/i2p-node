# AGENTS

Diese Datei beschreibt, wie Codex in diesem Repository arbeiten soll.

## Zweck
- Fokus auf Interop mit realen I2P-Peers (i2pd/Java I2P).
- Änderungen klein, testbar und protocol-first halten.
- Bei NTCP2/SSU2-Problemen immer zuerst Logs + Handshake-Status auswerten.

## Verhalten von Codex in diesem Repo
- Vor Änderungen zuerst vorhandene Implementierung lesen (`src/transport/ntcp2.ts`, `src/transport/ssu2.ts`, `src/router.ts`, `src/netdb/index.ts`).
- Root-Cause fixen, keine kosmetischen Workarounds.
- Keine unnötigen Refactors oder große Umbenennungen.
- Änderungen so halten, dass sie mit i2pd-Semantik kompatibel bleiben (Timeouts, Retry, State-Transitions).
- Nach Änderungen mindestens TypeScript-Fehler prüfen.
- Keine Commits/Branches automatisch erzeugen, außer explizit angefragt.

## Build/Run
```bash
npm run build
node start.mjs
```

## Logging und Debug-Umgebungsvariablen

### Allgemeines Log-Level
`start.mjs` setzt standardmäßig DEBUG:
- `logger.setLevel(LogLevel.DEBUG)`
- Router-Option: `logLevel: LogLevel.DEBUG`

Wenn in anderem Entry-Point nötig:
- `logger.setLevel(LogLevel.INFO | DEBUG | WARN | ERROR | FATAL)`

### Debug-Flags für Transporte
- `NTCP2_DEBUG=1`
  - Aktiviert ausführliche NTCP2-Handshake-/Frame-Debugausgaben.
- `TRANSPORT_KEY_DEBUG=1`
  - Aktiviert Key-/Interface-Snapshots für **beide** Transporte.
- `NTCP2_KEY_DEBUG=1`
  - Aktiviert Key-/Interface-Snapshots nur für NTCP2.
- `SSU2_KEY_DEBUG=1`
  - Aktiviert Key-/Interface-Snapshots nur für SSU2.

### Dateilog für Auswertung
- `I2P_LOG_FILE=/pfad/zur/datei.log`
  - Überschreibt den Zielpfad für JSON-Logzeilen aus `start.mjs`.
  - Default: `./i2p-test-data/router-debug.log`.

## Empfohlene Debug-Kommandos

### Voller Transport-Debug (empfohlen für Protokollfixes)
```bash
npm run build
TRANSPORT_KEY_DEBUG=1 NTCP2_DEBUG=1 node start.mjs
```

### Nur NTCP2-Key-Debug
```bash
NTCP2_KEY_DEBUG=1 NTCP2_DEBUG=1 node start.mjs
```

### Nur SSU2-Key-Debug
```bash
SSU2_KEY_DEBUG=1 node start.mjs
```

### Eigene Logdatei nutzen
```bash
I2P_LOG_FILE=./i2p-test-data/router-debug-run2.log TRANSPORT_KEY_DEBUG=1 NTCP2_DEBUG=1 node start.mjs
```

## Debug-Workflow (kurz)
1. Router 60–120s laufen lassen.
2. `i2p-test-data/router-debug.log` prüfen.
3. Auf Muster achten:
   - `NTCP2 connection failed` / `connect timeout`
   - `SSU2 connect timeout`
   - Interface-Snapshots bei `...-established` vs. Abbruchpfade
4. Nur gezielte Fixes auf den fehlschlagenden Handshake-Schritt anwenden.

## Prioritäten für nächste Protokollfixes
- SSU2 Retry/TokenRequest-Pfad weiter an i2pd angleichen.
- NTCP2 Timeout-/Termination-Gründe präzise mappen.
- IPv6-Pfade sauber trennen (udp4 vs. udp6) statt implizit zu failen.
