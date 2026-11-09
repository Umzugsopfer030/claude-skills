# Claude Code Skills

Eigene Slash-Commands für [Claude Code](https://claude.com/claude-code).

## `/hardening`: System Hardening & Enforce Administration

Prüft ein Windows-Gerät auf typische Härtungs-Kriterien (angelehnt an **BSI IT-Grundschutz SYS.2.2.3** und den
**CIS Microsoft Windows Benchmark**), schreibt einen Report mit Ampel-Bewertung und erzeugt ein PowerShell-Skript
für Administratoren, das die gefundenen Schwachstellen behebt.

### Ablauf

| Schritt | Was passiert |
|---|---|
| 1. Live-Audit | Nur lesende PowerShell-Abfragen: Firewall, Defender, lokale Konten, Kennwort- und Sperr-Richtlinie, SMBv1, RDP, lauschende Ports, BitLocker/TPM |
| 2. Report | `docs/hardening-report.md` mit 🟢 Gehärtet / 🟡 Warnung / 🔴 Risiko, Soll-Werten und Empfehlungen |
| 3. Enforce-Skript | `src/enforce-hardening.ps1` mit `-WhatIf` (Dry-Run) und `-Confirm`, idempotent, mit Protokoll |
| 4. Backup | Sichert alles per `/save`, aber **nur in ein privates Repository** |

### Sicherheitsprinzipien

- Der Audit ist **read-only**. Der Skill verbietet Claude alle ändernden Befehle.
- Das Enforce-Skript wird **nie automatisch ausgeführt**, auch nicht mit `-WhatIf`.
- Ohne Schalter zeigt das Skript nur die Hilfe an. Echte Änderungen brauchen Adminrechte.
- Das eingebaute Administrator-Konto wird nicht angefasst (Aussperr-Gefahr), RDP wird nur mit `-DisableRDP` abgeschaltet.
- Der Report wird nicht in öffentliche Repositorys hochgeladen, weil er Schwachstellen des Geräts verrät.

### Installation

1. `.claude/commands/hardening.md` in den Ordner `.claude/commands/` deines Projekts kopieren
   (oder nach `~/.claude/commands/`, dann gilt der Skill für alle Projekte).
2. In Claude Code `/hardening` eingeben.

Schritt 4 nutzt einen eigenen `/save`-Skill (committen und pushen). Ohne ihn überspringt Claude das Backup
oder du sicherst selbst mit `git`.

### Das Enforce-Skript

Ein Beispiel liegt unter [`examples/enforce-hardening.ps1`](examples/enforce-hardening.ps1).

```powershell
# Dry-Run: zeigt nur an, was geändert würde (geht ohne Adminrechte)
.\enforce-hardening.ps1 -All -WhatIf

# Echte Härtung mit Rückfrage vor jeder Änderung (PowerShell als Administrator)
.\enforce-hardening.ps1 -All -Confirm

# Nur einzelne Bereiche
.\enforce-hardening.ps1 -Firewall -PasswordPolicy -WhatIf
```

| Schalter | Wirkung |
|---|---|
| `-Firewall` | Alle Profile an, eingehend blockieren |
| `-Defender` | Echtzeitschutz an, Signaturen aktualisieren |
| `-GuestAccount` | Gastkonto deaktivieren |
| `-SMBv1` | SMBv1 abschalten (Neustart nötig) |
| `-PasswordPolicy` | Kennwortlänge 14, Chronik 24, Sperre nach 5 Versuchen für 15 Min. |
| `-RDP` | NLA erzwingen, mit `-DisableRDP` RDP ganz aus |
| `-FirewallRules` | Riskante eingehende Freigaben deaktivieren (Standard: MySQL 3306/33060, `node.exe` im Public-Profil) |

> ⚠️ **Auf verwalteten Geräten (Schule, Firma) nur nach Freigabe durch die IT ausführen.**
> Gruppenrichtlinien oder Intune können lokale Einstellungen überschreiben.

## Lizenz

[MIT](LICENSE)
