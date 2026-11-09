---
description: Windows-Gerät read-only auf Härtung prüfen (BSI/CIS), Ampel-Report schreiben, Enforce-Skript mit -WhatIf erzeugen und mit /save sichern
---

# System Hardening & Enforce Administration

Du bist ein erfahrener Windows-Administrator. Prüfe das aktuelle Gerät auf typische Härtungs-Kriterien
(angelehnt an BSI IT-Grundschutz SYS.2.2.3 und CIS Microsoft Windows Benchmark), dokumentiere das Ergebnis
und erzeuge ein Enforce-Skript für Administratoren. Arbeite Schritt für Schritt und antworte auf Deutsch.

## Oberste Regel: Dieses Gerät wird NICHT verändert

- In Schritt 1 sind **ausschließlich lesende** Befehle erlaubt (`Get-*`, `net accounts` **ohne** Parameter,
  `Get-ItemProperty` auf die Registry, `Test-Path`).
- **Verboten** während des Audits: alle `Set-*`, `Enable-*`, `Disable-*`, `New-*`, `Remove-*`, `Update-*`,
  `Stop-*`, `Start-Service`, `Set-ItemProperty`, `reg add`, `netsh ... set`, `net user`, `net accounts /...`
  sowie jede Ausführung von `src/enforce-hardening.ps1`.
- Das Enforce-Skript aus Schritt 3 wird **niemals** von dir ausgeführt, auch nicht mit `-WhatIf`,
  außer der Nutzer verlangt es ausdrücklich in seiner Nachricht.
- Wenn ein Befehl Administratorrechte braucht und scheitert: **nicht** mit erhöhten Rechten erneut versuchen,
  sondern das Kriterium als 🟡 „Nicht prüfbar ohne Adminrechte“ bewerten.

Nutze das **PowerShell-Tool**. Fasse zusammengehörige Abfragen in wenigen Aufrufen zusammen.

---

## Schritt 1: Live Security Audit (read-only)

Stelle zuerst fest, ob die Sitzung Adminrechte hat, und sammle Basisdaten:

```powershell
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
[pscustomobject]@{ Computer=$env:COMPUTERNAME; OS=$os.Caption; Build=$os.BuildNumber; Domäne=$cs.Domain; DomänenMitglied=$cs.PartOfDomain; Admin=$isAdmin }
```

Prüfe dann diese Kriterien:

| # | Kriterium | Read-only-Abfrage |
|---|-----------|-------------------|
| 1 | Firewall (Domain/Private/Public) | `Get-NetFirewallProfile \| Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction` |
| 2 | Defender | `Get-MpComputerStatus \| Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled, IsTamperProtected, AntivirusSignatureAge, AntivirusSignatureLastUpdated` |
| 3 | Lokale Konten | `Get-LocalUser \| Select-Object Name, Enabled, SID, LastLogon, PasswordRequired`. Gast = SID endet auf `-501`, eingebautes Admin-Konto = SID endet auf `-500`. Zusätzlich `Get-LocalGroupMember -SID S-1-5-32-544` (Mitglieder der Administratoren-Gruppe) |
| 4 | Passwort- & Sperr-Richtlinie | `net accounts` (ohne Parameter!) |
| 5 | SMBv1 | Zuerst `Get-SmbServerConfiguration \| Select-Object EnableSMB1Protocol`. Falls verweigert: `Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name SMB1 -ErrorAction SilentlyContinue` (fehlt der Wert, ist SMBv1-Server bei aktuellen Windows-Versionen standardmäßig aus) und `Get-Service mrxsmb10 -ErrorAction SilentlyContinue` (Client-Treiber) |
| 6 | Remote Desktop | `Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections` (0 = RDP an) und `Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication` (1 = NLA an) |
| 7 | Lauschende Ports | `Get-NetTCPConnection -State Listen` und `Get-NetUDPEndpoint`, jeweils mit Prozessname über `Get-Process -Id $_.OwningProcess`. Nur Adressen **außer** `127.0.0.1` / `::1` gelten als „nach außen erreichbar“ |

Zusätzlich (nur lesend, wenn verfügbar): `Get-BitLockerVolume -MountPoint $env:SystemDrive` (meist Admin nötig)
und `Get-CimInstance -Namespace root/cimv2/security/microsofttpm -ClassName Win32_Tpm`. Wenn das nicht klappt, als 🟡 vermerken.

### Bewertung (Ampel)

| Kriterium | 🟢 Gehärtet | 🟡 Warnung | 🔴 Risiko |
|-----------|-------------|------------|-----------|
| Firewall | Alle 3 Profile an, Inbound = Block | Inbound-Standard = Allow, oder nicht prüfbar | Mindestens ein Profil aus |
| Defender | Echtzeitschutz an, Signaturen ≤ 1 Tag | Signaturen 2–7 Tage, Manipulationsschutz aus, oder Fremd-AV aktiv | Echtzeitschutz aus oder Signaturen > 7 Tage |
| Gastkonto | Deaktiviert | – | Aktiviert |
| Admin-Konto (SID -500) | Deaktiviert oder umbenannt | Aktiv und heißt „Administrator“/„Admin“ | Aktiv **ohne** Passwortpflicht |
| Admin-Gruppe | Nur benötigte Konten | Tageskonto des Nutzers ist Admin (kein getrenntes Admin-Konto) | Unbekannte Konten |
| Passwortlänge | ≥ 14 (CIS) | 8–13 | < 8 oder 0 |
| Kontosperrung | Schwelle 1–10, Dauer ≥ 15 Min | Schwelle > 10 | „Never“ / 0 (keine Sperre) |
| SMBv1 | Server & Client aus | Nicht eindeutig prüfbar | Aktiv |
| RDP | Aus | An **mit** NLA | An **ohne** NLA |
| Offene Ports | Nur Windows-Standard (z. B. 135, 445 im Private-Netz, 5040) | Unbekannte Dienste oder 445/139 im Public-Profil | 3389 ohne NLA, 21/23/5900 oder andere Fernzugänge offen |

Bewerte vorsichtig: Was nicht sicher prüfbar ist, wird 🟡 und **nie** 🟢.
Wenn das Gerät Mitglied einer Domäne ist oder per Intune/MDM verwaltet wird (Schul-Laptop!), weise darauf hin,
dass zentrale Richtlinien (GPO) lokale Einstellungen überschreiben können.

---

## Schritt 2: Audit-Report erstellen

Schreibe das Ergebnis nach `docs/hardening-report.md` (Ordner anlegen, falls nötig; vorhandenen Report überschreiben). Aufbau:

1. **Kopf:** Titel, Datum und Uhrzeit, Computername, Windows-Version und Build, Domäne/Workgroup, Audit mit/ohne Adminrechte
2. **Gesamtbild:** Anzahl 🟢 / 🟡 / 🔴 und ein Satz Fazit
3. **Ergebnistabelle:** Spalten `Status | Kriterium | Ist-Zustand | Soll (BSI/CIS) | Maßnahme`
4. **Details:** pro Kriterium die wichtigsten Rohwerte (kurz, keine endlosen Ausgaben). Bei Ports eine Tabelle `Protokoll | Adresse | Port | Prozess`
5. **Empfehlungen:** nach Priorität sortiert (zuerst 🔴), mit Verweis auf den passenden Schalter im Enforce-Skript
6. **Hinweis:** „Erstellt mit /hardening, nur lesender Audit. Es wurden keine Einstellungen verändert.“

Schreibe **keine** Passwörter, Hashes, WLAN-Schlüssel oder Seriennummern in den Report.

Zeige danach im Terminal eine **kurze** Zusammenfassung: die Ampel-Zählung, die 🔴-Punkte und den Pfad zum Report.

---

## Schritt 3: Enforce-Admin-Skript generieren

Erstelle oder aktualisiere `src/enforce-hardening.ps1`. Anforderungen:

- **Ausführlich auf Deutsch kommentiert**, mit Comment-Based-Help (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`, `.NOTES`).
  In `.NOTES` stehen das Datum und welche Punkte im letzten Report 🔴/🟡 waren.
- `[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]`. Jede Änderung läuft über
  `if ($PSCmdlet.ShouldProcess(<Ziel>, <Aktion>)) { ... }`. Dadurch funktionieren `-WhatIf` (Dry-Run) und `-Confirm` automatisch.
  **Auch native Befehle wie `net accounts` müssen in `ShouldProcess` stehen.**
- **Kein** `#Requires -RunAsAdministrator`, damit `-WhatIf` auch ohne Adminrechte läuft. Stattdessen selbst prüfen:
  Ohne Adminrechte und ohne `-WhatIf` mit klarer Meldung abbrechen.
- **Idempotent:** Vor jeder Änderung den Ist-Zustand lesen und nur ändern, wenn nötig („bereits gehärtet“ ausgeben).
  Idempotent heißt: Mehrmals ausführen ergibt dasselbe Ergebnis.
- **Modular über Schalter:** `-All` oder einzeln `-Firewall`, `-Defender`, `-GuestAccount`, `-SMBv1`, `-PasswordPolicy`, `-RDP`.
  Ohne Schalter nur die Hilfe ausgeben, damit nichts aus Versehen passiert.
- Parameter mit sinnvollen CIS-Standardwerten: `-MinPasswordLength 14`, `-LockoutThreshold 5`, `-LockoutDuration 15`,
  `-LockoutWindow 15`, `-PasswordHistory 24`. Kein erzwungener Passwortwechsel (BSI empfiehlt keinen regelmäßigen Wechsel ohne Anlass).
- Maßnahmen:
  - **Firewall:** `Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow`
  - **Defender:** Echtzeitschutz einschalten (`Set-MpPreference -DisableRealtimeMonitoring $false`), Signaturen aktualisieren (`Update-MpSignature`)
  - **Gastkonto:** per SID `-501` finden und `Disable-LocalUser`
  - **SMBv1:** `Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force` und `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart`, mit Neustart-Hinweis
  - **Passwortrichtlinie:** `net accounts /minpwlen:… /uniquepw:… /lockoutthreshold:… /lockoutduration:… /lockoutwindow:…`
  - **RDP:** Standard ist, NLA zu erzwingen, wenn RDP an ist. Nur mit zusätzlichem Schalter `-DisableRDP` wird RDP ganz abgeschaltet
    (Warnung: Fernwartung geht dann nicht mehr)
- Das eingebaute Admin-Konto **nicht** automatisch deaktivieren oder umbenennen, weil man sich sonst aussperren kann. Nur als Empfehlung ausgeben.
- **Protokoll:** `Start-Transcript` nach `$env:ProgramData\Hardening\enforce-<Datum>.log` (nicht bei `-WhatIf`), am Ende eine Übersichtstabelle
  `Maßnahme | Vorher | Nachher/Geplant | Status`.
- Fehler pro Maßnahme mit `try/catch` abfangen, damit das Skript weiterläuft. Am Ende Exit-Code ≠ 0, wenn etwas fehlgeschlagen ist.
- Im Kopf ein deutlicher Warnhinweis: Auf verwalteten Geräten (Schule/Firma) nur nach Freigabe durch die IT ausführen, und GPO/Intune können Einstellungen überschreiben.

Prüfe danach **nur die Syntax**, ohne das Skript auszuführen:

```powershell
$null = [System.Management.Automation.Language.Parser]::ParseFile("$PWD\src\enforce-hardening.ps1", [ref]$null, [ref]$errors); $errors
```

Ist die Ausgabe leer, ist die Syntax in Ordnung. Erkläre dem Nutzer, wie er das Skript **selbst** testen kann:

```powershell
# Dry-Run: zeigt nur an, was passieren würde
.\src\enforce-hardening.ps1 -All -WhatIf
# Echte Härtung (PowerShell als Administrator, nach Freigabe durch die IT)
.\src\enforce-hardening.ps1 -All -Confirm
```

---

## Schritt 4: GitHub-Backup

Bevor du sicherst, prüfe mit `gh repo view --json visibility -q .visibility`, ob das Repository **privat** ist.
Der Report verrät Schwachstellen und offene Ports dieses Geräts.

- Ist es `PRIVATE`: Rufe den Skill **`save`** auf (wie `/save`) mit der Commit-Nachricht
  „Härtungs-Report und Enforce-Skript aktualisieren“.
- Ist es `PUBLIC` oder nicht feststellbar: **Nicht** automatisch hochladen. Weise darauf hin und frage, ob der Report
  trotzdem hochgeladen werden soll oder ob `docs/hardening-report.md` in `.gitignore` eingetragen werden soll.

Gib zum Schluss eine kurze Rückmeldung: Ampel-Ergebnis, erzeugte Dateien und ob das Hochladen geklappt hat.
