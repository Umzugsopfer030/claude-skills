<#
.SYNOPSIS
    Härtet ein Windows-Gerät nach BSI IT-Grundschutz (SYS.2.2.3) und CIS-Benchmark (Enforce-Modus).

.DESCRIPTION
    ======================================================================================
     ACHTUNG: Dieses Skript VERÄNDERT Systemeinstellungen!
     - Auf verwalteten Geräten (Schule, Firma) nur nach Freigabe durch die IT ausführen.
     - Gruppenrichtlinien (GPO) oder Intune/MDM können lokale Einstellungen wieder
       überschreiben oder Änderungen blockieren.
     - Immer zuerst mit -WhatIf testen (Dry-Run: zeigt nur an, ändert nichts).
    ======================================================================================

    Das Skript liest vor jeder Maßnahme den Ist-Zustand und ändert nur, was nötig ist
    (idempotent: mehrfaches Ausführen ergibt dasselbe Ergebnis).
    Jede Änderung läuft über ShouldProcess. Dadurch funktionieren -WhatIf und -Confirm.

    Maßnahmen (einzeln per Schalter oder alle mit -All):
      -Firewall        Alle Profile an, eingehend blockieren, ausgehend zulassen
      -Defender        Echtzeitschutz an, Signaturen aktualisieren
      -GuestAccount    Gastkonto (SID ...-501) deaktivieren
      -SMBv1           SMBv1-Server und -Feature abschalten (Neustart nötig)
      -PasswordPolicy  Kennwortlänge, Kennwortchronik, Kontosperrung setzen
      -RDP             NLA erzwingen (mit -DisableRDP: Remote Desktop ganz aus)
      -FirewallRules   Riskante eingehende Freigaben deaktivieren (z. B. MySQL, node.exe im Public-Profil)

    Bewusst NICHT automatisch: das eingebaute Administrator-Konto deaktivieren oder umbenennen
    (Aussperr-Gefahr). Das Skript gibt dazu nur eine Empfehlung aus.

.PARAMETER All
    Führt alle Maßnahmen aus (außer -DisableRDP, das muss extra angegeben werden).

.PARAMETER Firewall
    Erzwingt die Windows-Firewall für Domain-, Private- und Public-Profil.

.PARAMETER Defender
    Schaltet den Echtzeitschutz von Microsoft Defender ein und aktualisiert die Signaturen.

.PARAMETER GuestAccount
    Deaktiviert das eingebaute Gastkonto.

.PARAMETER SMBv1
    Deaktiviert das veraltete und unsichere SMBv1-Protokoll.

.PARAMETER PasswordPolicy
    Setzt die lokale Kennwort- und Kontosperr-Richtlinie (net accounts).

.PARAMETER RDP
    Erzwingt Network Level Authentication (NLA) für Remote Desktop.

.PARAMETER DisableRDP
    Nur zusammen mit -RDP oder -All: schaltet Remote Desktop komplett ab.
    WARNUNG: Fernwartung per RDP ist danach nicht mehr möglich.

.PARAMETER FirewallRules
    Deaktiviert eingehende Freigaberegeln für -RiskyInboundPorts sowie Regeln für
    -PublicBlockedPrograms, die im Public-Profil gelten.

.PARAMETER MinPasswordLength
    Minimale Kennwortlänge. Standard 14 (CIS). net accounts erlaubt maximal 14.

.PARAMETER PasswordHistory
    Anzahl gemerkter alter Kennwörter. Standard 24 (CIS).

.PARAMETER LockoutThreshold
    Fehlversuche bis zur Kontosperrung. Standard 5 (CIS).

.PARAMETER LockoutDuration
    Sperrdauer in Minuten. Standard 15 (CIS).

.PARAMETER LockoutWindow
    Zeitfenster in Minuten, in dem Fehlversuche gezählt werden. Standard 15 (CIS).
    Muss kleiner oder gleich LockoutDuration sein.

.PARAMETER RiskyInboundPorts
    TCP/UDP-Ports, deren eingehende Freigaben deaktiviert werden. Standard 3306, 33060 (MySQL).

.PARAMETER PublicBlockedPrograms
    Programme (Dateiname), deren eingehende Freigaben im Public-Profil deaktiviert werden. Standard node.exe.

.EXAMPLE
    .\enforce-hardening.ps1 -All -WhatIf
    Dry-Run: zeigt, was geändert würde. Läuft auch ohne Adminrechte.

.EXAMPLE
    .\enforce-hardening.ps1 -All -Confirm
    Echte Härtung mit Rückfrage vor jeder Änderung (PowerShell als Administrator).

.EXAMPLE
    .\enforce-hardening.ps1 -PasswordPolicy -MinPasswordLength 12 -LockoutThreshold 10
    Nur die Kennwort-Richtlinie, mit eigenen Werten.

.NOTES
    Beispiel-Skript, erzeugt mit dem Claude-Code-Skill /hardening (.claude/commands/hardening.md).
    Bei jedem Aufruf von /hardening wird das Skript passend zum Audit-Ergebnis des jeweiligen
    Geräts neu erzeugt. In diesem Abschnitt stehen dann Datum und die gefundenen 🔴/🟡-Punkte.
    Standardwerte orientieren sich am CIS Microsoft Windows 11 Benchmark (L1) und BSI SYS.2.2.3.
    Protokoll: $env:ProgramData\Hardening\enforce-<Datum>.log (nicht bei -WhatIf).
    Exit-Code: 0 = alles ok, 1 = mindestens eine Maßnahme fehlgeschlagen, 2 = keine Adminrechte.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$All,
    [switch]$Firewall,
    [switch]$Defender,
    [switch]$GuestAccount,
    [switch]$SMBv1,
    [switch]$PasswordPolicy,
    [switch]$RDP,
    [switch]$DisableRDP,
    [switch]$FirewallRules,

    [ValidateRange(1, 14)]   [int]$MinPasswordLength = 14,
    [ValidateRange(0, 24)]   [int]$PasswordHistory   = 24,
    [ValidateRange(1, 999)]  [int]$LockoutThreshold  = 5,
    [ValidateRange(1, 99999)][int]$LockoutDuration   = 15,
    [ValidateRange(1, 99999)][int]$LockoutWindow     = 15,

    [int[]]$RiskyInboundPorts       = @(3306, 33060),
    [string[]]$PublicBlockedPrograms = @('node.exe')
)

# ------------------------------------------------------------------------------------
# Vorbereitung
# ------------------------------------------------------------------------------------

# $PSCmdlet merken, damit auch die Funktionen unten ShouldProcess nutzen können.
$script:Cmdlet     = $PSCmdlet
$script:Ergebnisse = New-Object System.Collections.Generic.List[object]
$script:Fehler     = 0
$script:Neustart   = $false

# -All schaltet alle Einzelmaßnahmen ein.
if ($All) {
    $Firewall = $Defender = $GuestAccount = $SMBv1 = $PasswordPolicy = $RDP = $FirewallRules = [switch]$true
}

# Ohne Schalter nichts tun, nur die Hilfe zeigen (Schutz vor versehentlichem Start).
if (-not ($Firewall -or $Defender -or $GuestAccount -or $SMBv1 -or $PasswordPolicy -or $RDP -or $FirewallRules)) {
    Write-Host 'Keine Maßnahme gewählt. Es wird nichts geändert. Hilfe:' -ForegroundColor Yellow
    Get-Help $PSCommandPath -Detailed
    exit 0
}

if ($DisableRDP -and -not $RDP) {
    Write-Warning '-DisableRDP wirkt nur zusammen mit -RDP oder -All.'
}

if ($LockoutWindow -gt $LockoutDuration) {
    Write-Error "LockoutWindow ($LockoutWindow) darf nicht größer als LockoutDuration ($LockoutDuration) sein."
    exit 1
}

# Adminrechte prüfen. Für -WhatIf nicht nötig, für echte Änderungen schon.
$istAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $istAdmin -and -not $WhatIfPreference) {
    Write-Error 'Für echte Änderungen bitte PowerShell "Als Administrator ausführen". Zum Testen ohne Adminrechte: -WhatIf'
    exit 2
}

# Protokoll (Transcript) nur bei echten Änderungen schreiben.
$transcriptAktiv = $false
if (-not $WhatIfPreference) {
    $logOrdner = Join-Path $env:ProgramData 'Hardening'
    if (-not (Test-Path $logOrdner)) {
        New-Item -ItemType Directory -Path $logOrdner -WhatIf:$false -Confirm:$false | Out-Null
    }
    $logDatei = Join-Path $logOrdner ('enforce-{0:yyyy-MM-dd_HHmmss}.log' -f (Get-Date))
    Start-Transcript -Path $logDatei -WhatIf:$false -Confirm:$false | Out-Null
    $transcriptAktiv = $true
}

$modus = if ($WhatIfPreference) { 'DRY-RUN (-WhatIf): es wird nichts geändert' } else { 'ENFORCE: Änderungen werden angewendet' }
Write-Host "`n=== System Hardening auf $env:COMPUTERNAME | $modus ===`n" -ForegroundColor Cyan

# ------------------------------------------------------------------------------------
# Hilfsfunktionen
# ------------------------------------------------------------------------------------

# Speichert ein Ergebnis für die Übersichtstabelle am Ende.
function Add-Ergebnis {
    param([string]$Massnahme, [string]$Vorher, [string]$Nachher, [string]$Status)
    $script:Ergebnisse.Add([pscustomobject]@{
        'Maßnahme'         = $Massnahme
        'Vorher'           = $Vorher
        'Nachher/Geplant'  = $Nachher
        'Status'           = $Status
    })
    if ($Status -eq 'Fehler') { $script:Fehler++ }
}

# Führt eine Änderung nur aus, wenn ShouldProcess zustimmt (-WhatIf / -Confirm).
# Gibt den Status-Text zurück.
function Invoke-Aenderung {
    param([string]$Ziel, [string]$Aktion, [scriptblock]$Code)
    if ($script:Cmdlet.ShouldProcess($Ziel, $Aktion)) {
        & $Code | Out-Null
        return 'Geändert'
    }
    if ($WhatIfPreference) { return 'Geplant (WhatIf)' }
    return 'Abgelehnt'
}

# Liest "net accounts" sprachunabhängig über die feste Zeilen-Reihenfolge.
# Texte wie "Keine", "Nie", "None", "Never" werden zu 0.
function Get-KontoRichtlinie {
    $zeilen = @(net accounts) | Select-Object -First 8
    $werte = foreach ($z in $zeilen) {
        $wert = ($z -split '\s{2,}')[-1].Trim()
        if ($wert -match '^\d+$') { [int]$wert } else { 0 }
    }
    [pscustomobject]@{
        MinLaenge     = $werte[3]
        Chronik       = $werte[4]
        Sperrschwelle = $werte[5]
        Sperrdauer    = $werte[6]
        Sperrfenster  = $werte[7]
    }
}

# ------------------------------------------------------------------------------------
# 1) Firewall
# ------------------------------------------------------------------------------------
if ($Firewall) {
    Write-Host '--- Firewall' -ForegroundColor Cyan
    try {
        # ActiveStore zeigt die tatsächlich wirksamen Werte (statt "NotConfigured").
        $fwProfile = Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop
        $vorher  = ($fwProfile | ForEach-Object { "$($_.Name)=$($_.Enabled)/$($_.DefaultInboundAction)" }) -join ', '
        $ok = -not ($fwProfile | Where-Object { $_.Enabled -ne 'True' -or $_.DefaultInboundAction -ne 'Block' })

        if ($ok) {
            Write-Host '    Bereits gehärtet.' -ForegroundColor Green
            Add-Ergebnis 'Firewall' $vorher $vorher 'Bereits gehärtet'
        } else {
            $status = Invoke-Aenderung 'Firewall: Domain, Private, Public' 'Aktivieren, eingehend blockieren, ausgehend zulassen' {
                Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True `
                    -DefaultInboundAction Block -DefaultOutboundAction Allow -Confirm:$false -ErrorAction Stop
            }
            Add-Ergebnis 'Firewall' $vorher 'Alle an, Inbound=Block' $status
        }
    } catch {
        Write-Warning "Firewall: $($_.Exception.Message)"
        Add-Ergebnis 'Firewall' '?' '?' 'Fehler'
    }
}

# ------------------------------------------------------------------------------------
# 2) Microsoft Defender
# ------------------------------------------------------------------------------------
if ($Defender) {
    Write-Host '--- Defender' -ForegroundColor Cyan
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop

        # Echtzeitschutz
        if ($mp.RealTimeProtectionEnabled) {
            Write-Host '    Echtzeitschutz bereits aktiv.' -ForegroundColor Green
            Add-Ergebnis 'Defender Echtzeitschutz' 'An' 'An' 'Bereits gehärtet'
        } else {
            $status = Invoke-Aenderung 'Microsoft Defender' 'Echtzeitschutz einschalten' {
                Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
            }
            Add-Ergebnis 'Defender Echtzeitschutz' 'Aus' 'An' $status
        }

        # Signaturen: älter als 1 Tag -> aktualisieren
        $alter = $mp.AntivirusSignatureAge
        if ($alter -le 1) {
            Write-Host "    Signaturen aktuell ($alter Tage)." -ForegroundColor Green
            Add-Ergebnis 'Defender Signaturen' "$alter Tage" "$alter Tage" 'Bereits gehärtet'
        } else {
            $status = Invoke-Aenderung 'Microsoft Defender' 'Signaturen aktualisieren' {
                Update-MpSignature -ErrorAction Stop
            }
            Add-Ergebnis 'Defender Signaturen' "$alter Tage" 'Aktuell' $status
        }
    } catch {
        Write-Warning "Defender: $($_.Exception.Message) (Manipulationsschutz oder Fremd-Virenschutz kann Änderungen blockieren)"
        Add-Ergebnis 'Defender' '?' '?' 'Fehler'
    }
}

# ------------------------------------------------------------------------------------
# 3) Gastkonto
# ------------------------------------------------------------------------------------
if ($GuestAccount) {
    Write-Host '--- Gastkonto' -ForegroundColor Cyan
    try {
        # Über die SID suchen, denn der Name ist sprachabhängig ("Gast" / "Guest").
        $gast = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -like '*-501' }
        if (-not $gast) {
            Add-Ergebnis 'Gastkonto' 'Nicht vorhanden' '-' 'Bereits gehärtet'
        } elseif (-not $gast.Enabled) {
            Write-Host "    '$($gast.Name)' bereits deaktiviert." -ForegroundColor Green
            Add-Ergebnis 'Gastkonto' 'Deaktiviert' 'Deaktiviert' 'Bereits gehärtet'
        } else {
            $status = Invoke-Aenderung "Konto '$($gast.Name)'" 'Deaktivieren' {
                Disable-LocalUser -SID $gast.SID -Confirm:$false -ErrorAction Stop
            }
            Add-Ergebnis 'Gastkonto' 'Aktiv' 'Deaktiviert' $status
        }
    } catch {
        Write-Warning "Gastkonto: $($_.Exception.Message)"
        Add-Ergebnis 'Gastkonto' '?' '?' 'Fehler'
    }
}

# ------------------------------------------------------------------------------------
# 4) SMBv1
# ------------------------------------------------------------------------------------
if ($SMBv1) {
    Write-Host '--- SMBv1' -ForegroundColor Cyan

    # 4a) SMBv1 im SMB-Server
    try {
        $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol
        if (-not $smb1) {
            Write-Host '    SMBv1-Server bereits aus.' -ForegroundColor Green
            Add-Ergebnis 'SMBv1 Server' 'Aus' 'Aus' 'Bereits gehärtet'
        } else {
            $status = Invoke-Aenderung 'SMB-Server' 'SMBv1-Protokoll deaktivieren' {
                Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false -ErrorAction Stop
            }
            Add-Ergebnis 'SMBv1 Server' 'An' 'Aus' $status
        }
    } catch {
        Write-Warning "SMBv1 Server: $($_.Exception.Message)"
        Add-Ergebnis 'SMBv1 Server' '?' '?' 'Fehler'
    }

    # 4b) Windows-Feature SMB1Protocol (Client und Server). Abfrage braucht Adminrechte.
    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
        if ($feature.State -like 'Disabled*') {
            Write-Host "    Feature SMB1Protocol bereits aus ($($feature.State))." -ForegroundColor Green
            Add-Ergebnis 'SMBv1 Feature' $feature.State $feature.State 'Bereits gehärtet'
        } else {
            $status = Invoke-Aenderung 'Windows-Feature SMB1Protocol' 'Deaktivieren (Neustart nötig)' {
                Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null
                $script:Neustart = $true
            }
            Add-Ergebnis 'SMBv1 Feature' $feature.State 'Disabled' $status
        }
    } catch {
        if (-not $istAdmin) {
            Write-Host '    Feature-Status nur mit Adminrechten lesbar, übersprungen.' -ForegroundColor Yellow
            Add-Ergebnis 'SMBv1 Feature' '? (Admin nötig)' 'Disabled' 'Nicht prüfbar'
        } else {
            Write-Warning "SMBv1 Feature: $($_.Exception.Message)"
            Add-Ergebnis 'SMBv1 Feature' '?' '?' 'Fehler'
        }
    }
}

# ------------------------------------------------------------------------------------
# 5) Kennwort- und Kontosperr-Richtlinie (net accounts)
#    Kein erzwungener regelmäßiger Kennwortwechsel (BSI ORP.4): maxpwage bleibt unverändert.
# ------------------------------------------------------------------------------------
if ($PasswordPolicy) {
    Write-Host '--- Kennwort-Richtlinie' -ForegroundColor Cyan
    try {
        $ist = Get-KontoRichtlinie

        # Jede Einstellung einzeln: Ist, Soll, net-accounts-Parameter, "zu schwach?"
        # Reihenfolge wichtig: Sperrdauer vor Sperrfenster (Fenster darf nicht größer als Dauer sein).
        $regeln = @(
            @{ Name = 'Min. Kennwortlänge'; Ist = $ist.MinLaenge;     Soll = $MinPasswordLength; Param = "/minpwlen:$MinPasswordLength";          Schwach = ($ist.MinLaenge -lt $MinPasswordLength) }
            @{ Name = 'Kennwortchronik';    Ist = $ist.Chronik;       Soll = $PasswordHistory;   Param = "/uniquepw:$PasswordHistory";            Schwach = ($ist.Chronik -lt $PasswordHistory) }
            @{ Name = 'Sperrschwelle';      Ist = $ist.Sperrschwelle; Soll = $LockoutThreshold;  Param = "/lockoutthreshold:$LockoutThreshold";   Schwach = ($ist.Sperrschwelle -eq 0 -or $ist.Sperrschwelle -gt $LockoutThreshold) }
            @{ Name = 'Sperrdauer (Min.)';  Ist = $ist.Sperrdauer;    Soll = $LockoutDuration;   Param = "/lockoutduration:$LockoutDuration";     Schwach = ($ist.Sperrdauer -lt $LockoutDuration) }
            @{ Name = 'Sperrfenster (Min.)';Ist = $ist.Sperrfenster;  Soll = $LockoutWindow;     Param = "/lockoutwindow:$LockoutWindow";         Schwach = ($ist.Sperrfenster -lt $LockoutWindow) }
        )

        foreach ($r in $regeln) {
            if (-not $r.Schwach) {
                Write-Host "    $($r.Name): $($r.Ist) ok." -ForegroundColor Green
                Add-Ergebnis $r.Name "$($r.Ist)" "$($r.Ist)" 'Bereits gehärtet'
                continue
            }
            try {
                # Auch der native Befehl "net accounts" läuft über ShouldProcess.
                $status = Invoke-Aenderung 'Lokale Kontorichtlinie' "net accounts $($r.Param)" {
                    $ausgabe = net accounts $r.Param 2>&1
                    if ($LASTEXITCODE -ne 0) { throw "net accounts $($r.Param) fehlgeschlagen: $ausgabe" }
                }
                Add-Ergebnis $r.Name "$($r.Ist)" "$($r.Soll)" $status
            } catch {
                Write-Warning "$($r.Name): $($_.Exception.Message)"
                Add-Ergebnis $r.Name "$($r.Ist)" "$($r.Soll)" 'Fehler'
            }
        }
        Write-Host '    Hinweis: Für Microsoft-Konten gilt die Kennwortlänge von Microsoft, nicht die lokale Richtlinie.' -ForegroundColor DarkGray
    } catch {
        Write-Warning "Kennwort-Richtlinie: $($_.Exception.Message)"
        Add-Ergebnis 'Kennwort-Richtlinie' '?' '?' 'Fehler'
    }
}

# ------------------------------------------------------------------------------------
# 6) Remote Desktop
# ------------------------------------------------------------------------------------
if ($RDP) {
    Write-Host '--- Remote Desktop' -ForegroundColor Cyan
    $tsPfad  = 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
    $rdpPfad = 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    try {
        $rdpAn = (Get-ItemPropertyValue -Path $tsPfad -Name fDenyTSConnections -ErrorAction Stop) -eq 0
        $nla   = (Get-ItemPropertyValue -Path $rdpPfad -Name UserAuthentication -ErrorAction Stop) -eq 1

        # 6a) NLA erzwingen (schadet auch bei ausgeschaltetem RDP nicht)
        if ($nla) {
            Write-Host '    NLA bereits erzwungen.' -ForegroundColor Green
            Add-Ergebnis 'RDP NLA' 'An' 'An' 'Bereits gehärtet'
        } else {
            $status = Invoke-Aenderung 'Remote Desktop' 'Network Level Authentication erzwingen' {
                Set-ItemProperty -Path $rdpPfad -Name UserAuthentication -Value 1 -Confirm:$false -ErrorAction Stop
            }
            Add-Ergebnis 'RDP NLA' 'Aus' 'An' $status
        }

        # 6b) RDP ganz abschalten, nur mit -DisableRDP
        if ($DisableRDP) {
            if (-not $rdpAn) {
                Write-Host '    RDP bereits aus.' -ForegroundColor Green
                Add-Ergebnis 'RDP' 'Aus' 'Aus' 'Bereits gehärtet'
            } else {
                Write-Warning 'RDP wird abgeschaltet: Fernwartung per Remote Desktop ist danach nicht mehr möglich!'
                $status = Invoke-Aenderung 'Remote Desktop' 'Verbindungen verweigern und Firewall-Regeln deaktivieren' {
                    Set-ItemProperty -Path $tsPfad -Name fDenyTSConnections -Value 1 -Confirm:$false -ErrorAction Stop
                    # Regelgruppe "Remotedesktop" (sprachunabhängige ID)
                    Disable-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -Confirm:$false -ErrorAction SilentlyContinue
                }
                Add-Ergebnis 'RDP' 'An' 'Aus' $status
            }
        } else {
            $text = if ($rdpAn) { 'An (mit NLA abgesichert)' } else { 'Aus' }
            Add-Ergebnis 'RDP' $text $text 'Unverändert'
        }
    } catch {
        Write-Warning "RDP: $($_.Exception.Message)"
        Add-Ergebnis 'RDP' '?' '?' 'Fehler'
    }
}

# ------------------------------------------------------------------------------------
# 7) Riskante eingehende Firewall-Freigaben
# ------------------------------------------------------------------------------------
if ($FirewallRules) {
    Write-Host '--- Firewall-Freigaben' -ForegroundColor Cyan
    try {
        $portTexte = $RiskyInboundPorts | ForEach-Object { "$_" }

        # 7a) Regeln, die riskante Ports freigeben (z. B. MySQL 3306/33060)
        $portRegeln = Get-NetFirewallPortFilter -All -ErrorAction Stop |
            Where-Object { @($_.LocalPort | Where-Object { $_ -in $portTexte }).Count -gt 0 } |
            Get-NetFirewallRule -ErrorAction SilentlyContinue |
            Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' }

        # 7b) Regeln für bestimmte Programme, die im Public-Profil gelten (z. B. node.exe)
        $progRegeln = Get-NetFirewallApplicationFilter -All -ErrorAction Stop |
            Where-Object { $_.Program -and (Split-Path $_.Program -Leaf) -in $PublicBlockedPrograms } |
            Get-NetFirewallRule -ErrorAction SilentlyContinue |
            Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' -and
                           ($_.Profile.ToString() -match 'Public|Any') }

        $treffer = @($portRegeln) + @($progRegeln) | Where-Object { $_ } | Sort-Object Name -Unique

        if (-not $treffer) {
            Write-Host '    Keine riskanten Freigaben gefunden.' -ForegroundColor Green
            Add-Ergebnis 'Firewall-Freigaben' 'Keine' 'Keine' 'Bereits gehärtet'
        }
        foreach ($regel in $treffer) {
            $beschreibung = "$($regel.DisplayName) [$($regel.Profile)]"
            try {
                $status = Invoke-Aenderung "Firewall-Regel '$beschreibung'" 'Deaktivieren' {
                    Disable-NetFirewallRule -Name $regel.Name -Confirm:$false -ErrorAction Stop
                }
                Add-Ergebnis "Regel: $($regel.DisplayName)" "Aktiv [$($regel.Profile)]" 'Deaktiviert' $status
            } catch {
                # Per Gruppenrichtlinie verteilte Regeln lassen sich lokal nicht ändern.
                Write-Warning "Regel '$beschreibung': $($_.Exception.Message)"
                Add-Ergebnis "Regel: $($regel.DisplayName)" 'Aktiv' 'Deaktiviert' 'Fehler'
            }
        }
        Write-Host '    Tipp: Dienste zusätzlich nur an 127.0.0.1 binden (MySQL: bind-address, Node: server.listen(PORT, "127.0.0.1")).' -ForegroundColor DarkGray
    } catch {
        Write-Warning "Firewall-Freigaben: $($_.Exception.Message)"
        Add-Ergebnis 'Firewall-Freigaben' '?' '?' 'Fehler'
    }
}

# ------------------------------------------------------------------------------------
# Empfehlungen, die bewusst NICHT automatisch umgesetzt werden
# ------------------------------------------------------------------------------------
try {
    $admin = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -like '*-500' }
    if ($admin -and $admin.Enabled) {
        Write-Warning "Empfehlung: Eingebautes Admin-Konto '$($admin.Name)' ist aktiv. Manuell deaktivieren oder umbenennen, wenn ein anderes Admin-Konto existiert."
    }
} catch { }

# ------------------------------------------------------------------------------------
# Abschluss
# ------------------------------------------------------------------------------------
Write-Host "`n=== Übersicht ===" -ForegroundColor Cyan
$script:Ergebnisse | Format-Table -AutoSize -Wrap

if ($script:Neustart) {
    Write-Warning 'Ein Neustart ist nötig, damit alle Änderungen (SMBv1) wirksam werden.'
}
if ($WhatIfPreference) {
    Write-Host 'Dry-Run beendet. Es wurde nichts geändert.' -ForegroundColor Green
}

if ($transcriptAktiv) {
    Stop-Transcript | Out-Null
    Write-Host "Protokoll: $logDatei"
}

if ($script:Fehler -gt 0) {
    Write-Host "$($script:Fehler) Maßnahme(n) fehlgeschlagen." -ForegroundColor Red
    exit 1
}
exit 0
