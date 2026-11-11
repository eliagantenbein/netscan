# NetScan – IP Scanner & Network Scanner in Rust

**Fast IP scanner, network scanner and port scanner for Windows and macOS, written in Rust.** Finds every device on your LAN in seconds and identifies operating system (exact Windows version and edition), vendor, model and services. Network map, Excel/CSV export, one-click RDP, SSH, web and file shares – a free alternative to Advanced IP Scanner and Angry IP Scanner. One-line install on Windows and macOS, no admin rights, single executable.

IP- und Port-Scanner mit Geräteerkennung für ICT-Techniker – Windows und macOS.

## Installation

**Windows** – PowerShell öffnen (Startmenü → «PowerShell»), diese Zeile einfügen, Enter:

```powershell
irm https://raw.githubusercontent.com/eliagantenbein/netscan/main/install.ps1 | iex
```

**macOS** – Terminal öffnen, diese Zeile einfügen, Enter:

```bash
curl -fsSL https://raw.githubusercontent.com/eliagantenbein/netscan/main/install.sh | sh
```

Das ist alles: NetScan wird heruntergeladen, installiert (Windows: Startmenü, ohne Adminrechte; macOS: Programme) und gestartet. Dieselbe Zeile nochmals ausführen bringt die neuste Version; ob es eine gibt, zeigt NetScan unter «Info» (F1).

Lieber von Hand? Unter [Releases](https://github.com/eliagantenbein/netscan/releases/latest) liegen `NetScan.exe` (einfach starten, keine Installation) und `NetScan-macOS.zip` (entpacken, nach «Programme» ziehen). Beide sind nicht von Microsoft bzw. Apple signiert, deshalb beim ersten Start:

- **Windows** meldet «Der Computer wurde durch Windows geschützt» → «Weitere Informationen» → «Trotzdem ausführen».
- **macOS** meldet, die App könne nicht geprüft werden → Systemeinstellungen → Datenschutz & Sicherheit → «Dennoch öffnen».

Die Installationszeilen oben umgehen beides, weil die Datei nicht über den Browser kommt.

**Entfernen:** Windows: Ordner `%LOCALAPPDATA%\Programs\NetScan` und den Startmenü-Eintrag löschen. macOS: `NetScan.app` aus «Programme» in den Papierkorb.

## Funktionen

- **Hosts:** Ping, ARP und TCP finden auch Geräte hinter einer Firewall. Erkannt werden Betriebssystem (Windows-Version samt Client/Server-Edition über SMB oder WinRM, Linux über SSH, Apple-Modelle über mDNS), Hersteller, Modell, Domäne und Dienste. Die Spalten sind wählbar und werden gespeichert.
- **Netzwerkkarte:** Topologie Internet → Gateway → Gerätegruppen, dazu ein Adressraster des ganzen Bereichs.
- **Ports:** Pro Host die offenen Ports mit Dienst, Version bzw. Antwort des Dienstes und Sicherheitshinweisen; Vorlagen für Web, Windows/AD, Fernzugriff, Datenbanken, Drucker.
- **Export:** Excel-Bericht oder CSV (Semikolon, für Excel); «Tabelle kopieren» für Tickets.
- **Aktionen:** Web, RDP, SSH, VNC, Freigaben, C$, Dauerping, Traceroute, Wake-on-LAN.

Nichts davon meldet sich irgendwo an: NetScan liest nur, was ein Gerät jedem Client von sich aus mitteilt.

## Bedienung

| Taste | Wirkung |
|---|---|
| Enter / F5 | Scan starten |
| Esc | Scan stoppen bzw. Detailbereich schliessen |
| Ctrl+F | Filter |
| Ctrl+E | Excel-Export |
| Ctrl+C | ausgewählten Host kopieren (sichtbare Spalten) |
| F1 | Info: Version, Updates, Tastenkürzel |

Kommandozeile: `NetScan 10.0.0.0/24` scannt sofort; `--ports` (Port-Scan des Ziels) oder `--karte` öffnen den passenden Tab.

Einstellungen (Spalten, Portliste, zuletzt gescannte Bereiche): `%APPDATA%\NetScan\settings.txt` bzw. `~/Library/Application Support/NetScan/settings.txt`.

## Bauen

**Windows** (ohne Visual Studio, mit LLVM-MinGW):

```
winget install MartinStorsjo.LLVM-MinGW.UCRT
rustup override set stable-x86_64-pc-windows-gnullvm
cargo build --release
```

**macOS** (Rust und `xcode-select --install`):

```
sh mac/build-app.sh
```

Ergibt `target/NetScan.app` (Apple Silicon und Intel) und `target/NetScan-macOS.zip`. Beim ersten Scan fragt macOS nach dem Zugriff auf das lokale Netzwerk – erlauben, sonst findet NetScan nichts.

**Herstellerliste:** Die IEEE-Liste `oui.csv` von <https://standards-oui.ieee.org/oui/oui.csv> im Browser herunterladen, als `data/oui.csv` ablegen und neu bauen. Ohne sie kommen Hersteller nur aus den Gerätedaten und einer kurzen eingebauten Liste.

**Release:** Version in `Cargo.toml` erhöhen, committen, Tag `vX.Y.Z` pushen. GitHub Actions baut dann `NetScan.exe` und `NetScan-macOS.zip` und veröffentlicht sie als Release.

## Lizenz

MIT – siehe [LICENSE](LICENSE). Frei nutzbar, auch kommerziell; ohne Gewähr.
