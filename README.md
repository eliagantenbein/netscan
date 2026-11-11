# NetScan – IP Scanner & Network Scanner in Rust

**Fast IP scanner, network scanner and port scanner for Windows and macOS, written in Rust.** Finds every device on your LAN in seconds and identifies operating system (exact Windows version and edition), vendor, model and services. Network map, Excel/CSV export, one-click RDP, SSH, web and file shares – a free alternative to Advanced IP Scanner and Angry IP Scanner. No installation, no admin rights, single executable.

IP- und Port-Scanner mit Geräteerkennung für ICT-Techniker – Windows und macOS.

**Download:** fertige Versionen unter [Releases](https://github.com/eliagantenbein/netscan/releases). Windows: `NetScan.exe` herunterladen und starten, keine Installation nötig. Die eigene Version und die Suche nach Updates stehen im Fenster «Info» (F1).

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

Ergibt `target/NetScan.app`. Beim ersten Scan fragt macOS nach dem Zugriff auf das lokale Netzwerk – erlauben, sonst findet NetScan nichts.

**Herstellerliste:** Die IEEE-Liste `oui.csv` von <https://standards-oui.ieee.org/oui/oui.csv> im Browser herunterladen, als `data/oui.csv` ablegen und neu bauen. Ohne sie kommen Hersteller nur aus den Gerätedaten und einer kurzen eingebauten Liste.

## Lizenz

MIT – siehe [LICENSE](LICENSE). Frei nutzbar, auch kommerziell; ohne Gewähr.
