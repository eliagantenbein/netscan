# NetScan

IP- und Port-Scanner mit Geräteerkennung für ICT-Techniker – Windows und macOS.

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

Kommandozeile: `NetScan 10.0.0.0/24` scannt sofort; `--ports` (Port-Scan des Ziels) oder `--karte` öffnen den passenden Tab.

Einstellungen (Spalten, Portliste): `%APPDATA%\NetScan\settings.txt` bzw. `~/Library/Application Support/NetScan/settings.txt`.

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
