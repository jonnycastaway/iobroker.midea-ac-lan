# ioBroker.midea-ac

Lokaler ioBroker-Adapter für Midea M-Smart Klimaanlagen mit **Protokoll V3** (8370).  
Kompatibel mit Midea, Rotenso, Comfee, Inventor EVO und anderen OEM-Marken.

---

## Installation

### Manuell (lokal)

```bash
# Im ioBroker-Verzeichnis:
cd /opt/iobroker
npm install /pfad/zu/iobroker.midea-ac
iobroker add midea-ac
```

### Über GitHub (wenn hochgeladen)

Im Admin-Adapter: **Adapter → Eigenes → von URL installieren**  
URL: `https://github.com/DEIN_USER/iobroker.midea-ac/tarball/main`

---

## Konfiguration

Nach dem Hinzufügen einer Instanz die Admin-UI öffnen:

| Feld | Beschreibung | Beispiel |
|------|-------------|---------|
| **IP-Adresse** | Lokale IP der Klimaanlage | `192.168.66.45` |
| **Port** | TCP-Port | `6444` |
| **Device ID** | Numerische ID | `153931629271567` |
| **Token** | 128-stelliger Hex-String | `2e8d3e17...` |
| **Key** | 64-stelliger Hex-String | `821df7a2...` |
| **Abfrageintervall** | Polling-Interval in Sekunden | `30` |

---

## Datenpunkte

### `midea-ac.0.status.*` (nur lesen)

| Datenpunkt | Typ | Beschreibung |
|-----------|-----|-------------|
| `power` | boolean | Ein/Aus |
| `mode` | string | auto / cool / dry / heat / fan_only |
| `temperature` | number | Solltemperatur (°C) |
| `fan_speed` | string | silent / low / medium / high / auto / turbo |
| `swing_vertical` | boolean | Vertikale Lamelle |
| `swing_horizontal` | boolean | Horizontale Lamelle |
| `eco` | boolean | Eco-Modus |
| `turbo` | boolean | Turbo-Modus |
| `sleep` | boolean | Schlaf-Modus |
| `indoor_temp` | number | Innenraumtemperatur (°C) |
| `outdoor_temp` | number | Außentemperatur (°C) |

### `midea-ac.0.control.*` (schreiben)

Dieselben Felder wie oben — Schreiben löst sofort einen Set-Befehl aus,  
gefolgt von einem Status-Update nach 2 Sekunden.

---

## Token & Key ermitteln

Falls du noch kein Token/Key hast, kannst du diese über die HA-Integration  
`midea_ac_lan` oder das Python-Tool `midealocal` auslesen:

```bash
pip install midealocal
midea-discover --ip 192.168.66.45 --account EMAIL --password PASSWORT
```

---

## Protokoll-Hintergrund

Das V3-Protokoll (Portkennzeichen `8370`) verwendet:
1. **Handshake**: Token wird gesendet, Gerät antwortet mit 64 Bytes  
2. **TCP-Key-Ableitung**: SHA-256 aus (Response[:32] XOR Key[:32]) + Response[32:64]  
3. **AES-256-ECB** für alle weiteren Nachrichten  

---

## Lizenz

MIT
