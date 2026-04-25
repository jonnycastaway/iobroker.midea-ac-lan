'use strict';

const utils  = require('@iobroker/adapter-core');
const net    = require('net');
const crypto = require('crypto');

// ─── 8370 Protokoll-Header (8 Bytes) ─────────────────────────────────────────
// [0-1] magic:   0x83 0x70
// [2-3] paylen:  uint16be  (Länge der Nutzdaten NACH dem Header)
// [4]   msgtype: 0x20=Handshake, 0x03=Req, 0x04=Resp
// [5]   padding: 0x00
// [6-7] reserved/flags: 0x00 0x00
// [8..] payload

const MAGIC = Buffer.from([0x83, 0x70]);
const MSGTYPE_HANDSHAKE_REQUEST  = 0x20;
const MSGTYPE_ENCRYPTED_REQUEST  = 0x03;
const MSGTYPE_ENCRYPTED_RESPONSE = 0x04;

// Bestätigt durch pcap: 8370 0040 20 00 0000 <64-byte-token>
//                             ^^^^ ^^ ^^ ^^^^
//                              len typ pad rsv

const AC_CMD_STATUS = 0x41;
const AC_CMD_SET    = 0x40;

const MODES     = { 1: 'auto', 2: 'cool', 3: 'dry', 4: 'heat', 5: 'fan_only' };
const MODES_REV = { auto: 1, cool: 2, dry: 3, heat: 4, fan_only: 5 };
const FAN_SPEEDS     = { 20: 'silent', 40: 'low', 60: 'medium', 80: 'high', 101: 'auto', 102: 'turbo' };
const FAN_SPEEDS_REV = { silent: 20, low: 40, medium: 60, high: 80, auto: 101, turbo: 102 };

const CONNECT_TIMEOUT_MS = 10000;
const READ_TIMEOUT_MS    = 10000;
const POST_HANDSHAKE_DELAY_MS = 1000;  // Gerät braucht kurze Pause nach HS

// ─── CRC8 ────────────────────────────────────────────────────────────────────
const CRC8_TABLE = [
    0x00,0x07,0x0E,0x09,0x1C,0x1B,0x12,0x15,0x38,0x3F,0x36,0x31,0x24,0x23,0x2A,0x2D,
    0x70,0x77,0x7E,0x79,0x6C,0x6B,0x62,0x65,0x48,0x4F,0x46,0x41,0x54,0x53,0x5A,0x5D,
    0xE0,0xE7,0xEE,0xE9,0xFC,0xFB,0xF2,0xF5,0xD8,0xDF,0xD6,0xD1,0xC4,0xC3,0xCA,0xCD,
    0x90,0x97,0x9E,0x99,0x8C,0x8B,0x82,0x85,0xA8,0xAF,0xA6,0xA1,0xB4,0xB3,0xBA,0xBD,
    0xC7,0xC0,0xC9,0xCE,0xDB,0xDC,0xD5,0xD2,0xFF,0xF8,0xF1,0xF6,0xE3,0xE4,0xED,0xEA,
    0xB7,0xB0,0xB9,0xBE,0xAB,0xAC,0xA5,0xA2,0x8F,0x88,0x81,0x86,0x93,0x94,0x9D,0x9A,
    0x27,0x20,0x29,0x2E,0x3B,0x3C,0x35,0x32,0x1F,0x18,0x11,0x16,0x03,0x04,0x0D,0x0A,
    0x57,0x50,0x59,0x5E,0x4B,0x4C,0x45,0x42,0x6F,0x68,0x61,0x66,0x73,0x74,0x7D,0x7A,
    0x89,0x8E,0x87,0x80,0x95,0x92,0x9B,0x9C,0xB1,0xB6,0xBF,0xB8,0xAD,0xAA,0xA3,0xA4,
    0xF9,0xFE,0xF7,0xF0,0xE5,0xE2,0xEB,0xEC,0xC1,0xC6,0xCF,0xC8,0xDD,0xDA,0xD3,0xD4,
    0x69,0x6E,0x67,0x60,0x75,0x72,0x7B,0x7C,0x51,0x56,0x5F,0x58,0x4D,0x4A,0x43,0x44,
    0x19,0x1E,0x17,0x10,0x05,0x02,0x0B,0x0C,0x21,0x26,0x2F,0x28,0x3D,0x3A,0x33,0x34,
    0x4E,0x49,0x40,0x47,0x52,0x55,0x5C,0x5B,0x76,0x71,0x78,0x7F,0x6A,0x6D,0x64,0x63,
    0x3E,0x39,0x30,0x37,0x22,0x25,0x2C,0x2B,0x06,0x01,0x08,0x0F,0x1A,0x1D,0x14,0x13,
    0xAE,0xA9,0xA0,0xA7,0xB2,0xB5,0xBC,0xBB,0x96,0x91,0x98,0x9F,0x8A,0x8D,0x84,0x83,
    0xDE,0xD9,0xD0,0xD7,0xC2,0xC5,0xCC,0xCB,0xE6,0xE1,0xE8,0xEF,0xFA,0xFD,0xF4,0xF3,
];
function crc8(data) {
    let v = 0;
    for (const b of data) v = CRC8_TABLE[(v ^ b) & 0xFF];
    return v;
}

// ─── 8370 Paket bauen ─────────────────────────────────────────────────────────
function build8370(msgtype, payload) {
    // Header ist immer 8 Bytes: magic(2) + len(2) + type(1) + pad(1) + reserved(2)
    const hdr = Buffer.alloc(8, 0x00);
    MAGIC.copy(hdr, 0);
    hdr.writeUInt16BE(payload.length, 2);
    hdr[4] = msgtype;
    // hdr[5] = 0x00 (pad), hdr[6-7] = 0x00 0x00 (reserved) — bereits 0 durch alloc
    return Buffer.concat([hdr, payload]);
}

// ─── AC Frame ────────────────────────────────────────────────────────────────
function buildACFrame(cmd, params = {}) {
    const msg = Buffer.alloc(40, 0x00);
    msg[0] = 0xAA; msg[1] = 0x23; msg[2] = 0xAC; msg[8] = 0x03; msg[9] = cmd;
    if (cmd === AC_CMD_STATUS) {
        msg[10] = 0xFF; msg[11] = 0x03; msg[12] = 0xFF; msg[14] = 0x02;
        msg[21] = 0xFF; msg[22] = 0xFF;
    } else if (cmd === AC_CMD_SET) {
        const p = params;
        msg[10] = (p.power ? 0x40 : 0x00) | ((p.mode || 2) & 0x0F);
        msg[11] = Math.round((p.temperature || 24) * 2) & 0x1F;
        msg[12] = (p.fan_speed || 101) & 0x7F;
        msg[13] = (p.swing_horizontal ? 0x0F : 0x00) | (p.swing_vertical ? 0xF0 : 0x00);
        msg[14] = (p.eco   ? 0x80 : 0x00);
        msg[18] = (p.turbo ? 0x20 : 0x00) | (p.sleep ? 0x01 : 0x00);
        msg[21] = 0xFF; msg[22] = 0xFF;
    }
    msg[36] = crc8(msg.slice(10, 36));
    let sum = 0;
    for (let i = 1; i < 37; i++) sum = (sum + msg[i]) & 0xFF;
    msg[37] = (~sum + 1) & 0xFF;
    return msg.slice(0, 38);
}

// ─── MideaV3 ─────────────────────────────────────────────────────────────────
class MideaV3 {
    constructor(ip, port, token, key, log) {
        this.ip    = ip;
        this.port  = port;
        this.token = Buffer.from(token, 'hex');
        this.key   = Buffer.from(key,   'hex');
        this.log   = log;
        this.tcpKey   = null;
        this.socket   = null;
        this.rxBuf    = Buffer.alloc(0);
        this.msgCount = 0;
        this._pending = null;
    }

    // ── AES-256-ECB ──────────────────────────────────────────────────────────
    _aesEncrypt(plain) {
        const pad = (16 - (plain.length % 16)) % 16;
        const padded = Buffer.concat([plain, Buffer.alloc(pad, 0)]);
        const c = crypto.createCipheriv('aes-256-ecb', this.tcpKey, null);
        c.setAutoPadding(false);
        return Buffer.concat([c.update(padded), c.final()]);
    }

    _aesDecrypt(enc) {
        if (enc.length === 0) return Buffer.alloc(0);
        const d = crypto.createDecipheriv('aes-256-ecb', this.tcpKey, null);
        d.setAutoPadding(false);
        return Buffer.concat([d.update(enc), d.final()]);
    }

    // ── TCP-Key ableiten ─────────────────────────────────────────────────────
    // Handshake-Response: 8-Byte 8370-Header + 64 Byte Payload
    // payload[0:32] XOR key[0:32] → SHA256 → kombiniert mit payload[32:64] → SHA256
    _deriveKey(responsePacket) {
        const payload = responsePacket.slice(8, 72);
        if (payload.length < 64) {
            throw new Error('HS-Antwort Payload zu kurz: ' + payload.length + ' (erwartet 64)');
        }
        const xored = Buffer.alloc(32);
        for (let i = 0; i < 32; i++) xored[i] = payload[i] ^ this.key[i];
        const inner    = crypto.createHash('sha256').update(xored).digest();
        const combined = Buffer.concat([inner, payload.slice(32, 64)]);
        this.tcpKey    = crypto.createHash('sha256').update(combined).digest();
        this.log.debug('TCP-Key: ' + this.tcpKey.toString('hex'));
    }

    // ── Verschlüsseltes 8370-Paket bauen ─────────────────────────────────────
    // Format: 8370-Header(8) + msgcount(2) + encrypted(n)
    _wrapRequest(acFrame) {
        const enc = this._aesEncrypt(acFrame);
        const countBuf = Buffer.alloc(2);
        countBuf.writeUInt16BE(this.msgCount++ & 0xFFFF, 0);
        const payload = Buffer.concat([countBuf, enc]);
        return build8370(MSGTYPE_ENCRYPTED_REQUEST, payload);
    }

    // ── Puffer-Parser ─────────────────────────────────────────────────────────
    _tryConsume() {
        if (this.rxBuf.length < 8) return null;

        // Magic prüfen
        if (this.rxBuf[0] !== 0x83 || this.rxBuf[1] !== 0x70) {
            // Desync: bis zum nächsten 0x83 vorspulen
            const next = this.rxBuf.indexOf(0x83, 1);
            this.rxBuf = next >= 0 ? this.rxBuf.slice(next) : Buffer.alloc(0);
            this.log.warn('8370 Desync, neu synchronisiert');
            return null;
        }

        const payLen = this.rxBuf.readUInt16BE(2);
        const total  = 8 + payLen;
        if (this.rxBuf.length < total) return null;  // noch nicht komplett

        const packet  = this.rxBuf.slice(0, total);
        this.rxBuf    = this.rxBuf.slice(total);
        const msgType = packet[4];

        this.log.debug('RX Paket type=0x' + msgType.toString(16) + ' len=' + total + ': ' + packet.toString('hex'));

        if (msgType === MSGTYPE_HANDSHAKE_REQUEST) {
            // Handshake-Response hat denselben msgtype wie Request (0x20)
            return { type: 'handshake', raw: packet };
        }

        if (msgType === MSGTYPE_ENCRYPTED_RESPONSE) {
            if (this.tcpKey) {
                // Normaler verschlüsselter Response nach Handshake
                const encrypted = packet.slice(10);  // header(8) + count(2)
                const plain = this._aesDecrypt(encrypted);
                return { type: 'response', plain };
            } else {
                // Manche Geräte antworten auf HS mit msgtype 0x04 — als HS behandeln
                this.log.debug('Gerät antwortete auf HS mit msgtype 0x04 — behandle als Handshake');
                return { type: 'handshake', raw: packet };
            }
        }

        this.log.warn('Unbekannter msgtype: 0x' + msgType.toString(16));
        return { type: 'unknown', raw: packet };
    }

    // ── Socket-Callbacks ─────────────────────────────────────────────────────
    _onData(chunk) {
        this.rxBuf = Buffer.concat([this.rxBuf, chunk]);
        this.log.debug('RX chunk ' + chunk.length + 'B: ' + chunk.toString('hex'));

        let result;
        try { result = this._tryConsume(); } catch (e) {
            this.rxBuf = Buffer.alloc(0);
            this._settle(null, e);
            return;
        }
        if (result) this._settle(result, null);
    }

    _onError(err) {
        this.log.error('Socket-Fehler: ' + err.message);
        this._settle(null, err);
    }

    _settle(result, err) {
        if (!this._pending) return;
        const p = this._pending;
        this._pending = null;
        clearTimeout(p.timer);
        err ? p.reject(err) : p.resolve(result);
    }

    _waitPacket(timeoutMsg) {
        return new Promise((resolve, reject) => {
            this._pending = {
                resolve, reject,
                timer: setTimeout(() => {
                    this._pending = null;
                    reject(new Error(timeoutMsg));
                }, READ_TIMEOUT_MS),
            };
        });
    }

    // ── Öffentliche API ───────────────────────────────────────────────────────
    async connect() {
        // 1. TCP verbinden
        await new Promise((resolve, reject) => {
            this.socket = new net.Socket();
            this.socket.setKeepAlive(true, 5000);
            this.socket.on('data',  (c) => this._onData(c));
            this.socket.on('error', (e) => this._onError(e));
            this.socket.on('close', () => {
                this._settle(null, new Error('Verbindung unerwartet getrennt'));
            });

            const t = setTimeout(() => {
                this.socket.destroy();
                reject(new Error('TCP-Connect Timeout (' + this.ip + ':' + this.port + ')'));
            }, CONNECT_TIMEOUT_MS);

            this.socket.connect(this.port, this.ip, () => {
                clearTimeout(t);
                this.log.debug('TCP verbunden mit ' + this.ip + ':' + this.port);
                resolve();
            });
        });

        // 2. Handshake senden
        // Format (bestätigt durch pcap): 8370 0040 20 00 0000 <64-byte-token>
        const hsPacket = build8370(MSGTYPE_HANDSHAKE_REQUEST, this.token);
        this.log.debug('HS senden (' + hsPacket.length + 'B): ' + hsPacket.toString('hex'));
        this.socket.write(hsPacket);

        // 3. Auf HS-Antwort warten
        const hsResult = await this._waitPacket('Handshake Timeout — prüfe IP, Port und Token');
        // HS-Antwort enthält immer das rohe Paket in hsResult.raw
        if (!hsResult.raw) {
            throw new Error('Keine HS-Antwort mit raw-Daten erhalten (type=' + hsResult.type + ')');
        }
        this._deriveKey(hsResult.raw);

        // 4. Pflicht-Pause: Gerät braucht ~1s nach Handshake
        await new Promise((r) => setTimeout(r, POST_HANDSHAKE_DELAY_MS));
        this.log.info('Handshake OK, bereit für Befehle');
    }

    async sendCommand(acFrame) {
        const packet = this._wrapRequest(acFrame);
        this.log.debug('CMD senden (' + packet.length + 'B): ' + packet.toString('hex'));
        this.socket.write(packet);
        const result = await this._waitPacket('Antwort Timeout nach Befehl');
        return result.plain;
    }

    disconnect() {
        if (this._pending) { clearTimeout(this._pending.timer); this._pending = null; }
        if (this.socket)   { this.socket.destroy(); this.socket = null; }
        this.tcpKey = null;
        this.rxBuf  = Buffer.alloc(0);
    }
}

// ─── AC Status parsen ────────────────────────────────────────────────────────
function parseACStatus(payload) {
    // 0xAA-Startbyte suchen
    let off = -1;
    for (let i = 0; i < payload.length; i++) {
        if (payload[i] === 0xAA) { off = i; break; }
    }
    if (off < 0) return null;
    const p = payload.slice(off);
    if (p.length < 25) return null;

    return {
        power:            !!(p[9]  & 0x40),
        mode:             MODES[p[9] & 0x0F] || ('mode_' + (p[9] & 0x0F)),
        temperature:      (p[10] & 0x1F) + (!!(p[10] & 0x20) ? 0.5 : 0),
        fan_speed:        FAN_SPEEDS[p[11] & 0x7F] || String(p[11] & 0x7F),
        swing_vertical:   !!(p[12] & 0xF0),
        swing_horizontal: !!(p[12] & 0x0F),
        eco:              !!(p[13] & 0x80),
        turbo:            !!(p[14] & 0x20),
        sleep:            !!(p[14] & 0x01),
        indoor_temp:  (p.length > 22 && p[22] !== 0xFF) ? (p[22] - 50) / 2 : null,
        outdoor_temp: (p.length > 23 && p[23] !== 0xFF) ? (p[23] - 50) / 2 : null,
    };
}

// ─── Adapter ─────────────────────────────────────────────────────────────────
class MideaAcAdapter extends utils.Adapter {
    constructor(options) {
        super({ ...options, name: 'midea-ac-lan' });
        this._pollTimer = null;
        this._lastState = {};
        this._polling   = false;
        this.on('ready',       this.onReady.bind(this));
        this.on('stateChange', this.onStateChange.bind(this));
        this.on('unload',      this.onUnload.bind(this));
    }

    async onReady() {
        this.log.info('Midea AC-LAN Adapter gestartet');
        if (!this.config.ip_address || !this.config.token || !this.config.key) {
            this.log.error('Konfiguration unvollständig — IP, Token und Key in der Admin-UI eintragen!');
            return;
        }
        await this._createObjects();
        this.subscribeStates('control.*');
        await this._poll();
        const iv = Math.max(5, parseInt(this.config.poll_interval, 10) || 30);
        this._pollTimer = setInterval(() => this._poll(), iv * 1000);
    }

    async _createObjects() {
        const S = [
            { id: 'status.power',            t: 'boolean', r: 'switch.power',      n: 'Ein/Aus',                    w: false },
            { id: 'status.mode',             t: 'string',  r: 'value',             n: 'Betriebsart',                w: false },
            { id: 'status.temperature',      t: 'number',  r: 'value.temperature', n: 'Solltemperatur',             w: false, u: '°C' },
            { id: 'status.fan_speed',        t: 'string',  r: 'value',             n: 'Lüftergeschwindigkeit',      w: false },
            { id: 'status.swing_vertical',   t: 'boolean', r: 'value',             n: 'Lamelle vertikal',           w: false },
            { id: 'status.swing_horizontal', t: 'boolean', r: 'value',             n: 'Lamelle horizontal',         w: false },
            { id: 'status.eco',              t: 'boolean', r: 'value',             n: 'Eco-Modus',                  w: false },
            { id: 'status.turbo',            t: 'boolean', r: 'value',             n: 'Turbo-Modus',                w: false },
            { id: 'status.sleep',            t: 'boolean', r: 'value',             n: 'Schlaf-Modus',               w: false },
            { id: 'status.indoor_temp',      t: 'number',  r: 'value.temperature', n: 'Innenraumtemperatur',        w: false, u: '°C' },
            { id: 'status.outdoor_temp',     t: 'number',  r: 'value.temperature', n: 'Außentemperatur',            w: false, u: '°C' },
            { id: 'control.power',           t: 'boolean', r: 'switch.power',      n: 'Ein/Aus schalten',           w: true  },
            { id: 'control.mode',            t: 'string',  r: 'value',             n: 'Betriebsart setzen',         w: true  },
            { id: 'control.temperature',     t: 'number',  r: 'value.temperature', n: 'Solltemperatur setzen',      w: true, u: '°C' },
            { id: 'control.fan_speed',       t: 'string',  r: 'value',             n: 'Lüftergeschwindigkeit setzen', w: true },
            { id: 'control.swing_vertical',  t: 'boolean', r: 'button',            n: 'Lamelle vertikal setzen',    w: true  },
            { id: 'control.swing_horizontal',t: 'boolean', r: 'button',            n: 'Lamelle horizontal setzen',  w: true  },
            { id: 'control.eco',             t: 'boolean', r: 'button',            n: 'Eco-Modus setzen',           w: true  },
            { id: 'control.turbo',           t: 'boolean', r: 'button',            n: 'Turbo-Modus setzen',         w: true  },
            { id: 'control.sleep',           t: 'boolean', r: 'button',            n: 'Schlaf-Modus setzen',        w: true  },
        ];
        for (const s of S) {
            await this.setObjectNotExistsAsync(s.id, {
                type: 'state',
                common: { name: s.n, type: s.t, role: s.r, read: true, write: s.w, unit: s.u },
                native: {},
            });
        }
    }

    async _withDevice(fn) {
        const dev = new MideaV3(
            this.config.ip_address,
            parseInt(this.config.port, 10) || 6444,
            this.config.token,
            this.config.key,
            this.log
        );
        try   { await dev.connect(); return await fn(dev); }
        finally { dev.disconnect(); }
    }

    async _poll() {
        if (this._polling) return;
        this._polling = true;
        try {
            const plain = await this._withDevice((d) => d.sendCommand(buildACFrame(AC_CMD_STATUS)));
            if (!plain) { this.log.warn('Leere Antwort vom Gerät'); return; }
            this.log.debug('Status-Rohdaten: ' + plain.toString('hex'));
            const st = parseACStatus(plain);
            if (!st) { this.log.warn('Parse fehlgeschlagen. Roh: ' + plain.toString('hex')); return; }
            this.log.debug('Status: ' + JSON.stringify(st));
            this._lastState = { ...st };
            await this.setStateAsync('status.power',            { val: st.power,            ack: true });
            await this.setStateAsync('status.mode',             { val: st.mode,             ack: true });
            await this.setStateAsync('status.temperature',      { val: st.temperature,      ack: true });
            await this.setStateAsync('status.fan_speed',        { val: st.fan_speed,        ack: true });
            await this.setStateAsync('status.swing_vertical',   { val: st.swing_vertical,   ack: true });
            await this.setStateAsync('status.swing_horizontal', { val: st.swing_horizontal, ack: true });
            await this.setStateAsync('status.eco',              { val: st.eco,              ack: true });
            await this.setStateAsync('status.turbo',            { val: st.turbo,            ack: true });
            await this.setStateAsync('status.sleep',            { val: st.sleep,            ack: true });
            if (st.indoor_temp  !== null) await this.setStateAsync('status.indoor_temp',  { val: st.indoor_temp,  ack: true });
            if (st.outdoor_temp !== null) await this.setStateAsync('status.outdoor_temp', { val: st.outdoor_temp, ack: true });
            this.setState('info.connection', true, true);
        } catch (e) {
            this.log.error('Poll-Fehler: ' + e.message);
            this.setState('info.connection', false, true);
        } finally { this._polling = false; }
    }

    async onStateChange(id, state) {
        if (!state || state.ack) return;
        const shortId = id.split('.').slice(2).join('.');
        if (!shortId.startsWith('control.')) return;
        const key = shortId.replace('control.', '');
        this.log.info('Steuerbefehl: ' + key + ' = ' + state.val);
        const cur = { ...this._lastState };
        if (key === 'power')            cur.power            = !!state.val;
        if (key === 'mode')             cur.mode             = state.val;
        if (key === 'temperature')      cur.temperature      = parseFloat(state.val);
        if (key === 'fan_speed')        cur.fan_speed        = state.val;
        if (key === 'swing_vertical')   cur.swing_vertical   = !!state.val;
        if (key === 'swing_horizontal') cur.swing_horizontal = !!state.val;
        if (key === 'eco')              cur.eco              = !!state.val;
        if (key === 'turbo')            cur.turbo            = !!state.val;
        if (key === 'sleep')            cur.sleep            = !!state.val;
        const params = {
            power:            cur.power !== undefined ? cur.power : true,
            mode:             MODES_REV[cur.mode] || 2,
            temperature:      cur.temperature      || 24,
            fan_speed:        FAN_SPEEDS_REV[cur.fan_speed] || 101,
            swing_vertical:   !!cur.swing_vertical,
            swing_horizontal: !!cur.swing_horizontal,
            eco: !!cur.eco, turbo: !!cur.turbo, sleep: !!cur.sleep,
        };
        try {
            await this._withDevice((d) => d.sendCommand(buildACFrame(AC_CMD_SET, params)));
            this.log.info('Befehl gesendet');
            setTimeout(() => this._poll(), 1500);
        } catch (e) { this.log.error('Steuerfehler: ' + e.message); }
    }

    onUnload(callback) {
        if (this._pollTimer) { clearInterval(this._pollTimer); this._pollTimer = null; }
        callback();
    }
}

if (require.main !== module) {
    module.exports = (options) => new MideaAcAdapter(options);
} else {
    new MideaAcAdapter();
}
