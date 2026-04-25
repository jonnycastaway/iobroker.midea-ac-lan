'use strict';

/**
 * ioBroker Adapter für Midea AC-Geräte mit Protokoll V3 (8370)
 * Frame-Format verifiziert gegen msmart-ng (mill1000/midea-msmart)
 */

const utils  = require('@iobroker/adapter-core');
const net    = require('net');
const crypto = require('crypto');

// ─── 8370 Protokoll ───────────────────────────────────────────────────────────
// Header (8 Bytes): magic(2) + payloadLen(2) + msgType(1) + pad(1) + reserved(2)
// Bestätigt durch pcap: 8370 0040 20 00 0000 <64-byte-token>
const MAGIC_8370 = Buffer.from([0x83, 0x70]);
const MSGTYPE_HANDSHAKE = 0x20;
const MSGTYPE_REQUEST   = 0x03;
const MSGTYPE_RESPONSE  = 0x04;

// ─── AC Frame-Konstanten (nach msmart-ng frame.py / command.py) ───────────────
const FRAME_HEADER_LEN  = 10;
const FRAME_TYPE_QUERY  = 0x03;
const FRAME_TYPE_CONTROL = 0x02;
const DEVICE_TYPE_AC    = 0xAC;

// Betriebsmodi
const MODES     = { 1: 'auto', 2: 'cool', 3: 'dry', 4: 'heat', 5: 'fan_only' };
const MODES_REV = { auto: 1, cool: 2, dry: 3, heat: 4, fan_only: 5 };

const CONNECT_TIMEOUT_MS   = 10000;
const READ_TIMEOUT_MS      = 10000;
const POST_HANDSHAKE_DELAY = 1000;

// ─── CRC8 (Midea) ─────────────────────────────────────────────────────────────
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

// Rahmen-Checksumme: (~sum(data) + 1) & 0xFF
function frameChecksum(data) {
    let s = 0;
    for (const b of data) s = (s + b) & 0xFF;
    return (~s + 1) & 0xFF;
}

// ─── AC Frame bauen (nach msmart-ng frame.py + command.py) ───────────────────
// Frame-Struktur:
//   [0]     0xAA  start
//   [1]     len(payload) + HEADER_LEN  (Gesamtlänge - 1, da [0] nicht mitgezählt)
//   [2]     0xAC  device type
//   [3..7]  0x00  padding
//   [8]     0x00  protocol version
//   [9]     frame_type  (0x03=QUERY, 0x02=CONTROL)
//   [10..n] cmd-Nutzdaten + message_id + CRC8(nutzdaten+msg_id)
//   [last]  frameChecksum(frame[1:-1])
let _messageId = 0;
function nextMessageId() { return (++_messageId) & 0xFF; }

function buildFrame(frameType, payload) {
    const msgId = nextMessageId();
    const payloadWithId = Buffer.concat([payload, Buffer.from([msgId])]);
    const crcByte = crc8(payloadWithId);
    const data = Buffer.concat([payloadWithId, Buffer.from([crcByte])]);

    const header = Buffer.alloc(FRAME_HEADER_LEN, 0x00);
    header[0] = 0xAA;
    header[1] = data.length + FRAME_HEADER_LEN;  // Gesamtlänge inkl. Header
    header[2] = DEVICE_TYPE_AC;
    header[8] = 0x00;  // protocol version
    header[9] = frameType;

    const frame = Buffer.concat([header, data]);
    const chk = frameChecksum(frame.slice(1));
    return Buffer.concat([frame, Buffer.from([chk])]);
}

function buildGetStateFrame() {
    // GetStateCommand.tobytes() aus msmart-ng:
    // 0x41, 0x81, 0x00, 0xFF, 0x03, 0xFF, 0x00,
    // temperature_type(0x02=INDOOR), 0x00*12, 0x03
    const payload = Buffer.from([
        0x41,                   // GET_STATE cmd
        0x81, 0x00, 0xFF, 0x03, 0xFF, 0x00,
        0x02,                   // temperature_type = INDOOR
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x03,                   // unknown
    ]);
    return buildFrame(FRAME_TYPE_QUERY, payload);
}

function buildSetStateFrame(p) {
    // SetStateCommand.tobytes() aus msmart-ng
    const power    = p.power ? 0x01 : 0x00;
    const beep     = 0x40;  // Beep on
    const ctrlSrc  = 0x02;  // App control

    // Temperatur-Encoding: (temp - 16) & 0xF, plus 0x10 für halbe Grade
    const tempInt  = Math.floor(p.temperature || 24);
    const tempHalf = ((p.temperature || 24) % 1) >= 0.5 ? 0x10 : 0x00;
    const tempEnc  = ((tempInt - 16) & 0xF) | tempHalf;

    const mode     = ((MODES_REV[p.mode] || 2) & 0x7) << 5;
    const fanSpeed = p.fan_speed || 102;  // 102=auto
    const swingMode = 0x30 | (p.swing_mode || 0);
    const eco      = p.eco   ? 0x80 : 0x00;
    const turboAlt = p.turbo ? 0x20 : 0x00;
    const sleep    = p.sleep ? 0x01 : 0x00;
    const turbo    = p.turbo ? 0x02 : 0x00;

    const payload = Buffer.from([
        0x40,                       // SET_STATE cmd
        ctrlSrc | beep | power,     // beep + power
        tempEnc | mode,             // temperature + mode
        fanSpeed,
        0x7F, 0x7F, 0x00,          // timer off
        swingMode,
        turboAlt,                   // follow_me | turbo_alt
        eco,                        // eco
        sleep | turbo,              // sleep + turbo
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
        0x00,                       // temperature_alt
        0x00,                       // target_humidity
        0x00,
        0x00,                       // freeze_protection
        0x00,                       // independent_aux_heat
        0x00,
    ]);
    return buildFrame(FRAME_TYPE_CONTROL, payload);
}

// ─── AC Status-Response parsen (nach msmart-ng StateResponse._parse) ──────────
// Der Frame kommt vom Gerät über 8370 verschlüsselt.
// Nach der AES-Entschlüsselung beginnt bei Offset 0 der Midea-Frame (0xAA...).
// Die Nutzdaten (payload) beginnen nach dem 10-Byte-Header, also bei offset 10.
function parseStateResponse(plain) {
    // 0xAA-Header finden
    let off = -1;
    for (let i = 0; i < plain.length; i++) {
        if (plain[i] === 0xAA) { off = i; break; }
    }
    if (off < 0) return null;

    const frame = plain.slice(off);
    if (frame.length < FRAME_HEADER_LEN + 5) return null;

    // response_id muss 0xC0 sein (STATE)
    const responseId = frame[FRAME_HEADER_LEN];
    if (responseId !== 0xC0) {
        // Kein Status-Response, ignorieren
        return null;
    }

    // payload = frame ab Byte 10 (nach Header), ohne letztes Byte (Checksum) und CRC
    const payload = frame.slice(FRAME_HEADER_LEN);

    // Nach msmart-ng StateResponse._parse:
    // payload[0] = response_id (0xC0)
    // payload[1] = power | flags
    // payload[2] = temperature (low 4 bits) + mode (high 3 bits)
    // payload[3] = fan_speed
    // payload[7] = swing_mode
    // payload[8] = turbo_alt | follow_me
    // payload[9] = eco | aux_heat | purifier
    // payload[10] = sleep | turbo | fahrenheit
    // payload[11] = indoor_temp
    // payload[12] = outdoor_temp
    // payload[13] = target_temp_alt | filter_alert
    // payload[14] = display_on (!=0x70)
    // payload[15] = temp decimals

    const power   = !!(payload[1] & 0x01);
    const tempRaw = payload[2] & 0x0F;
    const tempHalf = !!(payload[2] & 0x10);
    const temperature = tempRaw + 16.0 + (tempHalf ? 0.5 : 0.0);
    const mode    = (payload[2] >> 5) & 0x7;
    const fanSpeed = payload[3] & 0x7F;
    const swingMode = payload[7] & 0x0F;
    const turbo   = !!(payload[8] & 0x20) || !!(payload[10] & 0x02);
    const eco     = !!(payload[9] & 0x10);
    const sleep   = !!(payload[10] & 0x01);

    // Temperaturen: (raw - 50) / 2
    let indoorTemp  = null;
    let outdoorTemp = null;
    if (payload.length > 11 && payload[11] !== 0xFF) {
        indoorTemp = (payload[11] - 50) / 2;
    }
    if (payload.length > 12 && payload[12] !== 0xFF) {
        outdoorTemp = (payload[12] - 50) / 2;
    }

    return {
        power,
        mode:         MODES[mode] || ('mode_' + mode),
        temperature,
        fan_speed:    fanSpeed,
        swing_mode:   swingMode,
        swing_vertical:   !!(swingMode & 0x01),
        swing_horizontal: !!(swingMode & 0x02),
        turbo,
        eco,
        sleep,
        indoor_temp:  indoorTemp,
        outdoor_temp: outdoorTemp,
    };
}

// ─── MideaV3 Kommunikationsklasse ────────────────────────────────────────────
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
        this._pending = null;
    }

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

    _deriveKey(responsePacket) {
        // 8-Byte-Header überspringen, dann 64 Bytes Payload
        const payload = responsePacket.slice(8, 72);
        if (payload.length < 64) throw new Error('HS-Antwort zu kurz: ' + payload.length);
        const xored = Buffer.alloc(32);
        for (let i = 0; i < 32; i++) xored[i] = payload[i] ^ this.key[i];
        const inner    = crypto.createHash('sha256').update(xored).digest();
        const combined = Buffer.concat([inner, payload.slice(32, 64)]);
        this.tcpKey    = crypto.createHash('sha256').update(combined).digest();
        this.log.debug('TCP-Key: ' + this.tcpKey.toString('hex'));
    }

    _wrap8370(acFrame) {
        const enc = this._aesEncrypt(acFrame);
        const countBuf = Buffer.alloc(2);
        // msgCount nicht mehr nötig — einfach 0x00 0x00 als Zähler
        const body = Buffer.concat([countBuf, enc]);
        const hdr  = Buffer.alloc(8, 0x00);
        MAGIC_8370.copy(hdr, 0);
        hdr.writeUInt16BE(body.length, 2);
        hdr[4] = MSGTYPE_REQUEST;
        return Buffer.concat([hdr, body]);
    }

    _tryConsume() {
        if (this.rxBuf.length < 8) return null;
        if (this.rxBuf[0] !== 0x83 || this.rxBuf[1] !== 0x70) {
            const next = this.rxBuf.indexOf(0x83, 1);
            this.rxBuf = next >= 0 ? this.rxBuf.slice(next) : Buffer.alloc(0);
            return null;
        }
        const payLen = this.rxBuf.readUInt16BE(2);
        const total  = 8 + payLen;
        if (this.rxBuf.length < total) return null;

        const packet  = this.rxBuf.slice(0, total);
        this.rxBuf    = this.rxBuf.slice(total);
        const msgType = packet[4];

        this.log.debug('RX type=0x' + msgType.toString(16) + ' (' + total + 'B): ' + packet.toString('hex'));

        if (msgType === MSGTYPE_HANDSHAKE) {
            return { type: 'handshake', raw: packet };
        }
        if (msgType === MSGTYPE_RESPONSE) {
            const plain = this._aesDecrypt(packet.slice(10));
            return { type: 'response', plain };
        }
        return { type: 'unknown', raw: packet };
    }

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

    _waitPacket(msg) {
        return new Promise((resolve, reject) => {
            this._pending = {
                resolve, reject,
                timer: setTimeout(() => {
                    this._pending = null;
                    reject(new Error(msg));
                }, READ_TIMEOUT_MS),
            };
        });
    }

    async connect() {
        await new Promise((resolve, reject) => {
            this.socket = new net.Socket();
            this.socket.setKeepAlive(true, 5000);
            this.socket.on('data',  (c) => this._onData(c));
            this.socket.on('error', (e) => this._onError(e));
            this.socket.on('close', () => this._settle(null, new Error('Verbindung getrennt')));
            const t = setTimeout(() => {
                this.socket.destroy();
                reject(new Error('TCP-Connect Timeout (' + this.ip + ':' + this.port + ')'));
            }, CONNECT_TIMEOUT_MS);
            this.socket.connect(this.port, this.ip, () => {
                clearTimeout(t);
                this.log.debug('Verbunden mit ' + this.ip + ':' + this.port);
                resolve();
            });
        });

        // Handshake: 8370-Header (8B) + Token (64B)
        const hsPacket = Buffer.alloc(8 + this.token.length, 0x00);
        MAGIC_8370.copy(hsPacket, 0);
        hsPacket.writeUInt16BE(this.token.length, 2);
        hsPacket[4] = MSGTYPE_HANDSHAKE;
        this.token.copy(hsPacket, 8);
        this.log.debug('HS senden (' + hsPacket.length + 'B): ' + hsPacket.toString('hex'));
        this.socket.write(hsPacket);

        const hsResult = await this._waitPacket('Handshake Timeout — prüfe IP, Port und Token');
        this._deriveKey(hsResult.raw);
        this.log.info('Handshake OK');

        // Pflicht-Pause nach Handshake
        await new Promise((r) => setTimeout(r, POST_HANDSHAKE_DELAY));
    }

    async sendCommand(acFrame) {
        const packet = this._wrap8370(acFrame);
        this.log.debug('CMD (' + packet.length + 'B): ' + packet.toString('hex'));
        this.socket.write(packet);
        const result = await this._waitPacket('Antwort Timeout');
        return result.plain;
    }

    disconnect() {
        if (this._pending) { clearTimeout(this._pending.timer); this._pending = null; }
        if (this.socket)   { this.socket.destroy(); this.socket = null; }
        this.tcpKey = null;
        this.rxBuf  = Buffer.alloc(0);
    }
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
            { id: 'status.power',           t: 'boolean', r: 'switch.power',      n: 'Ein/Aus',                    w: false },
            { id: 'status.mode',            t: 'string',  r: 'value',             n: 'Betriebsart',                w: false },
            { id: 'status.temperature',     t: 'number',  r: 'value.temperature', n: 'Solltemperatur',             w: false, u: '°C' },
            { id: 'status.fan_speed',       t: 'number',  r: 'value',             n: 'Lüftergeschwindigkeit',      w: false },
            { id: 'status.swing_vertical',  t: 'boolean', r: 'value',             n: 'Lamelle vertikal',           w: false },
            { id: 'status.swing_horizontal',t: 'boolean', r: 'value',             n: 'Lamelle horizontal',         w: false },
            { id: 'status.eco',             t: 'boolean', r: 'value',             n: 'Eco-Modus',                  w: false },
            { id: 'status.turbo',           t: 'boolean', r: 'value',             n: 'Turbo-Modus',                w: false },
            { id: 'status.sleep',           t: 'boolean', r: 'value',             n: 'Schlaf-Modus',               w: false },
            { id: 'status.indoor_temp',     t: 'number',  r: 'value.temperature', n: 'Innenraumtemperatur',        w: false, u: '°C' },
            { id: 'status.outdoor_temp',    t: 'number',  r: 'value.temperature', n: 'Außentemperatur',            w: false, u: '°C' },
            { id: 'control.power',          t: 'boolean', r: 'switch.power',      n: 'Ein/Aus schalten',           w: true  },
            { id: 'control.mode',           t: 'string',  r: 'value',             n: 'Betriebsart (auto/cool/dry/heat/fan_only)', w: true },
            { id: 'control.temperature',    t: 'number',  r: 'value.temperature', n: 'Solltemperatur setzen (16-30)', w: true, u: '°C' },
            { id: 'control.fan_speed',      t: 'number',  r: 'value',             n: 'Lüfter (20/40/60/80/102=auto)', w: true },
            { id: 'control.swing_vertical', t: 'boolean', r: 'button',            n: 'Lamelle vertikal',           w: true  },
            { id: 'control.swing_horizontal',t:'boolean', r: 'button',            n: 'Lamelle horizontal',         w: true  },
            { id: 'control.eco',            t: 'boolean', r: 'button',            n: 'Eco-Modus',                  w: true  },
            { id: 'control.turbo',          t: 'boolean', r: 'button',            n: 'Turbo-Modus',                w: true  },
            { id: 'control.sleep',          t: 'boolean', r: 'button',            n: 'Schlaf-Modus',               w: true  },
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
            const plain = await this._withDevice((d) => d.sendCommand(buildGetStateFrame()));
            if (!plain) { this.log.warn('Leere Antwort'); return; }
            this.log.debug('Antwort-Rohdaten: ' + plain.toString('hex'));

            const st = parseStateResponse(plain);
            if (!st) {
                this.log.warn('Kein Status-Response (0xC0) in Antwort. Roh: ' + plain.toString('hex'));
                return;
            }
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
        if (key === 'fan_speed')        cur.fan_speed        = parseInt(state.val, 10);
        if (key === 'swing_vertical')   cur.swing_vertical   = !!state.val;
        if (key === 'swing_horizontal') cur.swing_horizontal = !!state.val;
        if (key === 'eco')              cur.eco              = !!state.val;
        if (key === 'turbo')            cur.turbo            = !!state.val;
        if (key === 'sleep')            cur.sleep            = !!state.val;

        const swingMode = ((cur.swing_horizontal ? 0x02 : 0) | (cur.swing_vertical ? 0x01 : 0));
        const params = {
            power:       cur.power !== undefined ? cur.power : true,
            mode:        cur.mode        || 'cool',
            temperature: cur.temperature || 24,
            fan_speed:   cur.fan_speed   || 102,
            swing_mode:  swingMode,
            eco:         !!cur.eco,
            turbo:       !!cur.turbo,
            sleep:       !!cur.sleep,
        };

        try {
            await this._withDevice((d) => d.sendCommand(buildSetStateFrame(params)));
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
