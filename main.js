'use strict';

const utils = require('@iobroker/adapter-core');
const net = require('net');
const crypto = require('crypto');

// ─────────────────────────────────────────────
//  Midea Protocol V3 (8370) constants
// ─────────────────────────────────────────────
const MAGIC          = Buffer.from([0x83, 0x70]);
const MSGTYPE_HANDSHAKE_REQUEST  = 0x00;
const MSGTYPE_ENCRYPTED_REQUEST  = 0x03;
const MSGTYPE_ENCRYPTED_RESPONSE = 0x04;

const AC_CMD_STATUS  = 0x41; // Query
const AC_CMD_SET     = 0x40; // Set

// Mode mapping (Midea → readable)
const MODES = { 1: 'auto', 2: 'cool', 3: 'dry', 4: 'heat', 5: 'fan_only' };
const MODES_REV = { auto: 1, cool: 2, dry: 3, heat: 4, fan_only: 5 };
const FAN_SPEEDS = { 20: 'silent', 40: 'low', 60: 'medium', 80: 'high', 101: 'auto', 102: 'turbo' };
const FAN_SPEEDS_REV = { silent: 20, low: 40, medium: 60, high: 80, auto: 101, turbo: 102 };

// ─────────────────────────────────────────────
//  CRC8 table for Midea
// ─────────────────────────────────────────────
function crc8(data) {
    const TABLE = [
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
    let crc = 0;
    for (const b of data) crc = TABLE[(crc ^ b) & 0xFF];
    return crc;
}

// ─────────────────────────────────────────────
//  Build raw AC command frame (before 8370 wrap)
// ─────────────────────────────────────────────
function buildACFrame(cmd, params = {}) {
    // Standard Midea AC message structure
    const msg = Buffer.alloc(40, 0);
    msg[0]  = 0xAA;          // header
    msg[1]  = 0x23;          // length (35 bytes payload + header/len)
    msg[2]  = 0xAC;          // device type: AC
    msg[3]  = 0x00;
    msg[4]  = 0x00;
    msg[5]  = 0x00;
    msg[6]  = 0x00;
    msg[7]  = 0x00;
    msg[8]  = 0x03;          // frame type
    msg[9]  = cmd;           // command

    if (cmd === AC_CMD_STATUS) {
        msg[10] = 0xFF;
        msg[11] = 0x03;
        msg[12] = 0xFF;
        msg[13] = 0x00;
        // bytes 14-31 = 0x00 padding
        msg[14] = 0x02;
        msg[21] = 0xFF;
        msg[22] = 0xFF;
        msg[29] = 0x00;
    } else if (cmd === AC_CMD_SET) {
        const p = params;
        // power + mode
        msg[10] = (p.power ? 0x40 : 0x00) | ((p.mode || 2) & 0x0F) | 0x00;
        // temperature: (target * 2 & 0x1F) — supports 0.5 steps
        const tempRaw = Math.round((p.temperature || 24) * 2);
        msg[11] = tempRaw & 0x1F;
        // fan speed
        msg[12] = (p.fan_speed || 101) & 0x7F;
        // swing
        const swingH = p.swing_horizontal ? 0x0F : 0x00;
        const swingV = p.swing_vertical   ? 0xF0 : 0x00;
        msg[13] = swingH | swingV;
        // eco / turbo / sleep
        msg[14] = (p.eco ? 0x80 : 0x00);
        msg[18] = (p.turbo ? 0x20 : 0x00) | (p.sleep ? 0x01 : 0x00);
        msg[21] = 0xFF;
        msg[22] = 0xFF;
        msg[29] = 0x00;
    }

    // CRC byte at position 36, checksum at 37
    msg[36] = crc8(msg.slice(10, 36));
    let checksum = 0;
    for (let i = 1; i < 37; i++) checksum = (checksum + msg[i]) & 0xFF;
    msg[37] = (~checksum + 1) & 0xFF;

    return msg.slice(0, 38);
}

// ─────────────────────────────────────────────
//  Protocol 8370 / V3 wrapping
// ─────────────────────────────────────────────
class MideaV3 {
    constructor(ip, port, deviceId, token, key, log) {
        this.ip       = ip;
        this.port     = port;
        this.deviceId = BigInt(deviceId);
        this.token    = Buffer.from(token, 'hex');
        this.key      = Buffer.from(key, 'hex');
        this.log      = log;
        this.tcpKey   = null;
        this.socket   = null;
        this.msgCount = 0;
    }

    _buildHandshakeRequest() {
        // 8370 packet: MAGIC + len(2) + msgtype(1) + reserved(1) + payload
        const payload = this.token;
        const buf = Buffer.alloc(6 + payload.length);
        MAGIC.copy(buf, 0);
        buf.writeUInt16BE(payload.length, 2);
        buf[4] = MSGTYPE_HANDSHAKE_REQUEST;
        buf[5] = 0x00;
        payload.copy(buf, 6);
        return buf;
    }

    _decryptHandshakeResponse(data) {
        // response payload starts at byte 8 (skip 8-byte header)
        const response = data.slice(8, 72);
        // TCP key derivation: SHA-256 of (response[:32] XOR key[:32]) + response[32:64]
        const part1 = Buffer.alloc(32);
        for (let i = 0; i < 32; i++) part1[i] = response[i] ^ this.key[i];
        const hash  = crypto.createHash('sha256').update(part1).digest();
        const part2 = response.slice(32, 64);
        const combined = Buffer.concat([hash, part2]);
        this.tcpKey = crypto.createHash('sha256').update(combined).digest();
        this.log.debug(`TCP key derived: ${this.tcpKey.toString('hex')}`);
    }

    _encryptPayload(payload) {
        const padded = payload.length % 16 !== 0
            ? Buffer.concat([payload, Buffer.alloc(16 - (payload.length % 16), 0)])
            : payload;
        const cipher = crypto.createCipheriv('aes-256-ecb', this.tcpKey, null);
        cipher.setAutoPadding(false);
        return Buffer.concat([cipher.update(padded), cipher.final()]);
    }

    _decryptPayload(payload) {
        const decipher = crypto.createDecipheriv('aes-256-ecb', this.tcpKey, null);
        decipher.setAutoPadding(false);
        return Buffer.concat([decipher.update(payload), decipher.final()]);
    }

    _wrapEncrypted(plainPayload) {
        const encrypted = this._encryptPayload(plainPayload);
        // 8370 header: MAGIC(2) + dataLen(2) + msgtype(1) + reserved(1) + payload
        const header = Buffer.alloc(6);
        MAGIC.copy(header, 0);
        header.writeUInt16BE(encrypted.length + 2, 2); // +2 for the 2-byte count prefix
        header[4] = MSGTYPE_ENCRYPTED_REQUEST;
        header[5] = 0x00;
        // 2-byte message count before the encrypted payload
        const countBuf = Buffer.alloc(2);
        countBuf.writeUInt16BE(this.msgCount & 0xFFFF, 0);
        this.msgCount++;
        return Buffer.concat([header, countBuf, encrypted]);
    }

    _unwrapEncrypted(data) {
        if (data.length < 6) return null;
        if (data[0] !== 0x83 || data[1] !== 0x70) {
            this.log.warn('Invalid 8370 magic in response');
            return null;
        }
        const dataLen  = data.readUInt16BE(2);
        const msgType  = data[4];
        if (msgType !== MSGTYPE_ENCRYPTED_RESPONSE) {
            this.log.debug(`Unexpected msgtype: ${msgType}`);
            return null;
        }
        // payload starts at byte 6, skip 2-byte count prefix
        const encrypted = data.slice(8, 6 + dataLen);
        if (encrypted.length === 0) return null;
        return this._decryptPayload(encrypted);
    }

    async connect() {
        return new Promise((resolve, reject) => {
            this.socket = new net.Socket();
            this.socket.setTimeout(8000);
            this.socket.once('error', (err) => reject(err));
            this.socket.once('timeout', () => reject(new Error('Connection timeout')));

            this.socket.connect(this.port, this.ip, () => {
                this.log.debug(`Connected to ${this.ip}:${this.port}`);
                // Send handshake
                const hsReq = this._buildHandshakeRequest();
                this.log.debug(`HS request: ${hsReq.toString('hex')}`);
                this.socket.write(hsReq);
            });

            this.socket.once('data', (data) => {
                this.log.debug(`HS response: ${data.toString('hex')}`);
                try {
                    this._decryptHandshakeResponse(data);
                    resolve();
                } catch (e) {
                    reject(e);
                }
            });
        });
    }

    async sendCommand(acFrame) {
        return new Promise((resolve, reject) => {
            const packet = this._wrapEncrypted(acFrame);
            this.log.debug(`Sending: ${packet.toString('hex')}`);

            const timeout = setTimeout(() => {
                reject(new Error('Command response timeout'));
            }, 8000);

            this.socket.once('data', (data) => {
                clearTimeout(timeout);
                this.log.debug(`Response: ${data.toString('hex')}`);
                try {
                    const plain = this._unwrapEncrypted(data);
                    resolve(plain);
                } catch (e) {
                    reject(e);
                }
            });

            this.socket.write(packet);
        });
    }

    disconnect() {
        if (this.socket) {
            this.socket.destroy();
            this.socket = null;
            this.tcpKey = null;
        }
    }
}

// ─────────────────────────────────────────────
//  Parse AC status response
// ─────────────────────────────────────────────
function parseACStatus(payload) {
    // Find the 0xAA header in the decrypted payload
    let offset = 0;
    for (let i = 0; i < payload.length; i++) {
        if (payload[i] === 0xAA) { offset = i; break; }
    }
    const p = payload.slice(offset);
    if (p.length < 25) return null;

    const power         = !!(p[9] & 0x40);
    const mode          = p[9] & 0x0F;
    const tempRaw       = p[10] & 0x1F;
    const halfDegree    = !!(p[10] & 0x20);
    const temperature   = tempRaw + (halfDegree ? 0.5 : 0.0);
    const fanSpeed      = p[11] & 0x7F;
    const swingVertical = !!(p[12] & 0xF0);
    const swingHoriz    = !!(p[12] & 0x0F);
    const eco           = !!(p[13] & 0x80);
    const turbo         = !!(p[14] & 0x20);
    const sleep         = !!(p[14] & 0x01);

    // Indoor temperature (byte 22), signed: value/2 + 16 or similar
    let indoorTemp = null;
    if (p.length > 22 && p[22] !== 0xFF) {
        indoorTemp = (p[22] - 50) / 2.0;
    }
    // Outdoor temperature (byte 23)
    let outdoorTemp = null;
    if (p.length > 23 && p[23] !== 0xFF) {
        outdoorTemp = (p[23] - 50) / 2.0;
    }

    return {
        power,
        mode:             MODES[mode] || 'unknown',
        temperature,
        fan_speed:        FAN_SPEEDS[fanSpeed] || fanSpeed,
        swing_vertical:   swingVertical,
        swing_horizontal: swingHoriz,
        eco,
        turbo,
        sleep,
        indoor_temp:  indoorTemp,
        outdoor_temp: outdoorTemp,
    };
}

// ─────────────────────────────────────────────
//  Adapter
// ─────────────────────────────────────────────
class MideaAcAdapter extends utils.Adapter {
    constructor(options) {
        super({ ...options, name: 'midea-ac-lan' });
        this._pollTimer = null;
        this._lastState = {};
        this.on('ready',       this.onReady.bind(this));
        this.on('stateChange', this.onStateChange.bind(this));
        this.on('unload',      this.onUnload.bind(this));
    }

    async onReady() {
        this.log.info('Midea AC adapter starting...');
        await this._createObjects();

        const interval = parseInt(this.config.poll_interval, 10) || 30;
        await this._poll();
        this._pollTimer = setInterval(() => this._poll(), interval * 1000);

        this.subscribeStates('control.*');
    }

    async _createObjects() {
        const objs = [
            // Status (read)
            { id: 'status.power',         type: 'boolean', role: 'switch.power',       name: 'Power on/off',         read: true,  write: false },
            { id: 'status.mode',          type: 'string',  role: 'value',              name: 'Operating mode',       read: true,  write: false },
            { id: 'status.temperature',   type: 'number',  role: 'value.temperature',  name: 'Target temperature',   read: true,  write: false, unit: '°C' },
            { id: 'status.fan_speed',     type: 'string',  role: 'value',              name: 'Fan speed',            read: true,  write: false },
            { id: 'status.swing_vertical',   type: 'boolean', role: 'value',           name: 'Swing vertical',       read: true,  write: false },
            { id: 'status.swing_horizontal', type: 'boolean', role: 'value',           name: 'Swing horizontal',     read: true,  write: false },
            { id: 'status.eco',           type: 'boolean', role: 'value',              name: 'Eco mode',             read: true,  write: false },
            { id: 'status.turbo',         type: 'boolean', role: 'value',              name: 'Turbo mode',           read: true,  write: false },
            { id: 'status.sleep',         type: 'boolean', role: 'value',              name: 'Sleep mode',           read: true,  write: false },
            { id: 'status.indoor_temp',   type: 'number',  role: 'value.temperature',  name: 'Indoor temperature',   read: true,  write: false, unit: '°C' },
            { id: 'status.outdoor_temp',  type: 'number',  role: 'value.temperature',  name: 'Outdoor temperature',  read: true,  write: false, unit: '°C' },
            // Control (write)
            { id: 'control.power',        type: 'boolean', role: 'switch.power',       name: 'Set power',            read: true,  write: true  },
            { id: 'control.mode',         type: 'string',  role: 'value',              name: 'Set mode (auto/cool/dry/heat/fan_only)', read: true, write: true },
            { id: 'control.temperature',  type: 'number',  role: 'value.temperature',  name: 'Set temperature (16-30)', read: true, write: true, unit: '°C' },
            { id: 'control.fan_speed',    type: 'string',  role: 'value',              name: 'Set fan speed (silent/low/medium/high/auto/turbo)', read: true, write: true },
            { id: 'control.swing_vertical',   type: 'boolean', role: 'button',         name: 'Set swing vertical',   read: true,  write: true  },
            { id: 'control.swing_horizontal', type: 'boolean', role: 'button',         name: 'Set swing horizontal', read: true,  write: true  },
            { id: 'control.eco',          type: 'boolean', role: 'button',             name: 'Set eco mode',         read: true,  write: true  },
            { id: 'control.turbo',        type: 'boolean', role: 'button',             name: 'Set turbo mode',       read: true,  write: true  },
            { id: 'control.sleep',        type: 'boolean', role: 'button',             name: 'Set sleep mode',       read: true,  write: true  },
        ];

        for (const o of objs) {
            await this.setObjectNotExistsAsync(o.id, {
                type: 'state',
                common: {
                    name:  o.name,
                    type:  o.type,
                    role:  o.role,
                    read:  o.read,
                    write: o.write,
                    unit:  o.unit || undefined,
                },
                native: {},
            });
        }
    }

    async _withDevice(fn) {
        const dev = new MideaV3(
            this.config.ip_address,
            parseInt(this.config.port, 10) || 6444,
            this.config.device_id,
            this.config.token,
            this.config.key,
            this.log
        );
        try {
            await dev.connect();
            const result = await fn(dev);
            dev.disconnect();
            return result;
        } catch (e) {
            dev.disconnect();
            throw e;
        }
    }

    async _poll() {
        try {
            const frame  = buildACFrame(AC_CMD_STATUS);
            const result = await this._withDevice(async (dev) => dev.sendCommand(frame));
            if (!result) return;

            const status = parseACStatus(result);
            if (!status) {
                this.log.warn('Could not parse AC status response');
                return;
            }

            this.log.debug(`Status: ${JSON.stringify(status)}`);
            this._lastState = { ...status };

            await this.setStateAsync('status.power',            { val: status.power,            ack: true });
            await this.setStateAsync('status.mode',             { val: status.mode,             ack: true });
            await this.setStateAsync('status.temperature',      { val: status.temperature,      ack: true });
            await this.setStateAsync('status.fan_speed',        { val: status.fan_speed,        ack: true });
            await this.setStateAsync('status.swing_vertical',   { val: status.swing_vertical,   ack: true });
            await this.setStateAsync('status.swing_horizontal', { val: status.swing_horizontal, ack: true });
            await this.setStateAsync('status.eco',              { val: status.eco,              ack: true });
            await this.setStateAsync('status.turbo',            { val: status.turbo,            ack: true });
            await this.setStateAsync('status.sleep',            { val: status.sleep,            ack: true });
            if (status.indoor_temp  !== null) await this.setStateAsync('status.indoor_temp',  { val: status.indoor_temp,  ack: true });
            if (status.outdoor_temp !== null) await this.setStateAsync('status.outdoor_temp', { val: status.outdoor_temp, ack: true });

            this.setState('info.connection', true, true);
        } catch (e) {
            this.log.error(`Poll error: ${e.message}`);
            this.setState('info.connection', false, true);
        }
    }

    async onStateChange(id, state) {
        if (!state || state.ack) return;

        const shortId = id.split('.').slice(2).join('.');
        if (!shortId.startsWith('control.')) return;

        this.log.info(`Control: ${shortId} = ${state.val}`);

        // Merge new value into last known state
        const cur = { ...this._lastState };
        const key = shortId.replace('control.', '');

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
            power:            cur.power  !== undefined ? cur.power  : true,
            mode:             MODES_REV[cur.mode]      || 2,
            temperature:      cur.temperature           || 24,
            fan_speed:        FAN_SPEEDS_REV[cur.fan_speed] || 101,
            swing_vertical:   cur.swing_vertical   || false,
            swing_horizontal: cur.swing_horizontal || false,
            eco:              cur.eco              || false,
            turbo:            cur.turbo            || false,
            sleep:            cur.sleep            || false,
        };

        try {
            const frame = buildACFrame(AC_CMD_SET, params);
            await this._withDevice(async (dev) => dev.sendCommand(frame));
            this.log.info('Command sent successfully');
            // Refresh status after short delay
            setTimeout(() => this._poll(), 2000);
        } catch (e) {
            this.log.error(`Set error: ${e.message}`);
        }
    }

    onUnload(callback) {
        if (this._pollTimer) {
            clearInterval(this._pollTimer);
            this._pollTimer = null;
        }
        callback();
    }
}

if (require.main !== module) {
    module.exports = (options) => new MideaAcAdapter(options);
} else {
    new MideaAcAdapter();
}
