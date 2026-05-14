'use strict';

const utils = require('@iobroker/adapter-core');
const crypto = require('crypto');
const net = require('net');
const https = require('https');

const PORT_TCP = 6444;
const HEADER_8370_1ST = 0x83;
const HEADER_8370_2ND = 0x70;
const DEFAULT_KEY = Buffer.from('6a92ef406bad2f0359baad994171ea6d', 'hex');
const DEFAULT_IV = Buffer.alloc(16, 0);

const CRC8_TABLE = [
    0x00, 0x5E, 0xBC, 0xE2, 0x61, 0x3F, 0xDD, 0x83, 0xC2, 0x9C, 0x7E, 0x20, 0xA3, 0xFD, 0x1F, 0x41,
    0x9D, 0xC3, 0x21, 0x7F, 0xFC, 0xA2, 0x40, 0x1E, 0x5F, 0x01, 0xE3, 0xBD, 0x3E, 0x60, 0x82, 0xDC,
    0x23, 0x7D, 0x9F, 0xC1, 0x42, 0x1C, 0xFE, 0xA0, 0xE1, 0xBF, 0x5D, 0x03, 0x80, 0xDE, 0x3C, 0x62,
    0xBE, 0xE0, 0x02, 0x5C, 0xDF, 0x81, 0x63, 0x3D, 0x7C, 0x22, 0xC0, 0x9E, 0x1D, 0x43, 0xA1, 0xFF,
    0x46, 0x18, 0xFA, 0xA4, 0x27, 0x79, 0x9B, 0xC5, 0x84, 0xDA, 0x38, 0x66, 0xE5, 0xBB, 0x59, 0x07,
    0xDB, 0x85, 0x67, 0x39, 0xBA, 0xE4, 0x06, 0x58, 0x19, 0x47, 0xA5, 0xFB, 0x78, 0x26, 0xC4, 0x9A,
    0x65, 0x3B, 0xD9, 0x87, 0x04, 0x5A, 0xB8, 0xE6, 0xA7, 0xF9, 0x1B, 0x45, 0xC6, 0x98, 0x7A, 0x24,
    0xF8, 0xA6, 0x44, 0x1A, 0x99, 0xC7, 0x25, 0x7B, 0x3A, 0x64, 0x86, 0xD8, 0x5B, 0x05, 0xE7, 0xB9,
    0x8C, 0xD2, 0x30, 0x6E, 0xED, 0xB3, 0x51, 0x0F, 0x4E, 0x10, 0xF2, 0xAC, 0x2F, 0x71, 0x93, 0xCD,
    0x11, 0x4F, 0xAD, 0xF3, 0x70, 0x2E, 0xCC, 0x92, 0xD3, 0x8D, 0x6F, 0x31, 0xB2, 0xEC, 0x0E, 0x50,
    0xAF, 0xF1, 0x13, 0x4D, 0xCE, 0x90, 0x72, 0x2C, 0x6D, 0x33, 0xD1, 0x8F, 0x0C, 0x52, 0xB0, 0xEE,
    0x32, 0x6C, 0x8E, 0xD0, 0x53, 0x0D, 0xEF, 0xB1, 0xF0, 0xAE, 0x4C, 0x12, 0x91, 0xCF, 0x2D, 0x73,
    0xCA, 0x94, 0x76, 0x28, 0xAB, 0xF5, 0x17, 0x49, 0x08, 0x56, 0xB4, 0xEA, 0x69, 0x37, 0xD5, 0x8B,
    0x57, 0x09, 0xEB, 0xB5, 0x36, 0x68, 0x8A, 0xD4, 0x95, 0xCB, 0x29, 0x77, 0xF4, 0xAA, 0x48, 0x16,
    0xE9, 0xB7, 0x55, 0x0B, 0x88, 0xD6, 0x34, 0x6A, 0x2B, 0x75, 0x97, 0xC9, 0x4A, 0x14, 0xF6, 0xA8,
    0x74, 0x2A, 0xC8, 0x96, 0x15, 0x4B, 0xA9, 0xF7, 0xB6, 0xE8, 0x0A, 0x54, 0xD7, 0x89, 0x6B, 0x35,
];

function crc8(data) {
    let crc = 0;
    for (let i = 0; i < data.length; i++) {
        crc = CRC8_TABLE[(crc ^ data[i]) & 0xFF];
    }
    return crc & 0xFF;
}

function aesCbcDecrypt(ciphertext, key, iv = DEFAULT_IV) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    decipher.setAutoPadding(false);
    try {
        return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch (e) {
        return Buffer.alloc(0);
    }
}

function aesCbcEncrypt(plaintext, key, iv = DEFAULT_IV) {
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    cipher.setAutoPadding(false);
    return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}

function aesEcbEncrypt(plaintext, key) {
    const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
    cipher.setAutoPadding(false);
    return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}

function aesEcbDecrypt(ciphertext, key) {
    const decipher = crypto.createDecipheriv('aes-128-ecb', key, null);
    decipher.setAutoPadding(false);
    try {
        return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch (e) {
        return Buffer.alloc(0);
    }
}

function sha256(data) {
    return crypto.createHash('sha256').update(data).digest();
}

function md5HashWithSalt(data) {
    const CHECKSUM_SALT = Buffer.from('78686469776a6e6368656b6434643531326368646a783564386534633339344432443753', 'hex');
    return crypto.createHash('md5').update(Buffer.concat([data, CHECKSUM_SALT])).digest();
}

class MideaACClient {
    constructor(ip, port, token, key, deviceId) {
        this.ip = ip;
        this.port = port;
        this.token = Buffer.isBuffer(token) ? token : Buffer.from(token, 'hex');
        this.key = Buffer.isBuffer(key) ? key : Buffer.from(key, 'hex');
        this.deviceId = deviceId;
        this._socket = null;
        this._tcpKey = null;
        this._requestCount = 0;
    }

    connect() {
        return new Promise((resolve) => {
            this._socket = new net.Socket();
            this._socket.on('connect', () => resolve(true));
            this._socket.on('error', () => resolve(false));
            this._socket.on('timeout', () => { this._socket.destroy(); resolve(false); });
            this._socket.setTimeout(15000);
            this._socket.connect(this.port, this.ip);
        });
    }

    disconnect() {
        if (this._socket) {
            this._socket.destroy();
            this._socket = null;
        }
    }

    authenticate() {
        return new Promise((resolve) => {
            if (!this._socket) { resolve(false); return; }

            const handshakeData = Buffer.concat([
                Buffer.from([HEADER_8370_1ST, HEADER_8370_2ND, 0x00, 0x40, 0x20, 0x20, 0x00, 0x00]),
                this.token
            ]);

            let buffer = Buffer.alloc(0);
            const dataHandler = (chunk) => {
                buffer = Buffer.concat([buffer, chunk]);
                if (buffer.length >= 72) {
                    this._socket.removeListener('data', dataHandler);
                    clearTimeout(timeout);
                    const authResponse = buffer.slice(8, 72);
                    const payload = authResponse.slice(0, 32);
                    const plain = aesCbcDecrypt(payload, this.key, DEFAULT_IV);
                    if (plain.length === 0) { resolve(false); return; }
                    this._tcpKey = Buffer.alloc(plain.length);
                    for (let i = 0; i < plain.length; i++) {
                        this._tcpKey[i] = plain[i] ^ this.key[i];
                    }
                    this._requestCount = 0;
                    resolve(true);
                } else if (buffer.length >= 6 && (buffer[5] & 0x0F) === 0x0F) {
                    this._socket.removeListener('data', dataHandler);
                    resolve(false);
                }
            };

            const timeout = setTimeout(() => {
                this._socket.removeListener('data', dataHandler);
                resolve(false);
            }, 10000);

            this._socket.on('data', dataHandler);
            this._socket.on('close', () => { if (this._socket) { this._socket.destroy(); this._socket = null; } });
            this._socket.on('error', () => {});
            this._socket.write(handshakeData);
        });
    }

    buildMessageQuery() {
        const bodyType = 0x41;
        const body = Buffer.alloc(19);
        body[0] = 0x81;
        body[2] = 0xFF;
        const bodyData = Buffer.concat([Buffer.from([bodyType]), body]);
        const messageId = Buffer.from([1]);
        const bodyWithId = Buffer.concat([bodyData, messageId]);
        const bodyCrc = Buffer.from([crc8(bodyWithId)]);
        const fullBody = Buffer.concat([bodyWithId, bodyCrc]);
        const length = 10 + fullBody.length;
        const header = Buffer.from([0xAA, length, 0xAC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03]);
        let message = Buffer.concat([header, fullBody]);
        const msgChecksum = (~(message.slice(1).reduce((a, b) => a + b, 0)) + 1) & 0xFF;
        message = Buffer.concat([message, Buffer.from([msgChecksum])]);
        return message;
    }

    buildPacket(command) {
        const now = new Date();
        const dtStr = now.getUTCFullYear().toString().padStart(2, '0') +
            (now.getUTCMonth() + 1).toString().padStart(2, '0') +
            now.getUTCDate().toString().padStart(2, '0') +
            now.getUTCHours().toString().padStart(2, '0') +
            now.getUTCMinutes().toString().padStart(2, '0') +
            now.getUTCSeconds().toString().padStart(2, '0') +
            now.getUTCMilliseconds().toString().padStart(3, '0').slice(0, 3).padStart(6, '0');

        const dtArray = [];
        for (let i = 0; i < 16; i += 2) {
            dtArray.unshift(parseInt(dtStr.slice(i, i + 2), 10));
        }
        const dtBytes = Buffer.from(dtArray);

        const paddedCommand = Buffer.alloc(Math.ceil(command.length / 16) * 16);
        command.copy(paddedCommand);
        const encrypted = aesEcbEncrypt(paddedCommand, DEFAULT_KEY);

        const packet = Buffer.alloc(40 + encrypted.length);
        packet[0] = 0x5A; packet[1] = 0x5A;
        packet[2] = 0x01; packet[3] = 0x11;
        packet[6] = 0x20; packet[7] = 0x00;
        dtBytes.copy(packet, 12);
        packet.writeBigInt64LE(BigInt(this.deviceId), 20);
        encrypted.copy(packet, 40);

        const length = (packet.length + 16);
        packet[4] = length & 0xFF;
        packet[5] = (length >> 8) & 0xFF;

        const checksum = md5HashWithSalt(packet);
        return Buffer.concat([packet, checksum]);
    }

    encode8370(data, msgType) {
        if (!this._tcpKey) throw new Error('TCP key not initialized');

        const header = Buffer.from([HEADER_8370_1ST, HEADER_8370_2ND]);
        let size = data.length;
        let padding = 0;

        if (msgType === 0x06 || msgType === 0x03) {
            const remainder = (size + 2) % 16;
            if (remainder !== 0) padding = 16 - remainder;
            size += padding + 32;
        }

        const sizeBytes = Buffer.alloc(2);
        sizeBytes.writeUInt16BE(size, 0);
        const flags = Buffer.from([0x20, (padding << 4) | msgType]);
        const count = Buffer.alloc(2);
        count.writeUInt16BE(this._requestCount, 0);
        this._requestCount = (this._requestCount + 1) % 0xFFFF;

        let payloadData = Buffer.concat([count, data]);
        if (msgType === 0x06 || msgType === 0x03) {
            if (padding > 0) payloadData = Buffer.concat([payloadData, crypto.randomBytes(padding)]);
            const encrypted = aesCbcEncrypt(payloadData, this._tcpKey, DEFAULT_IV);
            const sign = sha256(Buffer.concat([header, sizeBytes, flags, payloadData]));
            payloadData = Buffer.concat([encrypted, sign]);
        }
        return Buffer.concat([header, sizeBytes, flags, payloadData]);
    }

    decode8370(data) {
        if (data.length < 6 || data[0] !== HEADER_8370_1ST || data[1] !== HEADER_8370_2ND) return null;

        const size = data.readUInt16BE(2) + 8;
        const padding = data[5] >> 4;
        const msgType = data[5] & 0x0F;
        if (data.length < size) return null;

        const payload = data.slice(6, size);
        if (msgType === 0x03 || msgType === 0x06) {
            const encryptedData = payload.slice(0, -32);
            const decrypted = aesCbcDecrypt(encryptedData, this._tcpKey, DEFAULT_IV);
            if (padding > 0 && decrypted.length > padding) {
                const unpadded = decrypted.slice(0, -padding);
                return unpadded.length >= 2 ? unpadded.slice(2) : unpadded;
            }
            return decrypted.length >= 2 ? decrypted.slice(2) : decrypted;
        }
        return payload;
    }

    getStatus() {
        return new Promise((resolve) => {
            if (!this._socket) { resolve(null); return; }

            const message = this.buildMessageQuery();
            const packet = this.buildPacket(message);
            const encoded = this.encode8370(packet, 0x06);

            let buffer = Buffer.alloc(0);
            const dataHandler = (chunk) => {
                buffer = Buffer.concat([buffer, chunk]);
                console.log('[MideaAC] Received ' + buffer.length + ' bytes, waiting for more...');
                if (buffer.length >= 6) {
                    const msgType = buffer[5] & 0x0F;
                    console.log('[MideaAC] MsgType: 0x' + msgType.toString(16));
                    if (msgType === 0x0F) { this._socket.removeListener('data', dataHandler); resolve(null); return; }
                    if (msgType === 0x03) {
                        console.log('[MideaAC] Got 0x03 response, buffer length: ' + buffer.length);
                        this._socket.removeListener('data', dataHandler);
                        clearTimeout(timeout);
                        const packet5a5a = this.decode8370(buffer);
                        console.log('[MideaAC] Decoded 5A5A packet length: ' + (packet5a5a ? packet5a5a.length : 'null'));
                        if (packet5a5a && packet5a5a.length >= 104) {
                            const encryptedData = packet5a5a.slice(40, 104);
                            console.log('[MideaAC] Encrypted data (40-104): ' + encryptedData.toString('hex'));
                            const decrypted = aesEcbDecrypt(encryptedData, DEFAULT_KEY);
                            console.log('[MideaAC] Decrypted AC status (' + decrypted.length + ' bytes): ' + decrypted.toString('hex'));
                            resolve(decrypted);
                            return;
                        }
                        resolve(null);
                    }
                }
            };

            const timeout = setTimeout(() => {
                if (this._socket) this._socket.removeListener('data', dataHandler);
                resolve(null);
            }, 10000);

            this._socket.on('data', dataHandler);
            this._socket.write(encoded);
        });
    }

    sendSetCommand(power, mode, temperature, fanSpeed, swingVertical, swingHorizontal) {
        return new Promise((resolve) => {
            const powerVal = power ? 0x01 : 0;
            const promptTone = 0x40;
            const modeByte = (mode << 5) & 0xE0;
            const tempVal = Math.floor(temperature);
            const tempFrac = (Math.round(temperature * 2) % 2 !== 0) ? 0x10 : 0;
            const targetTemp = (tempVal & 0x0F) | tempFrac;
            const fan = fanSpeed & 0x7F;

            let swing = 0x30;
            if (swingVertical) swing |= 0x0C;
            if (swingHorizontal) swing |= 0x03;

            const body = Buffer.alloc(22);
            body[0] = powerVal | promptTone;
            body[1] = modeByte | targetTemp;
            body[2] = fan;
            body[6] = swing;

            const bodyType = 0x40;
            const bodyData = Buffer.concat([Buffer.from([bodyType]), body, Buffer.from([this._requestCount])]);

            let crc = 0;
            for (let i = 0; i < bodyData.length; i++) crc = CRC8_TABLE[(crc ^ bodyData[i]) & 0xFF];

            const fullBody = Buffer.concat([bodyData, Buffer.from([crc])]);
            const length = 10 + fullBody.length;
            const header = Buffer.from([0xAA, length, 0xAC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x02]);

            let message = Buffer.concat([header, fullBody]);
            let sum = 0;
            for (let i = 1; i < message.length; i++) sum += message[i];
            const checksum = (~sum + 1) & 0xFF;
            message = Buffer.concat([message, Buffer.from([checksum])]);

            this._requestCount = (this._requestCount + 1) % 0xFFFF;

            const packet = this.buildPacket(message);
            const encoded = this.encode8370(packet, 0x06);

            let buffer = Buffer.alloc(0);
            const dataHandler = (chunk) => {
                buffer = Buffer.concat([buffer, chunk]);
                if (buffer.length >= 6) {
                    const msgType = buffer[5] & 0x0F;
                    if (msgType === 0x0F) { this._socket.removeListener('data', dataHandler); resolve(false); return; }
                    if (msgType === 0x03) { this._socket.removeListener('data', dataHandler); clearTimeout(timeout); resolve(true); }
                }
            };

            const timeout = setTimeout(() => { this._socket.removeListener('data', dataHandler); resolve(false); }, 10000);
            this._socket.on('data', dataHandler);
            this._socket.write(encoded);
        });
    }
}

function parseACStatus(data) {
    if (!data || data.length < 40) return null;
    const body = data.slice(10);
    return {
        power: (body[1] & 0x01) > 0,
        mode: (body[2] >> 5) & 0x07,
        targetTemp: (body[2] & 0x0F) + 16 + (((body[2] >> 4) & 0x01) ? 0.5 : 0),
        fanSpeed: body[3] & 0x7F,
        swingVertical: (body[7] & 0x0C) > 0,
        swingHorizontal: (body[7] & 0x03) > 0,
        indoorTemp: ((body[11] - 50) / 2) + ((body[15] & 0x0F) * 0.1)
    };
}

class MideaAcAdapter extends utils.Adapter {
    constructor(options) {
        super({ ...options, name: 'midea-ac-lan' });
        this._client = null;
        this._pollInterval = null;
        this.on('ready', this._onReady.bind(this));
        this.on('stateChange', this._onStateChange.bind(this));
        this.on('unload', this._onUnload.bind(this));
    }

    async _onReady() {
        this.log.info('Midea AC LAN adapter starting...');

        if (!this.config.ip_address || !this.config.device_id) {
            this.log.error('IP address and Device ID are required!');
            return;
        }

        this.log.info('Config: IP=' + this.config.ip_address + ', Device ID=' + this.config.device_id);

        const hasTokenAndKey = this.config.token && this.config.key;
        this.log.info('Has token/key: ' + hasTokenAndKey + ', use_cloud_auth: ' + this.config.use_cloud_auth);

        if (!hasTokenAndKey && this.config.use_cloud_auth) {
            this.log.info('Fetching token from cloud...');
            const success = await this._fetchTokenFromCloud();
            if (!success) { this.log.error('Cloud auth failed'); return; }
            this.log.info('Cloud auth successful');
        } else if (!hasTokenAndKey) {
            this.log.error('No token/key available');
            return;
        }

        this._createStates();

        this._client = new MideaACClient(
            this.config.ip_address, PORT_TCP,
            this.config.token, this.config.key,
            parseInt(this.config.device_id)
        );

        this.log.info('Connecting to ' + this.config.ip_address + '...');
        const connected = await this._client.connect();
        this.log.info('Connected: ' + connected);
        if (!connected) { this.log.error('Connection failed'); return; }

        this.log.info('Authenticating...');
        const authenticated = await this._client.authenticate();
        this.log.info('Authenticated: ' + authenticated);
        if (!authenticated) { this.log.error('Authentication failed'); this._client.disconnect(); return; }

        this.log.info('Fetching status...');
        const status = await this._client.getStatus();
        this.log.info('Status received: ' + (status ? status.length + ' bytes, hex: ' + status.toString('hex') : 'null'));
        if (!status) { this.log.error('Failed to get status'); return; }

        const parsed = parseACStatus(status);
        this.log.info('AC Status parsed - Power=' + parsed.power + ', Mode=' + parsed.mode + ', Temp=' + parsed.targetTemp + ', Fan=' + parsed.fanSpeed + ', SwingV=' + parsed.swingVertical + ', SwingH=' + parsed.swingHorizontal + ', Indoor=' + parsed.indoorTemp);
        this._updateStates(parsed);

        this._pollInterval = setInterval(async () => {
            this.log.info('Poll tick...');
            try {
                const s = await this._client.getStatus();
                if (s) {
                    this._updateStates(parseACStatus(s));
                    this.log.info('Poll update successful');
                } else {
                    this.log.warn('Poll returned null - reconnecting...');
                    this._client.disconnect();
                    const connected = await this._client.connect();
                    if (!connected) { this.log.error('Reconnect failed'); return; }
                    const authenticated = await this._client.authenticate();
                    if (!authenticated) { this.log.error('Re-auth failed'); return; }
                    this.log.info('Reconnected and re-authenticated');
                }
            } catch (e) { this.log.error('Poll error: ' + e.message); }
        }, (this.config.poll_interval || 60) * 1000);

        this.log.info('Adapter started successfully');
    }

    _onUnload(callback) {
        if (this._pollInterval) clearInterval(this._pollInterval);
        if (this._client) this._client.disconnect();
        callback();
    }

    _createStates() {
        const states = [
            { id: 'power', name: 'Power', type: 'boolean', role: 'switch' },
            { id: 'mode', name: 'Mode', type: 'number', role: 'value' },
            { id: 'target_temperature', name: 'Target Temperature', type: 'number', role: 'value.temperature' },
            { id: 'fan_speed', name: 'Fan Speed', type: 'number', role: 'value' },
            { id: 'swing_vertical', name: 'Vertical Swing', type: 'boolean', role: 'switch' },
            { id: 'swing_horizontal', name: 'Horizontal Swing', type: 'boolean', role: 'switch' },
            { id: 'indoor_temperature', name: 'Indoor Temperature', type: 'number', role: 'value.temperature' }
        ];
        states.forEach(s => {
            this.setObjectNotExistsAsync('ac.' + s.id, {
                type: 'state', common: { name: s.name, type: s.type, role: s.role, write: true, read: true }, native: {}
            });
        });
    }

    _updateStates(status) {
        if (!status) return;
        this.setStateAsync('ac.power', { val: status.power, ack: true });
        this.setStateAsync('ac.mode', { val: status.mode, ack: true });
        this.setStateAsync('ac.target_temperature', { val: status.targetTemp, ack: true });
        this.setStateAsync('ac.fan_speed', { val: status.fanSpeed, ack: true });
        this.setStateAsync('ac.swing_vertical', { val: status.swingVertical, ack: true });
        this.setStateAsync('ac.swing_horizontal', { val: status.swingHorizontal, ack: true });
        this.setStateAsync('ac.indoor_temperature', { val: status.indoorTemp, ack: true });
    }

    async _onStateChange(id, state) {
        if (!state || state.ack) return;
        if (!this._client) return;

        const stateName = id.replace(this.namespace + '.ac.', '');
        let current;
        try {
            const s = await this._client.getStatus();
            if (s) current = parseACStatus(s);
        } catch (e) { this.log.warn('Cannot get current status'); return; }
        if (!current) return;

        switch (stateName) {
            case 'power':
                await this._client.sendSetCommand(state.val, current.mode, current.targetTemp, current.fanSpeed, current.swingVertical, current.swingHorizontal);
                break;
            case 'mode':
                await this._client.sendSetCommand(current.power, state.val, current.targetTemp, current.fanSpeed, current.swingVertical, current.swingHorizontal);
                break;
            case 'target_temperature':
                await this._client.sendSetCommand(current.power, current.mode, state.val, current.fanSpeed, current.swingVertical, current.swingHorizontal);
                break;
            case 'fan_speed':
                await this._client.sendSetCommand(current.power, current.mode, current.targetTemp, state.val, current.swingVertical, current.swingHorizontal);
                break;
            case 'swing_vertical':
                await this._client.sendSetCommand(current.power, current.mode, current.targetTemp, current.fanSpeed, state.val, current.swingHorizontal);
                break;
            case 'swing_horizontal':
                await this._client.sendSetCommand(current.power, current.mode, current.targetTemp, current.fanSpeed, current.swingVertical, state.val);
                break;
        }
    }

    async _fetchTokenFromCloud() {
        return new Promise((resolve) => {
            const postData = JSON.stringify({ userId: this.config.cloud_username, password: this.config.cloud_password });
            const options = {
                hostname: 'midea-app.iobroker.uk', port: 443, path: '/api/v1/login/login',
                method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(postData) }
            };
            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', c => data += c);
                res.on('end', () => {
                    try {
                        const result = JSON.parse(data);
                        if (result.result && result.result.token && result.result.iotKey) {
                            this.config.token = result.result.token;
                            this.config.key = result.result.iotKey;
                            resolve(true);
                        } else { resolve(false); }
                    } catch (e) { resolve(false); }
                });
            });
            req.on('error', () => resolve(false));
            req.write(postData);
            req.end();
        });
    }
}

if (require.main !== module) {
    module.exports = (options) => new MideaAcAdapter(options);
} else {
    new MideaAcAdapter();
}