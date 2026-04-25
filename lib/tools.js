'use strict';

const net = require('net');
const crypto = require('crypto');

const DEFAULT_PORT = 6444;
const MSGTYPE_HANDSHAKE_REQUEST = 0x00;
const MSGTYPE_ENCRYPTED_REQUEST = 0x06;
const MSGTYPE_ENCRYPTED_RESPONSE = 0x03;

class MideaProtocol {
    constructor(token, key) {
        this.token = Buffer.from(token, 'hex');
        this.key = Buffer.from(key, 'hex');
        console.log('Token buffer len:', this.token.length);
        console.log('Key buffer len:', this.key.length);
        this.tcpKey = null;
        this._requestCount = 0;
    }
    
    calculateTcpKey(responseData, deviceId) {
        console.log(`[${deviceId}] calculateTcpKey: key=${this.key.toString('hex').slice(0,32)}...`);
        
        const encrypted = responseData.slice(0, 32);
        const signature = responseData.slice(32, 64);
        
        try {
            const iv = Buffer.alloc(16, 0);
            const decipher = crypto.createDecipheriv('aes-128-cbc', this.key.slice(0, 16), iv);
            let plain = Buffer.concat([decipher.update(encrypted), decipher.final()]);
            
            console.log(`[${deviceId}] Decrypted: ${plain.toString('hex').slice(0,32)}...`);
            
            // Try to detect padding - PKCS7
            const padLen = plain[plain.length - 1];
            if (padLen > 0 && padLen <= 16 && padLen <= plain.length) {
                plain = plain.slice(0, plain.length - padLen);
            }
            
            console.log(`[${deviceId}] Unpadded: ${plain.toString('hex').slice(0,32)}...`);
            
            // Verify signature
            const hash = crypto.createHash('sha256').update(plain).digest();
            let match = true;
            for(let i = 0; i < 32; i++) {
                if (hash[i] !== signature[i]) {
                    match = false;
                    break;
                }
            }
            
if (!match) {
                console.warn(`[${deviceId}] Signature mismatch!`);
                return null;
            }
            
            // XOR plain with key to get TCP key
            const tcpKey = Buffer.alloc(32);
            for (let i = 0; i < 32; i++) tcpKey[i] = plain[i] ^ this.key[i];
            this.tcpKey = tcpKey;
            console.log(`[${deviceId}] TCP Key: ${tcpKey.toString('hex').slice(0,32)}...`);
            return this.tcpKey;
        } catch(e) {
            console.error(`[${deviceId}] AES error: ${e.message}`);
            return null;
        }
    }
            
            // XOR plain with key to get TCP key
            const tcpKey = Buffer.alloc(32);
            for (let i = 0; i < 32; i++) tcpKey[i] = plain[i] ^ this.key[i];
            this.tcpKey = tcpKey;
            this.log.info(`[${this.deviceId}] TCP Key: ${tcpKey.toString('hex').slice(0,32)}...`);
            return this.tcpKey;
        } catch(e) {
            this.log.error(`[${this.deviceId}] AES error: ${e.message}`);
            return null;
        }
    }
    
    encode8370(data, msgType) {
        const payload = Buffer.isBuffer(data) ? data : Buffer.from(data);
        
        // HANDSHAKE: Simple packet, NO encryption, NO padding
        if (msgType === MSGTYPE_HANDSHAKE_REQUEST) {
            const frame = Buffer.alloc(8 + payload.length);
            frame[0] = 0x83;              // Byte 0
            frame[1] = 0x70;              // Byte 1
            frame.writeUInt16BE(payload.length, 2);  // Bytes 2-3: size
            frame[3] = 0x20;              // Byte 3: flag
            frame[4] = msgType;           // Byte 4: msgType
            frame[5] = 0;                 // Byte 5
            frame[6] = 0;                 // Byte 6
            frame[7] = 0;                 // Byte 7
            payload.copy(frame, 8);       // Bytes 8+
            return frame;
        }
        
        // ENCRYPTED REQUEST
        const dataLen = payload.length;
        let padding = 0;
        let size = dataLen;
        
        // Add request count (2 bytes)
        size = dataLen + 2;
        
        // Calculate encryption padding
        if (size % 16 !== 0) {
            padding = 16 - (size % 16);
            size += padding;
        }
        // Add signature (32 bytes)
        size += 32;
        
        // Build with padding
        let paddedData = Buffer.concat([payload]);
        if (padding > 0) {
            const pad = Buffer.alloc(padding);
            for(let i = 0; i < padding; i++) pad[i] = padding;
            paddedData = Buffer.concat([payload, pad]);
        }
        
        // Prepend request count
        const reqCount = Buffer.alloc(2);
        reqCount.writeUInt16BE(this._requestCount++, 0);
        let finalData = Buffer.concat([reqCount, paddedData]);
        
        // Encrypt with AES-CBC
        const iv = Buffer.alloc(16, 0);
        const cipher = crypto.createCipheriv('aes-128-cbc', this.tcpKey.slice(0, 16), iv);
        const encrypted = Buffer.concat([cipher.update(finalData), cipher.final()]);
        
        // Build header
        const header = Buffer.alloc(6);
        header[0] = 0x83;
        header[1] = 0x70;
        header.writeUInt16BE(size, 2);
        header[3] = 0x20;
        header[4] = (padding << 4) | msgType;
        header[5] = 0;
        
        // Sign: SHA256(header + finalData)
        const signData = Buffer.concat([header, finalData]);
        const signature = crypto.createHash('sha256').update(signData).digest();
        
        return Buffer.concat([header, encrypted, signature]);
    }
    
    decode8370(data) {
        if (data.length < 6) return null;
        if (data[0] !== 0x83 || data[1] !== 0x70) return null;
        
        const size = data.readUInt16BE(2);
        const totalSize = size + 6;
        const msgType = data[4] & 0x0F;
        
        if (msgType === MSGTYPE_ENCRYPTED_RESPONSE && this.tcpKey) {
            const encrypted = data.slice(6, totalSize - 32);
            const signature = data.slice(totalSize - 32, totalSize);
            
            const iv = Buffer.alloc(16, 0);
            const decipher = crypto.createDecipheriv('aes-128-cbc', this.tcpKey.slice(0, 16), iv);
            let plain = Buffer.concat([decipher.update(encrypted), decipher.final()]);
            
            const padLen = plain[plain.length - 1];
            plain = plain.slice(0, plain.length - padLen);
            
            const signData = Buffer.concat([data.slice(0, 6), plain]);
            const expectedSig = crypto.createHash('sha256').update(signData).digest();
            if (!expectedSig.equals(signature)) return null;
            
            plain = plain.slice(2);
            
            return plain;
        }
        
        return null;
    }
}

class MideaAC {
    constructor(config, log) {
        this.config = config;
        this.log = log;
        this.deviceId = config.deviceId;
        this.ipAddress = config.ipAddress;
        this.port = config.port || DEFAULT_PORT;
        this.token = config.token;
        this.key = config.key;
        this.protocol = new MideaProtocol(this.token, this.key);
        this.socket = null;
        this.connected = false;
        this.available = false;
        this.updateCallbacks = [];
        this.buffer = Buffer.alloc(0);
        this.refreshInterval = null;
    }
    
    onUpdate(cb) {
        this.updateCallbacks.push(cb);
    }
    
    connect() {
        return new Promise((resolve) => {
            this.log.info(`[${this.deviceId}] Connecting to ${this.ipAddress}:${this.port}`);
            this.socket = net.createConnection(this.port, this.ipAddress);
            this.socket.setTimeout(0);
            this.socket.on('connect', () => {
                this.log.info(`[${this.deviceId}] TCP connected`);
                this.sendHandshake();
            });
            this.socket.on('data', (data) => {
                this.buffer = Buffer.concat([this.buffer, data]);
                while (this.buffer.length >= 8) {
                    const len = this.buffer.readUInt16BE(2) + 8;
                    if (this.buffer.length < len) break;
                    const packet = this.buffer.slice(0, len);
                    this.buffer = this.buffer.slice(len);
                    this.processMessage(packet);
                }
            });
            this.socket.on('close', () => {
                this.log.warn(`[${this.deviceId}] Connection closed (buffer had ${this.buffer.length} bytes)`);
                this.connected = false;
                this.available = false;
            });
            this.socket.on('error', (e) => this.log.error(`[${this.deviceId}] Socket error: ${e.message}`));
            setTimeout(() => resolve(true), 500);
        });
    }
    
    sendHandshake() {
        const payload = this.protocol.token;
        const payloadLen = payload.length;
        
        // Format: 8370 + size(2) + 20 + 00 + 00 + 00 + payload
        const frame = Buffer.alloc(8 + payloadLen);
        frame[0] = 0x83;
        frame[1] = 0x70;
        frame[2] = (payloadLen >> 8) & 0xFF;  // size high
        frame[3] = payloadLen & 0xFF;          // size low
        frame[4] = 0x20;                        // fixed 0x20
        frame[5] = 0x00;                        // fixed 0x00
        frame[6] = 0x00;
        frame[7] = 0x00;
        payload.copy(frame, 8);
        
        this.log.info(`[${this.deviceId}] Handshake: ${frame.toString('hex')}`);
        this.socket.write(frame);
    }
    
processMessage(packet) {
        this.log.info(`[${this.deviceId}] Packet bytes: ${packet[0].toString(16)} ${packet[1].toString(16)} ${packet[2].toString(16)} ${packet[3].toString(16)} ${packet[4].toString(16)} ${packet[5].toString(16)}`);
        
        if (!packet || packet.length < 8) return;
        
        const size = packet.readUInt16BE(2) + 8;
        
        // Byte 4 lower nibble = error check
        if ((packet[4] & 0x0F) === 0x0F) {
            this.log.warn(`[${this.deviceId}] Device error`);
            return;
        }
        
        // Byte 4 = 0x20 means handshake response, if length >= 72 and not connected
        if (packet[4] === 0x20 && packet.length >= 72 && !this.connected) {
            this.log.info(`[${this.deviceId}] Handshake response!`);
            const responseData = packet.slice(8, 72);
            this.protocol.calculateTcpKey(responseData, this.deviceId);
            this.connected = true;
            this.log.info(`[${this.deviceId}] Authentication success! TCP Key set.`);
            // Wait 3 seconds before sending queries
            setTimeout(() => this.startReceiving(), 3000);
            return;
        }
        
        if ((packet[4] & 0x0F) === MSGTYPE_ENCRYPTED_RESPONSE && this.protocol.tcpKey && size <= packet.length) {
            this.log.info(`[${this.deviceId}] Encrypted response`);
            const decoded = this.protocol.decode8370(packet);
            if (decoded && decoded.length >= 30) {
                this.parseStatus(decoded);
            }
        }
    }
    
    startReceiving() {
        if (!this.socket || !this.connected) return;
        this.log.info(`[${this.deviceId}] Listening for updates...`);
        
        const queryData = Buffer.from([
            0xAA, 0x20, 0xAC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
            0x81, 0x00, 0x87, 0x66, 0x7F, 0x7F, 0x00, 0x3F, 0x00, 0x00, 0x00,
            0x69, 0xFF, 0x0B, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x2C
        ]);
        
        this.socket.write(this.protocol.encode8370(queryData, MSGTYPE_ENCRYPTED_REQUEST));
        
        this.refreshInterval = setInterval(() => {
            if (this.socket && this.connected) {
                this.socket.write(this.protocol.encode8370(queryData, MSGTYPE_ENCRYPTED_REQUEST));
            }
        }, 30000);
    }
    
    parseStatus(data) {
        if (data.length < 30) return;
        
        let inner = data;
        if (data[0] === 0x5A && data[1] === 0x5A) {
            inner = data.slice(8);
        }
        
        this.available = true;
        const status = {
            power: (inner[10] & 0x01) !== 0,
            mode: inner[10] & 0x0F,
            targetTemperature: ((inner[11] - 30) / 2 + 16),
            fanSpeed: inner[12]
        };
        this.log.info(`[${this.deviceId}] Status: power=${status.power} mode=${status.mode} temp=${status.targetTemperature} fan=${status.fanSpeed}`);
        for (const cb of this.updateCallbacks) {
            try { cb(status); } catch(e) {}
        }
    }
    
    close() {
        if (this.refreshInterval) clearInterval(this.refreshInterval);
        if (this.socket) { this.socket.destroy(); this.socket = null; }
        this.connected = false;
        this.available = false;
    }
}

class MideaAdapter {
    constructor() {
        this.config = null;
        this.adapter = null;
        this.device = null;
    }
    
    async start(adapter) {
        this.adapter = adapter;
        adapter.log.info('Midea AC LAN starting...');
        try {
            this.config = (await adapter.getObjectAsync('system.adapter.midea-ac-lan.0')).native || {};
        } catch {
            this.config = adapter.config || {};
        }
        this.startDevice();
        adapter.log.info('Midea adapter ready');
    }
    
    startDevice() {
        const { deviceId, ipAddress, token, key } = this.config;
        if (!deviceId || !ipAddress || !token || !key) {
            return this.adapter.log.error('Missing config');
        }
        const s = ['power', 'mode', 'targetTemperature', 'fanSpeed', 'connected'];
        for (const st of s) {
            try {
                this.adapter.setObjectNotExistsAsync(deviceId + '.' + st, {
                    type: 'state',
                    common: {
                        name: st,
                        type: (st === 'power' || st === 'connected') ? 'boolean' : 'number',
                        role: st === 'power' ? 'switch' : st === 'connected' ? 'indicator.connected' : 'value',
                        read: true,
                        write: false
                    },
                    native: {}
                });
            } catch(e) {}
        }
        this.device = new MideaAC({ deviceId, ipAddress, port: this.config.port || DEFAULT_PORT, token, key, deviceName: this.config.deviceName || '' }, this.adapter.log);
        this.device.onUpdate((s) => this.updateStates(deviceId, s));
        this.device.connect();
    }
    
    async updateStates(deviceId, status) {
        try {
            await this.adapter.setStateAsync(deviceId + '.power', status.power || false, true);
            await this.adapter.setStateAsync(deviceId + '.mode', status.mode || 0, true);
            await this.adapter.setStateAsync(deviceId + '.targetTemperature', status.targetTemperature || 20, true);
            await this.adapter.setStateAsync(deviceId + '.fanSpeed', status.fanSpeed || 0, true);
            await this.adapter.setStateAsync(deviceId + '.connected', true, true);
        } catch(e) {}
    }
    
    async stop() {
        if (this.device) this.device.close();
    }
    
    setDeviceState(name, value) {
        this.adapter.log.info(`setDeviceState: ${name} = ${value}`);
    }
}

module.exports = { MideaAdapter, MideaAC, MideaProtocol };