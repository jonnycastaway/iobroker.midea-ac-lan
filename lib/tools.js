'use strict';

const net = require('net');
const crypto = require('crypto');

const DEFAULT_PORT = 6444;
const MSGTYPE_HANDSHAKE_REQUEST = 0x20;
const MSGTYPE_ENCRYPTED_REQUEST = 0x06;
const MSGTYPE_ENCRYPTED_RESPONSE = 0x03;
const DEVICE_TYPE_AC = 0xAC;

class MideaProtocol {
    constructor(token, key) {
        this.token = Buffer.from(token, 'hex');
        this.key = Buffer.from(key, 'hex');
        this.tcpKey = null;
        this._requestCount = 0;
        this._socket = null;
    }
    
    setSocket(socket) {
        this._socket = socket;
    }
    
    calculateTcpKey(responseData) {
        if (!responseData || responseData.length < 64) return null;
        
        const encryptedPart = responseData.slice(0, 32);
        const signaturePart = responseData.slice(32, 64);
        
        const iv = Buffer.alloc(16, 0);
        const decipher = crypto.createDecipheriv('aes-128-cbc', this.key.slice(0, 16), iv);
        let plain;
        try {
            plain = Buffer.concat([decipher.update(encryptedPart), decipher.final()]);
        } catch(e) {
            return null;
        }
        
        const hash = crypto.createHash('sha256').update(plain).digest();
        let match = true;
        for(let i = 0; i < 32; i++) {
            if (hash[i] !== signaturePart[i]) { match = false; break; }
        }
        if (!match) return null;
        
        const tcpKey = Buffer.alloc(32);
        for (let i = 0; i < 32; i++) {
            tcpKey[i] = plain[i] ^ this.key[i];
        }
        
        this.tcpKey = Buffer.concat([tcpKey, tcpKey]);
        return this.tcpKey;
    }
    
    encode8370(data, msgType) {
        const payload = Buffer.isBuffer(data) ? data : Buffer.from(data);
        
        if (msgType === MSGTYPE_ENCRYPTED_REQUEST) {
            const requestCount = Buffer.alloc(2);
            requestCount.writeUInt16BE(this._requestCount++, 0);
            
            let paddedData = Buffer.concat([requestCount, payload]);
            
            const size = paddedData.length;
            const remainder = (size + 2) % 16;
            let paddingNeeded = 0;
            if (remainder !== 0) {
                paddingNeeded = 16 - remainder;
            }
            
            if (paddingNeeded > 0) {
                const randomPadding = crypto.randomBytes(paddingNeeded);
                paddedData = Buffer.concat([paddedData, randomPadding]);
            }
            
            const iv = Buffer.alloc(16, 0);
            const aesKey = this.tcpKey ? this.tcpKey.slice(0, 16) : Buffer.alloc(16, 0);
            const cipher = crypto.createCipheriv('aes-128-cbc', aesKey, iv);
            const encrypted = Buffer.concat([cipher.update(paddedData), cipher.final()]);
            
            const totalLength = encrypted.length + 2;
            
            const header = Buffer.alloc(8);
            header[0] = 0x83;
            header[1] = 0x70;
            header.writeUInt16BE(totalLength, 2);
            header[4] = 0x20;
            header[5] = msgType;
            header[6] = 0x00;
            header[7] = 0x00;
            
            const signData = Buffer.concat([header, encrypted]);
            const signature = crypto.createHash('sha256').update(signData).digest();
            
            return Buffer.concat([header, encrypted, signature]);
        }
        
        const length = payload.length;
        const frame = Buffer.alloc(length + 9);
        frame[0] = 0x83;
        frame[1] = 0x70;
        frame.writeUInt16BE(length, 2);
        frame[4] = 0x20;
        frame[5] = msgType;
        frame[6] = 0x00;
        frame[7] = 0x00;
        
        payload.copy(frame, 8);
        
        const checksum = this.xorChecksum(frame.slice(0, length + 8));
        frame[length + 8] = checksum;
        
        return frame;
    }
    
    xorChecksum(data) {
        let checksum = 0;
        for (let i = 0; i < data.length; i++) {
            checksum ^= data[i];
        }
        return checksum;
    }
    
    decryptResponse(response, tcpKey) {
        if (response.length < 8) return null;
        
        const msgType = response[4];
        
        if (response[5] === 0x0f) {
            const asciiData = response.slice(6).toString('ascii');
            if (asciiData.includes('ERROR')) return 'ERROR';
            return 'ERROR_' + response[5];
        }
        
        if (msgType === 0x20 && response.length >= 72) {
            return { type: 'handshake', data: response };
        }
        
        if (msgType === MSGTYPE_ENCRYPTED_RESPONSE) {
            const length = response.readUInt16BE(2);
            const encryptedData = response.slice(8, 8 + length - 2);
            
            if (tcpKey) {
                const iv = Buffer.alloc(16, 0);
                const aesKey = tcpKey.slice(0, 16);
                try {
                    const decipher = crypto.createDecipheriv('aes-128-cbc', aesKey, iv);
                    const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);
                    return decrypted;
                } catch (e) {
                    return response.toString('ascii');
                }
            }
        }
        
        return response.toString('ascii');
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
        this.name = config.deviceName || 'AC_' + this.deviceId;
        
        this.protocol = null;
        this.socket = null;
        this.connected = false;
        this.available = false;
        
        this.attributes = {};
        this.updateCallbacks = [];
        this.buffer = Buffer.alloc(0);
        this.refreshInterval = null;
    }
    
    onUpdate(callback) {
        this.updateCallbacks.push(callback);
    }
    
    connect() {
        return new Promise((resolve) => {
            this.log.info(`[${this.deviceId}] Connecting to ${this.ipAddress}:${this.port}`);
            
            this.protocol = new MideaProtocol(this.token, this.key);
            
            this.socket = net.createConnection(this.port, this.ipAddress);
            this.protocol.setSocket(this.socket);
            
            this.socket.on('connect', () => {
                this.log.info(`[${this.deviceId}] TCP connected`);
                this.sendHandshake();
            });
            
            this.socket.on('data', (data) => {
                this.handleData(data);
            });
            
            this.socket.on('error', (err) => {
                this.log.error(`[${this.deviceId}] Socket error: ${err.message}`);
            });
            
            this.socket.on('close', () => {
                this.log.warn(`[${this.deviceId}] Connection closed`);
                this.connected = false;
                this.available = false;
            });
            
            setTimeout(() => resolve(true), 500);
        });
    }
    
    sendHandshake() {
        const request = this.protocol.encode8370(this.protocol.token, MSGTYPE_HANDSHAKE_REQUEST);
        this.log.info(`[${this.deviceId}] Sending handshake`);
        this.socket.write(request);
    }
    
    handleData(data) {
        this.buffer = Buffer.concat([this.buffer, data]);
        
        while (this.buffer.length >= 8) {
            const length = this.buffer.readUInt16BE(2) + 8;
            
            if (this.buffer.length < length) break;
            
            const packet = this.buffer.slice(0, length);
            this.buffer = this.buffer.slice(length);
            
            const result = this.protocol.decryptResponse(packet, this.protocol.tcpKey);
            this.processMessage(result);
        }
    }
    
    processMessage(message) {
        if (!message) return;
        
        if (typeof message === 'object' && message.type === 'handshake') {
            if (message.data.length >= 72) {
                const responseData = message.data.slice(8, 72);
                this.protocol.calculateTcpKey(responseData);
                this.connected = true;
                this.log.info(`[${this.deviceId}] Authentication success`);
                setTimeout(() => this.startReceiving(), 500);
            }
            return;
        }
        
        if (typeof message === 'string' && message.includes('ERROR')) {
            this.log.warn(`[${this.deviceId}] Device error: ${message}`);
            return;
        }
        
        if (message.length >= 30) {
            this.parseStatusResponse(message);
        }
    }
    
    startReceiving() {
        if (!this.socket || !this.connected) return;
        
        this.log.info(`[${this.deviceId}] Listening for updates...`);
        
        this.sendApplianceQuery();
        
        this.refreshInterval = setInterval(() => {
            if (this.socket && this.connected) {
                this.sendStatusQuery();
            }
        }, 30000);
    }
    
    sendApplianceQuery() {
        if (!this.socket || !this.connected) return;
        
        const header = Buffer.from([0xAA, 0x20, DEVICE_TYPE_AC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03]);
        const body = Buffer.from([
            0x81, 0x00, 0x87, 0x66, 0x7F, 0x7F, 0x00, 0x3F,
            0x00, 0x00, 0x00, 0x69, 0xFF, 0x0B, 0x00, 0x09,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x2C
        ]);
        
        const packet = Buffer.concat([header, body]);
        const encrypted = this.protocol.encode8370(packet, MSGTYPE_ENCRYPTED_REQUEST);
        this.socket.write(encrypted);
        this.log.info(`[${this.deviceId}] Query sent`);
    }
    
    sendStatusQuery() {
        if (!this.socket || !this.connected) return;
        
        this.sendApplianceQuery();
    }
    
    parseStatusResponse(data) {
        if (data.length < 30) return;
        
        this.available = true;
        
        const powerByte = data[15];
        const power = (powerByte & 0x08) !== 0;
        
        const mode = data[16] & 0x0F;
        
        const tempByte = data[17];
        const targetTemp = (tempByte & 0x0F) + 16;
        
        const fanByte = data[18];
        const fanSpeed = fanByte & 0x7F;
        
        const status = { power, mode, targetTemperature: targetTemp, fanSpeed };
        
        this.log.info(`[${this.deviceId}] Status: power=${power} mode=${mode} temp=${targetTemp} fan=${fanSpeed}`);
        
        for (const cb of this.updateCallbacks) {
            try { cb(status); } catch(e) {}
        }
    }
    
    close() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
            this.refreshInterval = null;
        }
        if (this.socket) {
            this.socket.destroy();
            this.socket = null;
        }
        this.connected = false;
        this.available = false;
    }
}

class MideaAdapter {
    constructor() {
        this.config = null;
        this.adapter = null;
        this.device = null;
        this.refreshInterval = null;
    }
    
    async start(adapter) {
        this.adapter = adapter;
        adapter.log.info('Midea AC LAN adapter starting...');
        
        try {
            const adapterObj = await adapter.getObjectAsync('system.adapter.midea-ac-lan.0');
            this.config = adapterObj.native || {};
        } catch (e) {
            this.config = adapter.config || {};
        }
        
        this.startDevice();
        adapter.log.info('Midea adapter ready');
    }
    
    startDevice() {
        const { deviceId, ipAddress, token, key } = this.config;
        
        if (!deviceId || !ipAddress || !token || !key) {
            this.adapter.log.error('Missing config: deviceId, ipAddress, token, key');
            return;
        }
        
        this.createDeviceStates(deviceId);
        
        this.device = new MideaAC({
            deviceId, ipAddress, port: this.config.port || DEFAULT_PORT,
            token, key, deviceName: this.config.deviceName || ''
        }, this.adapter.log);
        
        this.device.onUpdate((status) => {
            this.updateStates(deviceId, status);
        });
        
        this.device.connect();
    }
    
    createDeviceStates(deviceId) {
        const states = [
            { id: 'power', type: 'boolean', role: 'switch', write: true },
            { id: 'mode', type: 'number', role: 'value', write: true },
            { id: 'targetTemperature', type: 'number', role: 'value.temperature', write: true },
            { id: 'fanSpeed', type: 'number', role: 'value', write: true },
            { id: 'indoorTemperature', type: 'number', role: 'value.temperature' },
            { id: 'connected', type: 'boolean', role: 'indicator.connected' }
        ];
        
        for (const s of states) {
            try {
                this.adapter.setObjectNotExistsAsync(deviceId + '.' + s.id, {
                    type: 'state',
                    common: { name: s.id, type: s.type, role: s.role, read: true, write: s.write || false },
                    native: {}
                });
            } catch (e) {}
        }
    }
    
    async updateStates(deviceId, status) {
        try {
            await this.adapter.setStateAsync(deviceId + '.power', status.power || false, true);
            await this.adapter.setStateAsync(deviceId + '.mode', status.mode || 0, true);
            await this.adapter.setStateAsync(deviceId + '.targetTemperature', status.targetTemperature || 20, true);
            await this.adapter.setStateAsync(deviceId + '.fanSpeed', status.fanSpeed || 0, true);
            await this.adapter.setStateAsync(deviceId + '.connected', true, true);
        } catch (e) {}
    }
    
    async setDeviceState(state, value) {
        return false;
    }
    
    async stop() {
        if (this.refreshInterval) clearInterval(this.refreshInterval);
        if (this.device) this.device.close();
    }
}

module.exports = { MideaAdapter, MideaAC, MideaProtocol };