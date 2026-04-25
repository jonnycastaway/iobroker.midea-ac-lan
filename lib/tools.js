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
    }
    
    calculateTcpKey(responseData) {
        const encryptedPart = responseData.slice(0, 32);
        const signaturePart = responseData.slice(32, 64);
        const iv = Buffer.alloc(16, 0);
        const decipher = crypto.createDecipheriv('aes-128-cbc', this.key.slice(0, 16), iv);
        let plain = Buffer.concat([decipher.update(encryptedPart), decipher.final()]);
        const hash = crypto.createHash('sha256').update(plain).digest();
        for(let i = 0; i < 32; i++) {
            if (hash[i] !== signaturePart[i]) return null;
        }
        const tcpKey = Buffer.alloc(32);
        for (let i = 0; i < 32; i++) tcpKey[i] = plain[i] ^ this.key[i];
        this.tcpKey = Buffer.concat([tcpKey, tcpKey]);
        return this.tcpKey;
    }
    
    encode8370(data, msgType) {
        const payload = Buffer.isBuffer(data) ? data : Buffer.from(data);
        
        if (msgType === MSGTYPE_ENCRYPTED_REQUEST) {
            const requestCount = Buffer.alloc(2);
            requestCount.writeUInt16BE(this._requestCount++, 0);
            let paddedData = Buffer.concat([requestCount, payload]);
            
            // Calculate padding: 16 - ((size + 2) % 16)
            const sizeAfterCount = paddedData.length;
            const remainder = (sizeAfterCount + 2) % 16;
            let padding = 0;
            if (remainder !== 0) {
                padding = 16 - remainder;
            }
            
            if (padding > 0) paddedData = Buffer.concat([paddedData, crypto.randomBytes(padding)]);
            
            const iv = Buffer.alloc(16, 0);
            const cipher = crypto.createCipheriv('aes-128-cbc', this.tcpKey ? this.tcpKey.slice(0, 16) : Buffer.alloc(16, 0), iv);
            const encrypted = Buffer.concat([cipher.update(paddedData), cipher.final()]);
            
            const totalSize = encrypted.length + 2; // +2 for request count
            
            const header = Buffer.alloc(8);
            header[0] = 0x83;
            header[1] = 0x70;
            header.writeUInt16BE(totalSize, 2);
            header[4] = 0x20;
            header[5] = (padding << 4) | msgType;  // CORRECT: padding in upper nibble
            header[6] = 0;
            header[7] = 0;
            
            const signData = Buffer.concat([header, encrypted]);
            const signature = crypto.createHash('sha256').update(signData).digest();
            
            return Buffer.concat([header, encrypted, signature]);
        }
        
        const frame = Buffer.alloc(payload.length + 9);
        frame[0] = 0x83; frame[1] = 0x70;
        frame.writeUInt16BE(payload.length, 2);
        frame[4] = 0x20; frame[5] = msgType;
        payload.copy(frame, 8);
        let checksum = 0;
        for(let i = 0; i < payload.length + 8; i++) checksum ^= frame[i];
        frame[payload.length + 8] = checksum;
        return frame;
    }
    
    decryptResponse(response) {
        if (response.length < 8) return null;
        
        // Check for ERROR response
        if (response[5] === 0x0f) return 'ERROR';
        
        // Check for handshake response
        if (response[4] === 0x20 && response.length >= 72) {
            return { type: 'handshake', data: response };
        }
        
        // Check for encrypted response
        if (response[4] === MSGTYPE_ENCRYPTED_RESPONSE && this.tcpKey) {
            // Length field is from byte 2-3
            const len = response.readUInt16BE(2);
            // Full packet = len + 8 (header)
            const fullLen = len + 8;
            
            // Extract encrypted data (after 8-byte header, before 32-byte signature)
            const encryptedData = response.slice(8, fullLen - 32);
            
            try {
                const decipher = crypto.createDecipheriv('aes-128-cbc', this.tcpKey.slice(0, 16), Buffer.alloc(16, 0));
                return Buffer.concat([decipher.update(encryptedData), decipher.final()]);
            } catch(e) { return null; }
        }
        
        return null;
    }
}

class MideaAC {
    constructor(config, log) {
        this.config = config; this.log = log;
        this.deviceId = config.deviceId; this.ipAddress = config.ipAddress;
        this.port = config.port || DEFAULT_PORT; this.token = config.token; this.key = config.key;
        this.protocol = new MideaProtocol(this.token, this.key);
        this.socket = null; this.connected = false; this.available = false;
        this.updateCallbacks = []; this.buffer = Buffer.alloc(0); this.refreshInterval = null;
    }
    
    onUpdate(cb) { this.updateCallbacks.push(cb); }
    
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
                    this.processMessage(this.protocol.decryptResponse(packet));
                }
            });
            this.socket.on('close', () => {
                this.log.warn(`[${this.deviceId}] Connection closed`);
                this.connected = false;
            });
            this.socket.on('error', (e) => this.log.error(`[${this.deviceId}] Socket error: ${e.message}`));
            setTimeout(() => resolve(true), 500);
        });
    }
    
    sendHandshake() {
        const req = this.protocol.encode8370(this.protocol.token, MSGTYPE_HANDSHAKE_REQUEST);
        this.socket.write(req);
    }
    
    processMessage(msg) {
        if (!msg) return;
        if (typeof msg === 'object' && msg.type === 'handshake') {
            this.protocol.calculateTcpKey(msg.data.slice(8, 72));
            this.connected = true;
            this.log.info(`[${this.deviceId}] Authentication success`);
            return setTimeout(() => this.startReceiving(), 1000);
        }
        if (typeof msg === 'string' && msg.includes('ERROR')) {
            this.log.warn(`[${this.deviceId}] Device error`);
            return;
        }
        if (Buffer.isBuffer(msg) && msg.length >= 30) this.parseStatus(msg);
    }
    
    startReceiving() {
        if (!this.socket || !this.connected) return;
        this.log.info(`[${this.deviceId}] Listening for updates...`);
        // Use aa20ac query format (same as HA)
        const queryData = Buffer.from([
            0xAA, 0x20, 0xAC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
            0x81, 0x00, 0x87, 0x66, 0x7F, 0x7F, 0x00, 0x3F, 0x00, 0x00, 0x00,
            0x69, 0xFF, 0x0B, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x2C
        ]);
        this.socket.write(this.protocol.encode8370(queryData, MSGTYPE_ENCRYPTED_REQUEST));
        this.refreshInterval = setInterval(() => {
            if(this.socket && this.connected) {
                this.socket.write(this.protocol.encode8370(queryData, MSGTYPE_ENCRYPTED_REQUEST));
            }
        }, 30000);
    }
    
    parseStatus(data) {
        if (data.length < 30) return;
        this.available = true;
        const status = { power: (data[15] & 0x08) !== 0, mode: data[16] & 0x0F, targetTemperature: ((data[17] & 0x0F) + 16), fanSpeed: (data[18] & 0x7F) };
        this.log.info(`[${this.deviceId}] Status: power=${status.power} mode=${status.mode} temp=${status.targetTemperature} fan=${status.fanSpeed}`);
        for(const cb of this.updateCallbacks) try{cb(status)}catch(e){}
    }
    
    close() {
        if (this.refreshInterval) clearInterval(this.refreshInterval);
        if (this.socket) { this.socket.destroy(); this.socket = null; }
        this.connected = false; this.available = false;
    }
}

class MideaAdapter {
    constructor() { this.config = null; this.adapter = null; this.device = null; }
    
    async start(adapter) {
        this.adapter = adapter;
        adapter.log.info('Midea AC LAN starting...');
        try { this.config = (await adapter.getObjectAsync('system.adapter.midea-ac-lan.0')).native || {}; }
        catch { this.config = adapter.config || {}; }
        this.startDevice();
        adapter.log.info('Midea adapter ready');
    }
    
    startDevice() {
        const { deviceId, ipAddress, token, key } = this.config;
        if (!deviceId || !ipAddress || !token || !key) return this.adapter.log.error('Missing config');
        for(const s of ['power','mode','targetTemperature','fanSpeed','connected']) {
            try{this.adapter.setObjectNotExistsAsync(deviceId+'.'+s,{type:'state',common:{name:s,type:(s==='power'||s==='connected')?'boolean':'number',role:(s==='power'?'switch':s==='connected'?'indicator.connected':'value'),read:true,write:false},native:{}})}catch(e){}
        }
        this.device = new MideaAC({deviceId,ipAddress,port:this.config.port||DEFAULT_PORT,token,key,deviceName:this.config.deviceName||''},this.adapter.log);
        this.device.onUpdate((s)=>this.updateStates(deviceId,s));
        this.device.connect();
    }
    
    async updateStates(deviceId, status) {
        try {
            await this.adapter.setStateAsync(deviceId+'.power', status.power||false, true);
            await this.adapter.setStateAsync(deviceId+'.mode', status.mode||0, true);
            await this.adapter.setStateAsync(deviceId+'.targetTemperature', status.targetTemperature||20, true);
            await this.adapter.setStateAsync(deviceId+'.fanSpeed', status.fanSpeed||0, true);
            await this.adapter.setStateAsync(deviceId+'.connected', true, true);
        } catch(e) {}
    }
    
    async stop() { if (this.device) this.device.close(); }
}

module.exports = { MideaAdapter, MideaAC, MideaProtocol };