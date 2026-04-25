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
        console.log('[MideaProtocol] Created with token length:', this.token.length, 'key length:', this.key.length);
    }
    
    setSocket(socket) {
        this._socket = socket;
    }
    
    calculateTcpKey(responseData) {
        console.log('[MideaProtocol] calculateTcpKey called, response length:', responseData ? responseData.length : 0);
        
        if (!responseData || responseData.length < 64) {
            console.log('[MideaProtocol] Invalid response data for tcpKey');
            return null;
        }
        
        const data = responseData.slice(0, 64);
        
        const step1 = Buffer.alloc(64);
        for (let i = 0; i < 64; i++) {
            step1[i] = data[i] ^ this.key[i];
        }
        
        const hash = crypto.createHash('sha256').update(step1).digest();
        
        const step2 = Buffer.alloc(64);
        for (let i = 0; i < 64; i++) {
            step2[i] = step1[i] ^ hash[i];
        }
        
        this.tcpKey = step2;
        console.log('[MideaProtocol] tcpKey calculated:', this.tcpKey ? this.tcpKey.toString('hex').substring(0, 32) + '...' : 'NULL');
        return this.tcpKey;
    }

    setSocket(socket) {
        this._socket = socket;
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
        
        // Check for ERROR response - byte 5 contains error code 0x0f
        const errorCode = response[5];
        if (errorCode === 0x0f) {
            // Check if body contains 'ERROR' string
            const asciiData = response.slice(6).toString('ascii');
            if (asciiData.includes('ERROR')) {
                return 'ERROR';
            }
            return `ERROR_${errorCode}`;
        }
        
        // Handshake response (byte 4 = 0x20 with data length >= 72)
        if (msgType === 0x20 && response.length >= 72) {
            return { type: 'handshake', data: response };
        }
        
        // Encrypted response (for status updates)
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
                    // Decryption failed - return raw
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
        this.log.info(`[${this.deviceId}] Received ${data.length} bytes: ${data.toString('hex').substring(0, 60)}...`);
        this.buffer = Buffer.concat([this.buffer, data]);
        
        while (this.buffer.length >= 8) {
            const length = this.buffer.readUInt16BE(2) + 8;
            
            if (this.buffer.length < length) {
                break;
            }
            
            const packet = this.buffer.slice(0, length);
            this.buffer = this.buffer.slice(length);
            
            const result = this.protocol.decryptResponse(packet, this.protocol.tcpKey);
            let resultStr = 'null';
            if (result) {
                if (typeof result === 'string') {
                    resultStr = 'String:' + result;
                } else if (Buffer.isBuffer(result)) {
                    resultStr = 'Buffer hex:' + result.toString('hex');
                } else {
                    resultStr = 'Object';
                }
            }
            this.log.info(`[${this.deviceId}] Decrypt result: ${resultStr}`);
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
                
                // Start listening for async updates - the AC will send updates, not direct responses
                setTimeout(() => this.startReceiving(), 500);
            }
            return;
        }
        
        if (typeof message === 'string') {
            if (message.includes('ERROR')) {
                this.log.warn(`[${this.deviceId}] Device error: ${message}`);
            }
            return;
        }
        
        // For encrypted responses (async updates from AC)
        if (message.length >= 30) {
            this.parseStatusResponse(message);
        }
    }
    
    startReceiving() {
        // After authentication, the AC sends async updates periodically
        // We don't expect direct responses to queries - just listen for updates
        if (!this.socket || !this.connected) return;
        
        this.log.info(`[${this.deviceId}] Listening for updates...`);
        
        // Send initial query to trigger data response (if any)
        this.sendApplianceQuery();
        
        // Set up periodic queries, but DON'T wait for responses
        // Just keep the connection open for async updates
        this.refreshInterval = setInterval(() => {
            if (this.socket && this.connected) {
                this.sendStatusQuery();
            }
        }, 30000);
    }

    sendApplianceQuery() {
        if (!this.socket || !this.connected) {
            this.log.warn(`[${this.deviceId}] Not connected`);
            return;
        }
        
        // Use MessageQuery format like HA: aa20ac + body
        const header = Buffer.from([0xAA, 0x20, DEVICE_TYPE_AC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03]);
        const body = Buffer.from([
            0x81, 0x00, 0x87, 0x66, 0x7F, 0x7F, 0x00, 0x3F,
            0x00, 0x00, 0x00, 0x69, 0xFF, 0x0B, 0x00, 0x09,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x2C
        ]);
        
        const packet = Buffer.concat([header, body]);
        const encrypted = this.protocol.encode8370(packet, MSGTYPE_ENCRYPTED_REQUEST);
        this.socket.write(encrypted);
        this.log.info(`[${this.deviceId}] Query Appliance sent (MessageQuery)`);
    }

    sendStatusQuery() {
        if (!this.socket || !this.connected) return;
        
        // Use MessageQuery format: aa20ac
        const header = Buffer.from([0xAA, 0x20, DEVICE_TYPE_AC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03]);
        const body = Buffer.from([
            0x81, 0x00, 0x87, 0x66, 0x7F, 0x7F, 0x00, 0x3F,
            0x00, 0x00, 0x00, 0x69, 0xFF, 0x0B, 0x00, 0x09,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x2C
        ]);
        
        const packet = Buffer.concat([header, body]);
        const encrypted = this.protocol.encode8370(packet, MSGTYPE_ENCRYPTED_REQUEST);
        this.socket.write(encrypted);
        this.log.info(`[${this.deviceId}] Status Query sent (MessageQuery)`);
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
        const fanSpeed = fanByte;
        
        const indoorTempRaw = data[19];
        const indoorTemp = indoorTempRaw / 10;
        
        this.attributes = {
            power: power,
            mode: mode,
            target_temperature: targetTemp,
            fan_speed: fanSpeed,
            indoor_temperature: indoorTemp
        };
        
        this.log.info(`[${this.deviceId}] Status: power=${power}, mode=${mode}, temp=${targetTemp}C, indoor=${indoorTemp}C`);
        
        this.notifyUpdate();
    }

    notifyUpdate() {
        const status = {
            power: this.attributes.power || false,
            mode: this.attributes.mode || 0,
            targetTemperature: this.attributes.target_temperature || 20,
            fanSpeed: this.attributes.fan_speed || 0,
            indoorTemperature: this.attributes.indoor_temperature || 0,
            connected: this.available
        };
        
        for (const cb of this.updateCallbacks) {
            cb(status);
        }
    }

    set_attribute(name, value) {
        if (name === 'power_on') {
            this.attributes.power = value;
        } else if (name === 'target_temperature') {
            this.attributes.target_temperature = value;
        } else if (name === 'mode') {
            this.attributes.mode = value;
        } else if (name === 'fan_speed') {
            this.attributes.fan_speed = value;
        }
    }

    apply() {
        if (!this.connected || !this.socket) {
            this.log.warn(`[${this.deviceId}] Not connected`);
            return;
        }
        
        const power = this.attributes.power ? 0x08 : 0x00;
        const mode = this.attributes.mode || 0;
        const temp = this.attributes.target_temperature || 20;
        const fan = this.attributes.fan_speed || 102;
        
        const header = Buffer.from([0xAA, 0x28, DEVICE_TYPE_AC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03]);
        const body = Buffer.from([
            0xC1, 0x01, 0x01, power | mode,
            temp, fan, 0x7F, 0x7F,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
            0x2C
        ]);
        
        const packet = Buffer.concat([header, body]);
        const encrypted = this.protocol.encode8370(packet, MSGTYPE_ENCRYPTED_REQUEST);
        this.socket.write(encrypted);
        this.log.info(`[${this.deviceId}] Control sent`);
        
        setTimeout(() => this.sendStatusQuery(), 1000);
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
        
        this.refreshInterval = setInterval(() => {
            if (this.device?.connected && this.device?.available) {
                this.device.sendStatusQuery();
            }
        }, (this.config.refreshInterval || 30) * 1000);
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
            await this.adapter.setStateAsync(deviceId + '.indoorTemperature', status.indoorTemperature || 0, true);
            await this.adapter.setStateAsync(deviceId + '.connected', status.connected || false, true);
        } catch (e) {}
    }

    async setDeviceState(state, value) {
        if (!this.device) return false;
        
        try {
            if (state === 'power') this.device.set_attribute('power_on', value);
            else if (state === 'targetTemperature') this.device.set_attribute('target_temperature', value);
            else if (state === 'mode') this.device.set_attribute('mode', value);
            else if (state === 'fanSpeed') this.device.set_attribute('fan_speed', value);
            
            this.device.apply();
            return true;
        } catch (e) {
            this.adapter.log.error('Set state error: ' + e.message);
            return false;
        }
    }

    async stop() {
        if (this.refreshInterval) clearInterval(this.refreshInterval);
        if (this.device) this.device.close();
    }
}

module.exports = { MideaAdapter, MideaAC, MideaProtocol };