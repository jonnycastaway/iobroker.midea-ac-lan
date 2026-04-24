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
        this._socket = null;
    }

    setSocket(socket) {
        this._socket = socket;
    }

    encode8370(data, msgType) {
        const payload = Buffer.isBuffer(data) ? data : Buffer.from(data);
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

    tcpKey(responseData) {
        const key = this.key;
        const data = responseData.slice(0, 64);
        
        const step1 = Buffer.alloc(64);
        for (let i = 0; i < 64; i++) {
            step1[i] = data[i] ^ key[i];
        }
        
        const hash = crypto.createHash('sha256').update(step1).digest();
        
        const step2 = Buffer.alloc(64);
        for (let i = 0; i < 64; i++) {
            step2[i] = step1[i] ^ hash[i];
        }
        
        this.tcpKey = step2;
        return step2;
    }

    decryptResponse(response) {
        if (response.length < 8) return null;
        
        const msgType = response[4];
        
        if (msgType === 0x20 || msgType === 0x01) {
            return { type: 'handshake', data: response };
        }
        
        if (msgType === 0x03) {
            const encrypted = response.slice(8, response.length - 1);
            const decrypted = Buffer.alloc(encrypted.length);
            for (let i = 0; i < encrypted.length; i++) {
                decrypted[i] = encrypted[i] ^ (this.tcpKey ? this.tcpKey[i % 64] : 0);
            }
            return decrypted;
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
    }

    onUpdate(callback) {
        this.updateCallbacks.push(callback);
    }

    connect() {
        return new Promise((resolve, reject) => {
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
            
            setTimeout(() => {
                resolve(true);
            }, 500);
        });
    }

    sendHandshake() {
        const request = this.protocol.encode8370(this.protocol.token, MSGTYPE_HANDSHAKE_REQUEST);
        this.log.info(`[${this.deviceId}] Handshake: ${request.toString('hex')}`);
        this.socket.write(request, (err) => {
            if (err) {
                this.log.error(`[${this.deviceId}] Write error: ${err.message}`);
            } else {
                this.log.info(`[${this.deviceId}] Handshake written successfully`);
            }
        });
    }

    handleData(data) {
        this.log.info(`[${this.deviceId}] DATA: ${data.toString('hex')} (${data.length} bytes)`);
        
        this.buffer = Buffer.concat([this.buffer, data]);
        
        while (this.buffer.length >= 8) {
            const length = this.buffer.readUInt16BE(2) + 8;
            
            if (this.buffer.length < length) {
                break;
            }
            
            const packet = this.buffer.slice(0, length);
            this.buffer = this.buffer.slice(length);
            
            const result = this.protocol.decryptResponse(packet);
            this.processMessage(result);
        }
    }

    processMessage(message) {
        if (!message) return;
        
        if (typeof message === 'object' && message.type === 'handshake') {
            const responseData = message.data.slice(8, 72);
            const key = this.protocol.key;
            
            const step1 = Buffer.alloc(64);
            for (let i = 0; i < 64; i++) {
                step1[i] = responseData[i] ^ key[i];
            }
            
            const hash = crypto.createHash('sha256').update(step1).digest();
            
            const step2 = Buffer.alloc(64);
            for (let i = 0; i < 64; i++) {
                step2[i] = step1[i] ^ hash[i];
            }
            
            this.protocol.tcpKey = step2;
            
            this.connected = true;
            this.log.info(`[${this.deviceId}] Authentication success`);
            
            setTimeout(() => this.sendApplianceQuery(), 500);
            return;
        }
        
        if (typeof message === 'string') {
            if (message.includes('ERROR')) {
                this.log.warn(`[${this.deviceId}] Device error: ${message}`);
            }
            return;
        }
        
        if (message.length < 10) return;
        
        const msgType = message[9];
        
        if (msgType === 0xA0) {
            this.log.info(`[${this.deviceId}] Appliance response received`);
            this.available = true;
            setTimeout(() => this.sendStatusQuery(), 500);
        } else if (msgType === 0x03) {
            this.parseStatusResponse(message);
        }
    }

    sendApplianceQuery() {
        const body = Buffer.alloc(19);
        body.fill(0);
        
        const packet = Buffer.concat([
            Buffer.from([0xAA, 0x1D, DEVICE_TYPE_AC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA0]),
            body
        ]);
        
        packet[packet.length - 1] = this.twoComplementChecksum(packet.slice(1));
        
        const encrypted = this.protocol.encode8370(packet, MSGTYPE_ENCRYPTED_REQUEST);
        this.socket.write(encrypted);
        this.log.info(`[${this.deviceId}] Query Appliance sent`);
    }

    sendStatusQuery() {
        const body = Buffer.from([
            0xC0, 0x00, 0x87, 0x66, 0x7F, 0x7F, 0x00, 0x3F,
            0x00, 0x00, 0x00, 0x69, 0xFF, 0x0B, 0x00, 0x09,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x2C
        ]);
        
        const packet = Buffer.concat([
            Buffer.from([0xAA, 0x28, DEVICE_TYPE_AC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03]),
            body
        ]);
        
        const encrypted = this.protocol.encode8370(packet, MSGTYPE_ENCRYPTED_REQUEST);
        this.socket.write(encrypted);
        this.log.info(`[${this.deviceId}] Status Query sent`);
    }

    parseStatusResponse(data) {
        if (data.length < 40) return;
        
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
        
        this.log.info(`[${this.deviceId}] Status: power=${power}, mode=${mode}, temp=${targetTemp}°C, indoor=${indoorTemp}°C`);
        
        this.notifyUpdate();
    }

    twoComplementChecksum(data) {
        const sum = data.reduce((acc, b) => acc + b, 0);
        return (-sum) & 0xFF;
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
        this.log.info(`[${this.deviceId}] Set ${name} = ${value}`);
        
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
        
        const body = Buffer.from([
            0xC1, 0x01, 0x01, power | mode,
            temp, fan, 0x7F, 0x7F,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
            0x2C
        ]);
        
        const packet = Buffer.concat([
            Buffer.from([0xAA, 0x28, DEVICE_TYPE_AC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03]),
            body
        ]);
        
        const encrypted = this.protocol.encode8370(packet, MSGTYPE_ENCRYPTED_REQUEST);
        this.socket.write(encrypted);
        this.log.info(`[${this.deviceId}] Control command sent`);
        
        setTimeout(() => this.sendStatusQuery(), 1000);
    }

    close() {
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
        const deviceId = this.config.deviceId;
        const ipAddress = this.config.ipAddress;
        const token = this.config.token;
        const key = this.config.key;
        
        if (!deviceId || !ipAddress || !token || !key) {
            this.adapter.log.error('Missing configuration: deviceId, ipAddress, token, key');
            return;
        }
        
        this.createDeviceStates(deviceId);
        
        this.device = new MideaAC({
            deviceId: deviceId,
            deviceName: this.config.deviceName || '',
            ipAddress: ipAddress,
            port: this.config.port || DEFAULT_PORT,
            token: token,
            key: key
        }, this.adapter.log);
        
        this.device.onUpdate((status) => {
            this.updateStates(deviceId, status);
        });
        
        this.connectDevice();
        
        const interval = (this.config.refreshInterval || 30) * 1000;
        this.refreshInterval = setInterval(() => {
            if (this.device && this.device.connected && this.device.available) {
                this.device.sendStatusQuery();
            }
        }, interval);
    }

    async connectDevice() {
        try {
            await this.device.connect();
        } catch (e) {
            this.adapter.log.error('Failed to connect: ' + e.message);
        }
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
                const common = {
                    name: s.id,
                    type: s.type,
                    role: s.role,
                    read: true,
                    write: s.write || false
                };
                
                if (s.min !== undefined) common.min = s.min;
                if (s.max !== undefined) common.max = s.max;
                
                this.adapter.setObjectNotExistsAsync(deviceId + '.' + s.id, {
                    type: 'state',
                    common: common,
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
        if (!this.device) {
            this.adapter.log.warn('Device not initialized');
            return false;
        }
        
        this.adapter.log.info('Set ' + state + ' = ' + value);
        
        try {
            if (state === 'power') {
                this.device.set_attribute('power_on', value);
            } else if (state === 'targetTemperature') {
                this.device.set_attribute('target_temperature', value);
            } else if (state === 'mode') {
                this.device.set_attribute('mode', value);
            } else if (state === 'fanSpeed') {
                this.device.set_attribute('fan_speed', value);
            }
            this.device.apply();
            return true;
        } catch (e) {
            this.adapter.log.error('Error setting state: ' + e.message);
            return false;
        }
    }

    async stop() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
        }
        if (this.device) {
            this.device.close();
        }
    }
}

module.exports = { MideaAdapter };