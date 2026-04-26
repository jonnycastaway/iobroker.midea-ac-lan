'use strict';

const crypto = require('crypto');

const AES_KEY = Buffer.from([
    0x1F, 0x86, 0x89, 0x70, 0xA9, 0x43, 0x7B, 0x59, 0xB3, 0x8E,
    0xEF, 0x83, 0x3F, 0xB4, 0x8C, 0x2B
]);

const DEFAULT_PORT = 6444;

class MideaAdapter {
    constructor() {
        this.devices = new Map();
        this.config = null;
        this.adapter = null;
        this.refreshTimer = null;
        this.tcpKey = null;
        this.requestCount = 0;
    }

    async start(adapter) {
        this.adapter = adapter;
        
        // Use console.log to ensure output appears
        console.log('*** MIDEA START, PID:', process.pid, '***');
        
        try {
            const adapterObj = await adapter.getObjectAsync('system.adapter.midea-ac-lan.0');
            this.config = adapterObj.native || {};
            console.log('*** NATIVE CONFIG:', JSON.stringify(this.config).substring(0, 300) || 'empty', '***');
        } catch (e) {
            console.log('*** CONFIG FALLBACK:', e.message, '***');
            this.config = adapter.config || {};
        }
        
        this.loadDevicesFromConfig();
        this.startRefreshLoop();
        
        console.log('*** MIDEA READY, DEVICES:', this.devices.size, '***');
        adapter.log.info('Midea ready, ' + this.devices.size + ' devices');
    }

    loadDevicesFromConfig() {
        this.adapter.log.info('=== loadDevicesFromConfig START');
        
        let configDevices = this.config.devices || [];
        
        this.adapter.log.info('=== CONFIG raw: ' + JSON.stringify(this.config).substring(0, 500));
        
        // If devices array is empty but individual fields exist, use single device
        if (configDevices.length === 0 && this.config.ipAddress && this.config.token && this.config.key) {
            configDevices = [{
                id: this.config.deviceId || 'ac_' + this.config.ipAddress.replace(/\./g, ''),
                ipAddress: this.config.ipAddress,
                port: this.config.port || DEFAULT_PORT,
                token: this.config.token,
                key: this.config.key,
                deviceId: this.config.deviceId,
                protocol: 3
            }];
            this.adapter.log.info('=== Using single device from config fields');
        }
        
        this.adapter.log.info('=== CONFIG DEVICES raw: ' + JSON.stringify(configDevices));
        
        if (typeof configDevices === 'string') {
            try {
                configDevices = JSON.parse(configDevices);
            } catch (e) {
                this.adapter.log.error('JSON parse error: ' + e.message);
                configDevices = [];
            }
        }
        
        if (!Array.isArray(configDevices)) {
            this.adapter.log.warn('=== DEBUG: devices is not array, using empty');
            configDevices = [];
        }
        
        this.adapter.log.info('=== DEBUG: Found ' + configDevices.length + ' devices in config');
        
        let counter = 1;
        for (const dev of configDevices) {
            this.adapter.log.info('=== DEBUG: Processing device: ' + JSON.stringify(dev));
            
            if (dev.ipAddress) {
                const id = dev.id || this.generateIdFromIp(dev.ipAddress, counter++);
                
                this.devices.set(id, {
                    id: id,
                    ipAddress: dev.ipAddress,
                    port: dev.port || DEFAULT_PORT,
                    token: dev.token || '',
                    key: dev.key || '',
                    protocol: dev.protocol || 3,
                    connected: false
                });
                
                this.createDeviceStates(id);
                this.adapter.log.info('Device ' + id + ': ' + dev.ipAddress);
            }
        }
    }

    generateIdFromIp(ip, fallback) {
        const parts = ip.split('.');
        if (parts.length === 4) {
            return parseInt(parts.map(p => p.padStart(3, '0')).join(''), 10);
        }
        return fallback;
    }

    createDeviceStates(deviceId) {
        const baseId = deviceId;
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
                this.adapter.setObjectNotExistsAsync(baseId + '.' + s.id, {
                    type: 'state',
                    common: {
                        name: s.id,
                        type: s.type,
                        role: s.role,
                        read: true,
                        write: s.write || false
                    },
                    native: {}
                });
            } catch (e) {}
        }
    }

    startRefreshLoop() {
        const interval = (this.config.refreshInterval || 30) * 1000;
        
        this.adapter.log.info('=== START REFRESH LOOP, interval: ' + interval + 'ms, devices: ' + this.devices.size);
        
        this.refreshTimer = setInterval(async () => {
            this.adapter.log.info('=== REFRESH TICK, devices: ' + this.devices.size);
            
            for (const [deviceId, device] of this.devices) {
                this.adapter.log.info('=== QUERY DEVICE: ' + deviceId + ' at ' + device.ipAddress + ' protocol:' + device.protocol);
                
                try {
                    const status = await this.queryDevice(device);
                    if (status) {
                        this.adapter.log.info('=== GOT STATUS: ' + JSON.stringify(status));
                        await this.updateStates(deviceId, status);
                    } else {
                        this.adapter.log.warn('=== NO STATUS for device: ' + deviceId);
                        await this.updateConnected(deviceId, false);
                    }
                } catch (e) {
                    this.adapter.log.warn('Device ' + deviceId + ' error: ' + e.message);
                    await this.updateConnected(deviceId, false);
                }
            }
        }, interval);
        
        this.adapter.log.info('Refresh interval: ' + interval + 'ms');
    }

    async queryDevice(device) {
        if (device.protocol === 3) {
            return await this.queryDeviceV3(device);
        } else {
            return await this.queryDeviceV2(device);
        }
    }

    async queryDeviceV2(device) {
        const net = require('net');
        
        return new Promise((resolve) => {
            const socket = new net.Socket();
            socket.setTimeout(5000);
            
            socket.connect(device.port, device.ipAddress, () => {
                const msg = Buffer.alloc(64);
                msg[0] = 0x5A; msg[1] = 0x5A;
                msg[2] = 0x01; msg[3] = 0x11;
                msg.writeUInt32LE(device.id, 4);
                socket.write(msg);
            });
            
            socket.on('data', (data) => {
                socket.destroy();
                try {
                    const encrypted = data.slice(40, data.length - 16);
                    const decrypted = this.aesDecrypt(encrypted);
                    resolve({
                        power: decrypted[0] === 1,
                        mode: decrypted[1],
                        targetTemp: (decrypted[3] + 150) / 2,
                        fanSpeed: decrypted[2],
                        indoorTemp: (decrypted[25] - 50) / 2
                    });
                } catch (e) { resolve(null); }
            });
            
            socket.on('timeout', () => { socket.destroy(); resolve(null); });
            socket.on('error', () => { resolve(null); });
        });
    }

    async queryDeviceV3(device) {
        const net = require('net');
        
        this.adapter.log.info('=== V3: Starting query for device ' + device.id + ' at ' + device.ipAddress);
        
        if (!device.token || !device.key) {
            this.adapter.log.warn('Device ' + device.id + ': No token/key');
            return null;
        }
        
        return new Promise((resolve) => {
            const socket = new net.Socket();
            
            socket.on('error', (e) => {
                this.adapter.log.warn('=== V3 Socket error: ' + e.message);
                resolve(null);
            });
            
            socket.connect(device.port, device.ipAddress, () => {
                this.adapter.log.info('=== V3: Connected');
                
                socket.setNoDelay(true);
                socket.setTimeout(5000);
                
                try {
                    const token = Buffer.from(device.token, 'hex');
                    const key = Buffer.from(device.key, 'hex');
                    
                    this.adapter.log.info('=== V3: Token length: ' + token.length + ', key length: ' + key.length);
                    
                    const handshake = this.encode8370(token, 0x00);
                    this.adapter.log.info('=== V3: Handshake: ' + handshake.toString('hex'));
                    this.adapter.log.info('=== V3: Handshake length: ' + handshake.length);
                    
                    socket.write(handshake);
                    this.adapter.log.info('=== V3: Handshake written, waiting for response...');
                    
                    socket.once('data', (d) => {
                        this.adapter.log.info('=== V3: Response: ' + d.toString('hex') + ' (' + d.length + ' bytes)');
                    
                        if (d.length >= 64) {
                            const response = d.slice(8, 72);
                            this.initTcpKey(response, key);
                            
                            if (!this.tcpKey) {
                                this.adapter.log.warn('=== V3: TCP key failed');
                                socket.destroy();
                                resolve(null);
                                return;
                            }
                            
                            const query = this.buildV3Query(device);
                            this.adapter.log.info('=== Sending query: ' + query.toString('hex'));
                            socket.write(query);
                            
                            // Wait for response with timeout
                            let responseData = Buffer.alloc(0);
                            const onData = (data) => {
                                responseData = Buffer.concat([responseData, data]);
                                this.adapter.log.info('=== Got data: ' + data.toString('hex').substring(0, 64));
                                
                                // Process if we have enough data
                                if (responseData.length >= 8) {
                                    const size = responseData.readUInt16BE(2);
                                    if (responseData.length >= size) {
                                        socket.removeListener('data', onData);
                                        const packet = responseData.slice(0, size);
                                        const msgs = this.decode8370(packet);
                                        socket.destroy();
                                        if (msgs.length > 0) {
                                            resolve(this.parseV3Status(msgs[0]));
                                        } else {
                                            this.adapter.log.warn('=== No messages decoded');
                                            resolve(null);
                                        }
                                    }
                                }
                            };
                            
                            socket.on('data', onData);
                        } else {
                            this.adapter.log.warn('=== V3: Response too short: ' + d.length);
                            socket.destroy();
                            resolve(null);
                        }
                    });
                } catch (e) {
                    this.adapter.log.error('=== V3 Error: ' + e.message);
                    socket.destroy();
                    resolve(null);
                }
            });
            
            socket.on('timeout', () => {
                this.adapter.log.warn('=== V3: Socket timeout - no response from device');
                socket.destroy();
                resolve(null);
            });
        });
    }

initTcpKey(response, key) {
        try {
            const payload = response.slice(0, 32);
            const sign = response.slice(32, 64);
            
            this.adapter.log.info('=== DEBUG key=' + key.toString('hex') + ' len=' + key.length);
            this.adapter.log.info('=== DEBUG payload=' + payload.toString('hex') + ' len=' + payload.length);
            this.adapter.log.info('=== DEBUG sign=' + sign.toString('hex').substring(0, 32));
            
            const keyCopy = Buffer.from(key);
            const payloadCopy = Buffer.from(payload);
            const iv = Buffer.alloc(16, 0);
            
            const crypto2 = require('crypto');
            
            this.adapter.log.info('=== Trying with manual padding');
            const decipher = crypto2.createDecipheriv('aes-256-cbc', keyCopy, iv);
            decipher.setAutoPadding(false);
            let plain = Buffer.concat([decipher.update(payloadCopy), decipher.final()]);
            
            // Manual PKCS7 unpadding
            const padLen = plain[plain.length - 1];
if (padLen > 0 && padLen <= 16 && padLen <= plain.length) {
                plain = plain.slice(0, plain.length - padLen);
            }
            
            this.adapter.log.info('=== DEBUG plain=' + plain.toString('hex').substring(0, 32));
            
            // Verify signature
            const check = crypto.createHash('sha256').update(plain).digest();
            if (check.compare(sign) !== 0) {
                this.adapter.log.warn('=== DEBUG sign mismatch!');
                throw new Error('Sign mismatch');
            }
            
            const keyXor = Buffer.alloc(32);
            for (let i = 0; i < 32; i++) {
                keyXor[i] = plain[i] ^ key[i];
            }
            this.tcpKey = keyXor;
            
            this.adapter.log.info('=== DEBUG tcpKey=' + this.tcpKey.toString('hex').substring(0, 32));
            this.adapter.log.info('V3 TCP key initialized');
            this.requestCount = 0;
        } catch (e) {
            this.adapter.log.error('TCP key error: ' + e.message);
            this.tcpKey = null;
        }
    }
    
    encode8370(data, msgType) {
        const crypto = require('crypto');
        const header = Buffer.from([0x83, 0x70]);
        
        let size = data.length;
        let padding = 0;
        
        if (msgType === 0x00) {
        } else if ((msgType === 0x03 || msgType === 0x06) && this.tcpKey) {
            if ((size + 2) % 16 !== 0) {
                padding = 16 - ((size + 2) & 0xF);
                size = size + padding + 32;
            } else {
                size = size + 32;
            }
        }
        
        const sizeBuf = Buffer.alloc(2);
        sizeBuf.writeUInt16BE(data.length, 0);
        
        const flagBuf = Buffer.from([0x20, (padding << 4) | msgType]);
        
        let payload = data;
        
        if (msgType === 0x00) {
            const counter = Buffer.alloc(2);
            counter.writeUInt16BE(0, 0);
            payload = Buffer.concat([counter, payload]);
        } else {
            let counterValue = this.requestCount++;
            if (this.requestCount >= 0xFFFF) this.requestCount = 0;
            
            const counter = Buffer.alloc(2);
            counter.writeUInt16BE(counterValue, 0);
            
            if ((msgType === 0x03 || msgType === 0x06) && this.tcpKey) {
                if (padding > 0) {
                    payload = Buffer.concat([payload, crypto.randomBytes(padding)]);
                }
                payload = Buffer.concat([counter, payload]);
                
                const cipher = crypto.createCipheriv('aes-128-cbc', this.tcpKey.slice(0, 16), Buffer.alloc(16, 0));
                payload = Buffer.concat([cipher.update(payload), cipher.final()]);
                
                const sign = crypto.createHash('sha256').update(Buffer.concat([header, sizeBuf, flagBuf, payload])).digest();
                payload = Buffer.concat([payload, sign]);
            } else {
                payload = Buffer.concat([counter, payload]);
            }
        }
        
        return Buffer.concat([header, sizeBuf, flagBuf, payload]);
    }

    decode8370(data) {
        if (!this.tcpKey || data.length < 8) return [];
        
        try {
            const header = data.slice(0, 6);
            if (header[0] !== 0x83 || header[1] !== 0x70) return [];
            
            const size = header.readUInt16BE(2) + 8;
            if (data.length < size) return [];
            
            const msgType = header[5] & 0x0F;
            let payload = data.slice(6, size);
            
            if (msgType === 0x03 || msgType === 0x06) {
                payload = payload.slice(0, -32);
                const decipher = crypto.createDecipheriv('aes-128-cbc', this.tcpKey, Buffer.alloc(16, 0));
                payload = Buffer.concat([decipher.update(payload), decipher.final()]);
            }
            
            return [payload.slice(2)];
        } catch (e) {
            return [];
        }
    }

    buildV3Query(device) {
        // Simple query body per Python: 0x81 + 0x00 + 0xFF + 16 null bytes = 19 bytes
        const queryBody = Buffer.alloc(19);
        queryBody[0] = 0x81;
        queryBody[2] = 0xFF;
        
        this.adapter.log.info('buildV3Query: body=' + queryBody.toString('hex'));
        
        return this.encode8370(queryBody, 0x06);
    }

    parseV3Status(data) {
        if (!data || data.length < 40) return null;
        
        return {
            power: data[0] === 1,
            mode: data[1],
            targetTemp: (data[3] + 150) / 2,
            fanSpeed: data[2],
            indoorTemp: (data[25] - 50) / 2
        };
    }

    aesDecrypt(data) {
        try {
            const decipher = crypto.createDecipheriv('aes-128-ecb', AES_KEY, null);
            decipher.setAutoPadding(true);
            return Buffer.concat([decipher.update(data), decipher.final()]);
        } catch (e) { return Buffer.alloc(32); }
    }

    async updateStates(deviceId, status) {
        const baseId = deviceId;
        try {
            await this.adapter.setStateAsync(baseId + '.power', status.power || false, true);
            await this.adapter.setStateAsync(baseId + '.mode', status.mode || 0, true);
            await this.adapter.setStateAsync(baseId + '.targetTemperature', status.targetTemp || 0, true);
            await this.adapter.setStateAsync(baseId + '.fanSpeed', status.fanSpeed || 0, true);
            await this.adapter.setStateAsync(baseId + '.indoorTemperature', status.indoorTemp || 0, true);
            await this.adapter.setStateAsync(baseId + '.connected', true, true);
        } catch (e) {}
    }

    async updateConnected(deviceId, connected) {
        try {
            await this.adapter.setStateAsync(deviceId + '.connected', connected, true);
        } catch (e) {}
    }

    async setDeviceState(deviceId, state, value) {
        const device = this.devices.get(deviceId.toString());
        if (!device) {
            this.adapter.log.warn('Device ' + deviceId + ' not found');
            return false;
        }
        
        this.adapter.log.info('Set ' + deviceId + ' ' + state + ' = ' + value);
        return true;
    }

    async stop() {
        if (this.refreshTimer) clearInterval(this.refreshTimer);
    }
}

module.exports = { MideaAdapter };