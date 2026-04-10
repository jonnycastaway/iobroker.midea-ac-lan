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
            console.log('*** NATIVE CONFIG:', JSON.stringify(this.config).substring(0, 300), '***');
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
        
        let configDevices = this.config.devices;
        
        this.adapter.log.info('=== CONFIG DEVICES raw: ' + JSON.stringify(configDevices));
        
        this.adapter.log.info('=== DEBUG: devices = ' + JSON.stringify(configDevices).substring(0, 200));
        
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
                            this.adapter.log.info('=== V3: Query: ' + query.toString('hex'));
                            socket.write(query);
                            
                            let queryTimeout = setTimeout(() => {
                                this.adapter.log.warn('=== V3: Query timeout - no response');
                                socket.destroy();
                                resolve(null);
                            }, 5000);
                            
                            socket.once('data', (data) => {
                                clearTimeout(queryTimeout);
                                this.adapter.log.info('=== V3: Query Response: ' + data.toString('hex') + ' (' + data.length + ' bytes)');
                                socket.destroy();
                                const msgs = this.decode8370(data);
                                if (msgs.length > 0) {
                                    resolve(this.parseV3Status(msgs[0]));
                                } else {
                                    resolve(null);
                                }
                            });
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
            this.adapter.log.info('initTcpKey: response length = ' + response.length);
            this.adapter.log.info('initTcpKey: key length = ' + key.length);
            
            const payload = response.slice(0, 32);
            const sign = response.slice(32, 64);
            
            this.adapter.log.info('initTcpKey: payload = ' + payload.toString('hex'));
            this.adapter.log.info('initTcpKey: sign = ' + sign.toString('hex'));
            this.adapter.log.info('initTcpKey: key = ' + key.toString('hex'));
            
            // Try different AES configurations
            let plain = null;
            
            // Try AES-256-CBC with 32-byte key first
            try {
                const decipher = crypto.createDecipheriv('aes-256-cbc', key, Buffer.alloc(16, 0));
                decipher.setAutoPadding(false);
                plain = Buffer.concat([decipher.update(payload), decipher.final()]);
                this.adapter.log.info('Tried aes-256-cbc with 32-byte key');
            } catch (e) {
                this.adapter.log.info('aes-256-cbc failed: ' + e.message);
                
                // Fallback: Try AES-128 with 16-byte key
                try {
                    const decipher2 = crypto.createDecipheriv('aes-128-cbc', key.slice(0, 16), Buffer.alloc(16, 0));
                    decipher2.setAutoPadding(false);
                    plain = Buffer.concat([decipher2.update(payload), decipher2.final()]);
                    this.adapter.log.info('Tried aes-128-cbc with 16-byte key (fallback)');
                } catch (e2) {
                    this.adapter.log.info('aes-128-cbc also failed: ' + e2.message);
                    throw new Error('Both AES-256 and AES-128 failed');
                }
            }
            
            this.adapter.log.info('initTcpKey: plain = ' + plain.toString('hex'));
            
            const check = crypto.createHash('sha256').update(plain).digest();
            this.adapter.log.info('initTcpKey: check = ' + check.toString('hex'));
            this.adapter.log.info('initTcpKey: sign match = ' + (check.compare(sign) === 0));
            
            if (check.compare(sign) !== 0) {
                throw new Error('Sign mismatch');
            }
            
            const keyXor = Buffer.alloc(16);
            for (let i = 0; i < 16; i++) {
                keyXor[i] = plain[i] ^ key[i];
            }
            this.tcpKey = keyXor;
            this.requestCount = 0;
            this.adapter.log.info('V3 TCP key initialized');
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
        sizeBuf.writeUInt16BE(size, 0);
        
        // Flag is 2 bytes: [0x20, (padding << 4) | msgType]
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
                
                const cipher = crypto.createCipheriv('aes-128-cbc', this.tcpKey, Buffer.alloc(16, 0));
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
        // Build packet using Python's PacketBuilder format
        const idNum = device.id;
        
        const fullPacket = Buffer.alloc(28);  // 28 bytes + 16 for checksum = 44
        
        // Static header
        fullPacket[0] = 0x5A;
        fullPacket[1] = 0x5A;
        
        // Message type
        fullPacket[2] = 0x01;
        fullPacket[3] = 0x11;
        
        // Packet length - total + 16 for checksum
        const totalLen = 28 + 16;
        fullPacket[4] = totalLen & 0xFF;
        fullPacket[5] = (totalLen >> 8) & 0xFF;
        
        // Flags
        fullPacket[6] = 0x20;
        fullPacket[7] = 0x00;
        
        // Message ID (4 bytes at 8-11) - all zeros
        
        // Device ID (8 bytes little-endian) at bytes 20-27
        const devIdBuffer = Buffer.alloc(8);
        devIdBuffer.writeBigUInt64LE(BigInt(idNum), 0);
        devIdBuffer.copy(fullPacket, 20);
        
        this.adapter.log.info('buildV3Query: device.id=' + device.id + ', packet=' + fullPacket.toString('hex'));
        
        return this.encode8370(fullPacket, 0x06);
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