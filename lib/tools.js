'use strict';

const crypto = require('crypto');
const https = require('https');

const AES_KEY = Buffer.from([
    0x1F, 0x86, 0x89, 0x70, 0xA9, 0x43, 0x7B, 0x59, 0xB3, 0x8E,
    0xEF, 0x83, 0x3F, 0xB4, 0x8C, 0x2B
]);

const DEFAULT_PORT = 6444;

const CLOUD_CONFIG = {
    APP_ID: '1010',
    CLIENT_TYPE: 1,
    FORMAT: 2,
    LANGUAGE: 'en_US',
    IOT_KEY: 'meicloud',
    LOGIN_KEY: 'ac21b9f9cbfe4ca5a88562ef25e2b768',
    HMAC_KEY: 'PROD_VnoClJI9aikS8dyy'
};

const CLOUD_ENDPOINTS = {
    baseUrl: 'https://mp-prod.appsmb.com',
    loginId: '/mas/v5/app/proxy?alias=/v1/user/login/id/get',
    login: '/mas/v5/app/proxy?alias=/mj/user/login',
    deviceList: '/mas/v5/app/proxy?alias=/v1/appliance/user/list/get',
    getToken: '/mas/v5/app/proxy?alias=/v1/iot/secure/getToken'
};

const NETHOME_CONFIG = {
    APP_ID: '1017',
    APP_KEY: '3742e9e5842d4ad59c2db887e12449f9'
};

const NETHOME_ENDPOINTS = {
    baseUrl: 'https://mapp.appsmb.com',
    loginId: '/v1/user/login/id/get',
    login: '/v1/user/login',
    deviceList: '/v1/appliance/user/list/get',
    getToken: '/v1/iot/secure/getToken',
    getTokenByCode: '/mas/v5/app/proxy?alias=/v1/iot/secure/getToken'
};

function generateReqId() {
    return crypto.randomBytes(16).toString('hex');
}

function generateDeviceId() {
    return crypto.randomBytes(8).toString('hex');
}

function timestamp() {
    const now = new Date();
    return now.getUTCFullYear().toString() +
        (now.getUTCMonth() + 1).toString().padStart(2, '0') +
        now.getUTCDate().toString().padStart(2, '0') +
        now.getUTCHours().toString().padStart(2, '0') +
        now.getUTCMinutes().toString().padStart(2, '0') +
        now.getUTCSeconds().toString().padStart(2, '0');
}

function encryptPassword(loginId, password) {
    const m1 = crypto.createHash('sha256').update(password).digest('hex');
    const loginHash = loginId + m1 + CLOUD_CONFIG.LOGIN_KEY;
    return crypto.createHash('sha256').update(loginHash).digest('hex');
}

function encryptIamPassword(loginId, password) {
    const m1 = crypto.createHash('md5').update(password).digest('hex');
    const m2 = crypto.createHash('md5').update(m1).digest('hex');
    const loginHash = loginId + m2 + CLOUD_CONFIG.LOGIN_KEY;
    return crypto.createHash('sha256').update(loginHash).digest('hex');
}

function sign(data, random) {
    const msg = CLOUD_CONFIG.IOT_KEY + data + random;
    return crypto.createHmac('sha256', CLOUD_CONFIG.HMAC_KEY).update(msg).digest('hex');
}

class MideaCloud {
    constructor() {
        this.accessToken = '';
        this.userId = null;
        this.loginId = null;
        this.deviceId = generateDeviceId();
        this.session = {};
    }

    async request(path, data, timeoutMs = 10000) {
        return new Promise((resolve, reject) => {
            const body = {
                appId: CLOUD_CONFIG.APP_ID,
                src: CLOUD_CONFIG.APP_ID,
                format: CLOUD_CONFIG.FORMAT,
                clientType: CLOUD_CONFIG.CLIENT_TYPE,
                language: CLOUD_CONFIG.LANGUAGE,
                deviceId: this.deviceId,
                stamp: timestamp(),
                reqId: generateReqId(),
                ...data
            };

            const postData = JSON.stringify(body);
            const random = crypto.randomBytes(16).toString('hex');

            const signValue = sign(postData, random);

            const headers = {
                'Content-Type': 'application/json',
                'secretVersion': '1',
                'sign': signValue,
                'random': random,
                'accessToken': this.accessToken
            };

            const options = {
                hostname: 'mp-prod.appsmb.com',
                port: 443,
                path: path,
                method: 'POST',
                headers: headers,
                timeout: timeoutMs
            };

            const req = https.request(options, (res) => {
                let responseBody = '';
                res.on('data', chunk => responseBody += chunk);
                res.on('end', () => {
                    try {
                        const json = JSON.parse(responseBody);
                        const code = parseInt(json.code, 10);
                        if (code === 0) {
                            resolve(json.data);
                        } else {
                            reject(new Error(json.msg || `Error ${code}`));
                        }
                    } catch (e) {
                        reject(new Error('Invalid cloud response'));
                    }
                });
            });

            req.on('error', (e) => {
                reject(new Error('Network error: ' + e.message));
            });
            
            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });
            
            req.write(postData);
            req.end();
        });
    }

    async login(email, password) {
        if (!email || !password) {
            throw new Error('Email and password required');
        }
        
        const loginData = await this.request(CLOUD_ENDPOINTS.loginId, {
            loginAccount: email
        });

        this.loginId = loginData.loginId;
        if (!this.loginId) {
            throw new Error('Failed to get loginId');
        }

        const loginBody = {
            data: {
                platform: CLOUD_CONFIG.FORMAT,
                deviceId: this.deviceId
            },
            iotData: {
                appId: CLOUD_CONFIG.APP_ID,
                src: CLOUD_CONFIG.APP_ID,
                clientType: CLOUD_CONFIG.CLIENT_TYPE,
                loginAccount: this.loginId,
                iampwd: encryptIamPassword(this.loginId, password),
                password: encryptPassword(this.loginId, password),
                pushToken: crypto.randomBytes(120).toString('base64').substring(0, 120),
                stamp: timestamp(),
                reqId: generateReqId()
            }
        };

        const confirmData = await this.request(CLOUD_ENDPOINTS.login, loginBody);

        this.session = confirmData;
        this.accessToken = confirmData.mdata.accessToken;
        this.userId = confirmData.userId;

        if (!this.accessToken) {
            throw new Error('Failed to get accessToken');
        }

        return { userId: this.userId, loginId: this.loginId };
    }

    async getDeviceList() {
        if (!this.accessToken) {
            throw new Error('Not logged in');
        }

        const data = await this.request(CLOUD_ENDPOINTS.deviceList, {
            uid: this.userId
        });

        return data.applianceList || [];
    }

    async getToken(udpid) {
        if (!this.accessToken) {
            throw new Error('Not logged in');
        }

        const data = await this.request(CLOUD_ENDPOINTS.getToken, {
            udpid: udpid
        });

        if (data.tokenlist && data.tokenlist.length > 0) {
            for (const token of data.tokenlist) {
                if (token.udpId === udpid) {
                    return {
                        token: token.token,
                        key: token.key,
                        udpId: token.udpId
                    };
                }
            }
        }
        return null;
    }
}

class NetHomeCloud {
    constructor(adapter = null) {
        this.sessionId = '';
        this.userId = null;
        this.loginId = null;
        this.deviceId = generateDeviceId();
        this.session = {};
        this.adapter = adapter;
        this.email = null;
    }

    log(level, message) {
        if (this.adapter && this.adapter.log) {
            this.adapter.log[level](message);
        }
    }

    async request(path, data, timeoutMs = 10000, includeSession = true) {
        return new Promise((resolve, reject) => {
            // Build body in same order as Python
            const body = {
                appId: NETHOME_CONFIG.APP_ID,
                src: NETHOME_CONFIG.APP_ID,
                format: 2,
                clientType: 1,
                language: 'en_US',
                deviceId: this.deviceId,
                stamp: timestamp(),
                reqId: generateReqId(),
            };
            
            // Add optional fields in specific order
            if (includeSession && this.sessionId) body.sessionId = this.sessionId;
            
            // Add data fields
            Object.keys(data).forEach(k => body[k] = data[k]);

            const sortedKeys = Object.keys(body).sort();
            
            // Python uses urlencode(sorted(data.items())) 
            // Then unquote_plus converts + to space and keeps %XX
            const queryParts = sortedKeys.map(k => [k, String(body[k])]);
            const queryEncoded = new URLSearchParams(queryParts).toString();
            
            // First convert %20 -> +, then decode %XX -> char
            const queryForSign = queryEncoded.replace(/%20/g, '+').replace(/%([0-9A-Fa-f]{2})/g, (m, h) => String.fromCharCode(parseInt(h, 16)));
            
            const msg = path + queryForSign + NETHOME_CONFIG.APP_KEY;
            this.log('info', 'Sign msg: ' + msg);
            const signValue = crypto.createHash('sha256').update(msg).digest('hex');
            this.log('info', 'Sign result: ' + signValue);
            body.sign = signValue;

            const options = {
                hostname: 'mapp.appsmb.com',
                port: 443,
                path: path,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': '*/*'
                },
                timeout: timeoutMs
            };

            const postData = new URLSearchParams(Object.keys(body).sort().map(k => [k, String(body[k])])).toString();
            this.log('info', 'Post data: ' + postData);

            const req = https.request(options, (res) => {
                let responseBody = '';
                res.on('data', chunk => responseBody += chunk);
                res.on('end', () => {
                    this.log('info', 'NetHome response: ' + responseBody);
                    try {
                        const json = JSON.parse(responseBody);
                        const code = parseInt(json.errorCode, 10);
                        if (code === 0) {
                            resolve(json.result);
                        } else {
                            reject(new Error(json.msg || `Error ${code}`));
                        }
                    } catch (e) {
                        reject(new Error('Invalid cloud response: ' + e.message));
                    }
                });
            });

            req.on('error', (e) => {
                reject(new Error('Network error: ' + e.message));
            });
            
            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });
            
            req.write(postData);
            req.end();
        });
    }

    async login(email, password) {
        if (!email || !password) {
            throw new Error('Email and password required');
        }
        
        this.adapter.log.info('NetHome: Getting loginId for ' + email.replace(/(.{2})(.*)(@.*)/, '$1***$3'));
        
        const loginIdData = await this.request(NETHOME_ENDPOINTS.loginId, {
            loginAccount: email
        }, 10000, false);

        this.adapter.log.info('NetHome: loginId response: ' + JSON.stringify(loginIdData));

        this.loginId = loginIdData.loginId;
        if (!this.loginId) {
            throw new Error('Failed to get loginId');
        }

        this.adapter.log.info('NetHome: Logging in with loginId: ' + this.loginId);
        
        const m1 = crypto.createHash('sha256').update(password).digest('hex');
        const loginHash = this.loginId + m1 + NETHOME_CONFIG.APP_KEY;
        const encryptedPassword = crypto.createHash('sha256').update(loginHash).digest('hex');

        this.adapter.log.info('NetHome: Password m1: ' + m1.substring(0, 20) + '...');
        this.adapter.log.info('NetHome: Login hash: ' + loginHash.substring(0, 50) + '...');
        this.adapter.log.info('NetHome: Password encrypted: ' + encryptedPassword);
        
        // Python sends the ORIGINAL EMAIL, not the loginId!
        const loginData = await this.request(NETHOME_ENDPOINTS.login, {
            loginAccount: email,
            password: encryptedPassword
        }, 10000, false);

        this.adapter.log.info('NetHome: login response: ' + JSON.stringify(loginData));

        this.session = loginData;
        this.sessionId = loginData.sessionId;
        this.userId = loginData.userId;

        if (!this.sessionId) {
            throw new Error('Failed to get sessionId');
        }

        return { userId: this.userId, loginId: this.loginId };
    }

    async getDeviceList() {
        if (!this.sessionId) {
            throw new Error('Not logged in');
        }

        const data = await this.request(NETHOME_ENDPOINTS.deviceList, {
            uid: this.userId
        });

        return data.list || [];
    }

    async getToken(deviceId, sn = null) {
        if (!this.sessionId) {
            throw new Error('Not logged in');
        }

        // Try multiple approaches to get token
        const approaches = [
            { udpid: deviceId },
            { udpid: deviceId.substring(deviceId.length - 32) },
            { udpId: deviceId },
            { applianceCode: deviceId }
        ];
        
        // Also try with SN if available
        if (sn) {
            approaches.push({ udpid: sn }, { udpId: sn }, { applianceCode: sn });
        }

        for (const params of approaches) {
            try {
                this.log('info', 'Trying getToken with params: ' + JSON.stringify(params));
                const data = await this.request(NETHOME_ENDPOINTS.getToken, params);
                
                if (data.tokenlist && data.tokenlist.length > 0) {
                    this.log('info', 'Got tokenlist with ' + data.tokenlist.length + ' items');
                    return {
                        token: data.tokenlist[0].token,
                        key: data.tokenlist[0].key,
                        udpId: data.tokenlist[0].udpId
                    };
                }
            } catch (e) {
                this.log('info', 'getToken attempt failed: ' + e.message);
            }
        }
        
        this.log('info', 'No token found with any approach');
        return null;
    }
}

class MideaAdapter {
    constructor() {
        this.devices = new Map();
        this.config = null;
        this.adapter = null;
        this.refreshTimer = null;
        this.tcpKey = null;
        this.requestCount = 0;
        this.cloud = null;
    }

    async loginToCloud(email, password) {
        const maskedEmail = email ? email.replace(/(.{2})(.*)(@.*)/, '$1***$3') : '***';
        this.adapter.log.info('Cloud login for: ' + maskedEmail);
        try {
            await this.cloud.login(email, password);
            this.adapter.log.info('Cloud login successful');
            return true;
        } catch (e) {
            this.adapter.log.error('Cloud login failed: ' + e.message);
            return false;
        }
    }

    async discoverCloudDevices() {
        this.adapter.log.info('Discovering devices from cloud...');
        try {
            const deviceList = await this.cloud.getDeviceList();
            this.adapter.log.info('Found ' + deviceList.length + ' devices in cloud');
            
            for (const dev of deviceList) {
                this.adapter.log.info('Cloud device: ' + JSON.stringify(dev));
            }
            
            return deviceList;
        } catch (e) {
            this.adapter.log.error('Cloud discovery failed: ' + e.message);
            return [];
        }
    }

    async getCloudToken(applianceCode) {
        try {
            const tokenData = await this.cloud.getToken(applianceCode);
            if (tokenData) {
                return {
                    token: tokenData.token,
                    key: tokenData.key,
                    udpId: tokenData.udpId
                };
            }
        } catch (e) {
            this.adapter.log.error('Get token failed: ' + e.message);
        }
        return null;
    }

    async start(adapter) {
        this.adapter = adapter;
        
        console.log('*** MIDEA START, PID:', process.pid, '***');
        
        try {
            const adapterObj = await adapter.getObjectAsync('system.adapter.midea-ac-lan.0');
            this.config = adapterObj.native || {};
            console.log('*** NATIVE CONFIG:', JSON.stringify(this.config).substring(0, 300), '***');
        } catch (e) {
            console.log('*** CONFIG FALLBACK:', e.message, '***');
            this.config = adapter.config || {};
        }
        
        this.cloud = new NetHomeCloud(adapter);
        
        if (this.config.cloudEmail && this.config.cloudPassword) {
            this.adapter.log.info('Logging in to Midea Cloud...');
            try {
                await this.cloud.login(this.config.cloudEmail, this.config.cloudPassword);
                this.adapter.log.info('Cloud login successful');
            } catch (e) {
                this.adapter.log.error('Cloud login failed: ' + e.message);
            }
        }
        
        this.loadDevicesFromConfig();
        await this.fetchTokensForDevices();
        this.startRefreshLoop();
        
        console.log('*** MIDEA READY, DEVICES:', this.devices.size, '***');
        adapter.log.info('Midea ready, ' + this.devices.size + ' devices');
    }

    loadDevicesFromConfig() {
        this.adapter.log.info('=== loadDevicesFromConfig START');
        
        let configDevices = this.config.devices;
        
        if (typeof configDevices === 'string') {
            configDevices = configDevices
                .split('\n')
                .map(line => line.trim())
                .filter(line => line.length > 0)
                .map(ip => ({ ipAddress: ip }));
        }
        
        if (!Array.isArray(configDevices)) {
            configDevices = [];
        }
        
        this.adapter.log.info('=== DEBUG: Found ' + configDevices.length + ' devices in config');
        
        let counter = 1;
        for (const dev of configDevices) {
            if (dev.ipAddress) {
                const id = dev.id || this.generateIdFromIp(dev.ipAddress, counter++);
                
                this.devices.set(id, {
                    id: id,
                    ipAddress: dev.ipAddress,
                    port: dev.port || DEFAULT_PORT,
                    token: dev.token || '',
                    key: dev.key || '',
                    udpId: dev.udpId || '',
                    protocol: dev.protocol || 3,
                    connected: false
                });
                
                this.createDeviceStates(id);
                this.adapter.log.info('Device ' + id + ': ' + dev.ipAddress);
            }
        }
    }

    async fetchTokensForDevices() {
        if (!this.cloud.sessionId) {
            this.adapter.log.warn('Not logged in to cloud, cannot fetch tokens');
            return;
        }
        
        try {
            const cloudDevices = await this.cloud.getDeviceList();
            this.adapter.log.info('Found ' + cloudDevices.length + ' devices in cloud');
            
            // Since cloud devices don't have IPs, try to match by ID or just use the first device
            for (const cloudDev of cloudDevices) {
                this.adapter.log.info('Cloud device: id=' + cloudDev.id + ' name=' + cloudDev.name);
                
                // Try to find a matching local device
                let matchedDevice = null;
                
                // Try to match by ID conversion
                const cloudIdNum = parseInt(cloudDev.id, 10);
                for (const [localId, device] of this.devices) {
                    // Check if IDs match or are close
                    if (localId === cloudIdNum || localId === cloudIdNum % 100000000000) {
                        matchedDevice = device;
                        break;
                    }
                }
                
                // If no ID match, use the first local device
                if (!matchedDevice && this.devices.size > 0) {
                    matchedDevice = this.devices.values().next().value;
                }
                
                if (matchedDevice) {
                    this.adapter.log.info('Fetching token for device: ' + matchedDevice.ipAddress);
                    const tokenData = await this.cloud.getToken(cloudDev.id, cloudDev.sn);
                    if (tokenData) {
                        this.adapter.log.info('=== TOKEN: ' + tokenData.token);
                        this.adapter.log.info('=== KEY: ' + tokenData.key);
                        matchedDevice.token = tokenData.token;
                        matchedDevice.key = tokenData.key;
                        matchedDevice.udpId = tokenData.udpId;
                        this.adapter.log.info('Got token for device at ' + matchedDevice.ipAddress);
                    }
                }
            }
        } catch (e) {
            this.adapter.log.error('Failed to fetch tokens: ' + e.message);
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
            
            // Try AES-256 first
            let plain = null;
            try {
                const decipher = crypto.createDecipheriv('aes-256-cbc', key, Buffer.alloc(16, 0));
                decipher.setAutoPadding(false);
                plain = Buffer.concat([decipher.update(payload), decipher.final()]);
                this.adapter.log.info('Tried aes-256-cbc with 32-byte key');
            } catch (e) {
                // Fallback: try with first 16 bytes of key
                this.adapter.log.info('aes-256-cbc failed, trying aes-128');
                const decipher2 = crypto.createDecipheriv('aes-128-cbc', key.slice(0, 16), Buffer.alloc(16, 0));
                decipher2.setAutoPadding(false);
                plain = Buffer.concat([decipher2.update(payload), decipher2.final()]);
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
            
            // Start requestCount from a higher number to match what HA might use
            this.requestCount = 0x0100;  // Start from 256 instead of 0
            
            this.adapter.log.info('V3 TCP key initialized, requestCount=' + this.requestCount);
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
        
        const result = Buffer.concat([header, sizeBuf, flagBuf, payload]);
        this.adapter.log.info('encode8370: msgType=' + msgType + ', size=' + size + ', counter=' + (msgType === 0x00 ? 0 : this.requestCount - 1) + ', result=' + result.toString('hex'));
        
        return result;
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
        // Use the same format as Python's MessageQueryAppliance
        // aa [length] ac [body...] [checksum]
        
        const body = Buffer.alloc(30);
        body[0] = 0xAA;  // Flag
        body[1] = 0x1D;  // Length (29 bytes = 0x1D)
        body[2] = 0xAC;  // Device type (AC)
        // Rest are zeros (body content)
        
        // Calculate checksum: ~(sum of all bytes) + 1
        let sum = 0;
        for (let i = 0; i < body.length; i++) {
            sum += body[i];
        }
        const checksum = (~sum + 1) & 0xFF;
        body[body.length - 1] = checksum;
        
        this.adapter.log.info('buildV3Query: body=' + body.toString('hex'));
        
        // Try msgType 0x06 first (what we used before)
        return this.encode8370(body, 0x06);
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