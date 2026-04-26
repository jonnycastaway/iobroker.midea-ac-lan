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
            
            console.log(`[${deviceId}] Decrypted: ${plain.toString('hex')}`);
            
            // Try to detect padding - PKCS7
            const padLen = plain[plain.length - 1];
            if (padLen > 0 && padLen <= 16 && padLen <= plain.length) {
                plain = plain.slice(0, plain.length - padLen);
            }
            
            console.log(`[${deviceId}] Unpadded: ${plain.toString('hex')}`);
            
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
            console.log(`[${deviceId}] TCP Key: ${tcpKey.toString('hex')}`);
            return this.tcpKey;
        } catch(e) {
            console.error(`[${deviceId}] AES error: ${e.message}`);
            return null;
        }
    }
    
    encode8370(data, msgType) {
        const header = Buffer.from([0x83, 0x70]);
        const length = Buffer.alloc(2);
        length.writeUInt16BE(data.length + 8);
        const mt = Buffer.from([msgType]);
        const zero1 = Buffer.from([0x00, 0x00]);
        const packetId = Buffer.alloc(2);
        packetId.writeUInt16BE(this._requestCount++ & 0xFFFF);
        return Buffer.concat([header, length, mt, zero1, packetId, data]);
    }
    
    encrypt(data) {
        const padLen = 16 - (data.length % 16);
        const padded = Buffer.concat([data, Buffer.alloc(padLen, padLen)]);
        const iv = Buffer.alloc(16, 0);
        const cipher = crypto.createCipheriv('aes-128-cbc', this.tcpKey.slice(0, 16), iv);
        return Buffer.concat([cipher.update(padded), cipher.final()]);
    }
    
    decrypt(data) {
        const iv = Buffer.alloc(16, 0);
        const decipher = crypto.createDecipheriv('aes-128-cbc', this.tcpKey.slice(0, 16), iv);
        let plain = Buffer.concat([decipher.update(data), decipher.final()]);
        const padLen = plain[plain.length - 1];
        if (padLen > 0 && padLen <= 16 && padLen <= plain.length) {
            plain = plain.slice(0, plain.length - padLen);
        }
        return plain;
    }
    
    encodeQuery(subType, fields) {
        const body = Buffer.alloc(35);
        body[0] = 0xAA;
        body[1] = 0x20;
        body.writeUInt16BE(subType, 2);
        return this.encrypt(body);
    }
    
    sendCommand(command) {
        return this.encrypt(command);
    }
}

class MideaAC {
    constructor(deviceId, ip, port, token, key, log) {
        this.deviceId = deviceId;
        this.ip = ip;
        this.port = port || DEFAULT_PORT;
        this.token = token;
        this.key = key;
        this.log = log;
        this.protocol = new MideaProtocol(token, key);
        this.socket = null;
        this.connected = false;
        this.receiveBuffer = Buffer.alloc(0);
    }
    
    connect() {
        this.log.info(`[${this.deviceId}] Connecting to ${this.ip}:${this.port}`);
        
        this.socket = net.createConnection(this.port, this.ip);
        
        this.socket.on('connect', () => {
            this.log.info(`[${this.deviceId}] TCP connected`);
            this.sendHandshake();
        });
        
        this.socket.on('data', (data) => this.handleData(data));
        
        this.socket.on('error', (err) => {
            this.log.error(`[${this.deviceId}] Socket error: ${err.message}`);
            this.connected = false;
        });
        
        this.socket.on('close', () => {
            this.log.warn(`[${this.deviceId}] Connection closed`);
            this.connected = false;
        });
    }
    
    sendHandshake() {
        const data = Buffer.concat([this.protocol.token]);
        const packet = this.encode8370(data, MSGTYPE_HANDSHAKE_REQUEST);
        this.log.info(`[${this.deviceId}] Handshake: ${packet.toString('hex').slice(0,80)}...`);
        this.socket.write(packet);
    }
    
    encode8370(data, msgType) {
        const header = Buffer.from([0x83, 0x70]);
        const length = Buffer.alloc(2);
        length.writeUInt16BE(data.length + 8);
        const mt = Buffer.from([msgType]);
        const zero1 = Buffer.from([0x00, 0x00]);
        const packetId = Buffer.alloc(2);
        packetId.writeUInt16BE(this.protocol._requestCount++ & 0xFFFF);
        return Buffer.concat([header, length, mt, zero1, packetId, data]);
    }
    
    handleData(data) {
        this.log.info(`[${this.deviceId}] Received ${data.length} bytes`);
        this.receiveBuffer = Buffer.concat([this.receiveBuffer, data]);
        this.processBuffer();
    }
    
    processBuffer() {
        while (this.receiveBuffer.length >= 8) {
            const header = this.receiveBuffer.slice(0, 2);
            if (header[0] !== 0x83 || header[1] !== 0x70) {
                this.log.error(`[${this.deviceId}] Invalid header`);
                this.receiveBuffer = Buffer.alloc(0);
                return;
            }
            
            const size = this.receiveBuffer.readUInt16BE(2);
            const packet = this.receiveBuffer.slice(0, size);
            
            if (this.receiveBuffer.length < size) {
                return;
            }
            
            this.receiveBuffer = this.receiveBuffer.slice(size);
            
            // Byte 4 = 0x20 means handshake response
            if (packet[4] === 0x20 && packet.length >= 72 && !this.connected) {
                this.log.info(`[${this.deviceId}] Handshake response!`);
                const responseData = packet.slice(8, 72);
                this.protocol.calculateTcpKey(responseData, this.deviceId);
                this.connected = true;
                this.log.info(`[${this.deviceId}] Authentication success!`);
                setTimeout(() => this.startReceiving(), 3000);
                return;
            }
            
            if ((packet[4] & 0x0F) === MSGTYPE_ENCRYPTED_RESPONSE && this.protocol.tcpKey && size <= packet.length) {
                this.log.info(`[${this.deviceId}] Encrypted response`);
                const encrypted = packet.slice(8, size);
                const decrypted = this.protocol.decrypt(encrypted);
                this.log.info(`[${this.deviceId}] Decrypted: ${decrypted.toString('hex')}`);
            }
        }
    }
    
    startReceiving() {
        this.log.info(`[${this.deviceId}] Querying status...`);
        const query = this.protocol.encodeQuery(0x0201, []);
        const packet = this.encode8370(query, MSGTYPE_ENCRYPTED_REQUEST);
        this.log.info(`[${this.deviceId}] Query: ${packet.toString('hex')}`);
        this.socket.write(packet);
    }
}

module.exports = { MideaAC, MideaProtocol };