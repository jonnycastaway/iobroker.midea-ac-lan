'use strict';

const { device_selector } = require('midealocal.devices');
const { ProtocolVersion } = require('midealocal.devices');

const DEFAULT_PORT = 6444;

class MideaAdapter {
    constructor() {
        this.devices = new Map();
        this.config = null;
        this.adapter = null;
        this.mideaDevices = new Map();
    }

    async start(adapter) {
        this.adapter = adapter;
        
        adapter.log.info('Midea adapter starting with midealocal library...');
        
        try {
            const adapterObj = await adapter.getObjectAsync('system.adapter.midea-ac-lan.0');
            this.config = adapterObj.native || {};
        } catch (e) {
            this.config = adapter.config || {};
        }
        
        this.loadDevicesFromConfig();
        this.startDeviceLoops();
        
        adapter.log.info('Midea ready, ' + this.devices.size + ' devices');
    }

    loadDevicesFromConfig() {
        let configDevices = this.config.devices;
        
        if (typeof configDevices === 'string') {
            configDevices = configDevices.trim();
            if (configDevices.startsWith('[')) {
                try {
                    configDevices = JSON.parse(configDevices);
                } catch (e) {
                    configDevices = [];
                }
            } else if (configDevices.length > 0) {
                configDevices = configDevices
                    .split('\n')
                    .map(line => line.trim())
                    .filter(line => line.length > 0)
                    .map(line => {
                        const parts = line.split(/[,\t]+/);
                        return {
                            id: parts[0] || '',
                            ipAddress: parts[1] || '',
                            port: parts[2] || DEFAULT_PORT,
                            token: parts[3] || '',
                            key: parts[4] || '',
                            model: parts[5] || '',
                            subtype: parseInt(parts[6]) || 0
                        };
                    });
            } else {
                configDevices = [];
            }
        }
        
        if (!Array.isArray(configDevices)) {
            configDevices = [];
        }
        
        for (const dev of configDevices) {
            if (dev.id && dev.ipAddress) {
                this.devices.set(dev.id, {
                    id: dev.id,
                    ipAddress: dev.ipAddress,
                    port: dev.port || DEFAULT_PORT,
                    token: dev.token || '',
                    key: dev.key || '',
                    model: dev.model || '',
                    subtype: dev.subtype || 0,
                    protocol: dev.protocol || 3,
                    connected: false
                });
                
                this.createDeviceStates(dev.id);
                this.adapter.log.info('Device ' + dev.id + ' at ' + dev.ipAddress + ' model=' + (dev.model || 'auto'));
            }
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
                this.adapter.setObjectNotExistsAsync(deviceId + '.' + s.id, {
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

    startDeviceLoops() {
        const interval = (this.config.refreshInterval || 30) * 1000;
        
        this.adapter.log.info('Starting device loops, interval: ' + interval + 'ms');
        
        for (const [deviceId, device] of this.devices) {
            if (device.token && device.key && device.ipAddress) {
                this.startDevice(deviceId, device);
            }
        }
    }

    startDevice(deviceId, device) {
        this.adapter.log.info('Starting device ' + deviceId + ' at ' + device.ipAddress);
        
        try {
            const mideaDevice = device_selector(
                'AC_' + deviceId,
                parseInt(deviceId),
                0xAC,
                device.ipAddress,
                device.port,
                device.token,
                device.key,
                ProtocolVersion.V3,
                device.model || '',
                device.subtype || 0,
                ''
            );
            
            this.mideaDevices.set(deviceId, mideaDevice);
            
            mideaDevice.open();
            
            this.adapter.log.info('Device ' + deviceId + ' opened, waiting for status...');
            
            setTimeout(() => {
                this.updateFromMideaDevice(deviceId, mideaDevice);
            }, 3000);
            
        } catch (e) {
            this.adapter.log.error('Error starting device ' + deviceId + ': ' + e.message);
        }
    }

    updateFromMideaDevice(deviceId, mideaDevice) {
        try {
            const connected = mideaDevice.available || false;
            
            const status = {
                power: mideaDevice.get_attribute('power') || false,
                mode: mideaDevice.get_attribute('mode') || 0,
                targetTemp: mideaDevice.get_attribute('target_temperature') || 20,
                fanSpeed: mideaDevice.get_attribute('fan_speed') || 0,
                indoorTemp: mideaDevice.get_attribute('indoor_temperature') || 0,
                connected: connected
            };
            
            this.adapter.log.info('Device ' + deviceId + ' status: ' + JSON.stringify(status));
            
            this.updateStates(deviceId, status);
            
        } catch (e) {
            this.adapter.log.warn('Error updating device ' + deviceId + ': ' + e.message);
        }
    }

    async updateStates(deviceId, status) {
        try {
            await this.adapter.setStateAsync(deviceId + '.power', status.power || false, true);
            await this.adapter.setStateAsync(deviceId + '.mode', status.mode || 0, true);
            await this.adapter.setStateAsync(deviceId + '.targetTemperature', status.targetTemp || 0, true);
            await this.adapter.setStateAsync(deviceId + '.fanSpeed', status.fanSpeed || 0, true);
            await this.adapter.setStateAsync(deviceId + '.indoorTemperature', status.indoorTemp || 0, true);
            await this.adapter.setStateAsync(deviceId + '.connected', status.connected || false, true);
        } catch (e) {}
    }

    async setDeviceState(deviceId, state, value) {
        const mideaDevice = this.mideaDevices.get(deviceId.toString());
        if (!mideaDevice) {
            this.adapter.log.warn('Device ' + deviceId + ' not found');
            return false;
        }
        
        this.adapter.log.info('Set ' + deviceId + ' ' + state + ' = ' + value);
        
        try {
            if (state === 'power') {
                mideaDevice.set_attribute('power_on', value);
            } else if (state === 'targetTemperature') {
                mideaDevice.set_attribute('target_temperature', value);
            } else if (state === 'mode') {
                mideaDevice.set_attribute('mode', value);
            } else if (state === 'fanSpeed') {
                mideaDevice.set_attribute('fan_speed', value);
            }
            mideaDevice.apply();
            return true;
        } catch (e) {
            this.adapter.log.error('Error setting state: ' + e.message);
            return false;
        }
    }

    async stop() {
        for (const [deviceId, mideaDevice] of this.mideaDevices) {
            try {
                mideaDevice.close();
            } catch (e) {}
        }
        this.mideaDevices.clear();
    }
}

module.exports = { MideaAdapter };