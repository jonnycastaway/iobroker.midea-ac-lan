'use strict';

const adapterCore = require('@iobroker/adapter-core');
const { MideaAdapter } = require(__dirname + '/lib/tools');

const adapter = adapterCore.Adapter('midea-ac-lan');

const mideaAdapter = new MideaAdapter();

adapter.on('ready', async function() {
    adapter.log.info('Midea AC LAN adapter starting');
    adapter.connected = true;
    
    await mideaAdapter.start(adapter);
    
    adapter.subscribeStates('*');
    
    adapter.log.info('Adapter ready, waiting for operations');
});

adapter.on('stateChange', function(id, state) {
    if (state && !state.ack) {
        const parts = id.split('.');
        let deviceId, stateName;
        
        if (parts[0] === 'midea-ac-lan' && parts.length >= 3) {
            deviceId = parts[1];
            stateName = parts[2];
        } else if (parts.length >= 2) {
            deviceId = parts[0];
            stateName = parts[1];
        }
        
        if (deviceId && stateName) {
            mideaAdapter.setDeviceState(deviceId, stateName, state.val);
        }
    }
});

adapter.on('unload', async function(callback) {
    adapter.log.info('Midea AC LAN unloading');
    await mideaAdapter.stop();
    callback();
});

adapter.on('message', function(obj) {
    if (obj && obj.command) {
        adapter.log.info('Received message: ' + obj.command);
        if (obj.callback) {
            adapter.sendTo(obj.from, obj.command, {}, obj.callback);
        }
    }
});