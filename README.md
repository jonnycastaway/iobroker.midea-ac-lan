# iobroker.midea-ac-lan

Midea AC Local Network Controller - Control Midea air conditioners without cloud dependency.

## Features

- Local network control of Midea air conditioners
- No cloud dependency required (but cloud auth optional)
- Full status monitoring: power, mode, temperature, fan speed, swing
- Full control: set power, mode, temperature, fan speed, swing
- Auto token/key retrieval from cloud if needed
- Polling-based status updates
- State change handlers for real-time control

## Installation

1. Install via ioBroker admin
2. Configure the adapter:
   - Enter AC IP address
   - Enter Device ID
   - Either provide Token and Key from config file, OR enable cloud authentication

## Configuration

### Required
- **AC IP Address**: The local IP of your Midea AC
- **Device ID**: Your AC's device ID

### Optional
- **Token/Key**: From previous config file (if not provided, cloud auth will be used)
- **Cloud Authentication**: Enable and provide cloud credentials to auto-fetch token/key
- **Poll Interval**: How often to poll AC status (default: 60 seconds)

## States

| State | Type | Description |
|-------|------|-------------|
| ac.power | boolean | Power on/off |
| ac.mode | number | Mode: 0=Auto, 1=Cool, 2=Dry, 3=Fan, 4=Heat |
| ac.target_temperature | number | Target temperature (°C) |
| ac.fan_speed | number | Fan speed (0=Auto, 10-102=manual) |
| ac.swing_vertical | boolean | Vertical swing on/off |
| ac.swing_horizontal | boolean | Horizontal swing on/off |
| ac.indoor_temperature | number | Current indoor temperature (°C) |

## Usage

### Via ioBroker States
Simply write to the state to control the AC:
```javascript
setState('midea-ac-lan.0.ac.power', true);
setState('midea-ac-lan.0.ac.target_temperature', 24);
setState('midea-ac-lan.0.ac.swing_vertical', true);
```

### Via Scripts
```javascript
// Turn on AC with 24°C
setState('midea-ac-lan.0.ac.power', true);
setState('midea-ac-lan.0.ac.target_temperature', 24);

// Turn off
setState('midea-ac-lan.0.ac.power', false);
```

## How it Works

The adapter communicates with Midea AC via TCP port 6444 using a custom protocol:

1. **Authentication**: Uses token/key (from cloud or config) to establish secure connection
2. **Packet Building**: Creates 5A5A packets with AC commands, encrypted with DEFAULT_KEY
3. **8370 Framing**: Wraps packets in 8370 protocol with TCP key encryption
4. **Status Polling**: Regularly polls AC for current state

## Troubleshooting

### Connection Failed
- Check if AC IP is correct and AC is reachable
- Check if port 6444 is not blocked by firewall

### Authentication Failed
- If using cloud auth, check username/password
- If using manual token/key, verify they are correct

### States Not Updating
- Check poll interval
- Check AC is responding to queries

## License

MIT