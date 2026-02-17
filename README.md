# ⛏️ Rukka BTC Miner CPU v1.0

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/ebookcms/btc_miner)
[![Python](https://img.shields.io/badge/python-3.8%2B-green.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Bitcoin](https://img.shields.io/badge/Bitcoin-Solo%20Mining-orange.svg)](https://bitcoin.org/)

**High-performance CPU Bitcoin Solo Miner with C acceleration, statistics tracking, and enterprise features.**

⚠️ **Solo Mining**: This software mines directly to Bitcoin Core. Block rewards go directly to your wallet (minus optional dev fee). No pools, no intermediaries.



## ✨ Features

### Core Mining
- 🚀 **C Acceleration** - Uses compiled SHA256 library (10-20x faster than pure Python)
- 🧠 **Smart Transaction Selection** - Automatically selects optimal transactions from mempool
- ⛏️ **True Solo Mining** - Direct connection to Bitcoin Core via RPC
- 🔄 **Auto-restart** - Handles network issues and reconnects automatically

### v2.0 New Features
- 📊 **Real-time Statistics** - JSON stats export, hashrate history, block estimation
- 🐕 **Watchdog Monitor** - Auto-detects stalls and restarts workers
- 📈 **Benchmark Mode** - Test your hashrate without connecting to RPC
- 🔔 **Webhook Notifications** - Discord/Slack alerts when blocks are found
- 🎚️ **CPU Affinity** - Pin workers to specific cores for better performance
- 💝 **Optional Donations** - Built-in dev fee system (0-5%, completely optional)
- 🧪 **Test Mode** - Validate configuration before mining

### Safety & Reliability
- 💾 **Auto-save** - Statistics and found blocks are saved immediately
- 🛡️ **Input Validation** - Validates addresses, RPC connection, and configuration
- 📱 **Remote Monitoring** - Webhook integration for mobile notifications
- 📝 **Detailed Logging** - Full logging with rotation and debug modes

## 🚀 Quick Start

### Requirements
- **Bitcoin Core** (fully synchronized) - [Download here](https://bitcoincore.org/en/download/)
- **Python** 3.8 or higher - [Download here](https://www.python.org/)

### Installation

```bash
# Clone repository
git clone https://github.com/ebookcms/btc_minerV2.git
cd btc_minerV2

# Install Python dependencies
pip install requests python-bitcoinrpc colorama psutil

# (Optional) Compiled C acceleration for 10-20x speedup
# Linux/Mac:
sha256.so
# Windows:
sha256.dll
```

##Configuration

##Create data.cfg in the miner directory:
```ini
[CONFIG]
rpcPort = 8332
rpcUser = your_rpc_username
rpcPassword = your_rpc_password
rpcIp = 127.0.0.1
btcaddr = YOUR_BTC_ADDRESS_HERE
poolname = RukkaMiner
```

## 🎮 Usage

## Basic Mining

```bash
# Start with interactive worker selection
python miner2.py

# Start with 8 workers immediately
python miner2.py --workers 8

# Quiet mode (minimal output)
python miner2.py --workers 8 --quiet
```

## Testing & Benchmarking

```bash
# Validate your setup without mining
python miner2.py --test-mode

# Benchmark your CPU (no RPC required)
python miner2.py --benchmark --duration 300

# Test with verbose debugging
python miner2.py --test-mode --verbose
```


## Advanced Usage

```bash
# With Discord notifications
python miner2.py --workers 12 --webhook "https://discord.com/api/webhooks/..."

# With CPU affinity (pin workers to cores)
python miner2.py --workers 8 --cpu-affinity

# With 1% dev fee donation
python miner2.py --workers 8 --donation 1.0

# Custom config and stats file
python miner2.py --config pool.cfg --stats-file my_stats.json
```

## 📊 Statistics & Monitoring

The miner automatically saves statistics to mining_stats.json:

```JSON
{
  "version": "2.0.0",
  "uptime_seconds": 3600,
  "total_hashes": 15000000000,
  "current_hashrate_mhs": 45.2,
  "average_hashrate_mhs": 44.8,
  "blocks_found": 0,
  "best_share_difficulty": 125000,
  "history": [
    {"timestamp": "2024-01-15T10:00:00", "hashrate": 44.8}
  ]
}
```

## Webhook Notifications

Set up Discord/Slack notifications for block finds:

```bash
python miner2.py --webhook "YOUR_WEBHOOK_URL"
```

## 🏗️ Architecture

```plain
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Bitcoin Core   │◄────│  Rukka Miner v2  │────►│  C SHA256 Lib   │
│   (RPC/JSON)    │     │  - Process Pool  │     │  (Optional)     │
└─────────────────┘     │  - Watchdog      │     └─────────────────┘
                        │  - Stats         │
                        └──────────────────┘
                                 │
                        ┌──────────────────┐
                        │  Stats JSON File │
                        │  Webhook Alerts  │
                        └──────────────────┘
```

## ⚙️ Command Line Options


```table

| Option            | Description                  | Default             |
| ----------------- | ---------------------------- | ------------------- |
| `-w, --workers`   | Number of CPU workers        | Auto-detect         |
| `-c, --config`    | Configuration file           | `data.cfg`          |
| `-b, --benchmark` | Run benchmark mode           | False               |
| `-d, --duration`  | Benchmark duration (seconds) | 300                 |
| `--stats-file`    | JSON statistics file         | `mining_stats.json` |
| `--webhook`       | Notification webhook URL     | None                |
| `--cpu-affinity`  | Pin workers to CPU cores     | False               |
| `--donation`      | Dev fee percentage (0-5)     | 0.0                 |
| `-t, --test-mode` | Test configuration and exit  | False               |
| `-q, --quiet`     | Minimal console output       | False               |
| `-v, --verbose`   | Debug logging                | False               |
```


## 🔧 Troubleshooting

### "Connection failed"
- Ensure Bitcoin Core is running and synchronized
- Check RPC credentials in bitcoin.conf and data.cfg
- Verify firewall isn't blocking port 8332


### "C library not found"

The miner works without it, but slower. To compile:

- sha256.dll (windows)
- sha256.so (linux)

### Low hashrate
- Use --cpu-affinity to prevent context switching
- Close other CPU-intensive applications
- Ensure C library is compiled and detected


### Watchdog restarts

If the watchdog triggers frequently:

- Check Bitcoin Core responsiveness
- Increase timeout in source code (WATCHDOG_TIMEOUT)
- Monitor system memory usage


## 📈 Performance Tips

1 - Compiled C Library: 10-20x performance improvement
2 - CPU Affinity: Use --cpu-affinity on multi-core systems
3 - Disable HT: Physical cores perform better than hyperthreads for mining
4 - Nice Priority: Run with nice -n -20 on Linux for priority scheduling


## 🆕 Changelog v2.0

### Added

- ✅ Complete CLI with argparse
- ✅ JSON statistics tracking and history
- ✅ Benchmark mode (test without RPC)
- ✅ Watchdog monitoring system
- ✅ Webhook notifications (Discord/Slack)
- ✅ CPU affinity control
- ✅ Optional donation system
- ✅ Test mode for configuration validation
- ✅ Comprehensive logging system
- ✅ RPC retry logic with exponential backoff


### Changed

- 🔧 Reorganized code structure (OOP-style stats)
- 🔧 Improved error handling and recovery
- 🔧 Better Windows/Linux cross-platform support
- 🔧 Enhanced block submission reliability


### Fixed

🐛 Fixed worker restart issues
🐛 Improved template refresh handling
🐛 Better memory management for long runs


## 🤝 Contributing

Contributions welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

Development Fund: If you find this software useful, consider enabling the donation feature:

```bash
python miner2.py --donation 1.0  # 1% dev fee
```

## ☕ Donations

### Support continued development:

```bash
Bitcoin (Legacy): 13Jjf6kkM5yrDPRH8iVngCLiq6ahEDTLgy
Bitcoin (Bech32): bc1q54p0qum0c2zf00shkszf6v9xvsdg6aaj0cjvx2
Lightning Network: meltedbelgian77@walletofsatoshi.com
```

Your support helps maintain and improve this project!


## ⚠️ Disclaimer

- This software is provided "as is" without warranty
- Solo mining has extremely high variance. You may not find a block for years.
- Ensure you understand Bitcoin mining before using this software
- Always test with --test-mode before starting production mining
- The authors are not responsible for lost funds or system damage

## ⚠️ Executable

If you don't want to install python: [Executable](executable.rar)
After you need to extract file.

## 📜 License

MIT License - See [LICENSE](LICENSE.txt) file for details.


## Happy Mining! ⛏️🚀


