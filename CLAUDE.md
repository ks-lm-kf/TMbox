# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TMbox is a real-time web-based dashboard for monitoring system status and controlling security tools on Raspberry Pi/Linux environments. It provides a unified interface for running vulnerability scanners, network tools, and the Metasploit Framework with live output streaming via WebSockets.

## Running the Application

```bash
# Install dependencies
npm install

# Start the server
node server.js

# Access at http://localhost:3000 or http://<device-ip>:3000
```

**Note:** `package.json` specifies `main: "index.js"` but the actual entry point is `server.js`.

**No tests are configured** - the `npm test` command exits with an error.

## Routes

| Route | Page | Purpose |
|-------|------|---------|
| `/` | `index.html` | Main dashboard with all scan tools |
| `/msf` | `msf.html` | Dedicated Metasploit console |
| `/topology` | `topology.html` | Network topology visualization |

## Architecture

### Server-Side (`server.js`)

The application uses a multi-task process management pattern centered around:

- **`activeScans` dictionary**: Tracks concurrent scan processes by type (`system`, `nuclei`, `nmap`, `fscan`, `sqlmap`). Each tool type allows only one running process at a time.

- **`currentMsfProcess`**: Persistent Metasploit Framework console process that remains alive across sessions (unlike scans which terminate on completion).

- **Real-time monitoring**: System stats (CPU loadavg, memory) broadcast via `sys-update` event every 2 seconds.

### Process Execution Pattern

All external tools use `child_process.spawn` wrapped with `unbuffer` to force unbuffered stdout/stderr for real-time streaming to the web interface. The argument parsing pattern (`/[^\s"]+|"([^"]*)"/gi`) supports quoted arguments with spaces.

### Socket.IO Event Flow

| Direction | Event | Payload | Purpose |
|-----------|-------|---------|---------|
| Server → Client | `sys-update` | `{load, mem}` | System stats (2s interval) |
| Server → Client | `log` | `{source, data}` | Scan terminal output |
| Server → Client | `scan-status` | `{type, status}` | Tool running/stopped state |
| Client → Server | `term-input` | `{type, input}` or string | Send command to running process |
| Server → Client | `msf-output` | string | MSF console output |
| Client → Server | `start-msf` | none | Launch persistent MSF console |
| Client → Server | `msf-input` | string | Command to MSF stdin |
| Server → Client | `topology-node` | `{id, label, group, ip, ...}` | Network topology node data |
| Client → Server | `topology-scan` | `{subnet}` | Trigger network discovery scan |
| Client → Server | `node-action` | `{ip, action}` | Run action on topology node (portscan, alive, etc.) |

### Frontend Structure

All frontend code is embedded directly in HTML files within `public/`:
- `index.html`: Main dashboard with all scan tools and system monitoring
- `msf.html`: Dedicated Metasploit Framework console with module selection and job management
- `topology.html`: Network topology visualization with vis.js/D3.js, auto-discovers local /24 subnet

## Tool-Specific Notes

### Nuclei
- Executable path: `/usr/local/bin/nuclei`
- Auto-forces `-no-color` for terminal compatibility
- Auto-adds `-stats` if not user-specified
- Target passed via `-u` flag

### Nmap
- Executable path: `/usr/bin/nmap`
- Target appended as final argument
- Auto-adds `-v` if verbosity not specified

### Fscan
- Executable path: `/usr/local/bin/fscan`
- Target mapped to `-h` flag
- Auto-adds `-no` (no output files) unless user specifies `-o`

### Sqlmap
- Executable path: `/usr/bin/sqlmap`
- Target mapped to `-u` flag
- Always forces `--batch` mode for non-interactive execution

### Ping
- Uses system ping with `-c 10` (auto-terminates after 10 packets)
- Managed under `activeScans['system']`

### Metasploit Framework
- Persistent process: Unlike scan tools, MSF console stays alive across commands
- Job management: `msf.html` tracks running jobs via `jobs` command output
- Pre-configured modules: MS17-010, BlueKeep, NetAPI, SMB scanners, reverse handlers

## System Dependencies

Required tools must be installed and in `$PATH`:
- `nuclei` - Vulnerability scanner
- `nmap` - Network scanner
- `fscan` - Port scanner
- `sqlmap` - SQL injection tool
- `msfconsole` - Metasploit Framework
- `unbuffer` (from `expect` package) - Critical for real-time output streaming

Install unbuffer: `sudo apt install expect` (Debian/Ubuntu)
