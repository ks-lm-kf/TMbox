# TMbox - Raspberry Pi Attack/Defense Console

## Project Overview

**TMbox** is a real-time web-based dashboard designed for monitoring system status and controlling security tools, specifically targeted for use on Raspberry Pi or Linux environments. It provides a user-friendly interface to execute system commands and visualize their output.

### Key Features
*   **Real-time System Monitoring**: Displays CPU load and memory usage (updated every 2 seconds).
*   **Vulnerability Scanning**: Integrated control for **Nuclei** scanner.
*   **Network Utilities**: Built-in **Ping** tool for network connectivity testing.
*   **Live Terminal Output**: detailed command output is streamed directly to the web interface via WebSockets.
*   **Process Control**: Ability to start and stop scanning processes dynamically.

### Technology Stack
*   **Runtime**: Node.js
*   **Backend Framework**: Express.js
*   **Real-time Communication**: Socket.IO
*   **Frontend**: HTML5, Vanilla JavaScript, Tailwind CSS (via CDN)
*   **System Dependencies**: `nuclei`, `expect` (for `unbuffer`)

## Building and Running

### Prerequisites
Ensure the following system tools are installed and available in your `$PATH`:
*   **Node.js** (v14+ recommended)
*   **Nuclei**: [Project Discovery Nuclei](https://github.com/projectdiscovery/nuclei)
*   **Unbuffer**: Part of the `expect` package (e.g., `sudo apt install expect` on Debian/Ubuntu).

### Installation
1.  Install Node.js dependencies:
    ```bash
    npm install
    ```

### Starting the Application
1.  Start the server:
    ```bash
    node server.js
    ```
2.  Access the dashboard in your browser:
    *   **Local**: `http://localhost:3000`
    *   **Network**: `http://<device-ip>:3000`

## Development Conventions

### Project Structure
*   `server.js`: The main entry point. Handles Express setup, Socket.IO events (`start-nuclei`, `start-ping`, `stop-scan`), and system process management using `child_process.spawn`.
*   `public/`: Contains static frontend assets.
    *   `index.html`: The single-page application interface. Includes embedded JavaScript for Socket.IO client logic and Tailwind CSS styling.

### Code Style
*   **Backend**: CommonJS modules. Uses `spawn` for executing shell commands to allow for real-time output streaming.
*   **Frontend**: Direct DOM manipulation and inline scripts. Tailwind CSS is used for styling.
*   **Communication**: Event-based communication using Socket.IO (`sys-update`, `log`, `scan-status`).

### Key Considerations
*   **Process Management**: The server maintains a `currentScanProcess` variable to track running tasks, allowing only one major scan/ping task to run at a time to prevent resource exhaustion on low-power devices like Raspberry Pis.
*   **Output Buffering**: The project explicitly uses `unbuffer` to force standard output to be unbuffered, ensuring real-time log updates on the frontend.
