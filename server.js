/* server.js - TMbox 安全控制台 - HTTPS 版本 */
const express = require('express');
const http = require('http');
const https = require('https');
const { Server } = require("socket.io");
const { spawn } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');

// ==================== TLS 证书配置 ====================
const CERTS_DIR = path.join(__dirname, 'certs');
const HTTPS_PORT = 3443;
const HTTP_PORT = 3000;

// 检查证书文件是否存在
const keyPath = path.join(CERTS_DIR, 'tmbox-key.pem');
const certPath = path.join(CERTS_DIR, 'tmbox-cert.pem');

let sslOptions = null;
let useHTTPS = false;

if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    try {
        sslOptions = {
            key: fs.readFileSync(keyPath),
            cert: fs.readFileSync(certPath)
        };
        useHTTPS = true;
        console.log('[✓] TLS 证书加载成功');
    } catch (err) {
        console.error('[!] TLS 证书加载失败:', err.message);
    }
} else {
    console.log('[!] 未找到 TLS 证书，仅使用 HTTP 模式');
    console.log('    提示: 运行 node generate-certs.js 生成证书');
}

// ==================== Express 应用 ====================
const app = express();

// 安全头部
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
});

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// ==================== 路由配置 ====================

// 首页
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/index.html'));
});

// MSF 控制台
app.get('/msf', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/msf.html'));
});

// 网络拓扑图
app.get('/topology', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/topology.html'));
});

// 系统实时监控
app.get('/monitor', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/monitor.html'));
});

// Webshell 管理
app.get('/webshell', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/webshell.html'));
});

// ==================== API 路由 ====================

// Payload 文件管理
const PAYLOAD_DIR = '/tmp';

// 获取 payload 文件列表
app.get('/api/payloads', (req, res) => {
    try {
        const files = fs.readdirSync(PAYLOAD_DIR);
        const payloadFiles = files
            .filter(f => {
                const ext = path.extname(f).toLowerCase();
                return ['.exe', '.elf', '.php', '.jsp', '.asp', '.aspx', '.war', '.jar', '.py', '.pl', '.sh', '.raw', '.bin'].includes(ext) ||
                       f.startsWith('payload') || f.startsWith('shell') || f.startsWith('msf');
            })
            .map(f => {
                const filePath = path.join(PAYLOAD_DIR, f);
                const stats = fs.statSync(filePath);
                return {
                    name: f,
                    size: formatBytes(stats.size),
                    sizeBytes: stats.size,
                    created: stats.birthtime,
                    modified: stats.mtime
                };
            })
            .sort((a, b) => b.modified - a.modified);

        res.json({ success: true, files: payloadFiles });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// 下载 payload 文件
app.get('/api/payloads/download/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(PAYLOAD_DIR, filename);

    const normalizedPath = path.normalize(filePath);
    if (!normalizedPath.startsWith(PAYLOAD_DIR)) {
        return res.status(403).json({ error: 'Access denied' });
    }

    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'File not found' });
    }

    const stats = fs.statSync(filePath);
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length', stats.size);

    const ext = path.extname(filename).toLowerCase();
    const contentTypes = {
        '.exe': 'application/octet-stream',
        '.elf': 'application/x-elf',
        '.php': 'application/x-php',
        '.jsp': 'application/x-jsp',
        '.asp': 'application/x-asp',
        '.aspx': 'application/x-aspx',
        '.war': 'application/java-archive',
        '.jar': 'application/java-archive',
        '.py': 'text/x-python',
        '.pl': 'text/x-perl',
        '.sh': 'text/x-sh',
        '.raw': 'application/octet-stream',
        '.bin': 'application/octet-stream'
    };
    res.setHeader('Content-Type', contentTypes[ext] || 'application/octet-stream');

    const fileStream = fs.createReadStream(filePath);
    fileStream.pipe(res);

    fileStream.on('error', (err) => {
        console.error('Download error:', err);
        res.status(500).json({ error: 'Download failed' });
    });
});

// 删除 payload 文件
app.delete('/api/payloads/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(PAYLOAD_DIR, filename);

    const normalizedPath = path.normalize(filePath);
    if (!normalizedPath.startsWith(PAYLOAD_DIR)) {
        return res.status(403).json({ error: 'Access denied' });
    }

    try {
        fs.unlinkSync(filePath);
        res.json({ success: true });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// 格式化字节大小
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ==================== Webshell 代理 API ====================
const querystring = require('querystring');

// Webshell 代理请求
app.post('/api/webshell/proxy', express.urlencoded({ extended: true, limit: '10mb' }), async (req, res) => {
    let { url, method = 'POST', headers = '{}', body = '{}', timeout = 30000 } = req.body;

    if (!url) {
        return res.status(400).json({ success: false, error: 'URL is required' });
    }

    console.log(`[Webshell Proxy] ${method} ${url}`);
    console.log('[Webshell Proxy] Raw body param:', typeof body, body.substring ? body.substring(0, 100) : body);

    // 解析JSON字符串
    try {
        if (typeof headers === 'string') headers = JSON.parse(headers);
        if (typeof body === 'string') body = JSON.parse(body);
    } catch (e) {
        console.error('[Webshell Proxy] JSON parse error:', e.message);
    }

    console.log('[Webshell Proxy] Parsed body object:', JSON.stringify(body));

    try {
        const parsedUrl = new URL(url);
        const isHttps = parsedUrl.protocol === 'https:';
        const httpModule = isHttps ? https : http;

        // 构建请求体 - 确保body是对象后转url编码
        const bodyObj = typeof body === 'object' ? body : {};
        const bodyString = querystring.stringify(bodyObj);

        console.log('[Webshell Proxy] Final body string:', bodyString);
        console.log('[Webshell Proxy] Content-Length:', Buffer.byteLength(bodyString));

        // 构建请求选项
        const options = {
            hostname: parsedUrl.hostname,
            port: parsedUrl.port || (isHttps ? 443 : 80),
            path: parsedUrl.pathname + parsedUrl.search,
            method: method,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': Buffer.byteLength(bodyString),
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Cache-Control': 'no-cache'
            },
            timeout: parseInt(timeout) || 30000
        };

        // 合并自定义头部
        if (headers && typeof headers === 'object') {
            Object.keys(headers).forEach(key => {
                if (key.toLowerCase() !== 'content-type' && key.toLowerCase() !== 'content-length') {
                    options.headers[key] = headers[key];
                }
            });
        }

        const proxyReq = httpModule.request(options, (proxyRes) => {
            let data = '';
            const chunks = [];

            proxyRes.on('data', (chunk) => {
                chunks.push(chunk);
            });

            proxyRes.on('end', () => {
                const buffer = Buffer.concat(chunks);

                // 尝试检测编码
                const contentType = proxyRes.headers['content-type'] || '';
                let responseData;
                if (contentType.includes('application/octet-stream') || buffer.length > 100000) {
                    // 二进制数据返回 base64
                    responseData = buffer.toString('base64');
                    res.json({
                        success: true,
                        status: proxyRes.statusCode,
                        headers: proxyRes.headers,
                        data: responseData,
                        encoding: 'base64'
                    });
                } else {
                    // 文本数据
                    responseData = buffer.toString('utf8');
                    console.log('[Webshell Proxy] Response:', responseData.substring(0, 200));
                    res.json({
                        success: true,
                        status: proxyRes.statusCode,
                        headers: proxyRes.headers,
                        data: responseData
                    });
                }
            });
        });

        proxyReq.on('error', (err) => {
            console.error('[Webshell Proxy Error]', err.message);
            res.status(500).json({
                success: false,
                error: err.message,
                code: err.code
            });
        });

        proxyReq.on('timeout', () => {
            proxyReq.destroy();
            res.status(504).json({
                success: false,
                error: 'Request timeout'
            });
        });

        // 发送请求体
        if (bodyString && method !== 'GET') {
            proxyReq.write(bodyString);
        }

        proxyReq.end();

    } catch (err) {
        console.error('[Webshell Proxy Error]', err.message);
        res.status(500).json({
            success: false,
            error: err.message
        });
    }
});

// Webshell 测试连接
app.post('/api/webshell/test', express.urlencoded({ extended: true }), async (req, res) => {
    const { url, password = 'cmd', type = 'php8_eval' } = req.body;

    if (!url) {
        return res.status(400).json({ success: false, error: 'URL is required' });
    }

    console.log(`[Webshell Test] Testing ${url}`);

    // 生成测试标记
    const testMarker = 'TMBOX_TEST_' + Date.now();

    // 根据类型构建测试payload
    let testPayload = '';
    switch(type) {
        case 'php8_eval':
        case 'php_eval':
        case 'php_base64':
        case 'php_concat':
        case 'php_variable_func':
            testPayload = `echo '${testMarker}';`;
            break;
        case 'php8_system':
        case 'php8_passthru':
        case 'php8_shell_exec':
        case 'php8_exec':
        case 'php_system':
        case 'php_passthru':
        case 'php_shell_exec':
            testPayload = `echo "${testMarker}";`;
            break;
        default:
            testPayload = `echo '${testMarker}';`;
    }

    try {
        const parsedUrl = new URL(url);
        const isHttps = parsedUrl.protocol === 'https:';
        const httpModule = isHttps ? https : http;

        const bodyString = querystring.stringify({ [password]: testPayload });

        const options = {
            hostname: parsedUrl.hostname,
            port: parsedUrl.port || (isHttps ? 443 : 80),
            path: parsedUrl.pathname + parsedUrl.search,
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': Buffer.byteLength(bodyString),
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            timeout: 10000
        };

        const proxyReq = httpModule.request(options, (proxyRes) => {
            let data = '';
            proxyRes.on('data', (chunk) => { data += chunk; });
            proxyRes.on('end', () => {
                const success = data.includes(testMarker);
                res.json({
                    success: success,
                    status: proxyRes.statusCode,
                    contains: data.includes(testMarker),
                    responseLength: data.length,
                    preview: data.substring(0, 500),
                    message: success ? '连接成功!' : '连接失败，请检查密码或类型是否正确'
                });
            });
        });

        proxyReq.on('error', (err) => {
            res.json({
                success: false,
                error: err.message,
                message: '连接错误: ' + err.message
            });
        });

        proxyReq.on('timeout', () => {
            proxyReq.destroy();
            res.json({
                success: false,
                error: 'Timeout',
                message: '连接超时'
            });
        });

        proxyReq.write(bodyString);
        proxyReq.end();

    } catch (err) {
        res.json({
            success: false,
            error: err.message,
            message: '请求错误: ' + err.message
        });
    }
});

// 系统信息 API
app.get('/api/system-info', (req, res) => {
    try {
        const { execSync } = require('child_process');
        let diskUsage = [];
        try {
            const dfOutput = execSync('df -h | tail -n +2', { encoding: 'utf8' });
            const lines = dfOutput.trim().split('\n');
            diskUsage = lines.map(line => {
                const parts = line.split(/\s+/);
                return {
                    filesystem: parts[0],
                    size: parts[1],
                    used: parts[2],
                    avail: parts[3],
                    percent: parts[4],
                    mounted: parts[5] || parts[4]
                };
            }).filter(d => d.mounted && d.mounted.startsWith('/'));
        } catch (e) {
            console.error('获取磁盘信息失败:', e.message);
        }

        res.json({
            hostname: os.hostname(),
            platform: os.platform(),
            arch: os.arch(),
            uptime: os.uptime(),
            cpus: os.cpus().length,
            totalMem: os.totalmem(),
            freeMem: os.freemem(),
            networkInterfaces: os.networkInterfaces(),
            diskUsage: diskUsage
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// SSH 登录信息 API
app.get('/api/ssh-info', (req, res) => {
    try {
        const { execSync } = require('child_process');

        let currentUsers = [];
        try {
            const whoOutput = execSync('who 2>/dev/null || echo ""', { encoding: 'utf8', timeout: 5000 });
            const lines = whoOutput.trim().split('\n').filter(l => l.trim());
            currentUsers = lines.map(line => {
                const parts = line.split(/\s+/);
                const user = parts[0] || '';
                const tty = parts[1] || '';
                const ipMatch = line.match(/\(([^)]+)\)/);
                const ip = ipMatch ? ipMatch[1] : null;
                const isLocal = !ip || ip.startsWith(':') || ip === 'tty' || ip.startsWith('tty');
                const timeMatch = line.match(/(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})/);
                const time = timeMatch ? timeMatch[1] : '';

                return { user, tty, ip: isLocal ? null : ip, isLocal, time };
            });
        } catch (e) {
            console.error('who 命令执行失败:', e.message);
        }

        let todayLogins = 0;
        try {
            const lastOutput = execSync(`last -n 50 2>/dev/null | grep -E "^\\w" | head -30 || echo ""`, {
                encoding: 'utf8',
                timeout: 5000
            });
            const lines = lastOutput.trim().split('\n').filter(l => l.trim() && !l.startsWith('wtmp'));
            todayLogins = lines.filter(line => {
                return line.includes(new Date().toISOString().slice(5, 10)) ||
                       line.includes(new Date().toLocaleDateString('en-US', { month: 'short', day: '2-digit' }));
            }).length;
        } catch (e) {
            console.error('last 命令执行失败:', e.message);
        }

        let recentLogins = [];
        try {
            const lastOutput = execSync('last -n 10 2>/dev/null | grep -E "^\\w" | head -10 || echo ""', {
                encoding: 'utf8',
                timeout: 5000
            });
            const lines = lastOutput.trim().split('\n').filter(l => l.trim() && !l.startsWith('wtmp'));

            recentLogins = lines.slice(0, 8).map(line => {
                const parts = line.split(/\s+/);
                const user = parts[0] || '';
                const ipMatch = line.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
                const ip = ipMatch ? ipMatch[1] : (parts[2] || '本地');
                const status = line.includes('still logged in') ? 'active' : 'success';
                const isFailed = line.includes('gone') && !line.includes('still');
                const timeInfo = parts.slice(3, 7).join(' ');

                return {
                    user,
                    ip: ip.startsWith('tty') || ip.startsWith('pts') || ip.startsWith(':') ? '本地' : ip,
                    time: timeInfo,
                    status: isFailed ? 'failed' : status
                };
            });
        } catch (e) {
            console.error('获取最近登录记录失败:', e.message);
        }

        let failedAttempts = 0;
        try {
            const failedOutput = execSync(
                'grep -c "Failed password\\|authentication failure\\|Invalid user" /var/log/auth.log 2>/dev/null || ' +
                'journalctl -u ssh --since today 2>/dev/null | grep -c "Failed\\|Invalid" || echo 0',
                { encoding: 'utf8', timeout: 5000 }
            );
            failedAttempts = parseInt(failedOutput.trim()) || 0;
        } catch (e) {}

        const activeSSH = currentUsers.filter(u => !u.isLocal).length;

        res.json({
            activeCount: currentUsers.length,
            sshActive: activeSSH,
            todayLogins,
            failedAttempts,
            currentUsers,
            recentLogins
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== 服务器与 Socket.IO 配置 ====================

let server, io;

if (useHTTPS) {
    // HTTPS 模式
    server = https.createServer(sslOptions, app);
    io = new Server(server, {
        cors: { origin: "*" },
        // WebSocket 安全配置
        allowEIO3: true,
        transports: ['websocket', 'polling']
    });

    // HTTP 重定向到 HTTPS
    const httpRedirectServer = http.createServer((req, res) => {
        const host = req.headers.host ? req.headers.host.split(':')[0] : 'localhost';
        res.writeHead(301, { Location: `https://${host}:${HTTPS_PORT}${req.url}` });
        res.end();
    });
    httpRedirectServer.listen(HTTP_PORT, () => {
        console.log(`[→] HTTP 重定向服务: http://0.0.0.0:${HTTP_PORT} → https://...:${HTTPS_PORT}`);
    });

} else {
    // 仅 HTTP 模式
    server = http.createServer(app);
    io = new Server(server, { cors: { origin: "*" } });
}

// ==================== 多任务管理 ====================

const activeScans = {
    'system': null,
    'nuclei': null,
    'nmap': null,
    'fscan': null,
    'feroxbuster': null,
    'sqlmap': null
};

let currentMsfProcess = null;

// 系统负载监控 (每 2 秒一次)
setInterval(() => {
    const loads = os.loadavg();
    const usage = loads[0].toFixed(2);
    const total = os.totalmem();
    const free = os.freemem();
    const mem = ((total - free) / total * 100).toFixed(1);

    io.emit('sys-update', { load: usage, mem: mem, loads: loads.map(l => l.toFixed(2)) });
}, 2000);

// ==================== Socket.IO 事件处理 ====================

io.on('connection', (socket) => {
    console.log('[+] 新客户端连接:', socket.id);

    // 终端输入处理
    socket.on('term-input', (data) => {
        let type = 'system';
        let input = '';

        if (typeof data === 'string') {
            input = data;
        } else {
            type = data.type || 'system';
            input = data.input;
        }

        const proc = activeScans[type];
        if (proc && proc.stdin) {
            try {
                proc.stdin.write(input + '\n');
                socket.emit('log', { source: type, data: input + '\n' });
            } catch (e) {
                console.error("Input Error:", e);
            }
        }
    });

    // Ping 测试
    socket.on('start-ping', (data) => {
        const target = data.target;
        const type = 'system';

        if (activeScans[type]) {
            socket.emit('log', { source: type, data: '\n[ERR] 当前 Ping 任务正在运行，请先停止！\n' });
            return;
        }

        socket.emit('scan-status', { type: type, status: 'running' });
        socket.emit('log', { source: type, data: `\n[SYSTEM] 正在执行 PING 测试: ${target}...\n` });

        const ping = spawn('unbuffer', ['ping', '-c', '10', target]);
        activeScans[type] = ping;

        ping.stdout.on('data', (data) => {
            socket.emit('log', { source: type, data: data.toString() });
        });

        ping.stderr.on('data', (data) => {
            socket.emit('log', { source: type, data: `[ERR] ${data.toString()}` });
        });

        ping.on('close', (code) => {
            activeScans[type] = null;
            socket.emit('scan-status', { type: type, status: 'stopped' });
            socket.emit('log', { source: type, data: `\n[SYSTEM] Ping 测试结束 (代码: ${code})\n` });
        });

        ping.on('error', (err) => {
            activeScans[type] = null;
            socket.emit('scan-status', { type: type, status: 'stopped' });
            socket.emit('log', { source: type, data: `\n[FATAL] 无法启动 Ping: ${err.message}\n` });
        });
    });

    // Nuclei 扫描
    socket.on('start-nuclei', (data) => {
        const target = data.target;
        const customArgsStr = data.args || "";
        const type = 'nuclei';

        if (activeScans[type]) {
            socket.emit('log', { source: type, data: '\n[ERR] Nuclei 任务正在运行中，请等待...\n' });
            return;
        }

        socket.emit('scan-status', { type: type, status: 'running' });

        let logMsg = '\n[SYSTEM] 正在启动 Nuclei...\n';
        if(target) logMsg += `> 目标: ${target}\n`;
        if(customArgsStr) logMsg += `> 参数: ${customArgsStr}\n`;
        socket.emit('log', { source: type, data: logMsg });

        const cmd = 'unbuffer';
        const args = ['-p', '/usr/local/bin/nuclei'];

        if (target && target.trim() !== "") {
            args.push('-u', target);
        }

        const argRegex = /[^\s"]+|"([^"]*)"/gi;
        let match;
        while ((match = argRegex.exec(customArgsStr)) !== null) {
            let val = match[1] ? match[1] : match[0];
            args.push(val);
        }

        if (!args.includes('-stats')) {
            args.push('-stats');
        }

        console.log(`执行命令: ${cmd} ${args.join(' ')}`);

        const nuclei = spawn(cmd, args);
        activeScans[type] = nuclei;

        nuclei.stdout.on('data', (data) => {
            socket.emit('log', { source: type, data: data.toString() });
        });

        nuclei.stderr.on('data', (data) => {
            socket.emit('log', { source: type, data: data.toString() });
        });

        nuclei.on('close', (code) => {
            activeScans[type] = null;
            socket.emit('scan-status', { type: type, status: 'stopped' });
            socket.emit('log', { source: type, data: `\n[SYSTEM] 扫描完成 (Exit Code: ${code})\n` });
        });

        nuclei.on('error', (err) => {
            activeScans[type] = null;
            socket.emit('scan-status', { type: type, status: 'stopped' });
            socket.emit('log', { source: type, data: `\n[FATAL] 启动失败: ${err.message}\n` });
        });
    });

    // Nmap 扫描
    socket.on('start-nmap', (data) => {
        const target = data.target;
        const customArgsStr = data.args || "";
        const type = 'nmap';

        if (activeScans[type]) {
            socket.emit('log', { source: type, data: '\n[ERR] Nmap 任务正在运行中，请等待...\n' });
            return;
        }

        socket.emit('scan-status', { type: type, status: 'running' });

        let logMsg = '\n[SYSTEM] 正在启动 Nmap...\n';
        if(target) logMsg += `> 目标: ${target}\n`;
        if(customArgsStr) logMsg += `> 参数: ${customArgsStr}\n`;
        socket.emit('log', { source: type, data: logMsg });

        const cmd = 'unbuffer';
        const args = ['-p', '/usr/bin/nmap'];

        const argRegex = /[^\s"]+|"([^"]*)"/gi;
        let match;
        while ((match = argRegex.exec(customArgsStr)) !== null) {
            let val = match[1] ? match[1] : match[0];
            args.push(val);
        }

        if (target && target.trim() !== "") {
            args.push(target);
        }

        if (!args.includes('-v') && !args.includes('-vv')) {
            args.push('-v');
        }

        console.log(`执行 Nmap: ${cmd} ${args.join(' ')}`);

        const nmap = spawn(cmd, args);
        activeScans[type] = nmap;

        nmap.stdout.on('data', (data) => {
            socket.emit('log', { source: type, data: data.toString() });
        });

        nmap.stderr.on('data', (data) => {
            socket.emit('log', { source: type, data: `[NMAP ERR] ${data.toString()}` });
        });

        nmap.on('close', (code) => {
            activeScans[type] = null;
            socket.emit('scan-status', { type: type, status: 'stopped' });
            socket.emit('log', { source: type, data: `\n[SYSTEM] Nmap 扫描完成 (Exit Code: ${code})\n` });
        });

        nmap.on('error', (err) => {
            activeScans[type] = null;
            socket.emit('scan-status', { type: type, status: 'stopped' });
            socket.emit('log', { source: type, data: `\n[FATAL] 无法启动 Nmap: ${err.message}\n` });
        });
    });

    // Fscan 扫描
    socket.on('start-fscan', (data) => {
        const target = data.target;
        const customArgsStr = data.args || "";
        const type = 'fscan';

        if (activeScans[type]) {
            socket.emit('log', { source: type, data: '\n[ERR] Fscan 任务正在运行中，请等待...\n' });
            return;
        }

        socket.emit('scan-status', { type: type, status: 'running' });

        let logMsg = '\n[SYSTEM] 正在启动 Fscan...\n';
        if(target) logMsg += `> 目标: ${target}\n`;
        if(customArgsStr) logMsg += `> 参数: ${customArgsStr}\n`;
        socket.emit('log', { source: type, data: logMsg });

        const cmd = 'unbuffer';
        const args = ['-p', '/usr/local/bin/fscan'];

        const argRegex = /[^\s"]+|"([^"]*)"/gi;
        let match;
        while ((match = argRegex.exec(customArgsStr)) !== null) {
            let val = match[1] ? match[1] : match[0];
            args.push(val);
        }

        if (target && target.trim() !== "") {
            if (!args.includes('-h')) {
                args.push('-h', target);
            }
        }

        if (!args.includes('-o') && !args.includes('-no')) {
            args.push('-no');
        }

        console.log(`执行 Fscan: ${cmd} ${args.join(' ')}`);

        const fscan = spawn(cmd, args);
        activeScans[type] = fscan;

        fscan.stdout.on('data', (data) => {
            socket.emit('log', { source: type, data: data.toString() });
        });

        fscan.stderr.on('data', (data) => {
            socket.emit('log', { source: type, data: `[FSCAN ERR] ${data.toString()}` });
        });

        fscan.on('close', (code) => {
            activeScans[type] = null;
            socket.emit('scan-status', { type: type, status: 'stopped' });
            socket.emit('log', { source: type, data: `\n[SYSTEM] Fscan 扫描完成 (Exit Code: ${code})\n` });
        });

        fscan.on('error', (err) => {
            activeScans[type] = null;
            socket.emit('scan-status', { type: type, status: 'stopped' });
            socket.emit('log', { source: type, data: `\n[FATAL] 无法启动 Fscan: ${err.message}\n` });
        });
    });

    // Feroxbuster 目录爆破
    socket.on('start-feroxbuster', (data) => {
        const target = data.target;
        const customArgsStr = data.args || "";
        const type = 'feroxbuster';

        if (activeScans[type]) {
            socket.emit('log', { source: type, data: '\n[ERR] Feroxbuster 任务正在运行中，请等待...\n' });
            return;
        }

        socket.emit('scan-status', { type: type, status: 'running' });

        let logMsg = '\n[SYSTEM] 正在启动 Feroxbuster...\n';
        if(target) logMsg += `> 目标: ${target}\n`;
        if(customArgsStr) logMsg += `> 参数: ${customArgsStr}\n`;
        socket.emit('log', { source: type, data: logMsg });

        const cmd = 'unbuffer';
        const args = ['-p', '/usr/local/bin/feroxbuster'];

        const argRegex = /[^\s"]+|"([^"]*)"/gi;
        let match;
        while ((match = argRegex.exec(customArgsStr)) !== null) {
            let val = match[1] ? match[1] : match[0];
            args.push(val);
        }

        if (target && target.trim() !== "") {
            if (!args.includes('-u') && !args.includes('--url')) {
                args.push('-u', target);
            }
        }

        console.log(`执行 Feroxbuster: ${cmd} ${args.join(' ')}`);

        const feroxbuster = spawn(cmd, args);
        activeScans[type] = feroxbuster;

        feroxbuster.stdout.on('data', (data) => {
            socket.emit('log', { source: type, data: data.toString() });
        });

        feroxbuster.stderr.on('data', (data) => {
            socket.emit('log', { source: type, data: data.toString() });
        });

        feroxbuster.on('close', (code) => {
            activeScans[type] = null;
            socket.emit('scan-status', { type: type, status: 'stopped' });
            socket.emit('log', { source: type, data: `\n[SYSTEM] Feroxbuster 扫描完成 (Exit Code: ${code})\n` });
        });

        feroxbuster.on('error', (err) => {
            activeScans[type] = null;
            socket.emit('scan-status', { type: type, status: 'stopped' });
            socket.emit('log', { source: type, data: `\n[FATAL] 无法启动 Feroxbuster: ${err.message}\n` });
        });
    });

    // Sqlmap 扫描
    socket.on('start-sqlmap', (data) => {
        const target = data.target;
        const customArgsStr = data.args || "";
        const type = 'sqlmap';

        if (activeScans[type]) {
            socket.emit('log', { source: type, data: '\n[ERR] Sqlmap 任务正在运行中，请等待...\n' });
            return;
        }

        socket.emit('scan-status', { type: type, status: 'running' });

        let logMsg = '\n[SYSTEM] 正在启动 Sqlmap...\n';
        if(target) logMsg += `> 目标: ${target}\n`;
        if(customArgsStr) logMsg += `> 参数: ${customArgsStr}\n`;
        socket.emit('log', { source: type, data: logMsg });

        const cmd = 'unbuffer';
        const args = ['-p', '/usr/bin/sqlmap'];

        const argRegex = /[^\s"]+|"([^"]*)"/gi;
        let match;
        while ((match = argRegex.exec(customArgsStr)) !== null) {
            let val = match[1] ? match[1] : match[0];
            args.push(val);
        }

        if (target && target.trim() !== "") {
            if (!args.includes('-u') && !args.includes('--url')) {
                args.push('-u', target);
            }
        }

        if (!args.includes('--batch')) {
            args.push('--batch');
        }

        console.log(`执行 Sqlmap: ${cmd} ${args.join(' ')}`);

        const sqlmap = spawn(cmd, args);
        activeScans[type] = sqlmap;

        sqlmap.stdout.on('data', (data) => {
            socket.emit('log', { source: type, data: data.toString() });
        });

        sqlmap.stderr.on('data', (data) => {
            socket.emit('log', { source: type, data: data.toString() });
        });

        sqlmap.on('close', (code) => {
            activeScans[type] = null;
            socket.emit('scan-status', { type: type, status: 'stopped' });
            socket.emit('log', { source: type, data: `\n[SYSTEM] Sqlmap 扫描完成 (Exit Code: ${code})\n` });
        });

        sqlmap.on('error', (err) => {
            activeScans[type] = null;
            socket.emit('scan-status', { type: type, status: 'stopped' });
            socket.emit('log', { source: type, data: `\n[FATAL] 无法启动 Sqlmap: ${err.message}\n` });
        });
    });

    // Webshell 扫描 (使用 gobuster + seclists)
    socket.on('start-webshell-scan', (data) => {
        const target = data.target;
        const wordlist = data.wordlist || '/usr/share/seclists/Web-Shells/backdoor_list.txt';
        const threads = data.threads || 50;
        const type = 'webshell-scan';

        if (activeScans[type]) {
            socket.emit('log', { source: type, data: '\n[ERR] Webshell 扫描任务正在运行中...\n' });
            return;
        }

        socket.emit('scan-status', { type: type, status: 'running' });
        socket.emit('log', { source: type, data: `\n[SYSTEM] 开始 Webshell 扫描...\n> 目标: ${target}\n> 字典: ${wordlist}\n` });

        // 使用 gobuster 或 ffuf
        const fs = require('fs');
        let cmd, args;

        // 检查字典是否存在
        if (fs.existsSync(wordlist)) {
            // 优先使用 ffuf (更快)
            try {
                require('child_process').execSync('which ffuf', { stdio: 'ignore' });
                cmd = 'unbuffer';
                args = ['ffuf', '-u', target + '/FUZZ', '-w', wordlist, '-t', threads.toString(), '-mc', '200,301,302,403', '-fs', '0'];
            } catch {
                // 回退到 gobuster
                try {
                    require('child_process').execSync('which gobuster', { stdio: 'ignore' });
                    cmd = 'unbuffer';
                    args = ['gobuster', 'dir', '-u', target, '-w', wordlist, '-t', threads.toString(), '-q'];
                } catch {
                    // 使用 curl 脚本
                    socket.emit('log', { source: type, data: '[!] ffuf/gobuster 未安装，使用 curl 扫描...\n' });
                    cmd = 'bash';
                    args = ['-c', `
                        while IFS= read -r line; do
                            url="${target}/$line"
                            status=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 "$url" 2>/dev/null)
                            if [ "$status" = "200" ] || [ "$status" = "301" ] || [ "$status" = "302" ]; then
                                echo "[$status] $url"
                            fi
                        done < "${wordlist}"
                    `];
                }
            }
        } else {
            // 字典不存在，使用内置路径
            socket.emit('log', { source: type, data: '[!] 字典不存在，使用内置路径扫描...\n' });
            cmd = 'bash';
            args = ['-c', `
                paths="shell.php cmd.php c.php b.php a.php 1.php x.php test.php admin/shell.php admin/cmd.php upload/shell.php uploads/shell.php config.php behinder.php ant.php wso.php c99.php r57.php webshell.php"
                for p in $paths; do
                    url="${target}/$p"
                    status=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 "$url" 2>/dev/null)
                    if [ "$status" = "200" ]; then
                        echo "[200] $url"
                    fi
                done
            `];
        }

        console.log(`执行 Webshell 扫描: ${cmd} ${args.join(' ')}`);

        const scanner = spawn(cmd, args);
        activeScans[type] = scanner;

        scanner.stdout.on('data', (data) => {
            socket.emit('log', { source: type, data: data.toString() });
        });

        scanner.stderr.on('data', (data) => {
            socket.emit('log', { source: type, data: data.toString() });
        });

        scanner.on('close', (code) => {
            activeScans[type] = null;
            socket.emit('scan-status', { type: type, status: 'stopped' });
            socket.emit('log', { source: type, data: `\n[SYSTEM] Webshell 扫描完成 (Exit Code: ${code})\n` });
        });

        scanner.on('error', (err) => {
            activeScans[type] = null;
            socket.emit('scan-status', { type: type, status: 'stopped' });
            socket.emit('log', { source: type, data: `\n[FATAL] 扫描失败: ${err.message}\n` });
        });
    });

    // 停止扫描
    socket.on('stop-scan', (type) => {
        if (!type) type = 'nuclei';

        const proc = activeScans[type];
        if (proc) {
            proc.kill();
            activeScans[type] = null;
            socket.emit('scan-status', { type: type, status: 'stopped' });
            socket.emit('log', { source: type, data: '\n[WARN] 已停止.\n' });
        }
    });

    // MSF 交互式会话
    socket.on('start-msf', () => {
        if (currentMsfProcess) {
            socket.emit('msf-output', '\n[SYSTEM] MSF 会话已存在，已连接.\n');
            setTimeout(() => {
                if (currentMsfProcess) {
                    currentMsfProcess.stdin.write('sessions -l\n');
                }
            }, 500);
            return;
        }

        io.emit('msf-output', '\n[SYSTEM] 正在启动 Metasploit Framework...\n');

        const msf = spawn('unbuffer', ['-p', 'msfconsole', '-q']);
        currentMsfProcess = msf;

        msf.stdout.on('data', (data) => {
            io.emit('msf-output', data.toString());
        });

        msf.stderr.on('data', (data) => {
            io.emit('msf-output', data.toString());
        });

        msf.on('close', (code) => {
            currentMsfProcess = null;
            io.emit('msf-output', `\n[SYSTEM] MSF 会话结束 (Code: ${code})\n`);
        });
    });

    socket.on('msf-input', (cmd) => {
        if (currentMsfProcess) {
            currentMsfProcess.stdin.write(cmd + '\n');
        } else {
            socket.emit('msf-output', '\n[ERR] 会话未启动. 请刷新页面.\n');
        }
    });

    socket.on('kill-msf', () => {
        if (currentMsfProcess) {
            currentMsfProcess.kill();
            currentMsfProcess = null;
            socket.emit('msf-output', '\n[SYSTEM] 会话已强制终止.\n');
        }
    });

    // 网络拓扑扫描
    socket.on('start-topology-scan', (options) => {
        const doLiveCheck = options && options.liveCheck;
        const doOsDetect = options && options.osDetect;

        const interfaces = os.networkInterfaces();
        let localIP = '127.0.0.1';
        let cidr = '';
        let interfaceName = '';

        for (const name of Object.keys(interfaces)) {
            for (const iface of interfaces[name]) {
                if (!iface.internal && iface.family === 'IPv4') {
                    localIP = iface.address;
                    interfaceName = name;
                    const parts = localIP.split('.');
                    parts.pop();
                    cidr = parts.join('.') + '.0/24';
                    break;
                }
            }
            if (cidr) break;
        }

        if (!cidr) {
            socket.emit('log', '[ERR] 无法识别局域网网段，仅显示本机。\n');
            cidr = localIP;
        }

        const getGatewayProcess = spawn('ip', ['route', 'show', 'default']);
        let gatewayIP = null;

        getGatewayProcess.stdout.on('data', (data) => {
            const output = data.toString();
            const match = output.match(/default via ([0-9.]+)/);
            if (match) {
                gatewayIP = match[1];
            }
        });

        getGatewayProcess.on('close', () => {
            if (gatewayIP) {
                socket.emit('topology-node', {
                    id: gatewayIP,
                    label: `网关 (Gateway)\n${gatewayIP}`,
                    group: 'gateway',
                    ip: gatewayIP
                });
            }

            socket.emit('topology-node', {
                id: 'local',
                label: `本机 (Attacker)\n${localIP}`,
                group: 'attacker',
                ip: localIP,
                gateway: gatewayIP
            });

            const nmapArgs = [];
            if (doLiveCheck) {
                nmapArgs.push('-Pn');
            } else {
                nmapArgs.push('-sn');
            }

            if (doOsDetect) {
                nmapArgs.push('-O');
                nmapArgs.push('--osscan-guess');
            }

            nmapArgs.push('-oN');
            nmapArgs.push('-');
            nmapArgs.push(cidr);

            const nmap = spawn('nmap', nmapArgs);
            let buffer = '';

            nmap.stdout.on('data', (data) => {
                buffer += data.toString();
            });

            nmap.stderr.on('data', (err) => {
                console.error('Nmap Topology Error:', err.toString());
            });

            nmap.on('close', () => {
                const blocks = buffer.split('Nmap scan report for');
                blocks.forEach(block => {
                    let ip = null;
                    const parensMatch = block.match(/\(([\d\.]+)\)/);
                    if (parensMatch) {
                        ip = parensMatch[1];
                    } else {
                        const rawMatch = block.match(/^ *([\d\.]+)/);
                        if (rawMatch) {
                            ip = rawMatch[1];
                        }
                    }

                    if (ip) {
                        ip = ip.trim();
                        if (ip.split('.').length === 4) {
                            if (ip !== localIP && ip !== gatewayIP) {
                                const macMatch = block.match(/MAC Address: ([A-F0-9:]+) \((.*)\)/i);
                                const mac = macMatch ? macMatch[1] : 'Unknown';
                                const vendor = macMatch ? macMatch[2] : '';

                                const osMatch = block.match(/Running: (.*)/);
                                const osInfo = osMatch ? osMatch[1] : (doOsDetect ? 'Unknown' : '');

                                let osGuess = '';
                                if (!osInfo && doOsDetect) {
                                    const guessMatch = block.match(/OS details: (.*)/);
                                    if (guessMatch) osGuess = guessMatch[1];
                                }

                                const finalOS = osInfo || osGuess || (doOsDetect ? '未识别' : '');

                                socket.emit('topology-node', {
                                    id: ip,
                                    label: `设备\n${ip}`,
                                    group: 'target',
                                    ip: ip,
                                    mac: mac,
                                    vendor: vendor,
                                    os: finalOS,
                                    gateway: gatewayIP
                                });
                            }
                        }
                    }
                });
                socket.emit('topology-finish');
            });
        });
    });

    // 单目标详细扫描
    socket.on('start-single-scan', (data) => {
        const { target, type } = data;

        let args = [];
        let label = '';

        if (type === 'port') {
            args = ['-F', target];
            label = `快速端口扫描 (${target})`;
        } else if (type === 'service') {
            args = ['-sV', '--version-intensity', '5', target];
            label = `服务版本探测 (${target})`;
        } else if (type === 'alive') {
            args = ['-sn', '-PE', '-PP', '-PM', target];
            label = `主动存活探测 (${target})`;
        } else {
            return;
        }

        socket.emit('single-scan-log', `\n[SYSTEM] 开始 ${label}...\n`);

        const scan = spawn('nmap', args);

        scan.stdout.on('data', (d) => {
            socket.emit('single-scan-log', d.toString());
        });

        scan.stderr.on('data', (d) => {
            socket.emit('single-scan-log', `[ERR] ${d.toString()}`);
        });

        scan.on('close', (code) => {
            socket.emit('single-scan-log', `\n[SYSTEM] 任务结束 (Code: ${code})\n`);
        });
    });

    // 断开连接
    socket.on('disconnect', () => {
        console.log('[-] 客户端断开:', socket.id);
    });
});

// ==================== 启动服务器 ====================

const PORT = useHTTPS ? HTTPS_PORT : HTTP_PORT;
const PROTOCOL = useHTTPS ? 'https' : 'http';

server.listen(PORT, '0.0.0.0', () => {
    console.log('');
    console.log('╔════════════════════════════════════════════╗');
    console.log('║          TMbox Security Console            ║');
    console.log('╠════════════════════════════════════════════╣');
    console.log(`║  访问地址: ${PROTOCOL}://0.0.0.0:${PORT}              ║`);
    console.log(`║  安全模式: ${useHTTPS ? 'HTTPS (TLS 加密)' : 'HTTP (未加密)'}        ║`);
    console.log('╚════════════════════════════════════════════╝');
    console.log('');

    if (useHTTPS) {
        console.log('提示: 首次访问可能需要信任自签名证书');
        console.log(`      或在浏览器输入: thisisunsafe (Chrome)`);
    }
});
