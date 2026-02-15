/* server.js - 实时流数据修复版 */
const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const { spawn } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// --- 新增路由: MSF 控制台 ---
app.get('/msf', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/msf.html'));
});

// --- 新增路由: 网络拓扑图 ---
app.get('/topology', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/topology.html'));
});

// --- 新增路由: 系统实时监控 ---
app.get('/monitor', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/monitor.html'));
});

// --- Payload 文件管理 API ---
const PAYLOAD_DIR = '/tmp';

// 获取 payload 文件列表
app.get('/api/payloads', (req, res) => {
    try {
        const files = fs.readdirSync(PAYLOAD_DIR);
        const payloadFiles = files
            .filter(f => {
                // 过滤出可能是 payload 的文件
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
            .sort((a, b) => b.modified - a.modified); // 按修改时间倒序

        res.json({ success: true, files: payloadFiles });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

// 下载 payload 文件
app.get('/api/payloads/download/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(PAYLOAD_DIR, filename);

    // 安全检查：防止目录遍历攻击
    const normalizedPath = path.normalize(filePath);
    if (!normalizedPath.startsWith(PAYLOAD_DIR)) {
        return res.status(403).json({ error: 'Access denied' });
    }

    // 检查文件是否存在
    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'File not found' });
    }

    // 获取文件状态
    const stats = fs.statSync(filePath);

    // 设置响应头
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length', stats.size);

    // 根据扩展名设置 Content-Type
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

    // 流式传输文件
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

    // 安全检查
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

// --- 系统信息 API ---
app.get('/api/system-info', (req, res) => {
    try {
        // 获取磁盘使用情况
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

// --- SSH 登录信息 API ---
app.get('/api/ssh-info', (req, res) => {
    try {
        const { execSync } = require('child_process');

        // 1. 获取当前登录用户 (使用 who 命令)
        let currentUsers = [];
        try {
            const whoOutput = execSync('who 2>/dev/null || echo ""', { encoding: 'utf8', timeout: 5000 });
            const lines = whoOutput.trim().split('\n').filter(l => l.trim());
            currentUsers = lines.map(line => {
                // 格式: user    tty     2024-01-01 12:00 (192.168.1.1)
                const parts = line.split(/\s+/);
                const user = parts[0] || '';
                const tty = parts[1] || '';
                // 提取 IP 地址 (括号内)
                const ipMatch = line.match(/\(([^)]+)\)/);
                const ip = ipMatch ? ipMatch[1] : null;
                // 判断是否为本地登录
                const isLocal = !ip || ip.startsWith(':') || ip === 'tty' || ip.startsWith('tty');

                // 提取时间
                const timeMatch = line.match(/(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})/);
                const time = timeMatch ? timeMatch[1] : '';

                return { user, tty, ip: isLocal ? null : ip, isLocal, time };
            });
        } catch (e) {
            console.error('who 命令执行失败:', e.message);
        }

        // 2. 获取今日 SSH 登录次数
        let todayLogins = 0;
        try {
            const today = new Date().toISOString().slice(0, 10);
            // 使用 last 命令获取今天的登录记录
            const lastOutput = execSync(`last -n 50 2>/dev/null | grep -E "^\\w" | head -30 || echo ""`, {
                encoding: 'utf8',
                timeout: 5000
            });
            const lines = lastOutput.trim().split('\n').filter(l => l.trim() && !l.startsWith('wtmp'));

            // 统计今天的登录次数
            todayLogins = lines.filter(line => {
                // last 输出的日期格式: Jan 15 12:00 或 Mon Jan 15 12:00
                return line.includes(today.slice(5)) || line.includes(new Date().toLocaleDateString('en-US', { month: 'short', day: '2-digit' }));
            }).length;
        } catch (e) {
            console.error('last 命令执行失败:', e.message);
        }

        // 3. 获取最近登录记录
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
                // IP 可能在不同位置，尝试提取
                const ipMatch = line.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
                const ip = ipMatch ? ipMatch[1] : (parts[2] || '本地');

                // 检查是否仍在登录
                const status = line.includes('still logged in') ? 'active' : 'success';
                // 检查是否是失败登录
                const isFailed = line.includes('gone') && !line.includes('still');

                // 提取时间信息
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

        // 4. 获取失败登录尝试次数 (从 auth.log)
        let failedAttempts = 0;
        try {
            // 尝试读取今天的失败登录次数
            const failedOutput = execSync(
                'grep -c "Failed password\\|authentication failure\\|Invalid user" /var/log/auth.log 2>/dev/null || ' +
                'journalctl -u ssh --since today 2>/dev/null | grep -c "Failed\\|Invalid" || echo 0',
                { encoding: 'utf8', timeout: 5000 }
            );
            failedAttempts = parseInt(failedOutput.trim()) || 0;
        } catch (e) {
            // 忽略权限错误
        }

        // 5. 统计活跃 SSH 连接数 (排除本地登录)
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

// 多任务管理字典
const activeScans = {
    'system': null, // Ping
    'nuclei': null,
    'nmap': null,
    'fscan': null,
    'feroxbuster': null,
    'sqlmap': null
};

let currentMsfProcess = null; // 持久化 MSF 进程

// 系统负载监控 (每 2 秒一次)
setInterval(() => {
    const loads = os.loadavg();
    // 负载取 1 分钟平均值
    const usage = loads[0].toFixed(2);
    // 内存计算
    const total = os.totalmem();
    const free = os.freemem();
    const mem = ((total - free) / total * 100).toFixed(1);

    io.emit('sys-update', { load: usage, mem: mem, loads: loads.map(l => l.toFixed(2)) });
}, 2000);

io.on('connection', (socket) => {
    // --- 终端输入处理 ---
    socket.on('term-input', (data) => {
        // data 可是字符串(旧) 或 { type, input }
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
                // 回显用户的输入
                socket.emit('log', { source: type, data: input + '\n' });
            } catch (e) {
                console.error("Input Error:", e);
            }
        }
    });

        // --- 新增的功能: Ping 测试 ---
    socket.on('start-ping', (data) => {
        const target = data.target;
        const type = 'system'; // Ping 归类为 System

        // 1. 如果有其他任务在跑，先阻止
        if (activeScans[type]) {
            socket.emit('log', { source: type, data: '\n[ERR] 当前 Ping 任务正在运行，请先停止！\n' });
            return;
        }

        // 2. 更新状态
        socket.emit('scan-status', { type: type, status: 'running' });
        socket.emit('log', { source: type, data: `\n[SYSTEM] 正在执行 PING 测试: ${target}...\n` });

        // 3. 执行系统 ping 命令
        // -c 10: 只平 10 次自动停止 (防止无限运行)
        const ping = spawn('unbuffer', ['ping', '-c', '10', target]);

        // 标记当前进程
        activeScans[type] = ping;

        // 4. 实时回显
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
    console.log('新客户端连接:', socket.id);
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

        // --- 核心修复：支持自定义参数组合 ---

        const cmd = 'unbuffer';

        // 基础命令结构: unbuffer -p /usr/local/bin/nuclei ...
        const args = [
            '-p',                    // 告诉 unbuffer 使用管道模式
            '/usr/local/bin/nuclei'  // Nuclei 路径
        ];

        // 1. 如果用户输入了 Target，自动加上 -u
        if (target && target.trim() !== "") {
            args.push('-u', target);
        }

        // 2. 解析自定义参数字符串 (支持双引号包含空格的参数)
        // 正则逻辑: 匹配 非空格字符 OR 双引号内的内容
        const argRegex = /[^\s"]+|"([^"]*)"/gi;
        let match;

        while ((match = argRegex.exec(customArgsStr)) !== null) {
            // match[1] 是引号内的内容 (如果有引号)，match[0] 是整个匹配串
            // 如果匹配到了引号内容，就用引号内的；否则用整个串
            let val = match[1] ? match[1] : match[0];
            args.push(val);
        }

        // 3. 强制追加关键参数 (保证 Web 终端体验)
        // -stats: 建议保留，用于保活显示，但如果用户在参数里写了就不重复加
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
            socket.emit('log', { source: type, data: `\n[FATAL] 启动失败: ${err.message}\n请检查是否安装了 coreutils\n` });
        });
    });

    // --- 新增的功能: Nmap 扫描 ---
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

        // Nmap 基础参数
        // 假设 nmap 在 PATH 中，或者使用 /usr/bin/nmap
        const args = [
            '-p',
            '/usr/bin/nmap'
        ];

        // 1. 解析自定义参数 (正则同 Nuclei)
        const argRegex = /[^\s"]+|"([^"]*)"/gi;
        let match;
        while ((match = argRegex.exec(customArgsStr)) !== null) {
            let val = match[1] ? match[1] : match[0];
            args.push(val);
        }

        // 2. 如果有 target，追加到最后 (Nmap target 通常在最后)
        if (target && target.trim() !== "") {
            args.push(target);
        }

        // 3. 强制无缓冲输出 (虽有 unbuffer，但 Nmap 有时需要 -v)
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

    // --- 新增的功能: Fscan 扫描 ---
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

        // Fscan 基础参数
        const args = [
            '-p',
            '/usr/local/bin/fscan' // 假设路径, 如果在 PATH 可直接用 'fscan'
        ];

        // 1. 解析自定义参数
        const argRegex = /[^\s"]+|"([^"]*)"/gi;
        let match;
        while ((match = argRegex.exec(customArgsStr)) !== null) {
            let val = match[1] ? match[1] : match[0];
            args.push(val);
        }

        // 2. 如果有 target，自动映射为 -h 参数 (Fscan 使用 -h 指定主机)
        if (target && target.trim() !== "") {
            // 防止用户在参数里已经写了 -h
            if (!args.includes('-h')) {
                args.push('-h', target);
            }
        }

        // 3. 默认不保存文件 (避免垃圾文件堆积)，除非用户指定了 -o
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
            socket.emit('log', { source: type, data: `\n[FATAL] 无法启动 Fscan: ${err.message}\n请确认 /usr/local/bin/fscan 是否存在\n` });
        });
    });

    // --- 新增的功能: Feroxbuster 目录爆破 ---
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

        // Feroxbuster 基础参数
        const args = [
            '-p',
            '/usr/local/bin/feroxbuster'
        ];

        // 1. 解析自定义参数
        const argRegex = /[^\s"]+|"([^"]*)"/gi;
        let match;
        while ((match = argRegex.exec(customArgsStr)) !== null) {
            let val = match[1] ? match[1] : match[0];
            args.push(val);
        }

        // 2. 如果有 target，自动映射为 -u 参数
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
            socket.emit('log', { source: type, data: `\n[FATAL] 无法启动 Feroxbuster: ${err.message}\n请确认 /usr/local/bin/feroxbuster 是否存在\n` });
        });
    });

    // --- 新增的功能: Sqlmap 扫描 ---
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
        // 假设 sqlmap 在 PATH 中，或者使用 /usr/bin/sqlmap
        const args = [
            '-p',
            '/usr/bin/sqlmap'
        ];

        // 1. 解析自定义参数
        const argRegex = /[^\s"]+|"([^"]*)"/gi;
        let match;
        while ((match = argRegex.exec(customArgsStr)) !== null) {
            let val = match[1] ? match[1] : match[0];
            args.push(val);
        }

        // 2. 如果有 target，自动映射为 -u 参数
        if (target && target.trim() !== "") {
            if (!args.includes('-u') && !args.includes('--url')) {
                args.push('-u', target);
            }
        }

        // 3. 强制非交互模式 (batch) 以防止卡死在询问环节
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
            // Sqlmap 的部分正常信息也会输出到 stderr
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

    socket.on('stop-scan', (type) => {
        // 兼容: 如果没有 type，默认为 nuclei (旧行为) 或不做处理
        if (!type) type = 'nuclei';

        const proc = activeScans[type];
        if (proc) {
            proc.kill();
            activeScans[type] = null;
            socket.emit('scan-status', { type: type, status: 'stopped' });
            socket.emit('log', { source: type, data: '\n[WARN] 已停止.\n' });
        }
    });

    // --- MSF 交互式会话逻辑 ---
    socket.on('start-msf', () => {
        if (currentMsfProcess) {
            // MSF 已在运行，只通知当前客户端
            socket.emit('msf-output', '\n[SYSTEM] MSF 会话已存在，已连接.\n');
            // 立即刷新会话列表
            setTimeout(() => {
                if (currentMsfProcess) {
                    currentMsfProcess.stdin.write('sessions -l\n');
                }
            }, 500);
            return;
        }

        // 广播给所有客户端
        io.emit('msf-output', '\n[SYSTEM] 正在启动 Metasploit Framework (这可能需要几秒钟)...\n');

        // 使用 unbuffer -p 保证交互性, -q 启用静默启动
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
            // 写入命令并回车
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

    // --- 网络拓扑扫描逻辑 ---
    socket.on('start-topology-scan', (options) => {
        // 默认参数
        const doLiveCheck = options && options.liveCheck; // 主动探活 -Pn
        const doOsDetect = options && options.osDetect;   // 系统识别 -O
        
        // 1. 获取本机信息与网段
        const interfaces = os.networkInterfaces();
        let localIP = '127.0.0.1';
        let cidr = '';
        let interfaceName = '';

        for (const name of Object.keys(interfaces)) {
            for (const iface of interfaces[name]) {
                // 跳过内部回环和非IPv4
                if (!iface.internal && iface.family === 'IPv4') {
                    localIP = iface.address;
                    interfaceName = name;
                    // 简单的 /24 网段计算
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

        // 2. 尝试获取网关 IP (通过 ip route 命令)
        const getGatewayProcess = spawn('ip', ['route', 'show', 'default']);
        let gatewayIP = null;
        
        getGatewayProcess.stdout.on('data', (data) => {
            // 输出示例: default via 192.168.1.1 dev eth0 proto dhcp ...
            const output = data.toString();
            const match = output.match(/default via ([0-9.]+)/);
            if (match) {
                gatewayIP = match[1];
            }
        });

        getGatewayProcess.on('close', () => {
            // 网关获取完成后，推送基础节点信息
            
            // 推送网关节点 (如果存在)
            if (gatewayIP) {
                socket.emit('topology-node', {
                    id: gatewayIP,
                    label: `网关 (Gateway)\n${gatewayIP}`,
                    group: 'gateway',
                    ip: gatewayIP
                });
            }

            // 推送本机节点
            socket.emit('topology-node', {
                id: 'local',
                label: `本机 (Attacker)\n${localIP}`,
                group: 'attacker',
                ip: localIP,
                gateway: gatewayIP // 告诉前端谁是网关
            });

            // 3. 构建 Nmap 命令
            // -sn: Ping Scan (默认)
            // -Pn: Treat all hosts as online (主动探活)
            // -O: Enable OS detection (系统识别, 需要 root)
            // -oG: Grepable output
            
            const nmapArgs = [];
            if (doLiveCheck) {
                nmapArgs.push('-Pn'); // 跳过 Ping，强制扫描
            } else {
                nmapArgs.push('-sn'); // 默认 Ping 扫描
            }

            if (doOsDetect) {
                nmapArgs.push('-O');           // 系统探测
                nmapArgs.push('--osscan-guess'); // 猜测系统
            }

            nmapArgs.push('-oN'); // 使用标准输出方便解析 MAC/OS (Grepable 格式对 OS 支持不完整)
            nmapArgs.push('-');   // 输出到 stdout
            nmapArgs.push(cidr);

            // 如果选择了 OS 探测，通常需要 sudo，这里假设运行环境已有权限或通过 sudo
            // 为了演示兼容性，如果不是 root 可能会失败，但在 docker/pi 环境通常是 root
            const nmap = spawn('nmap', nmapArgs);
            
            let buffer = '';

            nmap.stdout.on('data', (data) => {
                buffer += data.toString();
            });

            nmap.stderr.on('data', (err) => {
                console.error('Nmap Topology Error:', err.toString());
            });

            nmap.on('close', () => {
                // 解析标准 Nmap 输出
                const blocks = buffer.split('Nmap scan report for');
                blocks.forEach(block => {
                    // 1. 优先尝试匹配括号里的 IP (针对有主机名的情况: "hostname (192.168.1.1)")
                    let ip = null;
                    const parensMatch = block.match(/\(([\d\.]+)\)/);
                    if (parensMatch) {
                        ip = parensMatch[1];
                    } else {
                        // 2. 如果没有括号，匹配行首的 IP (针对无主机名的情况: "192.168.1.1")
                        // split 之后 block 开头可能有空格
                        const rawMatch = block.match(/^ *([\d\.]+)/);
                        if (rawMatch) {
                            ip = rawMatch[1];
                        }
                    }

                    if (ip) {
                        ip = ip.trim();
                        // 简单校验 IP 格式
                        if (ip.split('.').length === 4) {
                            // 排除本机
                            if (ip !== localIP && ip !== gatewayIP) {
                                
                                // 提取 MAC 和 厂商
                                const macMatch = block.match(/MAC Address: ([A-F0-9:]+) \((.*)\)/i);
                                const mac = macMatch ? macMatch[1] : 'Unknown';
                                const vendor = macMatch ? macMatch[2] : '';

                                // 提取 OS
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
                                    label: `设备\n${ip}`, // 修复 Label 显示
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

    // --- 新增: 单目标详细扫描 ---
    socket.on('start-single-scan', (data) => {
        const { target, type } = data;
        // type: 'port', 'service', 'alive'

        let args = [];
        let label = '';

        if (type === 'port') {
            // 快速全端口
            args = ['-F', target];
            label = `快速端口扫描 (${target})`;
        } else if (type === 'service') {
            // 服务探测
            args = ['-sV', '--version-intensity', '5', target];
            label = `服务版本探测 (${target})`;
        } else if (type === 'alive') {
            // 强力探活 (ARP + TCP/ICMP)
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
});

const PORT = 3000;
server.listen(PORT, () => {
    console.log(`服务已启动: http://0.0.0.0:${PORT}`);
});