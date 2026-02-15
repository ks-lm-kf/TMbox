TMbox - 树莓派攻防控制台
========================

项目简介
--------
TMbox 是一个基于 Web 的实时监控仪表板，用于在树莓派/Linux 环境下监控系统状态并控制安全工具。
它提供了统一的界面来运行漏洞扫描器、网络工具和 Metasploit Framework，并通过 WebSocket 实时流式输出。

功能特性
--------
- 实时系统状态监控（CPU 负载、内存使用率）
- Nuclei 漏洞扫描器集成
- Nmap 端口扫描器集成
- Fscan 内网综合扫描工具集成
- Feroxbuster 目录爆破工具集成
- Sqlmap SQL 注入检测工具集成
- Metasploit Framework 专用控制台
- 网络拓扑可视化
- 多标签页终端输出
- 实时 WebSocket 通信

运行方法
--------
1. 安装依赖：
   npm install

2. 启动服务器：
   node server.js

3. 访问地址：
   http://localhost:3000
   或
   http://<设备IP>:3000

页面路由
--------
/           - 主仪表板（所有扫描工具）
/msf        - Metasploit 专用控制台
/topology   - 网络拓扑可视化

系统依赖
--------
需要安装以下工具并确保在 $PATH 中：
- nuclei      - 漏洞扫描器
- nmap        - 网络扫描器
- fscan       - 端口扫描器
- sqlmap      - SQL 注入工具
- msfconsole  - Metasploit Framework
- unbuffer    - 来自 expect 包，用于实时输出流

安装 unbuffer（Debian/Ubuntu）：
sudo apt install expect




项目截图
--------
![MSF功能展示](./images/screenshot.png)
![主界面截图](./images/907137fad01cc249b8ff2e261e5f7fb4.png)

版权声明
--------
本项目采用 GNU General Public License v3.0 (GPL v3) 协议开源。

本程序是自由软件：您可以根据自由软件基金会发布的 GNU 通用公共许可证的条款
（许可证的第3版或您选择的任何后续版本）重新分发和/或修改它。

分发本程序是希望它有用，但没有任何保证；甚至没有对适销性或特定用途适用性的暗示保证。
有关更多详细信息，请参阅 GNU 通用公共许可证。

特别声明：本软件仅供学习研究、安全测试和授权渗透测试使用。
          严禁用于任何商业用途。
          未经授权使用本软件进行攻击所产生的一切后果由使用者自行承担。
