# DSH 局域网远程协助（dsh-remote-assist-lan）

DeepSeek Harness 的**局域网远程协助 / 监督 / 合作**插件。

- **不走公网中继**：设备之间在局域网内直连，配对、命令、文件都不经过第三方服务器。
- **像远程桌面软件一样用**：设置页有设备代码、设备别名、永久/临时密码、连接输入框，对方凭密码可直接连。
- **授权可控**：同账号自动配对；不同账号**弹窗确认**；永久密码/临时密码直连；每个权限（执行/截图/注入）可单独关。
- **不止看屏幕**：远程执行 PowerShell、查系统状态、截屏、双向文件传输、**一键远程装插件**。

## 功能

- **发现**：UDP 广播自动发现同一局域网内的其他节点（也支持手动填 IP:端口）。
- **设置页**（设置 → 远程协助，或 插件详情页）：
  - 「允许控制本设备」总开关；
  - **设备代码**（默认打码，点「显示」才展开，可复制）；**设备别名**可自定义（对方看到的是别名）；
  - **连接密码**：永久密码（可自定义 / 随机生成 / 显示隐藏 / 复制）+ 临时随机密码（一次性，用后自动更换）；
  - **远程控制设备**：输入对方设备代码（或 `IP:端口`）+ 密码 + 连接按钮；
  - 待授权请求（对方发起配对时**自动弹窗**，点同意/拒绝）；
  - 已配对节点（可解除）；被协助权限开关；文件接收目录。
- **授权模型**：
  - **同账号**（同一 DeepSeek 账号，凭据 token 的 SHA-256 指纹一致）→ 自动配对；
  - 对方设置了**永久密码/临时密码** → 凭密码直接配对，无需确认；
  - 其他情况 → 被协助方 DSH **弹窗确认**（也可用 6 位配对码让模型 `remote_relay_approve`）。
- **远程能力**（配对后，HMAC-SHA256 签名调用）：
  - `remote_relay_exec`：在对面执行 PowerShell 命令；
  - `remote_relay_status`：查询对面系统状态（CPU/内存/运行时长）；
  - `remote_relay_screenshot`：截取对面屏幕（PNG base64）；
  - `remote_relay_upload` / `remote_relay_download`：双向文件传输（单文件上限 32MB）；
  - `remote_relay_install_plugin`：上传插件 tgz → 远程 `pnpm add` + 修复 bundles → 一步装好；
  - `remote_relay_list` / `remote_relay_pair` / `remote_relay_approve`：发现、配对、批准。

## 安全模型

**这是一个远程控制类插件，只安装你信任的来源，只与信任的人配对。**

1. 只接受**私网地址**（127/10/172.16-31/192.168/169.254）的连接；
2. 配对后所有远程调用要求 `X-Node-Id` + `X-Timestamp` + **HMAC-SHA256 签名**，时间戳窗口 5 分钟；
3. **不同账号默认需要被协助方确认**；永久/临时密码由本机设置，对方凭密码才可直接连；
4. 设置页数据源路由只允许**本机 loopback** + 同源 Origin，且**不下发配对密钥（token）**；账号指纹、监听端口不在界面显示；
5. 权限开关可随时关闭：`allowExec` / `allowScreenshot` / `allowInject`；关闭「允许控制本设备」即拒绝一切配对与远程操作；
6. **无公网中继**：所有流量只走局域网直连，不经过任何第三方服务器。

### 与「公网中继」方案的差异

部分同类插件通过公网中继站把 DSH 网页暴露给浏览器访问；本插件的取舍是：

- **不暴露 GUI**给网页访客，只提供受控的远程能力（执行/状态/截图/文件）；
- **不依赖公网和第三方服务器**，断网/内网即可用；
- 配对与权限状态保存在本机 `~/.dsh/remote-relay.json`，可随时解除。

## 安装

从插件市场安装（搜索「局域网远程协助」），或手动：

```powershell
$app  = "$env:LOCALAPPDATA\Programs\DeepSeek Harness\resources"
$node = "$app\runtime\primary-runtime\dependencies\node\bin\node.exe"
$pnpm = "$app\runtime\primary-runtime\dependencies\pnpm\bin\pnpm.cjs"
$prof = "$env:USERPROFILE\.dsh\profiles\desktop"

& $node $pnpm add dsh-remote-assist-lan --dir $prof
```

装完**完全退出并重启 DSH**（宿主与客户端 bundle 都是启动时收集，热重载无效）。

## 使用

1. 两台机器各自安装并重启 DSH；
2. 设置 → 远程协助：给对方看一眼**设备代码**（点显示），或让对方凭**永久密码**直接连；
3. 对话里让模型：
   - `remote_relay_list` 看发现到的节点；
   - `remote_relay_pair`（同账号自动 / 异账号对面弹窗确认 / 凭密码直连）；
   - `remote_relay_exec` / `remote_relay_status` / `remote_relay_screenshot` / `remote_relay_upload` / `remote_relay_download` / `remote_relay_install_plugin`。

例如远程装软件：

```
remote_relay_exec(nodeId: "<对面节点>", command: "Get-AppxPackage -Name '54311Bysyk.forWindows11'")
```

## 配置

`~/.dsh/remote-relay.json`：

```json
{
  "enabled": true,
  "port": 37261,
  "discoveryPort": 37262,
  "allowControl": true,
  "allowExec": true,
  "allowScreenshot": true,
  "allowInject": true,
  "alias": "",
  "pairPassword": "",
  "tempPassword": "",
  "peers": {},
  "pending": {}
}
```

- `port`：本机对外 HTTP 服务端口（0.0.0.0，给其它节点用）；
- `discoveryPort`：UDP 发现端口；
- 修改后重启 DSH 生效。

## 日志

`~/.dsh/remote-relay.log`（配对、执行、错误）。

## 隐私

- 数据只在本机与已配对节点之间传输，**不发送到任何第三方服务器**；
- 不收集遥测；
- 设置页的敏感信息（设备代码、密码）默认打码显示。

## License

MIT
