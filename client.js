/**
 * dsh-remote-relay 客户端半边（v0.4）。
 *
 * 参考远程桌面软件（RustDesk/ToDesk）的布局：
 *  - 允许控制本设备开关
 *  - 设备代码（默认打码，可点眼睛显示/复制）+ 设备别名（可自定义，对方看到别名）
 *  - 连接密码：永久密码（可自定义/随机生成，默认打码）+ 临时随机密码（可显示/刷新）
 *  - 远程控制设备：输入设备代码（或 IP:端口）+ 密码输入框 + 连接按钮
 *  - 权限开关、已配对节点、待授权请求（自动弹窗）
 *
 * 注意：
 *  - load 的 id 必须等于包名 dsh-remote-relay。
 *  - 数据走宿主同源路由 /dsh-remote-relay/*；host 侧的 state 已脱敏（不含账号指纹/监听端口）。
 *  - 敏感信息（设备代码、密码）默认打码，点眼睛才显示。
 */
window.__ModuleLoader__.load({
  id: 'dsh-remote-relay',
  factory: (require) => {
    var module = { exports: {} }
    var exports = module.exports
    Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' })

    const React = require('react')
    let UI = null
    try {
      UI = require('@deepseek-ai/dsh-client-ui-primitives')
    } catch {
      UI = null
    }
    const h = React.createElement

    const STATE_URL = '/dsh-remote-relay/state'
    const POLL_MS = 3000

    const mono = { fontFamily: 'ui-monospace, SFMono-Regular, Consolas, monospace' }
    const meta = { color: 'var(--dsw-alias-label-secondary, #8b949e)' }
    const sectionTitle = { fontWeight: 600, fontSize: 13, marginTop: 2 }
    const cardStyle = {
      border: '1px solid var(--dsw-alias-border-l1, #30363d)',
      borderRadius: 10,
      padding: '12px 14px',
      display: 'grid',
      gap: 8,
      background: 'var(--dsw-alias-bg-layer-1, transparent)',
    }
    const inputStyle = {
      width: '100%',
      boxSizing: 'border-box',
      padding: '7px 10px',
      borderRadius: 8,
      border: '1px solid var(--dsw-alias-border-l1, #30363d)',
      background: 'var(--dsw-alias-bg-layer-1, transparent)',
      color: 'inherit',
      fontSize: 13,
      outline: 'none',
    }
    const iconBtn = {
      border: '1px solid var(--dsw-alias-border-l1, #30363d)',
      background: 'transparent',
      borderRadius: 7,
      padding: '3px 8px',
      cursor: 'pointer',
      color: 'inherit',
      fontSize: 12,
    }

    // 打码文本：默认显示 •••，点「显示」切换
    function Secret({ value, length }) {
      const [show, setShow] = React.useState(false)
      const text = value ? (show ? value : '•'.repeat(Math.min(12, Math.max(6, length || 8)))) : '(未设置)'
      return h(
        'span',
        { style: { display: 'inline-flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' } },
        h('code', { style: { ...mono, fontSize: 13 } }, text),
        value
          ? h('button', { type: 'button', style: iconBtn, onClick: () => setShow((s) => !s) }, show ? '隐藏' : '显示')
          : null,
      )
    }

    function CopyBtn({ text, label }) {
      const [done, setDone] = React.useState(false)
      const copy = async () => {
        try {
          if (UI && typeof UI.writeClipboard === 'function') await UI.writeClipboard(text)
          else await navigator.clipboard.writeText(text)
          setDone(true)
          setTimeout(() => setDone(false), 1200)
        } catch {
          /* ignore */
        }
      }
      return h('button', { type: 'button', style: iconBtn, onClick: copy, disabled: !text }, done ? '已复制' : label || '复制')
    }

    function RelayPanel({ close }) {
      const [state, setState] = React.useState(null)
      const [err, setErr] = React.useState('')
      const [notice, setNotice] = React.useState('')
      const [busy, setBusy] = React.useState(false)
      const [modalCode, setModalCode] = React.useState(null)
      const seenRef = React.useRef(new Set())
      const mountedRef = React.useRef(true)

      // 远程控制设备表单
      const [target, setTarget] = React.useState('')
      const [targetPassword, setTargetPassword] = React.useState('')
      const [mode, setMode] = React.useState('control')
      // 别名 / 永久密码编辑
      const [aliasDraft, setAliasDraft] = React.useState('')
      const [passwordDraft, setPasswordDraft] = React.useState('')
      const aliasInit = React.useRef(false)
      const passwordInit = React.useRef(false)

      const load = React.useCallback(async () => {
        try {
          const r = await fetch(STATE_URL, { cache: 'no-store' })
          if (!r.ok) throw new Error('HTTP ' + r.status)
          const data = await r.json()
          if (!mountedRef.current) return
          setState(data)
          setErr('')
        } catch (e) {
          if (mountedRef.current) setErr(String((e && e.message) || e))
        }
      }, [])

      React.useEffect(() => {
        mountedRef.current = true
        load()
        const timer = setInterval(load, POLL_MS)
        return () => {
          mountedRef.current = false
          clearInterval(timer)
        }
      }, [load])

      // 回填别名/密码草稿（仅首次）
      React.useEffect(() => {
        if (!state) return
        if (!aliasInit.current) {
          aliasInit.current = true
          setAliasDraft((state.identity && state.identity.alias) || '')
        }
        if (!passwordInit.current) {
          passwordInit.current = true
          setPasswordDraft(state.password || '')
        }
      }, [state])

      // 新待授权请求 → 弹窗
      React.useEffect(() => {
        if (!state || !Array.isArray(state.pending)) return
        const fresh = state.pending.filter((p) => p && p.code && !seenRef.current.has(p.code))
        if (fresh.length === 0) return
        fresh.forEach((p) => seenRef.current.add(p.code))
        if (!modalCode) setModalCode(fresh[0].code)
      }, [state, modalCode])

      const post = async (path, body) => {
        const res = await fetch(path, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(body || {}),
        })
        let data = {}
        try {
          data = await res.json()
        } catch {
          /* 非 JSON */
        }
        if (!res.ok) throw new Error((data && data.error) || 'HTTP ' + res.status)
        return data
      }

      const guard = async (fn) => {
        if (busy) return
        setBusy(true)
        setErr('')
        try {
          await fn()
          await load()
        } catch (e) {
          setErr(String((e && e.message) || e))
        } finally {
          if (mountedRef.current) setBusy(false)
        }
      }
      const flash = (s) => {
        setNotice(s)
        setTimeout(() => setNotice(''), 2500)
      }

      const btn = (label, onClick, opts) =>
        UI && UI.Button
          ? h(UI.Button, { variant: 'outline', size: 'sm', disabled: busy, onClick, ...(opts || {}) }, label)
          : h('button', { type: 'button', disabled: busy, onClick, style: iconBtn }, label)

      const setAlias = () =>
        guard(async () => {
          const out = await post('/dsh-remote-relay/alias', { alias: aliasDraft })
          flash('别名已保存：' + out.alias)
        })
      const setPassword = () =>
        guard(async () => {
          await post('/dsh-remote-relay/password', { action: 'set', password: passwordDraft })
          flash('永久密码已保存')
        })
      const genPassword = () =>
        guard(async () => {
          const out = await post('/dsh-remote-relay/password', { action: 'generate' })
          setPasswordDraft(out.password)
          flash('已生成随机永久密码')
        })
      const refreshTemp = () =>
        guard(async () => {
          await post('/dsh-remote-relay/temp-password')
          flash('临时密码已刷新')
        })
      const toggleControl = (next) =>
        guard(async () => {
          await post('/dsh-remote-relay/control', { allowControl: next })
          flash(next ? '已允许控制本设备' : '已禁止控制本设备')
        })
      const toggleOption = (key, value) =>
        guard(async () => {
          await post('/dsh-remote-relay/options', { [key]: value })
        })
      const approve = (code) =>
        guard(async () => {
          await post('/dsh-remote-relay/approve', { code })
          setModalCode(null)
          flash('已同意配对')
        })
      const reject = (code) =>
        guard(async () => {
          await post('/dsh-remote-relay/reject', { code })
          setModalCode(null)
        })
      const unpair = (nodeId) =>
        guard(async () => {
          await post('/dsh-remote-relay/unpair', { nodeId })
          flash('已解除配对')
        })
      const connectRemote = () =>
        guard(async () => {
          if (!target.trim()) throw new Error('请填写设备代码或 IP:端口')
          const out = await post('/dsh-remote-relay/connect', { target: target.trim(), password: targetPassword })
          if (out.paired) {
            flash('已连接 ' + (out.hostname || out.nodeId))
            setTarget('')
            setTargetPassword('')
          } else {
            flash('对方需要确认，配对码 ' + out.code)
          }
        })

      const pendingItem = state && modalCode ? (state.pending || []).find((p) => p.code === modalCode) : null
      const modal =
        pendingItem && UI && UI.Modal
          ? h(
              UI.Modal,
              {
                open: true,
                onClose: () => setModalCode(null),
                title: '远程协助请求',
                footer: [
                  h('span', { key: 'spacer', style: { flex: 1 } }),
                  btn('拒绝', () => reject(pendingItem.code), { key: 'reject' }),
                  UI.Button
                    ? h(UI.Button, { key: 'ok', variant: 'primary', size: 'sm', disabled: busy, onClick: () => approve(pendingItem.code) }, '同意')
                    : h('button', { key: 'ok', type: 'button', onClick: () => approve(pendingItem.code) }, '同意'),
                ],
              },
              h(
                'div',
                { style: { display: 'grid', gap: 6 } },
                h('div', null, h('span', { style: { fontWeight: 600 } }, pendingItem.hostname || pendingItem.nodeId), ' 请求远程协助你'),
                h('div', { style: meta }, '来自 ' + (pendingItem.host || '?') + '，同意后对方可执行命令、查看系统状态与屏幕、传输文件。'),
                h('div', { style: { ...meta, ...mono } }, '设备代码 ' + pendingItem.nodeId + ' · 配对码 ' + pendingItem.code),
              ),
            )
          : null

      if (!state) {
        return h(
          'div',
          { style: { display: 'grid', gap: 10 } },
          h('div', null, '正在读取远程协助状态…'),
          err ? h('div', { style: { color: 'var(--dsw-alias-label-error, #f85149)' } }, err) : null,
          modal,
        )
      }

      const identity = state.identity || {}
      const peers = state.peers || []
      const pending = state.pending || []
      const options = state.options || {}
      const allowControl = state.allowControl !== false

      const pendingRow = (p) =>
        h(
          'div',
          { key: p.code, style: { display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' } },
          h(
            'span',
            null,
            h('span', { style: { fontWeight: 600 } }, p.hostname || p.nodeId),
            ' · ',
            h('span', { style: { ...meta, ...mono } }, p.host || '?'),
            ' · 配对码 ',
            h('span', { style: mono }, p.code),
          ),
          h('span', { style: { flex: 1 } }),
          btn('拒绝', () => reject(p.code)),
          UI && UI.Button
            ? h(UI.Button, { variant: 'primary', size: 'sm', disabled: busy, onClick: () => approve(p.code) }, '同意')
            : h('button', { type: 'button', onClick: () => approve(p.code) }, '同意'),
        )

      const peerRow = (p) =>
        h(
          'div',
          { key: p.nodeId, style: { display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' } },
          h(
            'span',
            null,
            h('span', { style: { fontWeight: 600 } }, p.hostname || p.nodeId),
            ' · ',
            h('span', { style: { ...meta, ...mono } }, p.host || '?'),
            ' · ',
            p.viaPassword ? '密码直连' : p.auto ? '自动配对' : '手动授权',
          ),
          h('span', { style: { flex: 1 } }),
          btn('解除', () => unpair(p.nodeId)),
        )

      const optionRow = (key, label, desc) =>
        h(
          'div',
          { key, style: { display: 'flex', gap: 10, alignItems: 'center' } },
          h('div', { style: { flex: 1 } }, h('div', null, label), h('div', { style: { ...meta, fontSize: 12 } }, desc)),
          UI && UI.Switch
            ? h(UI.Switch, { checked: options[key] !== false, onChange: (next) => toggleOption(key, next) })
            : h('input', { type: 'checkbox', checked: options[key] !== false, onChange: (e) => toggleOption(key, e.target.checked) }),
        )

      const modeOption = (key, label) =>
        h(
          'label',
          { key, style: { display: 'inline-flex', gap: 6, alignItems: 'center', cursor: 'pointer', ...meta, fontSize: 12 } },
          h('input', { type: 'radio', name: 'relay-mode', checked: mode === key, onChange: () => setMode(key) }),
          label,
        )

      return h(
        'div',
        { style: { display: 'grid', gap: 18, fontSize: 13 } },

        // 1) 允许控制本设备
        h(
          'div',
          { style: { ...cardStyle, gridTemplateColumns: '1fr auto', alignItems: 'center' } },
          h(
            'div',
            null,
            h('div', { style: { fontWeight: 600, fontSize: 14 } }, '允许控制本设备'),
            h('div', { style: { ...meta, fontSize: 12 } }, allowControl ? '开启中：对方可请求连接（不同账号仍需你同意）' : '已关闭：拒绝一切配对与远程操作'),
          ),
          UI && UI.Switch
            ? h(UI.Switch, { checked: allowControl, onChange: toggleControl })
            : h('input', { type: 'checkbox', checked: allowControl, onChange: (e) => toggleControl(e.target.checked) }),
        ),

        // 2) 设备代码 + 别名
        h(
          'div',
          { style: cardStyle },
          h(
            'div',
            { style: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, alignItems: 'start' } },
            h(
              'div',
              { style: { display: 'grid', gap: 4 } },
              h('div', { style: { ...meta, fontSize: 12 } }, '设备代码（对方输入这个连接）'),
              h(
                'div',
                { style: { display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' } },
                h('span', { style: { ...mono, fontSize: 20, letterSpacing: 1 } }, h(Secret, { value: identity.nodeId, length: 9 })),
                h(CopyBtn, { text: identity.nodeId, label: '复制' }),
              ),
            ),
            h(
              'div',
              { style: { display: 'grid', gap: 4 } },
              h('div', { style: { ...meta, fontSize: 12 } }, '设备别名（对方看到的名字）'),
              h(
                'div',
                { style: { display: 'flex', gap: 6, alignItems: 'center' } },
                h('input', { style: inputStyle, value: aliasDraft, maxLength: 32, placeholder: '自定义别名', onChange: (e) => setAliasDraft(e.target.value) }),
                btn('保存', setAlias),
              ),
            ),
          ),
          h('div', { style: { ...meta, fontSize: 12 } }, '账号指纹、监听端口等敏感信息已从界面隐藏，仅插件内部使用。'),
        ),

        // 3) 连接密码
        h(
          'div',
          { style: cardStyle },
          h('div', { style: sectionTitle }, '连接密码'),
          h(
            'div',
            { style: { display: 'grid', gap: 10 } },
            h(
              'div',
              { style: { display: 'grid', gap: 4 } },
              h('div', { style: { ...meta, fontSize: 12 } }, '永久密码（对方凭此密码可直接连接，无需确认）'),
              h(
                'div',
                { style: { display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' } },
                h('input', {
                  style: { ...inputStyle, flex: '1 1 200px', minWidth: 160 },
                  type: 'text',
                  value: passwordDraft,
                  placeholder: '自定义永久密码（留空=不使用）',
                  onChange: (e) => setPasswordDraft(e.target.value),
                }),
                btn('保存', setPassword),
                btn('随机生成', genPassword),
                h(CopyBtn, { text: state.password || '', label: '复制' }),
                h(Secret, { value: state.password, length: state.password ? state.password.length : 8 }),
              ),
            ),
            h(
              'div',
              { style: { display: 'grid', gap: 4 } },
              h('div', { style: { ...meta, fontSize: 12 } }, '临时随机密码（一次性，用后自动更换）'),
              h(
                'div',
                { style: { display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' } },
                h(Secret, { value: state.tempPassword, length: 6 }),
                btn('刷新', refreshTemp),
                h(CopyBtn, { text: state.tempPassword || '', label: '复制' }),
              ),
            ),
          ),
        ),

        // 4) 远程控制设备
        h(
          'div',
          { style: cardStyle },
          h('div', { style: sectionTitle }, '远程控制设备'),
          h(
            'div',
            { style: { display: 'grid', gap: 8 } },
            h(
              'div',
              { style: { display: 'flex', gap: 8, flexWrap: 'wrap' } },
              h('input', {
                style: { ...inputStyle, flex: '1 1 220px', minWidth: 180 },
                value: target,
                placeholder: '输入对方设备代码，或 IP:端口（如 192.168.1.72:37261）',
                onChange: (e) => setTarget(e.target.value),
              }),
              h('input', {
                style: { ...inputStyle, flex: '0 1 180px', minWidth: 140 },
                value: targetPassword,
                placeholder: '对方密码（可选）',
                type: 'password',
                onChange: (e) => setTargetPassword(e.target.value),
              }),
              UI && UI.Button
                ? h(UI.Button, { variant: 'primary', size: 'md', disabled: busy, onClick: connectRemote }, '连接')
                : h('button', { type: 'button', disabled: busy, onClick: connectRemote, style: iconBtn }, '连接'),
            ),
            h('div', { style: { display: 'flex', gap: 16, alignItems: 'center' } },
              modeOption('control', '远程控制'),
              modeOption('transfer', '文件传输'),
              modeOption('collab', '协作模式'),
            ),
            h('div', { style: { ...meta, fontSize: 12 } }, '提示：对方需要已安装本插件并开启「允许控制本设备」；设置了永久密码时可免确认直接连接。'),
          ),
        ),

        // 5) 待授权请求
        h(
          'div',
          { style: { display: 'grid', gap: 8 } },
          h('div', { style: sectionTitle }, '待授权请求（' + pending.length + '）'),
          pending.length === 0 ? h('div', { style: meta }, '暂无。对方发起配对时会在这里出现，并自动弹窗。') : h('div', { style: cardStyle }, pending.map(pendingRow)),
        ),

        // 6) 已配对节点
        h(
          'div',
          { style: { display: 'grid', gap: 8 } },
          h('div', { style: sectionTitle }, '已配对节点（' + peers.length + '）'),
          peers.length === 0 ? h('div', { style: meta }, '还没有配对节点。') : h('div', { style: cardStyle }, peers.map(peerRow)),
        ),

        // 7) 权限开关
        h(
          'div',
          { style: { display: 'grid', gap: 8 } },
          h('div', { style: sectionTitle }, '被协助权限'),
          optionRow('allowExec', '允许远程执行命令', '对方可在此机器上执行 PowerShell（安装软件、排障、传文件）'),
          optionRow('allowScreenshot', '允许远程截图', '对方可读取当前屏幕画面'),
          optionRow('allowInject', '允许合作消息注入', '对方可把消息注入本机 DSH 下一轮上下文'),
        ),

        // 8) 文件接收目录
        h(
          'div',
          { style: { display: 'grid', gap: 6 } },
          h('div', { style: sectionTitle }, '文件接收'),
          h('div', { style: { ...meta, fontSize: 12 } }, '对方通过 remote_relay_upload / remote_relay_install_plugin 传过来的文件会保存到：'),
          h('code', { style: { ...mono, fontSize: 12, wordBreak: 'break-all' } }, state.inbox || '~/.dsh/remote-relay-inbox'),
        ),

        notice ? h('div', { style: { color: 'var(--dsw-alias-label-success, #3fb950)', fontSize: 12 } }, notice) : null,
        err ? h('div', { style: { color: 'var(--dsw-alias-label-error, #f85149)' } }, err) : null,
        h('div', { style: { display: 'flex', gap: 8 } },
          UI && UI.Button ? h(UI.Button, { variant: 'outline', size: 'sm', onClick: close }, '关闭') : h('button', { type: 'button', onClick: close, style: iconBtn }, '关闭'),
        ),

        modal,
      )
    }

    const inject = ['slots']

    function apply(ctx) {
      const slots = ctx && typeof ctx.get === 'function' ? ctx.get('slots') : ctx && ctx.slots
      if (!slots) return
      slots.inject('settings.section', () =>
        slots.register({ name: 'settings.section', id: 'remote-relay', order: 55, label: '远程协助' }, () => React.createElement(RelayPanel, {})),
      )
      try {
        slots.inject('plugins.bundle.config', () =>
          slots.register({ name: 'plugins.bundle.config', key: 'dsh-remote-relay' }, () => React.createElement(RelayPanel, {})),
        )
      } catch {
        /* 槽不存在时 inject 不触发，忽略 */
      }
    }

    exports.name = 'dsh-remote-relay'
    exports.inject = inject
    exports.apply = apply
    return module.exports
  },
})
