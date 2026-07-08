// Chinese translations keyed by the source English string (natural-language
// keys). English is the source language, so only this map is needed.
export const zh: Record<string, string> = {
  // Chrome
  Language: '语言',
  Light: '浅色',
  Dark: '深色',
  System: '跟随系统',
  Theme: '主题',

  // Page
  'Challenge / identify playground': 'Challenge / identify 调试台',
  'Run the collect-only client flow against a fingerprintd server and inspect what it sends and what the server judges.':
    '对 fingerprintd 服务端运行「仅采集」的客户端流程，查看它提交了什么、服务端如何判定。',

  // Run panel
  'Server base URL': '服务端 Base URL',
  'Signing key (optional)': '签名密钥（可选）',
  'UTF-8 signing key to verify the T9 response signature':
    '用于校验 T9 响应签名的 UTF-8 密钥',
  'Run flow': '运行流程',
  'Running…': '运行中…',
  Reset: '重置',
  'Enter a server base URL first.': '请先填写服务端 Base URL。',
  'Flow failed': '流程失败',

  // Challenge
  Challenge: '挑战',
  nonce: 'nonce',
  'expires in': '有效期',
  targets: '采集目标',
  seconds: '秒',

  // Identity
  Identity: '身份',
  Confidence: '置信度',
  Decision: '判定',
  'New device': '新设备',
  'Collision risk': '碰撞风险',
  Signals: '信号',
  'UA / TLS consistent': 'UA / TLS 一致',
  'IP risk': 'IP 风险',
  Yes: '是',
  No: '否',
  match: '匹配',
  review: '待审',
  new_device: '新设备',

  // Evidence lanes
  'Collected evidence': '采集到的证据',
  'Stable components': 'Stable components',
  'the "who is this device" matching input': '用于「这是哪台设备」匹配的输入',
  'Challenge response': 'Challenge response',
  'nonce-seeded freshness proof — never a matching signal':
    'nonce 播种的新鲜度证明 — 绝不作为匹配信号',
  Probe: 'Probe',
  'hex(HMAC-SHA256(key, nonce)) computed in WASM':
    '在 WASM 中计算的 hex(HMAC-SHA256(key, nonce))',
  'Timestamp (ts)': '时间戳 (ts)',
  'client clock at collection': '采集时的客户端时钟',
  'not sent': '未发送',

  // Signature
  'Response signature': '响应签名',
  Signed: '已签名',
  Timestamp: '时间戳',
  Signature: '签名',
  Verified: '已校验',
  'not verified (no key)': '未校验（无密钥）',
  'Server did not sign this response.': '服务端未对此响应签名。',

  // Empty state
  'No run yet': '尚未运行',
  'Fill in a server base URL and run the flow to see the result here.':
    '填写服务端 Base URL 并运行流程，结果将显示在此处。',
}
