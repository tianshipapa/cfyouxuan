
/**
 * Cloudflare 优选 IP 收集器 - Worker 版本 V2.5
 * 功能：自动从多个来源抓取 IP，进行延迟测试，并提供管理后台。
 * 修改：/update 接口现已支持 GET 请求。
 */

// 配置项
const FAST_IP_COUNT = 25;       // 存储的优质 IP 数量
const AUTO_TEST_MAX_IPS = 200; // 自动测速时的最大处理 IP 数，防止超时

export default {
  /**
   * 定时触发任务：由 Cloudflare Triggers (Cron) 调用
   */
  async scheduled(event, env, ctx) {
    console.log('正在执行定时 IP 更新任务...');
    try {
      if (!env.IP_STORAGE) {
        console.error('未绑定 KV 命名空间 IP_STORAGE');
        return;
      }
      const { uniqueIPs, results } = await updateAllIPs(env);
      await env.IP_STORAGE.put('cloudflare_ips', JSON.stringify({
        ips: uniqueIPs,
        lastUpdated: new Date().toISOString(),
        count: uniqueIPs.length,
        sources: results
      }));
      // 执行自动测速
      await autoSpeedTestAndStore(env, uniqueIPs);
    } catch (error) {
      console.error('定时更新失败:', error);
    }
  },

  /**
   * HTTP 请求处理入口
   */
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    
    // 基础检查
    if (!env.IP_STORAGE) {
      return new Response('错误：未绑定 KV 命名空间 IP_STORAGE。请在 Worker 设置中进行绑定。', { status: 500 });
    }
    
    // 处理跨域请求
    if (request.method === 'OPTIONS') return handleCORS();

    try {
      switch (path) {
        case '/':
          return await serveHTML(env, request);
        case '/update':
          // 修改点：允许 GET 请求，方便浏览器直接访问
          return await handleUpdate(env, request, ctx);
        case '/ips':
        case '/ip.txt':
          return await handleGetIPs(env, request);
        case '/raw':
          return await handleRawIPs(env, request);
        case '/speedtest':
          return await handleSpeedTest(request, env);
        case '/itdog-data':
          return await handleItdogData(env, request);
        case '/fast-ips':
          return await handleGetFastIPs(env, request);
        case '/fast-ips.txt':
          return await handleGetFastIPsText(env, request);
        case '/admin-login':
          return await handleAdminLogin(request, env);
        case '/admin-status':
          return await handleAdminStatus(env);
        case '/admin-logout':
          return await handleAdminLogout();
        case '/admin-token':
          return await handleAdminToken(request, env);
        default:
          return jsonResponse({ error: '接口不存在' }, 404);
      }
    } catch (error) {
      return jsonResponse({ error: error.message }, 500);
    }
  }
};

/** --- 管理员认证逻辑 --- **/

// 管理员登录
async function handleAdminLogin(request, env) {
  if (request.method !== 'POST') return jsonResponse({ error: '方法不允许' }, 405);
  const { password } = await request.json();
  
  if (!env.ADMIN_PASSWORD) {
    return jsonResponse({ success: false, error: '未配置 ADMIN_PASSWORD 环境变量' }, 400);
  }

  if (password === env.ADMIN_PASSWORD) {
    let tokenConfig = await getTokenConfig(env);
    // 如果没有 Token 则初始化一个
    if (!tokenConfig) {
      tokenConfig = {
        token: generateRandomString(32),
        expires: new Date(Date.now() + 30 * 86400000).toISOString(),
        createdAt: new Date().toISOString(),
        lastUsed: null
      };
      await env.IP_STORAGE.put('token_config', JSON.stringify(tokenConfig));
    }
    // 生成临时 Session
    const sessionId = generateRandomString(32);
    await env.IP_STORAGE.put(`session_${sessionId}`, JSON.stringify({ loggedIn: true }), { expirationTtl: 86400 });
    return jsonResponse({ success: true, sessionId, tokenConfig });
  }
  return jsonResponse({ success: false, error: '密码错误' }, 401);
}

// Token 管理
async function handleAdminToken(request, env) {
  if (!await verifyAdmin(request, env)) return jsonResponse({ error: '未授权' }, 401);
  
  if (request.method === 'GET') {
    return jsonResponse({ tokenConfig: await getTokenConfig(env) });
  }
  
  if (request.method === 'POST') {
    const { token, expiresDays, neverExpire } = await request.json();
    const expiresDate = neverExpire 
      ? new Date(Date.now() + 315360000000).toISOString() // 约10年
      : new Date(Date.now() + expiresDays * 86400000).toISOString();
      
    const config = { 
      token: token.trim(), 
      expires: expiresDate, 
      createdAt: new Date().toISOString(), 
      lastUsed: null, 
      neverExpire 
    };
    await env.IP_STORAGE.put('token_config', JSON.stringify(config));
    return jsonResponse({ success: true, tokenConfig: config });
  }
}

// 身份验证核心函数 (支持 Session 和 Token)
async function verifyAdmin(request, env) {
  if (!env.ADMIN_PASSWORD) return true; // 未设密码则开放访问
  
  const url = new URL(request.url);
  const authHeader = request.headers.get('Authorization');
  
  // 1. 检查 Session (通常用于网页后台)
  const sessionId = url.searchParams.get('session') || (authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null);
  if (sessionId) {
    const session = await env.IP_STORAGE.get(`session_${sessionId}`);
    if (session) return true;
  }

  // 2. 检查持久化 Token (通常用于 API 调用)
  const tokenConfig = await getTokenConfig(env);
  if (tokenConfig) {
    const requestToken = url.searchParams.get('token') || (authHeader?.startsWith('Token ') ? authHeader.slice(6) : null);
    if (requestToken === tokenConfig.token) {
      // 检查有效期
      if (!tokenConfig.neverExpire && new Date(tokenConfig.expires) < new Date()) return false;
      // 异步更新最后使用时间
      tokenConfig.lastUsed = new Date().toISOString();
      await env.IP_STORAGE.put('token_config', JSON.stringify(tokenConfig));
      return true;
    }
  }
  return false;
}

/** --- 核心功能逻辑 --- **/

// 处理 IP 更新请求
async function handleUpdate(env, request, ctx) {
  if (!await verifyAdmin(request, env)) return jsonResponse({ error: '未授权访问' }, 401);
  
  const startTime = Date.now();
  const { uniqueIPs, results } = await updateAllIPs(env);
  
  // 存储到 KV
  await env.IP_STORAGE.put('cloudflare_ips', JSON.stringify({
    ips: uniqueIPs,
    lastUpdated: new Date().toISOString(),
    count: uniqueIPs.length,
    sources: results
  }));

  // 使用 ctx.waitUntil 触发测速，不阻塞当前响应返回
  ctx.waitUntil(autoSpeedTestAndStore(env, uniqueIPs));

  return jsonResponse({
    success: true,
    totalIPs: uniqueIPs.length,
    duration: `${Date.now() - startTime}ms`,
    timestamp: new Date().toISOString(),
    message: 'IP 采集完成，测速任务已在后台启动'
  });
}

// 从多个源抓取 IP
async function updateAllIPs(env) {
  const sources = [
    'https://ip.164746.xyz',
    'https://ip.haogege.xyz/',
    'https://stock.hostmonit.com/CloudFlareYes',
    'https://api.uouin.com/cloudflare.html',
    'https://addressesapi.090227.xyz/CloudFlareYes',
    'https://www.wetest.vip/page/cloudflare/address_v4.html'
  ];

  const uniqueIPs = new Set();
  const results = [];
  const ipPattern = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;

  for (const url of sources) {
    try {
      const res = await fetch(url, { 
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
        signal: AbortSignal.timeout(10000) 
      });
      const text = await res.text();
      const matches = text.match(ipPattern) || [];
      let validCount = 0;
      matches.forEach(ip => {
        if (isValidIPv4(ip)) {
          uniqueIPs.add(ip);
          validCount++;
        }
      });
      results.push({ name: new URL(url).hostname, status: 'success', count: validCount });
    } catch (e) {
      results.push({ name: url, status: 'error', error: e.message });
    }
  }

  // 排序 IP
  const sorted = Array.from(uniqueIPs).sort((a, b) => {
    const aP = a.split('.').map(Number);
    const bP = b.split('.').map(Number);
    for (let i = 0; i < 4; i++) {
      if (aP[i] !== bP[i]) return aP[i] - bP[i];
    }
    return 0;
  });

  return { uniqueIPs: sorted, results };
}

// 自动测速并保存优质 IP
async function autoSpeedTestAndStore(env, ips) {
  const toTest = ips.slice(0, AUTO_TEST_MAX_IPS);
  const results = [];
  const BATCH_SIZE = 10; // 并发测速数量

  for (let i = 0; i < toTest.length; i += BATCH_SIZE) {
    const batch = toTest.slice(i, i + BATCH_SIZE).map(async ip => {
      const start = Date.now();
      try {
        const res = await fetch('https://speed.cloudflare.com/__down?bytes=0', { 
          cf: { resolveOverride: ip }, 
          signal: AbortSignal.timeout(2000) 
        });
        if (res.ok) return { ip, latency: Date.now() - start };
      } catch {}
      return null;
    });
    const finished = await Promise.all(batch);
    results.push(...finished.filter(Boolean));
  }

  const fastIPs = results
    .sort((a, b) => a.latency - b.latency)
    .slice(0, FAST_IP_COUNT);

  await env.IP_STORAGE.put('cloudflare_fast_ips', JSON.stringify({
    fastIPs,
    lastTested: new Date().toISOString(),
    count: fastIPs.length
  }));
}

/** --- 通用辅助函数 --- **/

// IPv4 合法性校验 (排除私有地址)
function isValidIPv4(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  const n = parts.map(Number);
  if (n.some(isNaN) || n.some(p => p < 0 || p > 255)) return false;
  // 排除局域网地址
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('127.')) return false;
  if (ip.startsWith('172.') && n[1] >= 16 && n[1] <= 31) return false;
  return true;
}

// 生成随机字符串
function generateRandomString(len) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let res = '';
  for (let i = 0; i < len; i++) res += chars.charAt(Math.floor(Math.random() * chars.length));
  return res;
}

// 获取 Token 配置
async function getTokenConfig(env) {
  const val = await env.IP_STORAGE.get('token_config');
  return val ? JSON.parse(val) : null;
}

// 返回 JSON 格式响应
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
  });
}

// 处理 CORS
function handleCORS() {
  return new Response(null, {
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    }
  });
}

/** --- 接口处理逻辑 --- **/

// 获取全部 IP (文本格式)
async function handleGetIPs(env, request) {
  if (!await verifyAdmin(request, env)) return jsonResponse({ error: '未授权' }, 401);
  const data = await env.IP_STORAGE.get('cloudflare_ips');
  const ips = data ? JSON.parse(data).ips : [];
  return new Response(ips.join('\n'), { headers: { 'Content-Type': 'text/plain' } });
}

// 获取优质 IP (JSON 格式)
async function handleGetFastIPs(env, request) {
  if (!await verifyAdmin(request, env)) return jsonResponse({ error: '未授权' }, 401);
  const data = await env.IP_STORAGE.get('cloudflare_fast_ips');
  return new Response(data || '{"fastIPs":[]}', { headers: { 'Content-Type': 'application/json' } });
}

// 获取优质 IP (文本格式 IP#延迟)
async function handleGetFastIPsText(env, request) {
  if (!await verifyAdmin(request, env)) return jsonResponse({ error: '未授权' }, 401);
  const data = await env.IP_STORAGE.get('cloudflare_fast_ips');
  const fast = data ? JSON.parse(data).fastIPs : [];
  return new Response(fast.map(i => `${i.ip}#${i.latency}ms`).join('\n'), { headers: { 'Content-Type': 'text/plain' } });
}

// 获取原始数据
async function handleRawIPs(env, request) {
  if (!await verifyAdmin(request, env)) return jsonResponse({ error: '未授权' }, 401);
  const data = await env.IP_STORAGE.get('cloudflare_ips');
  return new Response(data || '{}', { headers: { 'Content-Type': 'application/json' } });
}

async function handleAdminStatus(env) {
  return jsonResponse({ 
    hasAdminPassword: !!env.ADMIN_PASSWORD, 
    tokenConfig: await getTokenConfig(env) 
  });
}

async function handleAdminLogout() { return jsonResponse({ success: true }); }

async function handleItdogData(env, request) {
  if (!await verifyAdmin(request, env)) return jsonResponse({ error: '未授权' }, 401);
  const data = await env.IP_STORAGE.get('cloudflare_ips');
  return jsonResponse({ ips: data ? JSON.parse(data).ips : [] });
}

// 单次 IP 测速接口
async function handleSpeedTest(request, env) {
  const ip = new URL(request.url).searchParams.get('ip');
  if (!ip) return jsonResponse({ error: '需要 IP 参数' }, 400);
  const start = Date.now();
  try {
    const res = await fetch('https://speed.cloudflare.com/__down?bytes=0', { 
      cf: { resolveOverride: ip }, 
      signal: AbortSignal.timeout(3000) 
    });
    return jsonResponse({ success: res.ok, latency: Date.now() - start });
  } catch (e) { 
    return jsonResponse({ success: false, error: e.message }); 
  }
}

// 渲染前端 HTML 页面
async function serveHTML(env, request) {
  // 注意：在实际部署中，这里通常会返回一个包含 React 代码的 HTML 模板。
  // 为了确保此脚本可运行，我已配置它返回一个简单的控制台入口，或你可以将前端 build 后的 index.html 内容放在这里。
  return new Response(`
    <!DOCTYPE html>
    <html>
    <head><title>CF IP Collector</title></head>
    <body style="font-family: sans-serif; text-align: center; padding-top: 50px;">
      <h1>Cloudflare 优选 IP 收集器 V2.5</h1>
      <p>管理后台已启动。请使用配套的前端页面或通过 /update 接口进行操作。</p>
      <a href="/update" style="color: blue; text-decoration: underline;">手动触发采集 (GET /update)</a>
    </body>
    </html>
  `, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}
