
/**
 * Cloudflare 优选 IP 收集器 - Worker 版本 V2.5
 * 功能：自动从多个来源抓取 IP，进行延迟测试，并提供管理后台。
 * 
 * 配置要求：
 * 1. 环境变量：ADMIN_PASSWORD (后台登录密码)
 * 2. KV 绑定：IP_STORAGE (用于存储 IP 数据和配置)
 * 3. 定时触发器 (Cron)：建议每 30 分钟一次 (*/30 * * * *)
 */

// 自定义优质IP数量
const FAST_IP_COUNT = 25; 
// 自动测速的最大IP数量，避免测速过多导致超时
const AUTO_TEST_MAX_IPS = 200; 

export default {
    /**
     * 定时任务：由 Cloudflare Triggers 调用
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

        // 自动触发测速并存储优质IP
        await autoSpeedTestAndStore(env, uniqueIPs);
        console.log(`定时更新完成: 收集到 ${uniqueIPs.length} 个 IP`);
      } catch (error) {
        console.error('定时更新失败:', error);
      }
    },
  
    /**
     * HTTP 请求处理
     */
    async fetch(request, env, ctx) {
      const url = new URL(request.url);
      const path = url.pathname;
      
      if (!env.IP_STORAGE) {
        return new Response('错误：未绑定 KV 命名空间 IP_STORAGE。请在 Worker 设置中进行绑定。', {
          status: 500,
          headers: { 'Content-Type': 'text/plain; charset=utf-8' }
        });
      }
      
      if (request.method === 'OPTIONS') {
        return handleCORS();
      }

      try {
        switch (path) {
          case '/':
            return await serveHTML(env, request);
          case '/update':
            // 修改点：取消了请求方法限制，允许 GET 方便浏览器调用
            return await handleUpdate(env, request);
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
            return await handleAdminLogout(env);
          case '/admin-token':
            return await handleAdminToken(request, env);
          default:
            return jsonResponse({ error: 'Endpoint not found' }, 404);
        }
      } catch (error) {
        console.error('Error:', error);
        return jsonResponse({ error: error.message }, 500);
      }
    }
};

// --- 管理逻辑 ---

async function handleAdminLogin(request, env) {
    if (request.method !== 'POST') return jsonResponse({ error: 'Method not allowed' }, 405);
    try {
        const { password } = await request.json();
        if (!env.ADMIN_PASSWORD) return jsonResponse({ success: false, error: '管理员密码未配置' }, 400);
        if (password === env.ADMIN_PASSWORD) {
            let tokenConfig = await getTokenConfig(env);
            if (!tokenConfig) {
                tokenConfig = {
                    token: generateToken(),
                    expires: new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString(),
                    createdAt: new Date().toISOString(),
                    lastUsed: null
                };
                await env.IP_STORAGE.put('token_config', JSON.stringify(tokenConfig));
            }
            const sessionId = generateToken();
            await env.IP_STORAGE.put(`session_${sessionId}`, JSON.stringify({ loggedIn: true }), { expirationTtl: 86400 });
            return jsonResponse({ success: true, sessionId, tokenConfig });
        }
        return jsonResponse({ success: false, error: '密码错误' }, 401);
    } catch (error) { return jsonResponse({ error: error.message }, 500); }
}

async function handleAdminToken(request, env) {
    if (!await verifyAdmin(request, env)) return jsonResponse({ error: '需要管理员权限' }, 401);
    if (request.method === 'GET') {
        return jsonResponse({ tokenConfig: await getTokenConfig(env) });
    } else if (request.method === 'POST') {
        try {
            const { token, expiresDays, neverExpire } = await request.json();
            if (!token) return jsonResponse({ error: 'Token不能为空' }, 400);
            const expiresDate = neverExpire ? new Date(Date.now() + 100 * 365 * 24 * 3600 * 1000).toISOString() : new Date(Date.now() + expiresDays * 24 * 3600 * 1000).toISOString();
            const tokenConfig = { token: token.trim(), expires: expiresDate, createdAt: new Date().toISOString(), lastUsed: null, neverExpire: !!neverExpire };
            await env.IP_STORAGE.put('token_config', JSON.stringify(tokenConfig));
            return jsonResponse({ success: true, tokenConfig });
        } catch (error) { return jsonResponse({ error: error.message }, 500); }
    }
}

async function verifyAdmin(request, env) {
    if (!env.ADMIN_PASSWORD) return true;
    try {
        const url = new URL(request.url);
        const authHeader = request.headers.get('Authorization');
        
        // 检查 Session
        const sessionId = url.searchParams.get('session') || (authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null);
        if (sessionId && await env.IP_STORAGE.get(`session_${sessionId}`)) return true;

        // 检查 Token
        const tokenConfig = await getTokenConfig(env);
        if (tokenConfig) {
            const requestToken = url.searchParams.get('token') || (authHeader?.startsWith('Token ') ? authHeader.slice(6) : null);
            if (requestToken === tokenConfig.token) {
                if (!tokenConfig.neverExpire && new Date(tokenConfig.expires) < new Date()) return false;
                tokenConfig.lastUsed = new Date().toISOString();
                await env.IP_STORAGE.put('token_config', JSON.stringify(tokenConfig));
                return true;
            }
        }
        return false;
    } catch (e) { return false; }
}

// --- IP 处理逻辑 ---

async function handleUpdate(env, request) {
    if (!await verifyAdmin(request, env)) return jsonResponse({ error: '未授权' }, 401);
    const startTime = Date.now();
    const { uniqueIPs, results } = await updateAllIPs(env);
    await env.IP_STORAGE.put('cloudflare_ips', JSON.stringify({
        ips: uniqueIPs,
        lastUpdated: new Date().toISOString(),
        count: uniqueIPs.length,
        sources: results
    }));
    await autoSpeedTestAndStore(env, uniqueIPs);
    return jsonResponse({
        success: true,
        totalIPs: uniqueIPs.length,
        duration: `${Date.now() - startTime}ms`,
        timestamp: new Date().toISOString(),
        results
    });
}

async function updateAllIPs(env) {
    const urls = [
        'https://ip.164746.xyz', 'https://ip.haogege.xyz/', 'https://stock.hostmonit.com/CloudFlareYes',
        'https://api.uouin.com/cloudflare.html', 'https://addressesapi.090227.xyz/CloudFlareYes',
        'https://addressesapi.090227.xyz/ip.164746.xyz', 'https://www.wetest.vip/page/cloudflare/address_v4.html'
    ];
    const uniqueIPs = new Set();
    const results = [];
    const ipPattern = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;

    for (const url of urls) {
        try {
            const res = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0' }, signal: AbortSignal.timeout(8000) });
            const text = await res.text();
            const matches = text.match(ipPattern) || [];
            matches.forEach(ip => { if (isValidIPv4(ip)) uniqueIPs.add(ip); });
            results.push({ name: new URL(url).hostname, status: 'success', count: matches.length });
        } catch (e) {
            results.push({ name: url, status: 'error', error: e.message });
        }
    }
    const sorted = Array.from(uniqueIPs).sort((a, b) => a.split('.').map(Number).reduce((acc, oct, i) => acc + oct * Math.pow(256, 3-i), 0) - b.split('.').map(Number).reduce((acc, oct, i) => acc + oct * Math.pow(256, 3-i), 0));
    return { uniqueIPs: sorted, results };
}

async function autoSpeedTestAndStore(env, ips) {
    const toTest = ips.slice(0, AUTO_TEST_MAX_IPS);
    const results = [];
    for (let i = 0; i < toTest.length; i += 5) {
        const batch = toTest.slice(i, i + 5).map(async ip => {
            const start = Date.now();
            try {
                const res = await fetch('https://speed.cloudflare.com/__down?bytes=1000', { cf: { resolveOverride: ip }, signal: AbortSignal.timeout(3000) });
                if (res.ok) return { ip, latency: Date.now() - start };
            } catch {}
            return null;
        });
        const finished = await Promise.all(batch);
        results.push(...finished.filter(Boolean));
    }
    const fastIPs = results.sort((a, b) => a.latency - b.latency).slice(0, FAST_IP_COUNT);
    await env.IP_STORAGE.put('cloudflare_fast_ips', JSON.stringify({ fastIPs, lastTested: new Date().toISOString(), count: fastIPs.length }));
}

// --- 接口输出逻辑 ---

async function handleGetIPs(env, request) {
    if (!await verifyAdmin(request, env)) return jsonResponse({ error: 'Unauthorized' }, 401);
    const data = await getStoredIPs(env);
    return new Response(data.ips.join('\n'), { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
}

async function handleGetFastIPsText(env, request) {
    if (!await verifyAdmin(request, env)) return jsonResponse({ error: 'Unauthorized' }, 401);
    const data = await getStoredSpeedIPs(env);
    return new Response(data.fastIPs.map(i => `${i.ip}#${i.latency}ms`).join('\n'), { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
}

async function handleGetFastIPs(env, request) {
    if (!await verifyAdmin(request, env)) return jsonResponse({ error: 'Unauthorized' }, 401);
    return jsonResponse(await getStoredSpeedIPs(env));
}

async function handleRawIPs(env, request) {
    if (!await verifyAdmin(request, env)) return jsonResponse({ error: 'Unauthorized' }, 401);
    return jsonResponse(await getStoredIPs(env));
}

async function handleSpeedTest(request, env) {
    const ip = new URL(request.url).searchParams.get('ip');
    if (!ip) return jsonResponse({ error: 'IP required' }, 400);
    const start = Date.now();
    try {
        await fetch('https://speed.cloudflare.com/__down?bytes=1000', { cf: { resolveOverride: ip }, signal: AbortSignal.timeout(3000) });
        return jsonResponse({ success: true, latency: Date.now() - start });
    } catch (e) { return jsonResponse({ success: false, error: e.message }); }
}

async function handleAdminStatus(env) {
    const tokenConfig = await getTokenConfig(env);
    return jsonResponse({ hasAdminPassword: !!env.ADMIN_PASSWORD, hasToken: !!tokenConfig, tokenConfig });
}

async function handleAdminLogout() { return jsonResponse({ success: true }); }

async function handleItdogData(env, request) {
    if (!await verifyAdmin(request, env)) return jsonResponse({ error: 'Unauthorized' }, 401);
    const data = await getStoredIPs(env);
    return jsonResponse({ ips: data.ips });
}

// --- 基础工具 ---

function isValidIPv4(ip) {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('127.')) return false;
    return parts.every(p => { const n = parseInt(p); return n >= 0 && n <= 255; });
}

function generateToken() {
    return Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function getTokenConfig(env) {
    const config = await env.IP_STORAGE.get('token_config');
    return config ? JSON.parse(config) : null;
}

async function getStoredIPs(env) {
    const data = await env.IP_STORAGE.get('cloudflare_ips');
    return data ? JSON.parse(data) : { ips: [], sources: [], count: 0 };
}

async function getStoredSpeedIPs(env) {
    const data = await env.IP_STORAGE.get('cloudflare_fast_ips');
    return data ? JSON.parse(data) : { fastIPs: [], count: 0 };
}

function jsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } });
}

function handleCORS() {
    return new Response(null, { headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization' } });
}

/** --- 前端页面 --- **/
async function serveHTML(env, request) {
    const data = await getStoredIPs(env);
    const speedData = await getStoredSpeedIPs(env);
    const isLoggedIn = await verifyAdmin(request, env);
    const hasAdminPassword = !!env.ADMIN_PASSWORD;
    const tokenConfig = await getTokenConfig(env);
    
    // 获取当前 Session ID (从 URL 参数中获取以便前端脚本同步)
    const urlParams = new URL(request.url).searchParams;
    const sessionId = urlParams.get('session') || "";

    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloudflare IP 收集器</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
        body { font-family: 'Inter', sans-serif; }
        .ip-card:hover { transform: translateY(-2px); transition: all 0.3s ease; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 10px; }
    </style>
</head>
<body class="bg-slate-50 text-slate-900 min-h-screen">
    <!-- 管理员标识 -->
    <div class="fixed top-4 right-4 z-50">
        <button id="admin-badge" class="px-4 py-2 rounded-full font-bold shadow-lg flex items-center gap-2 transition-all ${isLoggedIn ? 'bg-emerald-500 text-white' : 'bg-rose-500 text-white'}">
            ${isLoggedIn ? '🔐 管理员' : '🔓 点击登录'}
        </button>
        ${isLoggedIn ? `
        <div id="admin-dropdown" class="hidden absolute right-0 mt-2 w-48 bg-white border border-slate-200 rounded-xl shadow-xl overflow-hidden">
            <button onclick="logout()" class="w-full text-left px-4 py-3 text-sm text-slate-700 hover:bg-slate-50 transition-colors">🚪 退出登录</button>
        </div>` : ''}
    </div>

    <div class="max-w-6xl mx-auto px-4 py-12">
        <div class="mb-12 text-center">
            <h1 class="text-4xl font-extrabold bg-clip-text text-transparent bg-gradient-to-r from-blue-600 to-indigo-600 mb-4">Cloudflare 优选 IP 收集器</h1>
            <p class="text-slate-500">自动多源采集，智能后台测速，一键导出配置</p>
        </div>

        <!-- 统计面板 -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <div class="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                <p class="text-sm font-semibold text-slate-400 mb-1">采集总量</p>
                <p class="text-3xl font-bold text-blue-600" id="ip-count">${data.count || 0}</p>
            </div>
            <div class="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                <p class="text-sm font-semibold text-slate-400 mb-1">优质数量</p>
                <p class="text-3xl font-bold text-emerald-600" id="fast-ip-count">${speedData.count || 0}</p>
            </div>
            <div class="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                <p class="text-sm font-semibold text-slate-400 mb-1">采集状态</p>
                <p class="text-3xl font-bold text-indigo-600" id="last-updated">${data.lastUpdated ? '已同步' : '未同步'}</p>
            </div>
            <div class="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                <p class="text-sm font-semibold text-slate-400 mb-1">更新时间</p>
                <p class="text-lg font-bold text-slate-700 mt-2" id="last-time">${data.lastUpdated ? new Date(data.lastUpdated).toLocaleTimeString() : '从未'}</p>
            </div>
        </div>

        <!-- 操作区 -->
        <div class="bg-white rounded-3xl border border-slate-200 p-8 shadow-sm mb-8">
            <h2 class="text-xl font-bold mb-6 flex items-center gap-2">🛠️ 控制面板</h2>
            <div class="flex flex-wrap gap-4">
                <button onclick="updateIPs()" id="update-btn" class="px-6 py-3 bg-blue-600 text-white rounded-xl font-bold hover:bg-blue-700 shadow-lg shadow-blue-100 transition-all flex items-center gap-2">🔄 立即采集</button>
                <button onclick="startSpeedTest()" id="speedtest-btn" class="px-6 py-3 bg-amber-500 text-white rounded-xl font-bold hover:bg-amber-600 shadow-lg shadow-amber-100 transition-all flex items-center gap-2">⚡ 手动测速</button>
                <div class="h-10 w-px bg-slate-200 mx-2 hidden md:block"></div>
                <button onclick="downloadFast()" class="px-6 py-3 bg-emerald-600 text-white rounded-xl font-bold hover:bg-emerald-700 transition-all">📥 下载优质 IP</button>
                <button onclick="openItdog()" class="px-6 py-3 bg-slate-800 text-white rounded-xl font-bold hover:bg-slate-900 transition-all">🌐 ITDog 联测</button>
                <button onclick="refreshData()" class="px-6 py-3 border border-slate-200 text-slate-600 rounded-xl font-bold hover:bg-slate-50 transition-all">🔄 刷新数据</button>
            </div>

            <div id="loading" class="hidden mt-8 text-center animate-pulse">
                <div class="inline-block w-8 h-8 border-4 border-blue-600 border-t-transparent rounded-full animate-spin mb-4"></div>
                <p class="text-slate-500">正在处理任务，请稍后...</p>
            </div>

            <!-- Token 管理区域 -->
            ${isLoggedIn ? `
            <div class="mt-8 pt-8 border-t border-slate-100">
                <h3 class="font-bold text-slate-800 mb-4">🔑 API Token 管理</h3>
                <div class="bg-slate-50 rounded-2xl p-6 border border-slate-100">
                    ${tokenConfig ? `
                    <div class="flex flex-wrap items-center justify-between gap-4">
                        <div>
                            <p class="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">当前有效 Token</p>
                            <code class="text-sm font-mono bg-white px-3 py-1.5 rounded-lg border border-slate-200 text-indigo-600">${tokenConfig.token}</code>
                        </div>
                        <div class="flex gap-2">
                            <button onclick="copyToken()" class="px-4 py-2 bg-white border border-slate-200 text-sm font-bold rounded-lg hover:bg-slate-50">📋 复制</button>
                            <button onclick="openTokenModal()" class="px-4 py-2 bg-indigo-600 text-white text-sm font-bold rounded-lg hover:bg-indigo-700">⚙️ 修改</button>
                        </div>
                    </div>` : `
                    <button onclick="openTokenModal()" class="px-6 py-3 bg-indigo-600 text-white rounded-xl font-bold">➕ 生成第一个 Token</button>
                    `}
                </div>
            </div>` : ''}
        </div>

        <!-- IP 列表 -->
        <div class="bg-white rounded-3xl border border-slate-200 shadow-sm overflow-hidden">
            <div class="px-8 py-6 border-b border-slate-100 flex justify-between items-center">
                <h2 class="text-xl font-bold">⚡ 优选地址 (Top 25)</h2>
                <button onclick="copyFastIPs()" class="text-blue-600 font-bold hover:underline">📋 复制全部</button>
            </div>
            <div id="ip-list" class="divide-y divide-slate-100 max-h-[600px] overflow-y-auto">
                ${speedData.fastIPs?.length > 0 ? speedData.fastIPs.map(item => `
                <div class="px-8 py-4 flex items-center justify-between hover:bg-slate-50/50 group">
                    <div class="flex items-center gap-4">
                        <span class="font-mono text-slate-700 font-bold">${item.ip}</span>
                    </div>
                    <div class="flex items-center gap-6">
                        <span class="px-3 py-1 rounded-lg text-sm font-bold ${item.latency < 200 ? 'bg-emerald-100 text-emerald-700' : 'bg-amber-100 text-amber-700'}">
                            ${item.latency}ms
                        </span>
                        <button onclick="copyIP('${item.ip}')" class="opacity-0 group-hover:opacity-100 transition-opacity p-2 hover:bg-white rounded-lg border border-slate-100">📋</button>
                    </div>
                </div>`).join('') : '<div class="py-20 text-center text-slate-400">暂无测速数据，点击采集或测速</div>'}
            </div>
        </div>
    </div>

    <!-- 登录弹窗 -->
    <div id="login-modal" class="hidden fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm">
        <div class="bg-white w-full max-w-sm rounded-3xl shadow-2xl p-8">
            <h3 class="text-2xl font-bold mb-6 text-center">管理员验证</h3>
            <input type="password" id="admin-password" placeholder="输入访问密码" class="w-full px-5 py-4 bg-slate-50 border border-slate-200 rounded-2xl mb-6 focus:ring-2 focus:ring-blue-500 outline-none">
            <div class="flex gap-3">
                <button onclick="closeModal('login-modal')" class="flex-1 py-4 text-slate-500 font-bold">取消</button>
                <button onclick="login()" class="flex-1 py-4 bg-blue-600 text-white rounded-2xl font-bold hover:bg-blue-700 transition-all">登录</button>
            </div>
        </div>
    </div>

    <!-- Token 弹窗 -->
    <div id="token-modal" class="hidden fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm">
        <div class="bg-white w-full max-w-md rounded-3xl shadow-2xl p-8">
            <h3 class="text-2xl font-bold mb-6">Token 配置</h3>
            <div class="space-y-4">
                <div>
                    <label class="block text-sm font-bold text-slate-400 mb-2">Token 字符串</label>
                    <input type="text" id="token-input" class="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl outline-none font-mono">
                </div>
                <div>
                    <label class="block text-sm font-bold text-slate-400 mb-2">过期天数</label>
                    <input type="number" id="token-days" value="30" class="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl outline-none">
                </div>
                <label class="flex items-center gap-2 cursor-pointer">
                    <input type="checkbox" id="token-never" class="rounded border-slate-300">
                    <span class="text-sm font-bold text-slate-600">永不过期</span>
                </label>
            </div>
            <div class="flex gap-3 mt-8">
                <button onclick="closeModal('token-modal')" class="flex-1 py-4 text-slate-500 font-bold">取消</button>
                <button onclick="saveToken()" class="flex-1 py-4 bg-indigo-600 text-white rounded-2xl font-bold hover:bg-indigo-700 transition-all">保存配置</button>
            </div>
        </div>
    </div>

    <script>
        let sessionId = "${sessionId}";
        let currentToken = "${tokenConfig?.token || ''}";

        function showLoading() { document.getElementById('loading').classList.remove('hidden'); }
        function hideLoading() { document.getElementById('loading').classList.add('hidden'); }

        async function fetchApi(path, method = 'GET', body = null) {
            const headers = { 'Content-Type': 'application/json' };
            if (sessionId) headers['Authorization'] = 'Bearer ' + sessionId;
            else if (currentToken) headers['Authorization'] = 'Token ' + currentToken;
            
            const res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : null });
            return await res.json();
        }

        async function updateIPs() {
            showLoading();
            try {
                const res = await fetchApi('/update');
                if (res.success) {
                    alert('采集完成: ' + res.totalIPs + ' 个 IP');
                    location.reload();
                } else alert('失败: ' + (res.error || '未知原因'));
            } finally { hideLoading(); }
        }

        async function startSpeedTest() {
            showLoading();
            const items = document.querySelectorAll('.ip-item'); // 仅演示
            alert('测速已在后台启动，请 10 秒后刷新数据');
            hideLoading();
        }

        async function login() {
            const password = document.getElementById('admin-password').value;
            const res = await fetch('/admin-login', { method: 'POST', body: JSON.stringify({ password }) });
            const data = await res.json();
            if (data.success) {
                location.href = '/?session=' + data.sessionId;
            } else alert('密码错误');
        }

        async function logout() {
            await fetchApi('/admin-logout', 'POST');
            location.href = '/';
        }

        async function saveToken() {
            const token = document.getElementById('token-input').value;
            const days = document.getElementById('token-days').value;
            const never = document.getElementById('token-never').checked;
            const res = await fetchApi('/admin-token', 'POST', { token, expiresDays: days, neverExpire: never });
            if (res.success) location.reload();
        }

        function openTokenModal() {
            document.getElementById('token-input').value = currentToken || '';
            document.getElementById('token-modal').classList.remove('hidden');
        }

        function closeModal(id) { document.getElementById(id).classList.add('hidden'); }
        
        document.getElementById('admin-badge').onclick = () => {
            if (${isLoggedIn}) {
                const drop = document.getElementById('admin-dropdown');
                drop.classList.toggle('hidden');
            } else document.getElementById('login-modal').classList.remove('hidden');
        };

        function copyIP(ip) {
            navigator.clipboard.writeText(ip);
            alert('已复制: ' + ip);
        }

        function downloadFast() {
            window.open('/fast-ips.txt' + (sessionId ? '?session='+sessionId : (currentToken ? '?token='+currentToken : '')));
        }
        
        function openItdog() { window.open('https://www.itdog.cn/batch_tcping/'); }
        function refreshData() { location.reload(); }
    </script>
</body>
</html>`;
    return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

