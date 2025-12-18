//V2.5版本，添加管理员登录参数，需要到CF worker环境变量里添加 ADMIN_PASSWORD，网页增加Token管理，登陆后可用
// 自定义优质IP数量
const FAST_IP_COUNT = 25; // 修改这个数字来自定义优质IP数量
const AUTO_TEST_MAX_IPS = 200; // 自动测速的最大IP数量，避免测速过多导致超时

export default {
    async scheduled(event, env, ctx) {
      console.log('Running scheduled IP update...');

      try {
        if (!env.IP_STORAGE) {
          console.error('KV namespace IP_STORAGE is not bound');
          return;
        }

        const startTime = Date.now();
        const { uniqueIPs, results } = await updateAllIPs(env);
        const duration = Date.now() - startTime;

        await env.IP_STORAGE.put('cloudflare_ips', JSON.stringify({
          ips: uniqueIPs,
          lastUpdated: new Date().toISOString(),
          count: uniqueIPs.length,
          sources: results
        }));

        // 自动触发测速并存储优质IP
        await autoSpeedTestAndStore(env, uniqueIPs);

        console.log(`Scheduled update: ${uniqueIPs.length} IPs collected in ${duration}ms`);
      } catch (error) {
        console.error('Scheduled update failed:', error);
      }
    },
  
    async fetch(request, env, ctx) {
      const url = new URL(request.url);
      const path = url.pathname;
      
      // 检查 KV 是否绑定
      if (!env.IP_STORAGE) {
        return new Response('KV namespace IP_STORAGE is not bound. Please bind it in Worker settings.', {
          status: 500,
          headers: { 'Content-Type': 'text/plain' }
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
            if (request.method !== 'POST') {
              return jsonResponse({ error: 'Method not allowed' }, 405);
            }
            return await handleUpdate(env, request);
          case '/ips':
            return await handleGetIPs(env, request);
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

  // 管理员登录处理
  async function handleAdminLogin(request, env) {
    if (request.method !== 'POST') {
      return jsonResponse({ error: 'Method not allowed' }, 405);
    }

    try {
      const { password } = await request.json();
      
      if (!env.ADMIN_PASSWORD) {
        return jsonResponse({ 
          success: false, 
          error: '管理员密码未配置，请在环境变量中设置 ADMIN_PASSWORD' 
        }, 400);
      }

      if (password === env.ADMIN_PASSWORD) {
        // 检查是否已有token配置
        let tokenConfig = await getTokenConfig(env);
        
        // 如果没有token配置，创建一个默认的
        if (!tokenConfig) {
          tokenConfig = {
            token: generateToken(),
            expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(), // 默认30天
            createdAt: new Date().toISOString(),
            lastUsed: null
          };
          await env.IP_STORAGE.put('token_config', JSON.stringify(tokenConfig));
        }
        
        // 创建会话
        const sessionId = generateToken();
        await env.IP_STORAGE.put(`session_${sessionId}`, JSON.stringify({
          loggedIn: true,
          createdAt: new Date().toISOString()
        }), { expirationTtl: 86400 }); // 24小时过期
        
        return jsonResponse({ 
          success: true, 
          sessionId: sessionId,
          tokenConfig: tokenConfig,
          message: '登录成功'
        });
      } else {
        return jsonResponse({ 
          success: false, 
          error: '密码错误' 
        }, 401);
      }
    } catch (error) {
      return jsonResponse({ error: error.message }, 500);
    }
  }

  // Token管理
  async function handleAdminToken(request, env) {
    if (!await verifyAdmin(request, env)) {
      return jsonResponse({ error: '需要管理员权限' }, 401);
    }

    if (request.method === 'GET') {
      const tokenConfig = await getTokenConfig(env);
      return jsonResponse({ tokenConfig });
    } else if (request.method === 'POST') {
      try {
        const { token, expiresDays, neverExpire } = await request.json();
        
        if (!token) {
          return jsonResponse({ error: 'Token不能为空' }, 400);
        }
        
        let expiresDate;
        if (neverExpire) {
          // 设置一个很远的未来日期作为永不过期
          expiresDate = new Date(Date.now() + 100 * 365 * 24 * 60 * 60 * 1000).toISOString(); // 100年
        } else {
          if (!expiresDays) {
            return jsonResponse({ error: '过期时间不能为空' }, 400);
          }
          if (expiresDays < 1 || expiresDays > 365) {
            return jsonResponse({ error: '过期时间必须在1-365天之间' }, 400);
          }
          expiresDate = new Date(Date.now() + expiresDays * 24 * 60 * 60 * 1000).toISOString();
        }
        
        const tokenConfig = {
          token: token.trim(),
          expires: expiresDate,
          createdAt: new Date().toISOString(),
          lastUsed: null,
          neverExpire: neverExpire || false
        };
        
        await env.IP_STORAGE.put('token_config', JSON.stringify(tokenConfig));
        
        return jsonResponse({ 
          success: true, 
          tokenConfig,
          message: 'Token更新成功'
        });
      } catch (error) {
        return jsonResponse({ error: error.message }, 500);
      }
    } else {
      return jsonResponse({ error: 'Method not allowed' }, 405);
    }
  }

  // 检查管理员状态
  async function handleAdminStatus(env) {
    try {
      const tokenConfig = await getTokenConfig(env);
      return jsonResponse({ 
        hasAdminPassword: !!env.ADMIN_PASSWORD,
        hasToken: !!tokenConfig,
        tokenConfig: tokenConfig
      });
    } catch (error) {
      return jsonResponse({ error: error.message }, 500);
    }
  }

  // 管理员登出
  async function handleAdminLogout(env) {
    try {
      // 这里可以添加会话清理逻辑
      return jsonResponse({ 
        success: true,
        message: '已退出登录'
      });
    } catch (error) {
      return jsonResponse({ error: error.message }, 500);
    }
  }

  // 获取Token配置
  async function getTokenConfig(env) {
    try {
      const config = await env.IP_STORAGE.get('token_config');
      return config ? JSON.parse(config) : null;
    } catch (error) {
      return null;
    }
  }

  // 生成随机Token
  function generateToken() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < 32; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  // 验证管理员权限
  async function verifyAdmin(request, env) {
    if (!env.ADMIN_PASSWORD) {
      return true; // 如果没有设置管理员密码，则允许所有访问
    }

    try {
      // 检查会话
      const authHeader = request.headers.get('Authorization');
      if (authHeader && authHeader.startsWith('Bearer ')) {
        const sessionId = authHeader.slice(7);
        const session = await env.IP_STORAGE.get(`session_${sessionId}`);
        if (session) {
          return true;
        }
      }

      // 检查URL参数中的会话
      const url = new URL(request.url);
      const sessionId = url.searchParams.get('session');
      if (sessionId) {
        const session = await env.IP_STORAGE.get(`session_${sessionId}`);
        if (session) {
          return true;
        }
      }

      // 检查Token
      const tokenConfig = await getTokenConfig(env);
      if (tokenConfig) {
        // 检查Token是否过期（永不过期的token跳过此检查）
        if (!tokenConfig.neverExpire && new Date(tokenConfig.expires) < new Date()) {
          return false;
        }

        // 检查URL参数中的token
        const urlToken = url.searchParams.get('token');
        if (urlToken === tokenConfig.token) {
          // 更新最后使用时间
          tokenConfig.lastUsed = new Date().toISOString();
          await env.IP_STORAGE.put('token_config', JSON.stringify(tokenConfig));
          return true;
        }

        // 检查Authorization头中的token
        if (authHeader && authHeader.startsWith('Token ')) {
          const requestToken = authHeader.slice(6);
          if (requestToken === tokenConfig.token) {
            tokenConfig.lastUsed = new Date().toISOString();
            await env.IP_STORAGE.put('token_config', JSON.stringify(tokenConfig));
            return true;
          }
        }
      }

      return false;
    } catch (error) {
      return false;
    }
  }

  // 为URL添加认证参数
  function addAuthToUrl(url, sessionId, tokenConfig) {
    if (!sessionId && !tokenConfig) return url;
    
    const separator = url.includes('?') ? '&' : '?';
    
    if (sessionId) {
      return `${url}${separator}session=${encodeURIComponent(sessionId)}`;
    } else if (tokenConfig) {
      return `${url}${separator}token=${encodeURIComponent(tokenConfig.token)}`;
    }
    
    return url;
  }

  // 提供HTML页面
  async function serveHTML(env, request) {
    const data = await getStoredIPs(env);
    
    // 获取测速后的IP数据
    const speedData = await getStoredSpeedIPs(env);
    const fastIPs = speedData.fastIPs || [];
    
    // 检查管理员状态
    const isLoggedIn = await verifyAdmin(request, env);
    const hasAdminPassword = !!env.ADMIN_PASSWORD;
    const tokenConfig = await getTokenConfig(env);
    
    // 获取会话ID
    let sessionId = null;
    if (isLoggedIn) {
      const url = new URL(request.url);
      sessionId = url.searchParams.get('session');
      if (!sessionId) {
        const authHeader = request.headers.get('Authorization');
        if (authHeader && authHeader.startsWith('Bearer ')) {
          sessionId = authHeader.slice(7);
        }
      }
    }

    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloudflare IP 收集器</title>
    <style>
        * { 
            margin: 0; 
            padding: 0; 
            box-sizing: border-box; 
        }
        
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
            line-height: 1.6; 
            background: #f8fafc;
            color: #334155;
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        /* 头部和社交图标 */
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 40px;
            padding-bottom: 20px;
            border-bottom: 1px solid #e2e8f0;
        }
        
        .header-content h1 {
            font-size: 2.5rem;
            background: linear-gradient(135deg, #3b82f6 0%, #06b6d4 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 8px;
            font-weight: 700;
        }
        
        .header-content p {
            color: #64748b;
            font-size: 1.1rem;
        }
        
        .social-links {
            display: flex;
            gap: 15px;
        }
        
        .social-link {
            display: flex;
            align-items: center;
            justify-content: center;
            width: 44px;
            height: 44px;
            border-radius: 12px;
            background: white;
            border: 1px solid #e2e8f0;
            transition: all 0.3s ease;
            text-decoration: none;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        }
        
        .social-link:hover {
            background: #f8fafc;
            transform: translateY(-2px);
            border-color: #cbd5e1;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }
        
        .social-link.youtube {
            color: #dc2626;
        }
        
        .social-link.youtube:hover {
            background: #fef2f2;
            border-color: #fecaca;
        }
        
        .social-link.github {
            color: #1f2937;
        }
        
        .social-link.github:hover {
            background: #f8fafc;
            border-color: #cbd5e1;
        }
        
        .social-link.telegram {
            color: #3b82f6;
        }
        
        .social-link.telegram:hover {
            background: #eff6ff;
            border-color: #bfdbfe;
        }
        
        /* 卡片设计 */
        .card {
            background: white;
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 24px;
            border: 1px solid #e2e8f0;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
        }
        
        .card h2 {
            font-size: 1.5rem;
            color: #1e40af;
            margin-bottom: 20px;
            font-weight: 600;
        }
        
        /* 统计数字 */
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        
        .stat {
            background: #f8fafc;
            padding: 20px;
            border-radius: 12px;
            text-align: center;
            border: 1px solid #e2e8f0;
        }
        
        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            color: #3b82f6;
            margin-bottom: 8px;
        }
        
        /* 按钮组 */
        .button-group {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            margin-bottom: 20px;
        }
        
        .button {
            padding: 12px 20px;
            border: none;
            border-radius: 10px;
            font-size: 0.95rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: #3b82f6;
            color: white;
            border: 1px solid #3b82f6;
        }
        
        .button:hover {
            background: #2563eb;
            border-color: #2563eb;
            transform: translateY(-1px);
            box-shadow: 0 4px 8px rgba(59, 130, 246, 0.3);
        }
        
        .button:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
            background: #cbd5e1;
            border-color: #cbd5e1;
            color: #64748b;
        }
        
        .button-success {
            background: #10b981;
            border-color: #10b981;
        }
        
        .button-success:hover {
            background: #059669;
            border-color: #059669;
            box-shadow: 0 4px 8px rgba(16, 185, 129, 0.3);
        }
        
        .button-warning {
            background: #f59e0b;
            border-color: #f59e0b;
        }
        
        .button-warning:hover {
            background: #d97706;
            border-color: #d97706;
            box-shadow: 0 4px 8px rgba(245, 158, 11, 0.3);
        }
        
        .button-secondary {
            background: white;
            color: #475569;
            border-color: #cbd5e1;
        }
        
        .button-secondary:hover {
            background: #f8fafc;
            border-color: #94a3b8;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }
        
        /* 下拉按钮组 */
        .dropdown {
            position: relative;
            display: inline-block;
        }
        
        .dropdown-content {
            display: none;
            position: absolute;
            background-color: white;
            min-width: 160px;
            box-shadow: 0 8px 16px 0 rgba(0,0,0,0.1);
            z-index: 1;
            border-radius: 10px;
            border: 1px solid #e2e8f0;
            overflow: hidden;
            top: 100%;
            left: 0;
            margin-top: 5px;
        }
        
        .dropdown-content a {
            color: #475569;
            padding: 12px 16px;
            text-decoration: none;
            display: block;
            border-bottom: 1px solid #f1f5f9;
            transition: all 0.3s ease;
        }
        
        .dropdown-content a:hover {
            background-color: #f8fafc;
            color: #1e40af;
        }
        
        .dropdown-content a:last-child {
            border-bottom: none;
        }
        
        .dropdown:hover .dropdown-content {
            display: block;
        }
        
        .dropdown-btn {
            display: flex;
            align-items: center;
            gap: 4px;
        }
        
        /* IP 列表 */
        .ip-list-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            flex-wrap: wrap;
            gap: 15px;
        }
        
        .ip-list {
            background: #f8fafc;
            border-radius: 12px;
            padding: 20px;
            max-height: 500px;
            overflow-y: auto;
            border: 1px solid #e2e8f0;
        }
        
        .ip-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 16px;
            border-bottom: 1px solid #e2e8f0;
            transition: background 0.3s ease;
        }
        
        .ip-item:hover {
            background: #f1f5f9;
        }
        
        .ip-item:last-child {
            border-bottom: none;
        }
        
        .ip-info {
            display: flex;
            align-items: center;
            gap: 16px;
        }
        
        .ip-address {
            font-family: 'SF Mono', 'Courier New', monospace;
            font-weight: 600;
            min-width: 140px;
            color: #1e293b;
        }
        
        .speed-result {
            font-size: 0.85rem;
            padding: 4px 12px;
            border-radius: 8px;
            background: #e2e8f0;
            min-width: 70px;
            text-align: center;
            font-weight: 600;
        }
        
        .speed-fast {
            background: #d1fae5;
            color: #065f46;
        }
        
        .speed-medium {
            background: #fef3c7;
            color: #92400e;
        }
        
        .speed-slow {
            background: #fee2e2;
            color: #991b1b;
        }
        
        .action-buttons {
            display: flex;
            gap: 8px;
        }
        
        .small-btn {
            padding: 6px 12px;
            border-radius: 8px;
            font-size: 0.8rem;
            border: 1px solid #cbd5e1;
            background: white;
            color: #475569;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .small-btn:hover {
            background: #f8fafc;
            border-color: #94a3b8;
        }
        
        .small-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        
        /* 加载和状态 */
        .loading {
            display: none;
            text-align: center;
            padding: 30px;
        }
        
        .spinner {
            border: 3px solid #e2e8f0;
            border-top: 3px solid #3b82f6;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 16px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .result {
            margin: 20px 0;
            padding: 16px 20px;
            border-radius: 12px;
            display: none;
            border-left: 4px solid;
        }
        
        .success {
            background: #d1fae5;
            color: #065f46;
            border-left-color: #10b981;
        }
        
        .error {
            background: #fee2e2;
            color: #991b1b;
            border-left-color: #ef4444;
        }
        
        /* 进度条 */
        .speed-test-progress {
            margin: 16px 0;
            background: #e2e8f0;
            border-radius: 8px;
            height: 8px;
            overflow: hidden;
            display: none;
        }
        
        .speed-test-progress-bar {
            background: linear-gradient(90deg, #3b82f6, #06b6d4);
            height: 100%;
            width: 0%;
            transition: width 0.3s ease;
        }
        
        /* 数据来源 */
        .sources {
            display: grid;
            gap: 12px;
        }
        
        .source {
            padding: 12px 16px;
            background: #f8fafc;
            border-radius: 8px;
            border-left: 4px solid #10b981;
        }
        
        .source.error {
            border-left-color: #ef4444;
        }
        
        /* 页脚 */
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 30px;
            border-top: 1px solid #e2e8f0;
            color: #64748b;
        }
        
        /* 模态框 */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(5px);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }
        
        .modal-content {
            background: white;
            padding: 30px;
            border-radius: 16px;
            max-width: 500px;
            width: 90%;
            border: 1px solid #e2e8f0;
            box-shadow: 0 20px 25px rgba(0, 0, 0, 0.1);
        }
        
        .modal h3 {
            margin-bottom: 16px;
            color: #1e40af;
        }
        
        .modal-buttons {
            display: flex;
            gap: 12px;
            justify-content: flex-end;
            margin-top: 20px;
        }
        
        /* 登录相关样式 */
        .admin-indicator {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1000;
        }
        
        .admin-badge {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            color: white;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.9rem;
            font-weight: 600;
            box-shadow: 0 4px 6px rgba(16, 185, 129, 0.3);
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: all 0.3s ease;
        }
        
        .admin-badge.logged-out {
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            box-shadow: 0 4px 6px rgba(239, 68, 68, 0.3);
        }
        
        .admin-badge:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 12px rgba(16, 185, 129, 0.4);
        }
        
        .admin-badge.logged-out:hover {
            box-shadow: 0 6px 12px rgba(239, 68, 68, 0.4);
        }
        
        .login-modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(5px);
            z-index: 2000;
            justify-content: center;
            align-items: center;
        }
        
        .login-content {
            background: white;
            padding: 40px;
            border-radius: 16px;
            max-width: 400px;
            width: 90%;
            border: 1px solid #e2e8f0;
            box-shadow: 0 20px 25px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        
        .login-content h3 {
            margin-bottom: 20px;
            color: #1e40af;
        }
        
        .password-input {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e2e8f0;
            border-radius: 10px;
            font-size: 1rem;
            margin-bottom: 16px;
            transition: border-color 0.3s ease;
        }
        
        .password-input:focus {
            outline: none;
            border-color: #3b82f6;
        }
        
        .admin-hint {
            font-size: 0.9rem;
            color: #64748b;
            margin-bottom: 20px;
            text-align: left;
        }
        
        .admin-hint.warning {
            color: #ef4444;
            background: #fef2f2;
            padding: 12px;
            border-radius: 8px;
            border-left: 4px solid #ef4444;
        }
        
        /* Token管理样式 */
        .token-section {
            background: #f8fafc;
            border-radius: 12px;
            padding: 20px;
            margin-top: 20px;
            border: 1px solid #e2e8f0;
        }
        
        .token-info {
            background: white;
            padding: 16px;
            border-radius: 8px;
            margin-bottom: 16px;
            border: 1px solid #e2e8f0;
        }
        
        .token-display {
            font-family: 'SF Mono', 'Courier New', monospace;
            background: #1e293b;
            color: #f1f5f9;
            padding: 12px;
            border-radius: 6px;
            margin: 8px 0;
            word-break: break-all;
        }
        
        .form-group {
            margin-bottom: 16px;
            text-align: left;
        }
        
        .form-label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #374151;
        }
        
        .form-input {
            width: 100%;
            padding: 10px 12px;
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            font-size: 0.95rem;
            transition: border-color 0.3s ease;
        }
        
        .form-input:focus {
            outline: none;
            border-color: #3b82f6;
        }
        
        .form-input:disabled {
            background-color: #f8fafc;
            color: #64748b;
        }
        
        .form-help {
            font-size: 0.85rem;
            color: #64748b;
            margin-top: 4px;
        }
        
        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 16px;
        }
        
        .checkbox-label {
            font-weight: 600;
            color: #374151;
            cursor: pointer;
        }
        
        /* 响应式设计 */
        @media (max-width: 768px) {
            .header {
                flex-direction: column;
                gap: 20px;
                text-align: center;
            }
            
            .header-content h1 {
                font-size: 2rem;
            }
            
            .button-group {
                flex-direction: column;
            }
            
            .button {
                width: 100%;
                justify-content: center;
            }
            
            .dropdown {
                width: 100%;
            }
            
            .dropdown-content {
                width: 100%;
                position: static;
                box-shadow: none;
                border: 1px solid #e2e8f0;
                margin-top: 8px;
            }
            
            .ip-list-header {
                flex-direction: column;
                align-items: flex-start;
            }
            
            .ip-item {
                flex-direction: column;
                align-items: flex-start;
                gap: 12px;
            }
            
            .ip-info {
                width: 100%;
                justify-content: space-between;
            }
            
            .action-buttons {
                width: 100%;
                justify-content: flex-end;
            }
            
            .modal-buttons {
                flex-direction: column;
            }
            
            .admin-indicator {
                position: relative;
                top: auto;
                right: auto;
                margin-bottom: 20px;
                display: flex;
                justify-content: center;
            }
            
            .admin-badge {
                width: fit-content;
            }
        }
    </style>
</head>
<body>
    <!-- 管理员状态指示器 -->
    <div class="admin-indicator">
        <div class="admin-badge ${isLoggedIn ? '' : 'logged-out'}" id="admin-badge">
            ${isLoggedIn ? '🔐 管理员' : '🔓 点击登录'}
            ${isLoggedIn ? '<span style="font-size: 0.7rem; margin-left: 4px;">▼</span>' : ''}
        </div>
        ${isLoggedIn ? `
        <div class="dropdown-content" id="admin-dropdown">
            <a href="javascript:void(0)" onclick="logout()">🚪 退出登录</a>
        </div>
        ` : ''}
    </div>

    <div class="container">
        <!-- 头部区域 -->
        <div class="header">
            <div class="header-content">
                <h1>Cloudflare 优选IP 收集器</h1>
                <p> 自动定时拉取IP并测速</p>
            </div>
            <div class="social-links">
                <a href="https://youtu.be/rZl2jz--Oes" target="_blank" title="好软推荐" class="social-link youtube">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M23.498 6.186a3.016 3.016 0 0 0-2.122-2.136C19.505 3.546 12 3.546 12 3.546s-7.505 0-9.377.504A3.016 3.016 0 0 0 .502 6.186C0 8.07 0 12 0 12s0 3.93.502 5.814a3.016 3.016 0 0 0 2.122 2.136c1.871.504 9.376.504 9.376.504s7.505 0 9.377-.504a3.016 3.016 0 0 0 2.122-2.136C24 15.93 24 12 24 12s0-3.93-.502-5.814zM9.545 15.568V8.432L15.818 12 9.545 15.568z"/>
                    </svg>
                </a>
                <a href="https://github.com/ethgan/CF-Worker-BestIP-collector" target="_blank" title="GitHub" class="social-link github">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.085 8.199-11.386 0-6.627-5.373-12-12-12z"/>
                    </svg>
                </a>
                <a href="https://t.me/yt_hytj" target="_blank" title="Telegram" class="social-link telegram">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
                        <path d="m7.06510669 16.9258959c5.22739451-2.1065178 8.71314291-3.4952633 10.45724521-4.1662364 4.9797665-1.9157646 6.0145193-2.2485535 6.6889567-2.2595423.1483363-.0024169.480005.0315855.6948461.192827.1814076.1361492.23132.3200675.2552048.4491519.0238847.1290844.0536269.4231419.0299841.65291-.2698553 2.6225356-1.4375148 8.986738-2.0315537 11.9240228-.2513602 1.2428753-.7499132 1.5088847-1.2290685 1.5496672-1.0413153.0886298-1.8284257-.4857912-2.8369905-1.0972863-1.5782048-.9568691-2.5327083-1.3984317-4.0646293-2.3321592-1.7703998-1.0790837-.212559-1.583655.7963867-2.5529189.2640459-.2536609 4.7753906-4.3097041 4.755976-4.431706-.0070494-.0442984-.1409018-.481649-.2457499-.5678447-.104848-.0861957-.2595946-.0567202-.3712641-.033278-.1582881.0332286-2.6794907 1.5745492-7.5636077 4.6239616-.715635.4545193-1.3638349.6759763-1.9445998.6643712-.64024672-.0127938-1.87182452-.334829-2.78737602-.6100966-1.11296117-.3376271-1.53748501-.4966332-1.45976769-1.0700283.04048-.2986597.32581586-.610598.8560076-.935815z"/>
                    </svg>
                </a>
            </div>
        </div>

        <!-- 系统状态卡片 -->
        <div class="card">
            <h2>📊 系统状态</h2>
            <div class="stats">
                <div class="stat">
                    <div class="stat-value" id="ip-count">${data.count || 0}</div>
                    <div>IP 地址数量</div>
                </div>
                <div class="stat">
                    <div class="stat-value" id="last-updated">${data.lastUpdated ? '已更新' : '未更新'}</div>
                    <div>最后更新</div>
                </div>
                <div class="stat">
                    <div class="stat-value" id="last-time">${data.lastUpdated ? new Date(data.lastUpdated).toLocaleTimeString() : '从未更新'}</div>
                    <div>更新时间</div>
                </div>
                <div class="stat">
                    <div class="stat-value" id="fast-ip-count">${fastIPs.length}</div>
                    <div>优质 IP 数量</div>
                </div>
            </div>
            
            <div class="button-group">
                <button class="button" onclick="updateIPs()" id="update-btn">
                    🔄 立即更新
                </button>
                
                <!-- 下载按钮组 -->
                <div class="dropdown">
                    <a href="${addAuthToUrl('/fast-ips.txt', sessionId, tokenConfig)}" class="button button-success dropdown-btn" download="cloudflare_fast_ips.txt">
                        ⚡ 下载优质IP
                        <span style="font-size: 0.8rem;">▼</span>
                    </a>
                    <div class="dropdown-content">
                        <a href="${addAuthToUrl('/ips', sessionId, tokenConfig)}" download="cloudflare_ips.txt">📥 下载全部列表</a>
                    </div>
                </div>
                
                <!-- 查看按钮组 -->
                <div class="dropdown">
                    <a href="${addAuthToUrl('/fast-ips.txt', sessionId, tokenConfig)}" class="button button-secondary dropdown-btn" target="_blank">
                        🔗 查看优质IP
                        <span style="font-size: 0.8rem;">▼</span>
                    </a>
                    <div class="dropdown-content">
                        <a href="${addAuthToUrl('/ip.txt', sessionId, tokenConfig)}" target="_blank">📋 查看全部文本</a>
                    </div>
                </div>
                
                <button class="button button-warning" onclick="startSpeedTest()" id="speedtest-btn">
                    ⚡ 开始测速
                </button>
                <button class="button" onclick="openItdogModal()">
                    🌐 ITDog 测速
                </button>
                <button class="button button-secondary" onclick="refreshData()">
                    🔄 刷新状态
                </button>
                <!-- Token管理按钮放在刷新状态旁边 -->
                <button class="button ${isLoggedIn ? 'button-secondary' : ''}" onclick="openTokenModal()" id="token-btn" ${!isLoggedIn ? 'disabled' : ''}>
                    🔑 Token管理
                </button>
            </div>
            
            <div class="loading" id="loading">
                <div class="spinner"></div>
                <p>正在从多个来源收集 IP 地址，请稍候...</p>
            </div>
            
            <div class="result" id="result"></div>

            <!-- Token管理区域 - 确保登录后显示 -->
            ${isLoggedIn ? `
            <div class="token-section">
                <h3>🔑 API Token 管理</h3>
                ${tokenConfig ? `
                <div class="token-info">
                    <p><strong>当前 Token:</strong></p>
                    <div class="token-display">${tokenConfig.token}</div>
                    <p><strong>过期时间:</strong> ${tokenConfig.neverExpire ? '永不过期' : new Date(tokenConfig.expires).toLocaleString()}</p>
                    <p><strong>创建时间:</strong> ${new Date(tokenConfig.createdAt).toLocaleString()}</p>
                    ${tokenConfig.lastUsed ? `<p><strong>最后使用:</strong> ${new Date(tokenConfig.lastUsed).toLocaleString()}</p>` : ''}
                </div>
                ` : '<p>暂无Token配置，请点击下方按钮创建Token。</p>'}
                <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                    <button class="button button-warning" onclick="openTokenModal()">
                        ⚙️ 配置 Token
                    </button>
                    ${tokenConfig ? `
                    <button class="button button-secondary" onclick="copyToken()">
                        📋 复制 Token
                    </button>
                    <button class="button button-secondary" onclick="copyTokenUrl()">
                        🔗 复制带Token的链接
                    </button>
                    ` : ''}
                </div>
            </div>
            ` : ''}
        </div>

        <!-- 优质IP列表卡片 -->
        <div class="card">
            <div class="ip-list-header">
                <h2>⚡ 优质 IP 列表</h2>
                <div>
                    <button class="small-btn" onclick="copyAllFastIPs()">
                        📋 复制优质IP
                    </button>
                </div>
            </div>
            
            <div class="speed-test-progress" id="speed-test-progress">
                <div class="speed-test-progress-bar" id="speed-test-progress-bar"></div>
            </div>
            <div style="text-align: center; margin: 8px 0; font-size: 0.9rem; color: #64748b;" id="speed-test-status">准备测速...</div>
            
            <div class="ip-list" id="ip-list">
                ${fastIPs.length > 0 ? 
                  fastIPs.map(item => {
                    const ip = item.ip;
                    const latency = item.latency;
                    const speedClass = latency < 200 ? 'speed-fast' : latency < 500 ? 'speed-medium' : 'speed-slow';
                    return `
                    <div class="ip-item" data-ip="${ip}">
                        <div class="ip-info">
                            <span class="ip-address">${ip}</span>
                            <span class="speed-result ${speedClass}" id="speed-${ip.replace(/\./g, '-')}">${latency}ms</span>
                        </div>
                        <div class="action-buttons">
                            <button class="small-btn" onclick="copyIP('${ip}')">复制</button>
                        </div>
                    </div>
                  `}).join('') : 
                  '<p style="text-align: center; color: #64748b; padding: 40px;">暂无优质 IP 地址数据，请点击更新按钮获取</p>'
                }
            </div>
        </div>

        <!-- 数据来源卡片 -->
        <div class="card">
            <h2>🌍 数据来源状态</h2>
            <div class="sources" id="sources">
                ${data.sources ? data.sources.map(source => `
                    <div class="source ${source.status === 'success' ? '' : 'error'}">
                        <strong>${source.name}</strong>: 
                        ${source.status === 'success' ? 
                          `成功获取 ${source.count} 个IP` : 
                          `失败: ${source.error}`
                        }
                    </div>
                `).join('') : '<p style="color: #64748b;">暂无数据来源信息</p>'}
            </div>
        </div>

        <!-- 页脚 -->
        <div class="footer">
            <p>Cloudflare IP Collector &copy; ${new Date().getFullYear()} | 好软推荐</p>
        </div>
    </div>

    <!-- ITDog 模态框 -->
    <div class="modal" id="itdog-modal">
        <div class="modal-content">
            <h3>🌐 ITDog 批量 TCPing 测速</h3>
            <p>ITDog.cn 提供了从多个国内监测点进行 TCPing 测速的功能，可以更准确地测试 IP 在国内的连通性。</p>
            <p><strong>使用方法：</strong></p>
            <ol style="margin-left: 20px; margin-bottom: 16px;">
                <li>点击下方按钮复制所有 IP 地址</li>
                <li>打开 ITDog 批量 TCPing 页面</li>
                <li>将复制的 IP 粘贴到输入框中</li>
                <li>点击开始测试按钮</li>
            </ol>
            <p><strong>注意：</strong> ITDog 免费版可能有 IP 数量限制，如果 IP 过多请分批测试。</p>
            <div class="modal-buttons">
                <button class="button button-secondary" onclick="closeItdogModal()">取消</button>
                <button class="button" onclick="copyIPsForItdog()">复制 IP 列表</button>
                <a href="https://www.itdog.cn/batch_tcping/" class="button button-success" target="_blank">打开 ITDog</a>
            </div>
        </div>
    </div>

    <!-- 登录模态框 -->
    <div class="login-modal" id="login-modal">
        <div class="login-content">
            <h3>🔐 管理员登录</h3>
            <div class="admin-hint ${hasAdminPassword ? '' : 'warning'}" id="admin-hint">
                ${hasAdminPassword ? 
                  '请输入管理员密码访问受保护的资源' : 
                  '⚠️ 未设置管理员密码，请在环境变量中配置 ADMIN_PASSWORD'
                }
            </div>
            <input type="password" class="password-input" id="admin-password" placeholder="输入管理员密码" ${!hasAdminPassword ? 'disabled' : ''}>
            <div class="modal-buttons">
                <button class="button button-secondary" onclick="closeLoginModal()">取消</button>
                <button class="button" onclick="login()" id="login-btn" ${!hasAdminPassword ? 'disabled' : ''}>登录</button>
            </div>
        </div>
    </div>

    <!-- Token配置模态框 -->
    <div class="modal" id="token-modal">
        <div class="modal-content">
            <h3>⚙️ Token 配置</h3>
            <div class="form-group">
                <label class="form-label">Token 字符串</label>
                <input type="text" class="form-input" id="token-input" placeholder="输入自定义Token或留空自动生成">
                <div class="form-help">建议使用复杂的随机字符串，长度至少16位</div>
            </div>
            <div class="checkbox-group">
                <input type="checkbox" id="never-expire-checkbox" onchange="toggleExpireInput()">
                <label class="checkbox-label" for="never-expire-checkbox">永不过期</label>
            </div>
            <div class="form-group" id="expires-group">
                <label class="form-label">过期天数</label>
                <input type="number" class="form-input" id="expires-days" value="30" min="1" max="365">
                <div class="form-help">设置Token的有效期（1-365天）</div>
            </div>
            <div class="modal-buttons">
                <button class="button button-secondary" onclick="closeTokenModal()">取消</button>
                <button class="button" onclick="generateRandomToken()">🎲 随机生成</button>
                <button class="button button-success" onclick="saveTokenConfig()">保存</button>
            </div>
        </div>
    </div>

    <script>
        // JavaScript 代码
        let speedResults = {};
        let isTesting = false;
        let currentTestIndex = 0;
        let sessionId = '${sessionId || ''}';
        let isLoggedIn = ${isLoggedIn};
        let hasAdminPassword = ${hasAdminPassword};
        let tokenConfig = ${tokenConfig ? JSON.stringify(tokenConfig) : 'null'};

        // 更新管理员状态显示
        function updateAdminStatus() {
            const badge = document.getElementById('admin-badge');
            const dropdown = document.getElementById('admin-dropdown');
            const tokenBtn = document.getElementById('token-btn');
            
            if (isLoggedIn) {
                badge.classList.remove('logged-out');
                badge.innerHTML = '🔐 管理员 <span style="font-size: 0.7rem; margin-left: 4px;">▼</span>';
                if (dropdown) dropdown.style.display = 'none';
                
                // 启用Token管理按钮
                tokenBtn.disabled = false;
                tokenBtn.classList.add('button-secondary');
            } else {
                badge.classList.add('logged-out');
                badge.innerHTML = '🔓 点击登录';
                if (dropdown) dropdown.style.display = 'none';
                
                // 禁用Token管理按钮
                tokenBtn.disabled = true;
                tokenBtn.classList.remove('button-secondary');
            }
            
            // 更新所有链接的认证参数
            updateLinksWithAuth();
        }

        // 切换过期时间输入框
        function toggleExpireInput() {
            const checkbox = document.getElementById('never-expire-checkbox');
            const expiresGroup = document.getElementById('expires-group');
            const expiresInput = document.getElementById('expires-days');
            
            if (checkbox.checked) {
                expiresGroup.style.display = 'none';
                expiresInput.disabled = true;
            } else {
                expiresGroup.style.display = 'block';
                expiresInput.disabled = false;
            }
        }

        // 为所有链接添加认证参数
        function updateLinksWithAuth() {
            if (!isLoggedIn) return;
            
            const links = document.querySelectorAll('a[href*="/ips"], a[href*="/fast-ips"], a[href*="/ip.txt"], a[href*="/fast-ips.txt"]');
            links.forEach(link => {
                const url = new URL(link.href, window.location.origin);
                if (sessionId && !url.searchParams.get('session')) {
                    url.searchParams.set('session', sessionId);
                    link.href = url.toString();
                } else if (tokenConfig && !url.searchParams.get('token')) {
                    url.searchParams.set('token', tokenConfig.token);
                    link.href = url.toString();
                }
            });
        }

        // 管理员徽章点击事件
        document.getElementById('admin-badge').addEventListener('click', function(e) {
            if (isLoggedIn) {
                const dropdown = document.getElementById('admin-dropdown');
                if (dropdown) {
                    dropdown.style.display = dropdown.style.display === 'block' ? 'none' : 'block';
                }
            } else {
                openLoginModal();
            }
        });

        // 点击其他地方关闭下拉菜单
        document.addEventListener('click', function(e) {
            if (!e.target.closest('.admin-indicator')) {
                const dropdown = document.getElementById('admin-dropdown');
                if (dropdown) {
                    dropdown.style.display = 'none';
                }
            }
        });

        function openLoginModal() {
            document.getElementById('login-modal').style.display = 'flex';
            document.getElementById('admin-password').focus();
        }

        function closeLoginModal() {
            document.getElementById('login-modal').style.display = 'none';
            document.getElementById('admin-password').value = '';
        }

        function openTokenModal() {
            document.getElementById('token-modal').style.display = 'flex';
            if (tokenConfig) {
                document.getElementById('token-input').value = tokenConfig.token;
                const neverExpire = tokenConfig.neverExpire || false;
                document.getElementById('never-expire-checkbox').checked = neverExpire;
                
                if (neverExpire) {
                    document.getElementById('expires-group').style.display = 'none';
                    document.getElementById('expires-days').disabled = true;
                } else {
                    document.getElementById('expires-group').style.display = 'block';
                    document.getElementById('expires-days').disabled = false;
                    const expires = new Date(tokenConfig.expires);
                    const today = new Date();
                    const diffTime = expires - today;
                    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
                    document.getElementById('expires-days').value = diffDays > 0 ? diffDays : 30;
                }
            } else {
                document.getElementById('token-input').value = '';
                document.getElementById('never-expire-checkbox').checked = false;
                document.getElementById('expires-group').style.display = 'block';
                document.getElementById('expires-days').disabled = false;
                document.getElementById('expires-days').value = 30;
            }
        }

        function closeTokenModal() {
            document.getElementById('token-modal').style.display = 'none';
        }

        function generateRandomToken() {
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            let result = '';
            for (let i = 0; i < 32; i++) {
                result += chars.charAt(Math.floor(Math.random() * chars.length));
            }
            document.getElementById('token-input').value = result;
        }

        async function saveTokenConfig() {
            const token = document.getElementById('token-input').value.trim();
            const neverExpire = document.getElementById('never-expire-checkbox').checked;
            const expiresDays = neverExpire ? null : parseInt(document.getElementById('expires-days').value);
            
            if (!token) {
                showMessage('请输入Token字符串', 'error');
                return;
            }
            
            if (!neverExpire && (!expiresDays || expiresDays < 1 || expiresDays > 365)) {
                showMessage('请输入有效的过期天数（1-365）', 'error');
                return;
            }

            try {
                const response = await fetch('/admin-token', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': \`Bearer \${sessionId}\`
                    },
                    body: JSON.stringify({
                        token: token,
                        expiresDays: expiresDays,
                        neverExpire: neverExpire
                    })
                });

                const data = await response.json();

                if (data.success) {
                    tokenConfig = data.tokenConfig;
                    showMessage('Token配置已保存', 'success');
                    closeTokenModal();
                    refreshData();
                } else {
                    showMessage(data.error, 'error');
                }
            } catch (error) {
                showMessage('保存失败: ' + error.message, 'error');
            }
        }

        async function login() {
            const password = document.getElementById('admin-password').value;
            const loginBtn = document.getElementById('login-btn');
            
            if (!password) {
                showMessage('请输入密码', 'error');
                return;
            }

            loginBtn.disabled = true;
            loginBtn.textContent = '登录中...';

            try {
                const response = await fetch('/admin-login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ password: password })
                });

                const data = await response.json();

                if (data.success) {
                    sessionId = data.sessionId;
                    tokenConfig = data.tokenConfig;
                    isLoggedIn = true;
                    showMessage('登录成功！', 'success');
                    closeLoginModal();
                    updateAdminStatus();
                    
                    // 刷新数据以获取带认证参数的链接
                    refreshData();
                } else {
                    showMessage(data.error, 'error');
                }
            } catch (error) {
                showMessage('登录失败: ' + error.message, 'error');
            } finally {
                loginBtn.disabled = false;
                loginBtn.textContent = '登录';
            }
        }

        async function logout() {
            try {
                const response = await fetch('/admin-logout', { method: 'POST' });
                const data = await response.json();
                
                if (data.success) {
                    sessionId = null;
                    isLoggedIn = false;
                    tokenConfig = null;
                    showMessage('已退出登录', 'success');
                    updateAdminStatus();
                    refreshData();
                }
            } catch (error) {
                showMessage('退出登录失败: ' + error.message, 'error');
            }
        }

        function copyToken() {
            if (!tokenConfig) {
                showMessage('没有可复制的Token', 'error');
                return;
            }
            
            navigator.clipboard.writeText(tokenConfig.token).then(() => {
                showMessage('Token已复制到剪贴板');
            }).catch(err => {
                showMessage('复制失败，请手动复制', 'error');
            });
        }

        function copyTokenUrl() {
            if (!tokenConfig) {
                showMessage('没有可复制的Token', 'error');
                return;
            }
            
            const baseUrl = window.location.origin;
            const tokenUrl = \`\${baseUrl}/fast-ips.txt?token=\${encodeURIComponent(tokenConfig.token)}\`;
            
            navigator.clipboard.writeText(tokenUrl).then(() => {
                showMessage('带Token的链接已复制到剪贴板');
            }).catch(err => {
                showMessage('复制失败，请手动复制', 'error');
            });
        }

        function showMessage(message, type = 'success') {
            const result = document.getElementById('result');
            result.className = \`result \${type}\`;
            result.innerHTML = \`<p>\${message}</p>\`;
            result.style.display = 'block';
            setTimeout(() => {
                result.style.display = 'none';
            }, 3000);
        }

        function openItdogModal() {
            document.getElementById('itdog-modal').style.display = 'flex';
        }

        function closeItdogModal() {
            document.getElementById('itdog-modal').style.display = 'none';
        }

        async function copyIPsForItdog() {
            try {
                let url = '/itdog-data';
                if (isLoggedIn) {
                    if (sessionId) {
                        url += \`?session=\${encodeURIComponent(sessionId)}\`;
                    } else if (tokenConfig) {
                        url += \`?token=\${encodeURIComponent(tokenConfig.token)}\`;
                    }
                }
                
                const response = await fetch(url);
                const data = await response.json();
                
                if (data.ips && data.ips.length > 0) {
                    const ipText = data.ips.join('\\n');
                    await navigator.clipboard.writeText(ipText);
                    showMessage('已复制 IP 列表，请粘贴到 ITDog 网站');
                    closeItdogModal();
                } else {
                    showMessage('没有可测速的IP地址', 'error');
                }
            } catch (error) {
                console.error('获取 ITDog 数据失败:', error);
                showMessage('获取 IP 列表失败', 'error');
            }
        }

        function copyIP(ip) {
            navigator.clipboard.writeText(ip).then(() => {
                showMessage(\`已复制 IP: \${ip}\`);
            }).catch(err => {
                showMessage('复制失败，请手动复制', 'error');
            });
        }

        function copyAllIPs() {
            const ipItems = document.querySelectorAll('.ip-item span.ip-address');
            const allIPs = Array.from(ipItems).map(span => span.textContent).join('\\n');
            
            if (!allIPs) {
                showMessage('没有可复制的IP地址', 'error');
                return;
            }
            
            navigator.clipboard.writeText(allIPs).then(() => {
                showMessage(\`已复制 \${ipItems.length} 个IP地址\`);
            }).catch(err => {
                showMessage('复制失败，请手动复制', 'error');
            });
        }

        function copyAllFastIPs() {
            const ipItems = document.querySelectorAll('.ip-item span.ip-address');
            const allIPs = Array.from(ipItems).map(span => span.textContent).join('\\n');
            
            if (!allIPs) {
                showMessage('没有可复制的优质IP地址', 'error');
                return;
            }
            
            navigator.clipboard.writeText(allIPs).then(() => {
                showMessage(\`已复制 \${ipItems.length} 个优质IP地址\`);
            }).catch(err => {
                showMessage('复制失败，请手动复制', 'error');
            });
        }

        async function startSpeedTest() {
            if (isTesting) {
                showMessage('测速正在进行中，请稍候...', 'error');
                return;
            }
            
            const ipItems = document.querySelectorAll('.ip-item');
            if (ipItems.length === 0) {
                showMessage('没有可测速的IP地址', 'error');
                return;
            }
            
            const speedtestBtn = document.getElementById('speedtest-btn');
            const progressBar = document.getElementById('speed-test-progress');
            const progressBarInner = document.getElementById('speed-test-progress-bar');
            const statusElement = document.getElementById('speed-test-status');
            
            isTesting = true;
            speedtestBtn.disabled = true;
            speedtestBtn.textContent = '测速中...';
            progressBar.style.display = 'block';
            
            const totalIPs = ipItems.length;
            currentTestIndex = 0;
            
            document.querySelectorAll('.speed-result').forEach(el => {
                el.textContent = '测试中...';
                el.className = 'speed-result';
            });
            
            for (let i = 0; i < totalIPs; i++) {
                if (!isTesting) break;
                
                const ip = ipItems[i].dataset.ip;
                
                statusElement.textContent = \`正在测速 \${i+1}/\${totalIPs}: \${ip}\`;
                
                const startTime = performance.now();
                try {
                    const response = await fetch(\`/speedtest?ip=\${ip}\`, {
                        method: 'GET',
                        headers: {
                            'Content-Type': 'application/json'
                        }
                    });
                    
                    if (!response.ok) {
                        throw new Error(\`HTTP \${response.status}\`);
                    }
                    
                    const data = await response.json();
                    const endTime = performance.now();
                    const latency = endTime - startTime;
                    
                    speedResults[ip] = {
                        latency: latency,
                        success: data.success,
                        time: data.time || '未知'
                    };
                    
                    const speedElement = document.getElementById(\`speed-\${ip.replace(/\./g, '-')}\`);
                    if (data.success) {
                        const speedClass = latency < 200 ? 'speed-fast' : latency < 500 ? 'speed-medium' : 'speed-slow';
                        speedElement.textContent = \`\${Math.round(latency)}ms\`;
                        speedElement.className = \`speed-result \${speedClass}\`;
                    } else {
                        speedElement.textContent = '失败';
                        speedElement.className = 'speed-result speed-slow';
                    }
                } catch (error) {
                    const speedElement = document.getElementById(\`speed-\${ip.replace(/\./g, '-')}\`);
                    speedElement.textContent = '错误';
                    speedElement.className = 'speed-result speed-slow';
                }
                
                currentTestIndex = i + 1;
                const progress = (currentTestIndex / totalIPs) * 100;
                progressBarInner.style.width = \`\${progress}%\`;
                
                await new Promise(resolve => setTimeout(resolve, 300));
            }
            
            isTesting = false;
            speedtestBtn.disabled = false;
            speedtestBtn.textContent = '⚡ 开始测速';
            progressBar.style.display = 'none';
            
            showMessage(\`测速完成，已测试 \${currentTestIndex} 个IP地址\`);
            
            // 测速完成后刷新数据，显示最新的优质IP列表
            setTimeout(refreshData, 1000);
        }

        async function updateIPs() {
            const btn = document.getElementById('update-btn');
            const loading = document.getElementById('loading');
            const result = document.getElementById('result');
            
            btn.disabled = true;
            loading.style.display = 'block';
            result.style.display = 'none';
            
            try {
                const headers = {
                    'Content-Type': 'application/json'
                };
                
                if (isLoggedIn) {
                    if (sessionId) {
                        headers['Authorization'] = \`Bearer \${sessionId}\`;
                    } else if (tokenConfig) {
                        headers['Authorization'] = \`Token \${tokenConfig.token}\`;
                    }
                }
                
                const response = await fetch('/update', { 
                    method: 'POST',
                    headers: headers
                });
                
                const data = await response.json();
                
                if (data.success) {
                    result.className = 'result success';
                    result.innerHTML = \`
                        <h3>✅ 更新成功！</h3>
                        <p>耗时: \${data.duration}</p>
                        <p>收集到 \${data.totalIPs} 个唯一 IP 地址</p>
                        <p>时间: \${new Date(data.timestamp).toLocaleString()}</p>
                    \`;
                } else {
                    result.className = 'result error';
                    result.innerHTML = \`
                        <h3>❌ 更新失败</h3>
                        <p>\${data.error}</p>
                    \`;
                }
                result.style.display = 'block';
                
                setTimeout(refreshData, 1000);
                
            } catch (error) {
                result.className = 'result error';
                result.innerHTML = \`
                    <h3>❌ 请求失败</h3>
                    <p>\${error.message}</p>
                \`;
                result.style.display = 'block';
            } finally {
                btn.disabled = false;
                loading.style.display = 'none';
            }
        }
        
        async function refreshData() {
            try {
                let url = '/raw';
                if (isLoggedIn) {
                    if (sessionId) {
                        url += \`?session=\${encodeURIComponent(sessionId)}\`;
                    } else if (tokenConfig) {
                        url += \`?token=\${encodeURIComponent(tokenConfig.token)}\`;
                    }
                }
                
                const response = await fetch(url);
                const data = await response.json();
                
                document.getElementById('ip-count').textContent = data.count || 0;
                document.getElementById('last-updated').textContent = data.lastUpdated ? '已更新' : '未更新';
                document.getElementById('last-time').textContent = data.lastUpdated ? 
                    new Date(data.lastUpdated).toLocaleTimeString() : '从未更新';
                
                // 获取优质IP数据
                let fastUrl = '/fast-ips';
                if (isLoggedIn) {
                    if (sessionId) {
                        fastUrl += \`?session=\${encodeURIComponent(sessionId)}\`;
                    } else if (tokenConfig) {
                        fastUrl += \`?token=\${encodeURIComponent(tokenConfig.token)}\`;
                    }
                }
                
                const fastResponse = await fetch(fastUrl);
                const fastData = await fastResponse.json();
                
                document.getElementById('fast-ip-count').textContent = fastData.fastIPs ? fastData.fastIPs.length : 0;
                
                const ipList = document.getElementById('ip-list');
                if (fastData.fastIPs && fastData.fastIPs.length > 0) {
                    ipList.innerHTML = fastData.fastIPs.map(item => {
                        const ip = item.ip;
                        const latency = item.latency;
                        const speedClass = latency < 200 ? 'speed-fast' : latency < 500 ? 'speed-medium' : 'speed-slow';
                        return \`
                        <div class="ip-item" data-ip="\${ip}">
                            <div class="ip-info">
                                <span class="ip-address">\${ip}</span>
                                <span class="speed-result \${speedClass}" id="speed-\${ip.replace(/\./g, '-')}">\${latency}ms</span>
                            </div>
                            <div class="action-buttons">
                                <button class="small-btn" onclick="copyIP('\${ip}')">复制</button>
                            </div>
                        </div>
                        \`;
                    }).join('');
                } else {
                    ipList.innerHTML = '<p style="text-align: center; color: #64748b; padding: 40px;">暂无优质 IP 地址数据，请点击更新按钮获取</p>';
                }
                
                const sources = document.getElementById('sources');
                if (data.sources && data.sources.length > 0) {
                    sources.innerHTML = data.sources.map(source => \`
                        <div class="source \${source.status === 'success' ? '' : 'error'}">
                            <strong>\${source.name}</strong>: 
                            \${source.status === 'success' ? 
                              \`成功获取 \${source.count} 个IP\` : 
                              \`失败: \${source.error}\`
                            }
                        </div>
                    \`).join('');
                }
            } catch (error) {
                console.error('刷新数据失败:', error);
            }
        }
        
        document.addEventListener('DOMContentLoaded', function() {
            updateAdminStatus();
            refreshData();
        });
    </script>
</body>
</html>`;
    
    return new Response(html, {
      headers: { 
        'Content-Type': 'text/html; charset=utf-8',
      }
    });
  }

  // 处理优质IP列表获取（JSON格式）
  async function handleGetFastIPs(env, request) {
    if (!await verifyAdmin(request, env)) {
      return jsonResponse({ error: '需要管理员权限' }, 401);
    }
    
    const data = await getStoredSpeedIPs(env);
    return jsonResponse(data);
  }
  
  // 处理优质IP列表获取（文本格式，IP#实际的延迟ms格式）
  async function handleGetFastIPsText(env, request) {
    if (!await verifyAdmin(request, env)) {
      return jsonResponse({ error: '需要管理员权限' }, 401);
    }
    
    const data = await getStoredSpeedIPs(env);
    const fastIPs = data.fastIPs || [];
    
    // 格式化为 IP#实际的延迟ms
    const ipList = fastIPs.map(item => `${item.ip}#${item.latency}ms`).join('\n');
    
    return new Response(ipList, {
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'Content-Disposition': 'inline; filename="cloudflare_fast_ips.txt"',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }
  
  // 处理 ITDog 数据获取
  async function handleItdogData(env, request) {
    if (!await verifyAdmin(request, env)) {
      return jsonResponse({ error: '需要管理员权限' }, 401);
    }
    
    const data = await getStoredIPs(env);
    return jsonResponse({
      ips: data.ips || [],
      count: data.count || 0
    });
  }
  
  // 处理测速请求
  async function handleSpeedTest(request, env) {
    const url = new URL(request.url);
    const ip = url.searchParams.get('ip');
    
    if (!ip) {
      return jsonResponse({ error: 'IP parameter is required' }, 400);
    }
    
    try {
      // 使用 Cloudflare 的测速域名
      const testUrl = `https://speed.cloudflare.com/__down?bytes=1000`;
      
      // 设置自定义 Host 头来指向特定 IP
      const response = await fetch(testUrl, {
        headers: {
          'Host': 'speed.cloudflare.com'
        },
        cf: {
          // 使用 resolveOverride 来指定 IP
          resolveOverride: ip
        }
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      // 读取响应以确保连接完成
      await response.text();
      
      return jsonResponse({
        success: true,
        ip: ip,
        time: new Date().toISOString()
      });
      
    } catch (error) {
      console.error(`Speed test failed for IP ${ip}:`, error);
      return jsonResponse({
        success: false,
        ip: ip,
        error: error.message,
        time: new Date().toISOString()
      }, 500);
    }
  }
  
  // 处理手动更新
  async function handleUpdate(env, request) {
    if (!await verifyAdmin(request, env)) {
      return jsonResponse({ error: '需要管理员权限' }, 401);
    }
    
    try {
      // 再次检查 KV 绑定
      if (!env.IP_STORAGE) {
        throw new Error('KV namespace IP_STORAGE is not bound. Please check your Worker settings.');
      }

      const startTime = Date.now();
      const { uniqueIPs, results } = await updateAllIPs(env);
      const duration = Date.now() - startTime;

      // 存储到 KV
      await env.IP_STORAGE.put('cloudflare_ips', JSON.stringify({
        ips: uniqueIPs,
        lastUpdated: new Date().toISOString(),
        count: uniqueIPs.length,
        sources: results
      }));

      // 自动触发测速并存储优质IP
      await autoSpeedTestAndStore(env, uniqueIPs);

      return jsonResponse({
        success: true,
        message: 'IPs collected and speed test completed successfully',
        duration: `${duration}ms`,
        totalIPs: uniqueIPs.length,
        timestamp: new Date().toISOString(),
        results: results
      });
    } catch (error) {
      console.error('Update error:', error);
      return jsonResponse({
        success: false,
        error: error.message
      }, 500);
    }
  }
  
  // 自动测速并存储优质IP - 优化后的逻辑
  async function autoSpeedTestAndStore(env, ips) {
    if (!ips || ips.length === 0) return;
    
    const speedResults = [];
    const BATCH_SIZE = 5; // 控制并发数
    
    // 对所有IP进行测速，但限制最大数量避免超时
    const ipsToTest = ips.slice(0, AUTO_TEST_MAX_IPS);
    
    console.log(`Starting auto speed test for ${ipsToTest.length} IPs (out of ${ips.length} total)...`);
    
    for (let i = 0; i < ipsToTest.length; i += BATCH_SIZE) {
      const batch = ipsToTest.slice(i, i + BATCH_SIZE);
      const batchPromises = batch.map(ip => testIPSpeed(ip));
      
      const batchResults = await Promise.allSettled(batchPromises);
      
      for (let j = 0; j < batchResults.length; j++) {
        const result = batchResults[j];
        const ip = batch[j];
        
        if (result.status === 'fulfilled') {
          const speedData = result.value;
          if (speedData.success && speedData.latency) {
            speedResults.push({
              ip: ip,
              latency: Math.round(speedData.latency) // 确保延迟是整数
            });
          }
        }
      }
      
      // 批次间延迟
      if (i + BATCH_SIZE < ipsToTest.length) {
        await new Promise(resolve => setTimeout(resolve, 500));
      }
    }
    
    // 按延迟排序，取前FAST_IP_COUNT个最快的IP
    speedResults.sort((a, b) => a.latency - b.latency);
    const fastIPs = speedResults.slice(0, FAST_IP_COUNT);
    
    console.log(`Speed test results: ${speedResults.length} IPs tested successfully`);
    console.log(`Fastest IP: ${fastIPs[0]?.ip} (${fastIPs[0]?.latency}ms)`);
    console.log(`Slowest fast IP: ${fastIPs[fastIPs.length-1]?.ip} (${fastIPs[fastIPs.length-1]?.latency}ms)`);
    
    // 存储优质IP
    await env.IP_STORAGE.put('cloudflare_fast_ips', JSON.stringify({
      fastIPs: fastIPs,
      lastTested: new Date().toISOString(),
      count: fastIPs.length,
      testedCount: speedResults.length,
      totalIPs: ips.length
    }));
    
    console.log(`Auto speed test completed. Found ${fastIPs.length} fast IPs out of ${speedResults.length} tested.`);
  }
  
  // 测试单个IP的速度
  async function testIPSpeed(ip) {
    try {
      const startTime = Date.now();
      const testUrl = `https://speed.cloudflare.com/__down?bytes=1000`;
      
      const response = await fetch(testUrl, {
        headers: {
          'Host': 'speed.cloudflare.com'
        },
        cf: {
          resolveOverride: ip
        },
        // 设置较短的超时时间
        signal: AbortSignal.timeout(5000)
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      await response.text();
      const endTime = Date.now();
      const latency = endTime - startTime;
      
      return {
        success: true,
        ip: ip,
        latency: latency
      };
      
    } catch (error) {
      return {
        success: false,
        ip: ip,
        error: error.message
      };
    }
  }
  
  // 处理获取IP列表 - 纯文本格式
  async function handleGetIPs(env, request) {
    if (!await verifyAdmin(request, env)) {
      return jsonResponse({ error: '需要管理员权限' }, 401);
    }
    
    const data = await getStoredIPs(env);
    return new Response(data.ips.join('\n'), {
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'Content-Disposition': 'inline; filename="cloudflare_ips.txt"',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }
  
  // 处理获取原始数据
  async function handleRawIPs(env, request) {
    if (!await verifyAdmin(request, env)) {
      return jsonResponse({ error: '需要管理员权限' }, 401);
    }
    
    const data = await getStoredIPs(env);
    return jsonResponse(data);
  }
  
  // 主要的IP收集逻辑
  async function updateAllIPs(env) {
    const urls = [
      'https://ip.164746.xyz', 
      'https://ip.haogege.xyz/',
      'https://stock.hostmonit.com/CloudFlareYes', 
      'https://api.uouin.com/cloudflare.html',
      'https://addressesapi.090227.xyz/CloudFlareYes',
      'https://addressesapi.090227.xyz/ip.164746.xyz',
      'https://www.wetest.vip/page/cloudflare/address_v4.html'
    ];

    const uniqueIPs = new Set();
    const results = [];
  
    // 使用与Python脚本相同的正则表达式
    const ipPattern = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/gi;
  
    // 批量处理URL，控制并发数
    const BATCH_SIZE = 3;
    for (let i = 0; i < urls.length; i += BATCH_SIZE) {
      const batch = urls.slice(i, i + BATCH_SIZE);
      const batchPromises = batch.map(url => fetchURLWithTimeout(url, 8000));
      
      const batchResults = await Promise.allSettled(batchPromises);
      
      for (let j = 0; j < batchResults.length; j++) {
        const result = batchResults[j];
        const url = batch[j];
        const sourceName = getSourceName(url);
        
        if (result.status === 'fulfilled') {
          const content = result.value;
          const ipMatches = content.match(ipPattern) || [];
          
          // 添加到集合中（自动去重）
          ipMatches.forEach(ip => {
            if (isValidIPv4(ip)) {
              uniqueIPs.add(ip);
            }
          });
          
          results.push({
            name: sourceName,
            status: 'success',
            count: ipMatches.length,
            error: null
          });
          
          console.log(`Successfully collected ${ipMatches.length} IPs from ${sourceName}`);
        } else {
          console.error(`Failed to fetch ${sourceName}:`, result.reason);
          results.push({
            name: sourceName,
            status: 'error',
            count: 0,
            error: result.reason.message
          });
        }
      }
      
      // 批次间延迟
      if (i + BATCH_SIZE < urls.length) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }
  
    // 按IP地址的数字顺序排序（与Python脚本相同）
    const sortedIPs = Array.from(uniqueIPs).sort((a, b) => {
      const aParts = a.split('.').map(part => parseInt(part, 10));
      const bParts = b.split('.').map(part => parseInt(part, 10));
      
      for (let i = 0; i < 4; i++) {
        if (aParts[i] !== bParts[i]) {
          return aParts[i] - bParts[i];
        }
      }
      return 0;
    });
  
    return {
      uniqueIPs: sortedIPs,
      results: results
    };
  }
  
  // 获取URL的友好名称
  function getSourceName(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname + (urlObj.pathname !== '/' ? urlObj.pathname : '');
    } catch (e) {
      return url;
    }
  }
  
  // 带超时的fetch
  async function fetchURLWithTimeout(url, timeout = 8000) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    
    try {
      const response = await fetch(url, {
        signal: controller.signal,
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; Cloudflare-IP-Collector/1.0)',
          'Accept': 'text/html,application/json,text/plain,*/*'
        }
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      return await response.text();
    } finally {
      clearTimeout(timeoutId);
    }
  }
  
  // 从 KV 获取存储的 IPs
  async function getStoredIPs(env) {
    try {
      if (!env.IP_STORAGE) {
        console.error('KV namespace IP_STORAGE is not bound');
        return getDefaultData();
      }
      
      const data = await env.IP_STORAGE.get('cloudflare_ips');
      if (data) {
        return JSON.parse(data);
      }
    } catch (error) {
      console.error('Error reading from KV:', error);
    }
    
    return getDefaultData();
  }
  
  // 从 KV 获取存储的测速IPs
  async function getStoredSpeedIPs(env) {
    try {
      if (!env.IP_STORAGE) {
        console.error('KV namespace IP_STORAGE is not bound');
        return getDefaultSpeedData();
      }
      
      const data = await env.IP_STORAGE.get('cloudflare_fast_ips');
      if (data) {
        return JSON.parse(data);
      }
    } catch (error) {
      console.error('Error reading speed IPs from KV:', error);
    }
    
    return getDefaultSpeedData();
  }
  
  // 默认数据
  function getDefaultData() {
    return {
      ips: [],
      lastUpdated: null,
      count: 0,
      sources: []
    };
  }
  
  // 默认测速数据
  function getDefaultSpeedData() {
    return {
      fastIPs: [],
      lastTested: null,
      count: 0
    };
  }
  
  // IPv4地址验证
  function isValidIPv4(ip) {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    
    for (const part of parts) {
      const num = parseInt(part, 10);
      if (isNaN(num) || num < 0 || num > 255) return false;
      // 排除私有IP段
      if (part.startsWith('0') && part.length > 1) return false;
    }
    
    // 排除私有地址
    if (ip.startsWith('10.') || 
        ip.startsWith('192.168.') ||
        (ip.startsWith('172.') && parseInt(parts[1]) >= 16 && parseInt(parts[1]) <= 31) ||
        ip.startsWith('127.') ||
        ip.startsWith('169.254.') ||
        ip === '255.255.255.255') {
      return false;
    }
    
    return true;
  }
  
  // 工具函数
  function jsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data, null, 2), {
      status,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }
  
  function handleCORS() {
    return new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
      }
    });
  }
