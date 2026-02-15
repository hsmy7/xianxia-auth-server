/**
 * 模拟宗门 - TapTap 登录服务端
 * 处理 OAuth 授权流程，支持 MAC Token 鉴权
 */

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// TapTap 配置
const TAP_CONFIG = {
    clientId: 'csg5qlajcgr157ix01',
    clientToken: 'bvDH35Gw2SCcgkmNFrmQxLi0xaMylxLXEB6VNMUK',
    redirectUri: 'https://your-domain.com/taptap-callback.html', // 部署后需要修改
    authUrl: 'https://accounts.taptap.com/oauth2/v1/authorize',
    tokenUrl: 'https://accounts.taptap.com/oauth2/v1/token',
    userInfoUrl: 'https://open.tapapis.cn/account/profile/v1'
};

// 中间件
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

/**
 * 生成 MAC Token
 * @param {string} macKey - MAC 密钥
 * @param {string} kid - Key ID
 * @param {string} method - HTTP 方法
 * @param {string} uri - 请求路径
 * @param {string} host - 主机名
 * @param {string} port - 端口
 * @returns {string} - Authorization header
 */
function generateMacToken(macKey, kid, method, uri, host, port) {
    const ts = Math.floor(Date.now() / 1000).toString();
    const nonce = Math.random().toString(36).substring(2, 10);
    
    // 构建 normalized string
    const normalizedString = [
        ts,
        nonce,
        method.toUpperCase(),
        uri,
        host,
        port
    ].join('\n') + '\n';
    
    // 计算 MAC
    const mac = crypto
        .createHmac('sha1', macKey)
        .update(normalizedString)
        .digest('base64');
    
    // 构建 Authorization header
    const authHeader = `MAC id="${kid}",ts="${ts}",nonce="${nonce}",mac="${mac}"`;
    
    return authHeader;
}

/**
 * 获取授权 URL
 * GET /api/auth/url
 */
app.get('/api/auth/url', (req, res) => {
    const state = Math.random().toString(36).substring(2, 15);
    
    const authUrl = `${TAP_CONFIG.authUrl}?` +
        `client_id=${TAP_CONFIG.clientId}&` +
        `response_type=code&` +
        `scope=public_profile&` +
        `redirect_uri=${encodeURIComponent(TAP_CONFIG.redirectUri)}&` +
        `state=${state}`;
    
    res.json({
        success: true,
        authUrl: authUrl,
        state: state
    });
});

/**
 * 用 code 换取 access_token
 * POST /api/auth/token
 */
app.post('/api/auth/token', async (req, res) => {
    const { code } = req.body;
    
    if (!code) {
        return res.status(400).json({
            success: false,
            error: '缺少授权码'
        });
    }
    
    try {
        // 调用 TapTap API 换取 token
        const response = await axios.post(TAP_CONFIG.tokenUrl, {
            client_id: TAP_CONFIG.clientId,
            client_secret: TAP_CONFIG.clientToken,
            code: code,
            grant_type: 'authorization_code',
            redirect_uri: TAP_CONFIG.redirectUri
        }, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        const { access_token, expires_in, refresh_token, mac_key, mac_algorithm, kid } = response.data;
        
        res.json({
            success: true,
            accessToken: access_token,
            expiresIn: expires_in,
            refreshToken: refresh_token,
            macKey: mac_key,
            macAlgorithm: mac_algorithm,
            kid: kid
        });
        
    } catch (error) {
        console.error('获取 token 失败:', error.response?.data || error.message);
        res.status(500).json({
            success: false,
            error: '获取 token 失败',
            details: error.response?.data || error.message
        });
    }
});

/**
 * 获取用户信息（使用 MAC Token）
 * POST /api/user/info
 */
app.post('/api/user/info', async (req, res) => {
    const { access_token, mac_key, kid } = req.body;
    
    if (!access_token || !mac_key || !kid) {
        return res.status(400).json({
            success: false,
            error: '缺少必要参数'
        });
    }
    
    try {
        // 构建请求路径和主机
        const uri = `/account/profile/v1?client_id=${TAP_CONFIG.clientId}`;
        const host = 'open.tapapis.cn';
        const port = '443';
        
        // 生成 MAC Token
        const macToken = generateMacToken(mac_key, kid, 'GET', uri, host, port);
        
        console.log('MAC Token:', macToken);
        
        // 调用 TapTap API 获取用户信息
        const response = await axios.get(`https://${host}${uri}`, {
            headers: {
                'Authorization': macToken
            }
        });
        
        const userData = response.data.data;
        
        res.json({
            success: true,
            user: {
                id: userData.user_id || userData.openid,
                name: userData.name,
                avatar: userData.avatar,
                unionId: userData.union_id || userData.unionid,
                openId: userData.open_id || userData.openid
            }
        });
        
    } catch (error) {
        console.error('获取用户信息失败:', error.response?.data || error.message);
        res.status(500).json({
            success: false,
            error: '获取用户信息失败',
            details: error.response?.data || error.message
        });
    }
});

/**
 * 完整的登录流程（code -> token -> userInfo）
 * POST /api/auth/login
 */
app.post('/api/auth/login', async (req, res) => {
    const { code } = req.body;
    
    if (!code) {
        return res.status(400).json({
            success: false,
            error: '缺少授权码'
        });
    }
    
    try {
        console.log('开始登录流程，code:', code);
        
        // 第一步：用 code 换 token
        const tokenResponse = await axios.post(TAP_CONFIG.tokenUrl, {
            client_id: TAP_CONFIG.clientId,
            client_secret: TAP_CONFIG.clientToken,
            code: code,
            grant_type: 'authorization_code',
            redirect_uri: TAP_CONFIG.redirectUri
        }, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        const { access_token, mac_key, kid } = tokenResponse.data;
        
        console.log('获取 token 成功:', { access_token: access_token?.substring(0, 20) + '...', mac_key: mac_key?.substring(0, 10) + '...', kid });
        
        // 第二步：用 MAC Token 获取用户信息
        const uri = `/account/profile/v1?client_id=${TAP_CONFIG.clientId}`;
        const host = 'open.tapapis.cn';
        const port = '443';
        
        const macToken = generateMacToken(mac_key, kid, 'GET', uri, host, port);
        
        console.log('MAC Token:', macToken);
        
        const userResponse = await axios.get(`https://${host}${uri}`, {
            headers: {
                'Authorization': macToken
            }
        });
        
        const userData = userResponse.data.data;
        
        console.log('获取用户信息成功:', userData);
        
        res.json({
            success: true,
            accessToken: access_token,
            user: {
                id: userData.user_id || userData.openid,
                name: userData.name,
                avatar: userData.avatar,
                unionId: userData.union_id || userData.unionid,
                openId: userData.open_id || userData.openid
            }
        });
        
    } catch (error) {
        console.error('登录失败:', error.response?.data || error.message);
        res.status(500).json({
            success: false,
            error: '登录失败',
            details: error.response?.data || error.message
        });
    }
});

/**
 * 健康检查
 */
app.get('/health', (req, res) => {
    res.json({ status: 'ok', time: new Date().toISOString() });
});

// 启动服务器
app.listen(PORT, () => {
    console.log('========================================');
    console.log('模拟宗门 - TapTap 登录服务端');
    console.log('========================================');
    console.log(`服务器运行在: http://localhost:${PORT}`);
    console.log('');
    console.log('API 接口:');
    console.log(`  GET  http://localhost:${PORT}/api/auth/url    - 获取授权 URL`);
    console.log(`  POST http://localhost:${PORT}/api/auth/token   - 换取 access_token`);
    console.log(`  POST http://localhost:${PORT}/api/user/info    - 获取用户信息（MAC Token）`);
    console.log(`  POST http://localhost:${PORT}/api/auth/login   - 完整登录流程`);
    console.log('========================================');
});
