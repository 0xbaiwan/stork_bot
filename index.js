const AmazonCognitoIdentity = require('amazon-cognito-identity-js');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const { HttpsProxyAgent }= require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');
const crypto = require('crypto');

global.navigator = { userAgent: 'node' };

/**
 * 配置加密函数
 * @param {Object} data - 需要加密的配置数据
 * @param {Buffer} key - 加密密钥
 * @returns {Object} 返回加密后的数据、初始化向量和认证标签
 */
function encryptConfig(data, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();
  return { encrypted, iv: iv.toString('hex'), authTag: authTag.toString('hex') };
}

/**
 * 配置解密函数
 * @param {string} encrypted - 加密后的数据
 * @param {string} iv - 初始化向量
 * @param {string} authTag - 认证标签
 * @param {Buffer} key - 解密密钥
 * @returns {Object} 解密后的配置对象
 */
function decryptConfig(encrypted, iv, authTag, key) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(authTag, 'hex'));
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return JSON.parse(decrypted);
}

// Load configuration from config.json
function loadConfig() {
  try {
    const configPath = path.join(__dirname, 'config.json');
    if (!fs.existsSync(configPath)) {
      log(`未找到配置文件 ${configPath}，使用默认配置`, 'WARN');
      // 如果配置文件不存在则创建默认配置
      const defaultConfig = {
        cognito: {
          region: 'ap-northeast-1',
          clientId: '5msns4n49hmg3dftp2tp1t2iuh',
          userPoolId: 'ap-northeast-1_M22I44OpC',
          username: '',  // 用户需填写邮箱
          password: ''   // 用户需填写密码
        },
        stork: {
          intervalSeconds: 10  // 验证间隔时间(秒)
        },
        threads: {
          maxWorkers: 10      // 最大工作线程数
        }
      };
      fs.writeFileSync(configPath, JSON.stringify(defaultConfig, null, 2), 'utf8');
      return defaultConfig;
    }
    
    const userConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    log('Configuration loaded successfully from config.json');
    
    // 加密保存配置
    const key = crypto.scryptSync(process.env.CONFIG_KEY || 'default-key', 'salt', 32);
    const encryptedConfig = encryptConfig(userConfig, key);
    fs.writeFileSync(configPath + '.enc', JSON.stringify(encryptedConfig), 'utf8');
    
    return userConfig;
  } catch (error) {
    log(`Error loading config: ${error.message}`, 'ERROR');
    throw error;
  }
}

const userConfig = loadConfig();
const config = {
  cognito: {
    region: userConfig.cognito?.region || 'ap-northeast-1',
    clientId: userConfig.cognito?.clientId || '5msns4n49hmg3dftp2tp1t2iuh',
    userPoolId: userConfig.cognito?.userPoolId || 'ap-northeast-1_M22I44OpC',
    username: userConfig.cognito?.username || '',
    password: userConfig.cognito?.password || ''
  },
  stork: {
    baseURL: 'https://app-api.jp.stork-oracle.network/v1',
    authURL: 'https://api.jp.stork-oracle.network/auth',
    tokenPath: path.join(__dirname, 'tokens.json'),
    intervalSeconds: userConfig.stork?.intervalSeconds || 10,
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
    origin: 'chrome-extension://knnliglhgkmlblppdejchidfihjnockl'
  },
  threads: {
    maxWorkers: userConfig.threads?.maxWorkers || 10,
    proxyFile: path.join(__dirname, 'proxies.txt')
  }
};

function validateConfig() {
  if (!config.cognito.username || !config.cognito.password) {
    log('ERROR: Username and password must be set in config.json', 'ERROR');
    console.log('\nPlease update your config.json file with your credentials:');
    console.log(JSON.stringify({
      cognito: {
        username: "YOUR_EMAIL",
        password: "YOUR_PASSWORD"
      }
    }, null, 2));
    return false;
  }
  return true;
}

const poolData = { UserPoolId: config.cognito.userPoolId, ClientId: config.cognito.clientId };
const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

function getTimestamp() {
  const now = new Date();
  return now.toISOString().replace('T', ' ').substr(0, 19);
}

function getFormattedDate() {
  const now = new Date();
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')} ${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}`;
}

// 优化日志输出格式
function getLogPrefix(type = 'INFO') {
  const colors = {
    'INFO': '\x1b[36m',    // 青色
    'WARN': '\x1b[33m',    // 黄色
    'ERROR': '\x1b[31m',   // 红色
    'SUCCESS': '\x1b[32m', // 绿色
    'SYSTEM': '\x1b[35m'   // 紫色
  };
  const reset = '\x1b[0m';
  return `${colors[type]}[${getFormattedDate()}] [${type}]${reset}`;
}

function log(message, type = 'INFO') {
  console.log(`${getLogPrefix(type)} ${message}`);
}

function loadProxies() {
  try {
    if (!fs.existsSync(config.threads.proxyFile)) {
      log(`Proxy file not found at ${config.threads.proxyFile}, creating empty file`, 'WARN');
      fs.writeFileSync(config.threads.proxyFile, '', 'utf8');
      return [];
    }
    const proxyData = fs.readFileSync(config.threads.proxyFile, 'utf8');
    const proxies = proxyData
      .split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'));
    log(`Loaded ${proxies.length} proxies from ${config.threads.proxyFile}`);
    return proxies;
  } catch (error) {
    log(`Error loading proxies: ${error.message}`, 'ERROR');
    return [];
  }
}

class CognitoAuth {
  constructor(username, password) {
    this.username = username;
    this.password = password;
    this.authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails({ Username: username, Password: password });
    this.cognitoUser = new AmazonCognitoIdentity.CognitoUser({ Username: username, Pool: userPool });
  }

  authenticate() {
    return new Promise((resolve, reject) => {
      this.cognitoUser.authenticateUser(this.authenticationDetails, {
        onSuccess: (result) => resolve({
          accessToken: result.getAccessToken().getJwtToken(),
          idToken: result.getIdToken().getJwtToken(),
          refreshToken: result.getRefreshToken().getToken(),
          expiresIn: result.getAccessToken().getExpiration() * 1000 - Date.now()
        }),
        onFailure: (err) => reject(err),
        newPasswordRequired: () => reject(new Error('New password required'))
      });
    });
  }

  refreshSession(refreshToken) {
    const refreshTokenObj = new AmazonCognitoIdentity.CognitoRefreshToken({ RefreshToken: refreshToken });
    return new Promise((resolve, reject) => {
      this.cognitoUser.refreshSession(refreshTokenObj, (err, result) => {
        if (err) reject(err);
        else resolve({
          accessToken: result.getAccessToken().getJwtToken(),
          idToken: result.getIdToken().getJwtToken(),
          refreshToken: refreshToken,
          expiresIn: result.getAccessToken().getExpiration() * 1000 - Date.now()
        });
      });
    });
  }

  /**
   * 注册新用户
   * @param {string} email - 用户邮箱
   * @param {string} password - 用户密码
   * @param {string} referralCode - 邀请码(可选)
   * @returns {Promise} 注册结果
   */
  static async signUp(email, password, referralCode = '') {
    try {
      log('开始注册新用户...');
      
      // 验证邮箱格式
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        throw new Error('邮箱格式不正确');
      }
      
      // 验证密码强度
      if (password.length < 8) {
        throw new Error('密码长度必须大于8位');
      }

      // 使用 Cognito SDK 注册
      return new Promise((resolve, reject) => {
        const attributeList = [
          new AmazonCognitoIdentity.CognitoUserAttribute({
            Name: 'email',
            Value: email
          })
        ];

        if (referralCode) {
          attributeList.push(
            new AmazonCognitoIdentity.CognitoUserAttribute({
              Name: 'custom:referral_code',
              Value: referralCode
            })
          );
        }

        userPool.signUp(email, password, attributeList, null, (err, result) => {
          if (err) {
            log(`注册失败: ${err.message}`, 'ERROR');
            reject(err);
            return;
          }
          log('注册成功，请查收验证邮件', 'SUCCESS');
          resolve(result);
        });
      });
    } catch (error) {
      log(`注册失败: ${error.message}`, 'ERROR');
      throw error;
    }
  }

  /**
   * 验证邮箱
   * @param {string} email - 用户邮箱
   * @param {string} code - 验证码
   * @returns {Promise} 验证结果
   */
  static async verifyEmail(email, code) {
    try {
      log('正在验证邮箱...');
      
      return new Promise((resolve, reject) => {
        const userData = {
          Username: email,
          Pool: userPool
        };

        const cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);

        cognitoUser.confirmRegistration(code, true, (err, result) => {
          if (err) {
            log(`邮箱验证失败: ${err.message}`, 'ERROR');
            reject(err);
            return;
          }
          log('邮箱验证成功！', 'SUCCESS');
          resolve(result);
        });
      });
    } catch (error) {
      log(`邮箱验证失败: ${error.message}`, 'ERROR');
      throw error;
    }
  }
}

class TokenManager {
  constructor() {
    this.accessToken = null;
    this.refreshToken = null;
    this.idToken = null;
    this.expiresAt = null;
    this.auth = new CognitoAuth(config.cognito.username, config.cognito.password);
  }

  async getValidToken() {
    if (!this.accessToken || this.isTokenExpired()) await this.refreshOrAuthenticate();
    return this.accessToken;
  }

  isTokenExpired() {
    return Date.now() >= this.expiresAt;
  }

  async refreshOrAuthenticate() {
    try {
      let result = this.refreshToken ? await this.auth.refreshSession(this.refreshToken) : await this.auth.authenticate();
      await this.updateTokens(result);
    } catch (error) {
      log(`Token refresh/auth error: ${error.message}`, 'ERROR');
      throw error;
    }
  }

  async updateTokens(result) {
    this.accessToken = result.accessToken;
    this.idToken = result.idToken;
    this.refreshToken = result.refreshToken;
    this.expiresAt = Date.now() + result.expiresIn;
    const tokens = { accessToken: this.accessToken, idToken: this.idToken, refreshToken: this.refreshToken, isAuthenticated: true, isVerifying: false };
    await saveTokens(tokens);
    log('Tokens updated and saved to tokens.json');
  }
}

async function getTokens() {
  try {
    if (!fs.existsSync(config.stork.tokenPath)) throw new Error(`Tokens file not found at ${config.stork.tokenPath}`);
    const tokensData = await fs.promises.readFile(config.stork.tokenPath, 'utf8');
    const tokens = JSON.parse(tokensData);
    if (!tokens.accessToken || tokens.accessToken.length < 20) throw new Error('Invalid access token');
    log(`Successfully read access token: ${tokens.accessToken.substring(0, 10)}...`);
    return tokens;
  } catch (error) {
    log(`Error reading tokens: ${error.message}`, 'ERROR');
    throw error;
  }
}

async function saveTokens(tokens) {
  try {
    await fs.promises.writeFile(config.stork.tokenPath, JSON.stringify(tokens, null, 2), 'utf8');
    log('Tokens saved successfully');
    return true;
  } catch (error) {
    log(`Error saving tokens: ${error.message}`, 'ERROR');
    return false;
  }
}

function getProxyAgent(proxy) {
  if (!proxy) return null;
  if (proxy.startsWith('http')) return new HttpsProxyAgent(proxy);
  if (proxy.startsWith('socks4') || proxy.startsWith('socks5')) return new SocksProxyAgent(proxy);
  throw new Error(`Unsupported proxy protocol: ${proxy}`);
}

async function refreshTokens(refreshToken) {
  try {
    log('Refreshing access token via Stork API...');
    const response = await axios({
      method: 'POST',
      url: `${config.stork.authURL}/refresh`,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': config.stork.userAgent,
        'Origin': config.stork.origin
      },
      data: { refresh_token: refreshToken }
    });
    const tokens = {
      accessToken: response.data.access_token,
      idToken: response.data.id_token || '',
      refreshToken: response.data.refresh_token || refreshToken,
      isAuthenticated: true,
      isVerifying: false
    };
    await saveTokens(tokens);
    log('Token refreshed successfully via Stork API');
    return tokens;
  } catch (error) {
    log(`Token refresh failed: ${error.message}`, 'ERROR');
    throw error;
  }
}

async function getSignedPrices(tokens) {
  const maxRetries = 3;
  let retries = 0;
  
  while (retries < maxRetries) {
    try {
      const response = await axios({
        method: 'GET',
        url: `${config.stork.baseURL}/stork_signed_prices`,
        headers: {
          'Authorization': `Bearer ${tokens.accessToken}`,
          'Content-Type': 'application/json',
          'Origin': config.stork.origin,
          'User-Agent': config.stork.userAgent
        },
        timeout: 10000 // 10 seconds timeout
      });
      const dataObj = response.data.data;
      const result = Object.keys(dataObj).map(assetKey => {
        const assetData = dataObj[assetKey];
        return {
          asset: assetKey,
          msg_hash: assetData.timestamped_signature.msg_hash,
          price: assetData.price,
          timestamp: new Date(assetData.timestamped_signature.timestamp / 1000000).toISOString(),
          ...assetData
        };
      });
      log(`Successfully retrieved ${result.length} signed prices`);
      return result;
    } catch (error) {
      retries++;
      if (retries === maxRetries) throw error;
      log(`Retry ${retries}/${maxRetries} after error: ${error.message}`, 'WARN');
      await new Promise(resolve => setTimeout(resolve, 2000 * retries));
    }
  }
}

class RateLimit {
  constructor(maxRequests, timeWindow) {
    this.maxRequests = maxRequests;
    this.timeWindow = timeWindow;
    this.requests = [];
  }

  async checkLimit() {
    const now = Date.now();
    this.requests = this.requests.filter(time => now - time < this.timeWindow);
    
    if (this.requests.length >= this.maxRequests) {
      const oldestRequest = this.requests[0];
      const waitTime = this.timeWindow - (now - oldestRequest);
      await new Promise(resolve => setTimeout(resolve, waitTime));
    }
    
    this.requests.push(now);
  }
}

const rateLimit = new RateLimit(10, 60000); // 10 requests per minute

// 优化验证统计显示
function displayStats(userData) {
  if (!userData || !userData.stats) {
    log('暂无有效的统计数据', 'WARN');
    return;
  }

  console.clear();
  console.log('\x1b[36m=============================================\x1b[0m');
  console.log('\x1b[32m   STORK ORACLE 自动验证机器人 - 0xbaiwan\x1b[0m');
  console.log('\x1b[36m=============================================\x1b[0m');
  console.log(`🕒 当前时间: ${getTimestamp()}`);
  console.log('\x1b[36m---------------------------------------------\x1b[0m');
  console.log(`👤 用户邮箱: ${userData.email || '未知'}`);
  console.log(`📋 用户ID: ${userData.id || '未知'}`);
  console.log(`🎫 邀请码: ${userData.referral_code || '未知'}`);
  console.log('\x1b[36m---------------------------------------------\x1b[0m');
  console.log('📊 验证统计:');
  console.log(`✅ 有效验证次数: ${userData.stats.stork_signed_prices_valid_count || 0}`);
  console.log(`❌ 无效验证次数: ${userData.stats.stork_signed_prices_invalid_count || 0}`);
  console.log(`⏱️ 最后验证时间: ${userData.stats.stork_signed_prices_last_verified_at || '从未验证'}`);
  console.log(`👥 邀请使用次数: ${userData.stats.referral_usage_count || 0}`);
  console.log('\x1b[36m---------------------------------------------\x1b[0m');
  console.log(`⏳ ${config.stork.intervalSeconds} 秒后进行下一次验证...`);
  console.log('\x1b[36m=============================================\x1b[0m');
}

// 优化验证过程日志
async function sendValidation(tokens, msgHash, isValid, proxy) {
  await rateLimit.checkLimit();
  
  try {
    const agent = getProxyAgent(proxy);
    const response = await axios({
      method: 'POST',
      url: `${config.stork.baseURL}/stork_signed_prices/validations`,
      headers: {
        'Authorization': `Bearer ${tokens.accessToken}`,
        'Content-Type': 'application/json',
        'Origin': config.stork.origin,
        'User-Agent': config.stork.userAgent
      },
      httpsAgent: agent,
      data: { msg_hash: msgHash, valid: isValid }
    });
    log(`✅ 验证成功: ${msgHash.substring(0, 10)}... ${proxy ? `(代理: ${proxy})` : '(直连)'}`, 'SUCCESS');
    return response.data;
  } catch (error) {
    log(`❌ 验证失败: ${msgHash.substring(0, 10)}... 错误: ${error.message}`, 'ERROR');
    throw error;
  }
}

async function getUserStats(tokens) {
  try {
    log('Fetching user stats...');
    const response = await axios({
      method: 'GET',
      url: `${config.stork.baseURL}/me`,
      headers: {
        'Authorization': `Bearer ${tokens.accessToken}`,
        'Content-Type': 'application/json',
        'Origin': config.stork.origin,
        'User-Agent': config.stork.userAgent
      }
    });
    return response.data.data;
  } catch (error) {
    log(`Error getting user stats: ${error.message}`, 'ERROR');
    throw error;
  }
}

function validatePrice(priceData) {
  try {
    log(`Validating data for ${priceData.asset || 'unknown asset'}`);
    if (!priceData.msg_hash || !priceData.price || !priceData.timestamp) {
      log('Incomplete data, considered invalid', 'WARN');
      return false;
    }
    const currentTime = Date.now();
    const dataTime = new Date(priceData.timestamp).getTime();
    const timeDiffMinutes = (currentTime - dataTime) / (1000 * 60);
    if (timeDiffMinutes > 60) {
      log(`Data too old (${Math.round(timeDiffMinutes)} minutes ago)`, 'WARN');
      return false;
    }
    return true;
  } catch (error) {
    log(`Validation error: ${error.message}`, 'ERROR');
    return false;
  }
}

// 添加默认邀请码列表
const DEFAULT_REFERRAL_CODES = [
  'C206F14E3B',
  'WNNQC1YMG7',
  'NFM7C453T4',
  'FVC71O8KRF',
  'N79DTN4HYQ',
  'QF7NAMIVWM',
  'IHUSMIHTIH',
  'FOW3YB5800',
  '14IUPT639M',
  'GCRQBTGA9G'
];

// 获取随机邀请码函数
function getRandomReferralCode() {
  const randomIndex = Math.floor(Math.random() * DEFAULT_REFERRAL_CODES.length);
  return DEFAULT_REFERRAL_CODES[randomIndex];
}

if (!isMainThread) {
  const { priceData, tokens, proxy } = workerData;

  async function validateAndSend() {
    try {
      const isValid = validatePrice(priceData);
      await sendValidation(tokens, priceData.msg_hash, isValid, proxy);
      parentPort.postMessage({ success: true, msgHash: priceData.msg_hash, isValid });
    } catch (error) {
      parentPort.postMessage({ success: false, error: error.message, msgHash: priceData.msg_hash });
    }
  }

  validateAndSend();
} else {
  let previousStats = { validCount: 0, invalidCount: 0 };

  async function runValidationProcess(tokenManager) {
    try {
      log('--------- STARTING VALIDATION PROCESS ---------');
      const tokens = await getTokens();
      const initialUserData = await getUserStats(tokens);

      if (!initialUserData || !initialUserData.stats) {
        throw new Error('Could not fetch initial user stats');
      }

      const initialValidCount = initialUserData.stats.stork_signed_prices_valid_count || 0;
      const initialInvalidCount = initialUserData.stats.stork_signed_prices_invalid_count || 0;

      if (previousStats.validCount === 0 && previousStats.invalidCount === 0) {
        previousStats.validCount = initialValidCount;
        previousStats.invalidCount = initialInvalidCount;
      }

      const signedPrices = await getSignedPrices(tokens);
      const proxies = loadProxies();

      if (!signedPrices || signedPrices.length === 0) {
        log('No data to validate');
        const userData = await getUserStats(tokens);
        displayStats(userData);
        return;
      }

      log(`Processing ${signedPrices.length} data points with ${config.threads.maxWorkers} workers...`);
      const workers = [];

      const chunkSize = Math.ceil(signedPrices.length / config.threads.maxWorkers);
      const batches = [];
      for (let i = 0; i < signedPrices.length; i += chunkSize) {
        batches.push(signedPrices.slice(i, i + chunkSize));
      }

      for (let i = 0; i < Math.min(batches.length, config.threads.maxWorkers); i++) {
        const batch = batches[i];
        const proxy = proxies.length > 0 ? proxies[i % proxies.length] : null;

        batch.forEach(priceData => {
          workers.push(new Promise((resolve) => {
            const worker = new Worker(__filename, {
              workerData: { priceData, tokens, proxy }
            });
            worker.on('message', resolve);
            worker.on('error', (error) => resolve({ success: false, error: error.message }));
            worker.on('exit', () => resolve({ success: false, error: 'Worker exited' }));
          }));
        });
      }

      const results = await Promise.all(workers);
      const successCount = results.filter(r => r.success).length;
      log(`Processed ${successCount}/${results.length} validations successfully`);

      const updatedUserData = await getUserStats(tokens);
      const newValidCount = updatedUserData.stats.stork_signed_prices_valid_count || 0;
      const newInvalidCount = updatedUserData.stats.stork_signed_prices_invalid_count || 0;

      const actualValidIncrease = newValidCount - previousStats.validCount;
      const actualInvalidIncrease = newInvalidCount - previousStats.invalidCount;

      previousStats.validCount = newValidCount;
      previousStats.invalidCount = newInvalidCount;

      displayStats(updatedUserData);
      log(`--------- VALIDATION SUMMARY ---------`);
      log(`Total data processed: ${actualValidIncrease + actualInvalidIncrease}`);
      log(`Successful: ${actualValidIncrease}`);
      log(`Failed: ${actualInvalidIncrease}`);
      log('--------- COMPLETE ---------');
    } catch (error) {
      log(`Validation process stopped: ${error.message}`, 'ERROR');
    }
  }

  async function main() {
    try {
      // 重新加载最新配置
      const currentConfig = loadConfig();
      if (!currentConfig.cognito.username || !currentConfig.cognito.password) {
        log('请先登录或注册账号', 'ERROR');
        process.exit(1);
      }
      
      // 更新全局配置
      config.cognito.username = currentConfig.cognito.username;
      config.cognito.password = currentConfig.cognito.password;
      
      const tokenManager = new TokenManager();
      await tokenManager.getValidToken();
      log('初始认证成功', 'SUCCESS');

      runValidationProcess(tokenManager);
      setInterval(() => runValidationProcess(tokenManager), config.stork.intervalSeconds * 1000);
      setInterval(async () => {
        await tokenManager.getValidToken();
        log('Token 已刷新', 'SUCCESS');
      }, 50 * 60 * 1000);
    } catch (error) {
      log(`程序启动失败: ${error.message}`, 'ERROR');
      process.exit(1);
    }
  }

  // 添加自动更新配置文件的函数
  async function updateConfig(email, password) {
    try {
      const configPath = path.join(__dirname, 'config.json');
      let config = {};
      
      if (fs.existsSync(configPath)) {
        config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      } else {
        config = {
          cognito: {
            region: 'ap-northeast-1',
            clientId: '5msns4n49hmg3dftp2tp1t2iuh',
            userPoolId: 'ap-northeast-1_M22I44OpC'
          },
          stork: {
            intervalSeconds: 5
          },
          threads: {
            maxWorkers: 1
          }
        };
      }

      // 更新认证信息
      config.cognito.username = email;
      config.cognito.password = password;

      // 保存配置
      fs.writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf8');
      log('配置文件已更新');
    } catch (error) {
      log(`更新配置文件失败: ${error.message}`, 'ERROR');
      throw error;
    }
  }

  // 显示主菜单
  async function showMainMenu() {
    const readline = require('readline').createInterface({
      input: process.stdin,
      output: process.stdout
    });

    const question = (query) => new Promise((resolve) => readline.question(query, resolve));

    try {
      console.clear();
      console.log('=============================================');
      console.log('   STORK ORACLE AUTO BOT - 主菜单');
      console.log('=============================================');
      console.log('1. 注册新账号');
      console.log('2. 登录已有账号');
      console.log('3. 运行验证机器人');
      console.log('4. 退出程序');
      console.log('=============================================');

      const choice = await question('请选择操作 (1-4): ');

      switch (choice.trim()) {
        case '1':
          // 注册流程
          const email = await question('请输入邮箱: ');
          const password = await question('请输入密码: ');
          let referralCode = await question('请输入邀请码(直接回车使用随机邀请码): ');
          
          // 如果用户没有输入邀请码，使用随机邀请码
          if (!referralCode.trim()) {
            referralCode = getRandomReferralCode();
            log(`使用随机邀请码: ${referralCode}`);
          }

          await CognitoAuth.signUp(email, password, referralCode);
          
          const verifyCode = await question('请输入邮箱收到的验证码: ');
          await CognitoAuth.verifyEmail(email, verifyCode);

          // 自动更新配置文件
          await updateConfig(email, password);
          
          log('注册完成！配置文件已自动更新');
          
          // 询问是否立即启动机器人
          const startNow = await question('是否立即启动机器人？(y/n): ');
          if (startNow.toLowerCase() === 'y') {
            readline.close();
            main();
          } else {
            readline.close();
            process.exit(0);
          }
          break;

        case '2':
          // 登录流程
          try {
            const loginEmail = await question('请输入邮箱: ');
            const loginPassword = await question('请输入密码: ');
            
            // 先验证登录凭据
            const auth = new CognitoAuth(loginEmail, loginPassword);
            await auth.authenticate();
            log('登录验证成功！', 'SUCCESS');
            
            // 更新配置文件
            await updateConfig(loginEmail, loginPassword);
            log('配置文件已更新', 'SUCCESS');
            
            // 重新加载配置
            config.cognito.username = loginEmail;
            config.cognito.password = loginPassword;
            
            // 询问是否立即启动机器人
            const startNow = await question('是否立即启动机器人？(y/n): ');
            if (startNow.toLowerCase() === 'y') {
              readline.close();
              // 使用新的认证信息创建 tokenManager
              const tokenManager = new TokenManager();
              await tokenManager.getValidToken(); // 验证新的认证信息
              log('认证信息验证成功，正在启动机器人...', 'SUCCESS');
              main();
            } else {
              readline.close();
              process.exit(0);
            }
          } catch (error) {
            log(`登录失败: ${error.message}`, 'ERROR');
            readline.close();
            process.exit(1);
          }
          break;

        case '3':
          // 检查配置文件是否已设置
          const currentConfig = loadConfig();
          if (!currentConfig.cognito.username || !currentConfig.cognito.password) {
            log('请先登录或注册账号', 'ERROR');
            readline.close();
            process.exit(1);
          }
          // 直接运行机器人
          readline.close();
          main();
          break;

        case '4':
          // 退出程序
          console.log('感谢使用，再见！');
          readline.close();
          process.exit(0);
          break;

        default:
          log('无效的选择，请重新运行程序', 'ERROR');
          readline.close();
          process.exit(1);
      }
    } catch (error) {
      log(`操作失败: ${error.message}`, 'ERROR');
      readline.close();
      process.exit(1);
    }
  }

  // 修改主程序入口
  showMainMenu();
}
