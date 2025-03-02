# Stork Oracle 自动验证机器人

## 项目介绍

种子轮融资400万美金的Stork目前可以通过挂机赚取积分奖励。这是一个用于 Stork Oracle 网络的自动验证机器人，可以帮助用户自动完成价格验证过程，赚取 Stork Oracle 系统的奖励。

## 功能特点

✨ **核心功能**
- 自动验证价格数据
- 智能多线程处理
- 实时统计展示
- 自动令牌刷新

🛡️ **安全特性**
- 配置文件加密存储
- 请求速率限制
- 代理支持
- 异常重试机制

🎯 **便捷功能**
- 交互式操作菜单
- 账号注册/登录
- 随机邀请码
- 自动配置管理

## 系统要求

- Node.js 14.0.0 或更高版本
- 稳定的网络连接

## 快速开始

1. **克隆项目**
```bash
git clone https://github.com/0xbaiwan/stork_bot.git
cd stork_bot
```

2. **安装依赖**
```bash
npm install
```

3. **运行程序**
```bash
node index.js
```

## 使用说明

### 主菜单选项

1. **注册新账号**
   - 输入邮箱和密码
   - 可选使用随机邀请码
   - 完成邮箱验证
   - 自动保存配置

2. **登录已有账号**
   - 输入邮箱和密码
   - 验证成功后自动保存

3. **运行验证机器人**
   - 自动执行验证任务
   - 显示实时统计信息

### 代理配置（可选）

在项目根目录创建 `proxies.txt` 文件，支持以下格式：
```
http://用户名:密码@主机:端口
socks5://用户名:密码@主机:端口
```

### 代理服务推荐（可选）

#### 免费静态住宅代理
- [WebShare](https://www.webshare.io/?referral_code=gtw7lwqqelgu)
- [ProxyScrape](https://proxyscrape.com/)
- [MonoSans](https://github.com/monosans/proxy-list)

#### 付费高级静态住宅代理
- [922proxy](https://www.922proxy.com/register?inviter_code=d6416857)
- [Proxy-Cheap](https://app.proxy-cheap.com/r/Pd6sqg)
- [Infatica](https://dashboard.infatica.io/aff.php?aff=580)

#### 付费动态IP代理
- [IPRoyal](https://iproyal.com/?r=733417)

### 高级配置

编辑 `config.json` 文件：
```json
{
  "stork": {
    "intervalSeconds": 5    // 验证间隔(秒)
  },
  "threads": {
    "maxWorkers": 1        // 工作线程数
  }
}
```

## 注意事项

- 请使用真实邮箱注册，方便接收验证码
- 建议使用代理以提高成功率
- 遵守 Stork Oracle 使用条款
- 定期备份配置文件

## 故障排除

1. **登录失败**
   - 检查邮箱密码是否正确
   - 确认网络连接正常
   - 查看错误日志信息

2. **验证失败**
   - 检查配置文件正确性
   - 尝试使用代理服务器
   - 适当调整验证间隔

3. **程序异常**
   - 删除 tokens.json 重新登录
   - 更新到最新版本
   - 检查 Node.js 版本

## 免责声明

本程序仅供学习交流使用，使用本程序产生的任何后果由用户自行承担。

## 开源协议

MIT License

