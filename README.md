# FanchMWRT - 企业级安全路由固件

基于 OpenWrt 24.10.4 的企业级安全路由固件，集成深度包检测(DPI)、入侵检测(IDS)、威胁情报、防病毒等安全功能。

## 功能特性

### 🛡️ 安全功能

| 模块 | 功能 | 状态 |
|------|------|------|
| **应用识别过滤 (fwx)** | 基于 DPI 的应用层流量识别与过滤 | ✅ 已实现 |
| **入侵检测 (fwx-ids)** | 端口扫描、SYN Flood、暴力破解检测 | ✅ 已实现 |
| **Suricata IDS** | 专业级 IDS 引擎集成 | ✅ 已实现 |
| **威胁情报 (fwx-threat)** | IP/域名黑名单，自动更新，热更新 | ✅ 已实现 |
| **防病毒 (fwx-av)** | ClamAV 集成，文件扫描 | ✅ 已实现 |
| **MAC 过滤** | 基于 MAC 地址的访问控制 | ✅ 已实现 |
| **设备画像** | 终端指纹识别、厂商识别、行为分析 | ✅ 已实现 |
| **安全告警** | 统一告警系统，支持通知推送 | ✅ 已实现 |

### 📊 监控与管理

- **LuCI Web 界面** - 完整的安全中心管理界面
- **流量统计** - 实时流量监控与分析
- **告警日志** - 安全事件记录与查询
- **UBUS API** - 完整的编程接口

## 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                    LuCI Web Interface                        │
│                   (luci-app-fwx)                            │
├─────────────────────────────────────────────────────────────┤
│                      UBUS API Layer                          │
├──────────┬──────────┬──────────┬──────────┬────────────────┤
│  fwxd    │ fwx-ids  │fwx-threat│  fwx-av  │ Device Profile │
│ (daemon) │  (IDS)   │ (Threat) │   (AV)   │   (Profiling)  │
├──────────┴──────────┴──────────┴──────────┴────────────────┤
│                   libfwx_common                              │
│            (共享库: 日志、配置、NFT原子操作)                   │
├─────────────────────────────────────────────────────────────┤
│                  fwx Kernel Module                           │
│                (Netfilter DPI 内核模块)                       │
├─────────────────────────────────────────────────────────────┤
│                    nftables / Netfilter                      │
└─────────────────────────────────────────────────────────────┘
```

## 模块说明

### fwx (内核模块)
深度包检测内核模块，基于 Netfilter 框架实现应用层协议识别。

### fwxd (用户态守护进程)
核心守护进程，提供：
- 应用过滤规则管理
- MAC 地址过滤
- 设备画像与指纹识别
- UBUS 接口服务
- 流量统计

### fwx-ids (入侵检测)
轻量级 IDS，检测：
- 端口扫描攻击
- SYN Flood 攻击
- SSH 暴力破解
- ICMP Flood 攻击

使用 nftables 原子规则集加载，零中断更新。

### fwx-ids-suricata (Suricata 集成)
专业级 IDS 引擎，支持：
- 规则自动更新 (ET Open)
- EVE JSON 日志
- 高级威胁检测

### fwx-threat (威胁情报)
IP/域名黑名单过滤：
- 多源威胁情报聚合
- 定时自动更新
- 热更新（增量更新，保留统计）
- 域名通过 dnsmasq 拦截

### fwx-av (防病毒)
ClamAV 集成：
- 文件扫描
- 病毒库更新
- 隔离区管理

### 设备画像 (Device Profiling)
终端识别与行为分析：
- MAC OUI 厂商识别
- TCP/IP 指纹分析
- User-Agent 解析
- DHCP 指纹
- 行为画像与风险评分

## 编译指南

### 环境要求
- Ubuntu 22.04 或更高版本
- 8GB+ RAM
- 50GB+ 磁盘空间

### 本地编译

```bash
# 安装依赖
sudo apt-get install build-essential clang flex bison g++ gawk \
  gcc-multilib g++-multilib gettext git libncurses5-dev libssl-dev \
  python3-setuptools rsync swig unzip zlib1g-dev file wget

# 更新 feeds
./scripts/feeds update -a
./scripts/feeds install -a

# 配置
cp configs/x86-64.config .config
make defconfig

# 编译
make -j$(nproc) V=s
```

### GitHub Actions 编译

项目已配置 GitHub Actions 自动编译：

1. Fork 本仓库
2. 进入 Actions 页面
3. 选择 "Build OpenWrt" workflow
4. 点击 "Run workflow"
5. 选择目标平台 (x86-64 或 ramips-mt7621)

编译产物将作为 Artifacts 上传。

## 支持的平台

| 平台 | 配置文件 | 状态 |
|------|----------|------|
| x86-64 | `configs/x86-64.config` | ✅ |
| Ramips MT7621 | `configs/ramips-mt7621.config` | ✅ |

## 配置文件

| 文件 | 说明 |
|------|------|
| `/etc/config/fwx` | 主配置 |
| `/etc/config/appfilter` | 应用过滤规则 |
| `/etc/config/macfilter` | MAC 过滤规则 |
| `/etc/config/fwx_ids` | IDS 配置 |
| `/etc/config/threat_intel` | 威胁情报配置 |
| `/etc/config/fwx_av` | 防病毒配置 |
| `/etc/config/fwx_notify` | 通知配置 |

## 命令行工具

```bash
# IDS 管理
fwx-ids start|stop|status|unblock <ip>

# 威胁情报
fwx-threat-update update|status
fwx-threat-apply apply|hot|status|add <ip>|remove <ip>

# 防病毒
fwx-av scan <path>
fwx-av update

# Suricata
fwx-suricata start|stop|status|update-rules

# 通知测试
fwx-notify test-email|test-webhook
```

## UBUS API

```bash
# 获取设备画像
ubus call fwx.profile get_all

# 获取安全告警
ubus call fwx alert_list

# 获取系统状态
ubus call fwx.security status
```

## 技术亮点

### NFTables 原子操作
所有 nftables 规则使用原子加载，避免规则更新时的流量中断：
- 使用 `nft -f` 批量加载
- 表级别锁机制防止并发冲突
- Set 元素导出/恢复保留状态

### 威胁情报热更新
支持增量更新威胁 IP 列表：
- 计算新旧列表差异
- 仅添加/删除变化的 IP
- 保留统计计数器
- 零中断更新

### 统一日志系统
使用 `LOG_*` 宏统一日志输出：
- 支持 DEBUG/INFO/WARN/ERROR 级别
- 生产环境可关闭 DEBUG
- 自动添加文件名和行号

## 硬件要求

| 防护级别 | 最小内存 | CPU | 说明 |
|----------|----------|-----|------|
| 最小 | 64MB | 1核 | 仅基础过滤 |
| 基础 | 128MB | 1核 | 应用过滤 + MAC 过滤 |
| 标准 | 256MB | 2核 | + IDS |
| 高级 | 512MB | 2核 | + 威胁情报 + 设备画像 |
| 最大 | 1GB+ | 4核 | + Suricata + 防病毒 |

## 路线图

### 计划中的功能
- [ ] IPS 主动阻断（基于 Suricata）
- [ ] SSL/TLS 解密检测
- [ ] VPN 集成 (WireGuard/OpenVPN)
- [ ] URL 过滤
- [ ] 带宽限速 (QoS)
- [ ] 安全报表
- [ ] 高可用 (HA)

## 许可证

本项目基于 GPL-2.0 许可证开源。

## 致谢

- [OpenWrt](https://openwrt.org/) - 基础系统
- [Suricata](https://suricata.io/) - IDS 引擎
- [ClamAV](https://www.clamav.net/) - 防病毒引擎
- [nftables](https://nftables.org/) - 防火墙框架

---

**FanchMWRT** - 让网络安全触手可及
