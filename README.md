# FanchMWRT - 企业级安全路由固件

基于 OpenWrt 24.10.4 的企业级安全路由固件，集成深度包检测(DPI)、入侵检测(IDS/IPS)、威胁情报、防病毒、VPN、SD-WAN、高可用等企业级安全功能。

## 功能特性

### 🛡️ 安全功能

| 模块 | 功能 | 状态 |
|------|------|------|
| **应用识别过滤 (fwx)** | 基于 DPI 的应用层流量识别与过滤 | ✅ 已实现 |
| **入侵检测 (fwx-ids)** | 端口扫描、SYN Flood、暴力破解检测 | ✅ 已实现 |
| **Suricata IDS** | 专业级 IDS 引擎集成 | ✅ 已实现 |
| **威胁情报 (fwx-threat)** | IP/域名黑名单，自动更新，热更新 | ✅ 已实现 |
| **防病毒 (fwx-av)** | ClamAV 集成，文件扫描 | ✅ 已实现 |
| **DDoS 防护 (fwx-ddos)** | SYN/UDP/ICMP Flood 防护，连接限制，自动封禁 | ✅ 已实现 |
| **URL 过滤 (fwx-urlfilter)** | 域名黑名单，分类过滤，安全搜索 | ✅ 已实现 |
| **MAC 过滤** | 基于 MAC 地址的访问控制 | ✅ 已实现 |
| **设备画像** | 终端指纹识别、厂商识别、行为分析 | ✅ 已实现 |
| **安全告警** | 统一告警系统，支持通知推送 | ✅ 已实现 |
| **日志审计 (fwx-audit)** | 操作日志，远程 Syslog，SIEM 集成 | ✅ 已实现 |
| **访问控制 (fwx-rbac)** | 角色权限管理，多用户支持 | ✅ 已实现 |

### 🌐 网络功能

| 模块 | 功能 | 状态 |
|------|------|------|
| **QoS 带宽管理 (fwx-qos)** | CAKE/HTB 流量整形，优先级队列 | ✅ 已实现 |
| **VLAN 管理 (fwx-vlan)** | 802.1Q VLAN，网络隔离，DHCP | ✅ 已实现 |
| **WireGuard VPN (fwx-vpn)** | VPN 服务器，客户端管理，QR 码生成 | ✅ 已实现 |
| **IPSec VPN (fwx-ipsec)** | 站点到站点 VPN，strongSwan 集成 | ✅ 已实现 |
| **SD-WAN (fwx-sdwan)** | 多链路负载均衡，故障切换，mwan3 集成 | ✅ 已实现 |
| **高可用 (fwx-ha)** | VRRP 主备切换，连接同步，keepalived 集成 | ✅ 已实现 |

### 📊 监控与管理

| 模块 | 功能 | 状态 |
|------|------|------|
| **统计报表 (fwx-reports)** | 流量统计，安全报告，数据导出 | ✅ 已实现 |
| **REST API (fwx-api)** | RESTful 接口，UBUS 集成，API 文档 | ✅ 已实现 |
| **LuCI Web 界面** | 完整的安全中心管理界面 | ✅ 已实现 |
| **流量分析** | 实时流量监控，Top Talkers，协议分布 | ✅ 已实现 |
| **告警日志** | 安全事件记录与查询 | ✅ 已实现 |
| **UBUS API** | 完整的编程接口 | ✅ 已实现 |

## 架构设计

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         LuCI Web Interface                               │
│                        (luci-app-fwx)                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                         UBUS / REST API Layer                            │
├────────┬────────┬────────┬────────┬────────┬────────┬────────┬─────────┤
│ fwxd   │fwx-ids │fwx-    │fwx-av  │fwx-ddos│fwx-vpn │fwx-    │fwx-ha   │
│(daemon)│ (IDS)  │threat  │ (AV)   │(DDoS)  │ (VPN)  │sdwan   │ (HA)    │
├────────┴────────┴────────┴────────┴────────┴────────┴────────┴─────────┤
│                         libfwx_common                                    │
│              (共享库: 日志、配置、NFT原子操作、UCI工具)                     │
├─────────────────────────────────────────────────────────────────────────┤
│                       fwx Kernel Module                                  │
│                    (Netfilter DPI 内核模块)                               │
├─────────────────────────────────────────────────────────────────────────┤
│              nftables / Netfilter / WireGuard / strongSwan               │
└─────────────────────────────────────────────────────────────────────────┘
```

## 模块说明

### 核心模块

#### fwx (内核模块)
深度包检测内核模块，基于 Netfilter 框架实现应用层协议识别。

#### fwxd (用户态守护进程)
核心守护进程，提供：
- 应用过滤规则管理
- MAC 地址过滤
- 设备画像与指纹识别
- UBUS 接口服务
- 流量统计

### 安全模块

#### fwx-ids (入侵检测)
轻量级 IDS，检测：
- 端口扫描攻击
- SYN Flood 攻击
- SSH 暴力破解
- ICMP Flood 攻击

使用 nftables 原子规则集加载，零中断更新。

#### fwx-threat (威胁情报)
IP/域名黑名单过滤：
- 多源威胁情报聚合
- 定时自动更新
- 热更新（增量更新，保留统计）
- 域名通过 dnsmasq 拦截

#### fwx-ddos (DDoS 防护)
分布式拒绝服务攻击防护：
- SYN/UDP/ICMP 速率限制
- 连接数限制
- SYN Cookie 防护
- 自动封禁攻击源

#### fwx-urlfilter (URL 过滤)
域名/URL 过滤：
- 分类黑名单（广告、恶意软件等）
- 自定义黑白名单
- 安全搜索强制
- dnsmasq 集成

#### fwx-av (防病毒)
ClamAV 集成：
- 文件扫描
- 病毒库更新
- 隔离区管理

### 网络模块

#### fwx-qos (QoS 带宽管理)
流量整形与优先级控制：
- CAKE/HTB 队列算法
- 上下行带宽限制
- 优先级队列
- 热插拔接口支持

#### fwx-vlan (VLAN 管理)
802.1Q VLAN 配置：
- VLAN 创建/删除
- 网络隔离
- 自动防火墙区域
- DHCP 服务

#### fwx-vpn (WireGuard VPN)
WireGuard VPN 服务器：
- 密钥自动生成
- 客户端管理
- QR 码配置导出
- 防火墙自动配置

#### fwx-ipsec (IPSec VPN)
站点到站点 VPN：
- strongSwan 集成
- IKEv2 支持
- 预共享密钥认证
- 多隧道管理

#### fwx-sdwan (SD-WAN)
软件定义广域网：
- 多链路负载均衡
- 故障自动切换
- 链路健康检测
- mwan3 集成

#### fwx-ha (高可用)
高可用集群：
- VRRP 主备切换
- 虚拟 IP 漂移
- 连接状态同步
- keepalived/conntrackd 集成

### 管理模块

#### fwx-audit (日志审计)
操作审计与日志管理：
- 操作日志记录
- 日志保留策略
- 远程 Syslog 转发
- SIEM 集成

#### fwx-reports (统计报表)
流量统计与报告：
- 实时流量统计
- 安全事件统计
- JSON 数据导出

#### fwx-rbac (访问控制)
角色权限管理：
- 多用户支持
- 角色定义（管理员/安全管理员/网络管理员/监控）
- 权限细分
- rpcd ACL 集成

#### fwx-api (REST API)
RESTful API 接口：
- UBUS 集成
- API 文档
- 认证授权

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

# 克隆仓库
git clone https://github.com/3129025464/fanchmwrt.git
cd fanchmwrt
git checkout fanchmwrt-24.10.4

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

编译产物将作为 Artifacts 上传，包含：
- 固件镜像 (squashfs/ext4)
- IPK 软件包
- 编译日志

## 支持的平台

| 平台 | 配置文件 | 输出格式 | 状态 |
|------|----------|----------|------|
| x86-64 | `configs/x86-64.config` | IMG/VMDK/EFI | ✅ |
| Ramips MT7621 | `configs/ramips-mt7621.config` | BIN/SYSUPGRADE | ✅ |

## 配置文件

| 文件 | 说明 |
|------|------|
| `/etc/config/fwx` | 主配置 |
| `/etc/config/appfilter` | 应用过滤规则 |
| `/etc/config/macfilter` | MAC 过滤规则 |
| `/etc/config/fwx_ids` | IDS 配置 |
| `/etc/config/threat_intel` | 威胁情报配置 |
| `/etc/config/fwx_av` | 防病毒配置 |
| `/etc/config/fwx_ddos` | DDoS 防护配置 |
| `/etc/config/fwx_urlfilter` | URL 过滤配置 |
| `/etc/config/fwx_qos` | QoS 配置 |
| `/etc/config/fwx_vlan` | VLAN 配置 |
| `/etc/config/fwx_vpn` | WireGuard VPN 配置 |
| `/etc/config/fwx_ipsec` | IPSec VPN 配置 |
| `/etc/config/fwx_sdwan` | SD-WAN 配置 |
| `/etc/config/fwx_ha` | 高可用配置 |
| `/etc/config/fwx_audit` | 审计日志配置 |
| `/etc/config/fwx_reports` | 报表配置 |
| `/etc/config/fwx_rbac` | 访问控制配置 |
| `/etc/config/fwx_notify` | 通知配置 |

## 命令行工具

```bash
# IDS 管理
fwx-ids start|stop|status|unblock <ip>

# 威胁情报
fwx-threat-update update|status
fwx-threat-apply apply|hot|status|add <ip>|remove <ip>

# DDoS 防护
fwx-ddos start|stop|status|ban <ip>|unban <ip>

# URL 过滤
fwx-urlfilter start|stop|restart|update

# 防病毒
fwx-av scan <path>
fwx-av update

# Suricata
fwx-suricata start|stop|status|update-rules

# QoS
fwx-qos start|stop|restart|status

# VLAN
fwx-vlan start|stop|restart|list

# WireGuard VPN
fwx-vpn start|stop|init|add-client <name>|status

# IPSec VPN
fwx-ipsec start|stop|restart|reload|status

# SD-WAN
fwx-sdwan start|stop|restart|status

# 高可用
fwx-ha start|stop|restart|status|failover

# 审计日志
fwx-audit view [category] [lines]|export [file]

# 报表
fwx-reports generate

# 访问控制
fwx-rbac add-user <user> <pass> [role]|del-user <user>|list

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

# 获取硬件配置推荐
ubus call fwx.security hardware_profile

# 应用安全档位
ubus call fwx.security apply_profile '{"level":3}'
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

### 模块化设计
- 所有功能模块独立打包
- 按需安装，节省资源
- 统一的 UCI 配置接口
- 共享库减少代码重复

## 硬件要求

| 防护级别 | 最小内存 | CPU | 说明 |
|----------|----------|-----|------|
| 最小 | 64MB | 1核 | 仅基础过滤 |
| 基础 | 128MB | 1核 | 应用过滤 + MAC 过滤 |
| 标准 | 256MB | 2核 | + IDS + DDoS |
| 高级 | 512MB | 2核 | + 威胁情报 + VPN + SD-WAN |
| 最大 | 1GB+ | 4核 | + Suricata + 防病毒 + HA |

## 路线图

### 已完成功能 ✅
- [x] 应用识别过滤 (DPI)
- [x] 入侵检测 (IDS)
- [x] Suricata IDS 集成
- [x] 威胁情报
- [x] 防病毒 (ClamAV)
- [x] DDoS 防护
- [x] URL 过滤
- [x] QoS 带宽管理
- [x] VLAN 管理
- [x] WireGuard VPN
- [x] IPSec VPN
- [x] SD-WAN 多链路
- [x] 高可用 (HA)
- [x] 日志审计
- [x] 统计报表
- [x] 访问控制 (RBAC)
- [x] REST API

### 计划中的功能
- [ ] SSL/TLS 解密检测
- [ ] 沙箱检测
- [ ] 集中管理平台

## 许可证

本项目基于 GPL-2.0 许可证开源。

## 致谢

- [OpenWrt](https://openwrt.org/) - 基础系统
- [Suricata](https://suricata.io/) - IDS 引擎
- [ClamAV](https://www.clamav.net/) - 防病毒引擎
- [nftables](https://nftables.org/) - 防火墙框架
- [WireGuard](https://www.wireguard.com/) - VPN 协议
- [strongSwan](https://www.strongswan.org/) - IPSec 实现
- [mwan3](https://openwrt.org/docs/guide-user/network/wan/multiwan/mwan3) - 多 WAN 管理
- [keepalived](https://www.keepalived.org/) - VRRP 实现

---

**FanchMWRT** - 企业级网络安全，触手可及
