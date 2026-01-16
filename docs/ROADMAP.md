# FanchMWRT Enterprise Firewall Roadmap

基于 OpenWrt 24.10.4 的企业级防火墙系统

## 已完成功能

### 核心安全模块
| 功能 | 包名 | 状态 | 说明 |
|------|------|------|------|
| 威胁情报 | fwx-threat | ✅ 完成 | IP/域名黑名单，自动更新 |
| IDS/IPS | fwx-ids | ✅ 完成 | 入侵检测与防护，nftables集成 |
| 防病毒 | fwx-av | ✅ 完成 | ClamAV集成，实时扫描 |
| Suricata IDS | fwx-suricata | ✅ 完成 | 深度包检测 |

### 网络管理模块
| 功能 | 包名 | 状态 | 说明 |
|------|------|------|------|
| QoS带宽管理 | fwx-qos | ✅ 完成 | SQM/tc集成，流量整形 |
| URL过滤 | fwx-urlfilter | ✅ 完成 | 域名/URL黑白名单 |
| DDoS防护 | fwx-ddos | ✅ 完成 | 连接限制，SYN flood防护 |
| VLAN管理 | fwx-vlan | ✅ 完成 | 802.1Q VLAN配置 |

### VPN模块
| 功能 | 包名 | 状态 | 说明 |
|------|------|------|------|
| WireGuard VPN | fwx-vpn | ✅ 完成 | WireGuard隧道管理 |
| IPSec VPN | fwx-ipsec | ✅ 完成 | strongSwan集成 |

### 管理模块
| 功能 | 包名 | 状态 | 说明 |
|------|------|------|------|
| 日志审计 | fwx-audit | ✅ 完成 | 操作日志，合规审计 |
| 统计报表 | fwx-reports | ✅ 完成 | 流量统计，安全报告 |
| 访问控制 | fwx-rbac | ✅ 完成 | 角色权限管理 |
| REST API | fwx-api | ✅ 完成 | uhttpd CGI接口 |

### 高级功能
| 功能 | 包名 | 状态 | 说明 |
|------|------|------|------|
| SD-WAN | fwx-sdwan | ✅ 完成 | 多链路负载均衡，mwan3集成 |
| 高可用 | fwx-ha | ✅ 完成 | VRRP主备切换，keepalived集成 |
| 深度包检测 | fwx-dpi | ✅ 完成 | nDPI集成，300+应用识别 |

### 界面模块
| 功能 | 包名 | 状态 | 说明 |
|------|------|------|------|
| LuCI应用 | luci-app-fwx | ✅ 完成 | Web管理界面 |
| 主题 | luci-theme-fanchmwrt | ✅ 完成 | 自定义主题 |

## 待实现功能（高难度/可选）

| 功能 | 难度 | 说明 |
|------|------|------|
| SSL/TLS解密 | 高 | 需要CA证书管理，性能影响大 |
| 沙箱检测 | 高 | 需要虚拟化支持，资源消耗大 |
| 集中管理平台 | 高 | 需要独立服务器，多设备管理 |

## 支持的目标平台

- x86-64 (通用PC/服务器)
- ramips-mt7621 (MT7621路由器)

## 构建说明

```bash
# 克隆仓库
git clone https://github.com/3129025464/fanchmwrt.git
cd fanchmwrt
git checkout fanchmwrt-24.10.4

# 更新feeds
./scripts/feeds update -a
./scripts/feeds install -a

# 使用预设配置
cp configs/x86-64.config .config
make defconfig

# 编译
make -j$(nproc) V=s
```

## 版本历史

### v24.10.4 (当前)
- 基于 OpenWrt 24.10.4
- 完成所有核心企业防火墙功能
- 支持 x86-64 和 MT7621 平台

## 许可证

GPL-2.0
