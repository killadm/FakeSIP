# FakeSIP

FakeSIP 使用 Netfilter Queue（NFQUEUE）把 UDP 流量伪装成 SIP 协议流量。
此项目 fork 自 [MikeWang000000/FakeSIP](https://github.com/MikeWang000000/FakeSIP)，
在原功能的基础上增加了过滤功能，避免不必要地处理正常流量。
对于 OpenWrt/ImmortalWrt 用户，建议直接安装
[killadm/luci-app-fakesip](https://github.com/killadm/luci-app-fakesip)，该项目包含
FakeSIP 软件包与 LuCI 管理界面。

## 快速开始

```
fakesip -i eth0
```

## 使用方法

```
Usage: fakesip [options]

Interface Options:
  -a                 在所有网络接口上工作（忽略 -i）
  -i <interface>     指定网络接口

Payload Options:
  -b <file>          从二进制文件读取 UDP payload
  -u <uri>           SIP 伪装使用的 URI

Filter Options:
  -l <file>          从文件加载 IP/端口黑白名单过滤规则

General Options:
  -0                 处理入站数据包
  -1                 处理出站数据包
  -4                 处理 IPv4 流量
  -6                 处理 IPv6 流量
  -d                 以 daemon 模式运行
  -k                 结束正在运行的进程
  -s                 静默模式，减少日志输出
  -w <file>          将日志写入文件，而不是 stderr
  --log-max-size <size>
                     日志达到指定大小后轮转，支持 K/M/G 后缀，0 表示关闭
  --log-rotate <count>
                     保留轮转日志份数，0 表示不保留历史

Advanced Options:
  -f                 跳过自动防火墙规则
  -g                 禁用跳数估算
  -m <mark>          用于绕过队列的 fwmark
  -n <number>        netfilter queue 编号
  -r <repeat>        fake packet 重复发送次数
  -t <ttl>           fake packet 使用的 TTL
  -x <mask>          设置 fwmark mask
  -y <pct>           按估算跳数的百分比动态提高 TTL
  -z                 使用 iptables 命令，而不是 nft
```

## 未开启过滤时的行为

未开启过滤时，FakeSIP 会处理所有被自动防火墙规则匹配到的 UDP 会话早期数据包。

默认行为：

- IPv4 和 IPv6 都启用，除非指定 `-4` 或 `-6`
- 入站和出站都启用，除非指定 `-0` 或 `-1`
- 只处理 `-i` 指定接口，或者 `-a` 指定的所有接口
- 跳过内网、保留地址段和带自身 `fwmark` 的包
- 主要处理 UDP 会话前 1 到 5 个数据包
- 不处理 TCP、ICMP 和已持续传输的大量 UDP payload

也就是说，未开启过滤时，在接口、方向、IP 协议版本匹配的范围内，所有符合条件
的 UDP 流量都可能进入 FakeSIP 处理路径。

## IP/端口黑白名单

使用 `-l <file>` 可以限制哪些 UDP 流量需要 FakeSIP 伪装。白名单中的 IP/端口
会生成 fake SIP payload，黑名单中的 IP/端口会跳过 FakeSIP 处理路径，原包正常
放行。

规则文件格式：

```
# action type value
allow ip 1.2.3.4
allow ip 1.2.3.0/24
allow ip 2001:db8::/32
deny ip 203.0.113.9
allow port 443
allow port 5000-6000
deny port 12345
```

规则只在启动时加载一次。`allow` 表示允许进入 FakeSIP 处理路径，`deny` 表示
不进入 FakeSIP 处理路径。

## 黑白名单匹配顺序

匹配顺序如下：

1. `deny` 优先级最高。
2. 只要源 IP、目的 IP、源端口或目的端口命中 `deny`，就不做 FakeSIP，原包
   正常放行。
3. 如果配置里存在任何 `allow ip`，那么源 IP 或目的 IP 必须命中至少一条
   `allow ip`。
4. 如果配置里存在任何 `allow port`，那么源端口或目的端口必须命中至少一条
   `allow port`。
5. 如果同时存在 `allow ip` 和 `allow port`，必须 IP 条件和端口条件同时满足。

常见组合：

- 只有黑名单：默认都处理，命中 `deny` 的不处理。
- 只有 IP 白名单：只处理源 IP 或目的 IP 命中的流量。
- 只有端口白名单：只处理源端口或目的端口命中的流量。
- 同时有 IP 白名单和端口白名单：必须 IP 命中且端口命中才处理。
- 同时命中 `allow` 和 `deny`：按 `deny` 处理，不做 FakeSIP。

示例：

```
allow ip 10.0.0.10
allow ip 10.0.0.11
allow port 443
deny ip 10.0.0.99
```

这个配置表示：只有源/目的 IP 涉及 `10.0.0.10` 或 `10.0.0.11`，并且源/目的
端口涉及 `443` 的 UDP 流量才会进入 FakeSIP。`10.0.0.99` 永远不进入
FakeSIP。

## 对网络性能的影响

FakeSIP 的主要开销来自 NFQUEUE。符合规则的 UDP 早期数据包需要从内核复制到
用户态，用户态解析后返回 verdict，并在需要时构造和发送 fake SIP payload。

流量较大时，可能出现这些影响：

- UDP 首包或早期包处理延迟上升
- 大量短会话场景下吞吐下降
- 用户态进程 CPU 占用上升
- NFQUEUE 队列积压时出现抖动
- 日志量过大时产生额外 I/O 开销

影响最大的场景是大量短 UDP 会话、扫描、代理出口、游戏或实时业务入口等高频
新建流量。持续传输的大流量通常受影响较小，因为自动规则主要把会话前 1 到 5
个 UDP 包送入队列，而不是持续处理同一会话里的所有 payload。

## 使用 `-l` 后为什么影响更小

默认 nftables 后端会把 `-l` 里的过滤规则转换成 nft sets。非白名单流量会在
内核规则阶段被跳过，不进入 NFQUEUE，也不会发生 packet copy、verdict 往返
和 fake payload 生成。

因此，在 `-l` 只放少量白名单 IP/端口时：

- 非白名单流量：只付出很小的内核 nft set 匹配成本。
- 白名单命中流量：仍然走完整 FakeSIP 处理路径。

如果白名单只覆盖很小一部分 UDP 流量，FakeSIP 对整机网络的影响通常会很低。
如果大部分流量都命中白名单，开销仍然接近默认全量处理。

## 低影响部署建议

推荐组合：

```
fakesip -i eth0 -l /etc/fakesip/filter.txt -s \
    -w /var/log/fakesip.log --log-max-size 10M --log-rotate 5
```

建议：

- 使用 `-l`，并尽量缩小 `allow ip` 和 `allow port` 范围
- 优先使用默认 nftables 后端，不要主动加 `-z`
- 不要使用 `-f`，除非必须自己维护外部防火墙规则
- 高流量环境建议加 `-s`，减少日志 I/O
- 能只处理 IPv4 就加 `-4`，能只处理 IPv6 就加 `-6`
- 能只处理入站就加 `-0`，能只处理出站就加 `-1`
- 尽量只指定需要的接口，避免不必要地使用 `-a`
- 按需使用 `-u` 或 `-b` 定制伪装 payload，避免生成不符合目标场景的 SIP 内容

注意：如果使用 `-f` 跳过自动防火墙规则，外部规则又把大量包送入 NFQUEUE，
那么 `-l` 只能在用户态兜底过滤，无法省掉 NFQUEUE packet copy 和 verdict
往返，性能收益会明显变小。

## 日志写入与轮转

指定 `-w <file>` 后，FakeSIP 会启用异步文件日志线程。主处理线程只负责把日志
格式化后放入固定大小队列，实际文件写入、flush、大小检查和轮转都由日志线程
完成，减少日志 I/O 对 NFQUEUE 热路径的影响。

默认行为：

- 单个日志文件达到 `1M` 后轮转。
- 默认保留 `3` 份历史日志。
- 轮转文件名格式为 `<logpath>.YYYYmmdd-HHMMSS`。
- 同一秒内多次轮转时会追加数字后缀，避免覆盖旧文件。
- 未指定 `-w` 时输出到 `stderr`，不启用异步线程和内置轮转。

可通过长参数调整：

```
--log-max-size 10M
--log-rotate 5
```

`--log-max-size` 支持纯数字字节数，也支持 `K`、`M`、`G` 后缀。设置为 `0` 表示
关闭内置轮转。`--log-rotate 0` 表示超过大小后不保留历史日志。

在高流量场景下，如果日志队列已满，逐包/info 日志会被丢弃并累计计数；错误和
关键日志会优先保留，必要时短暂等待队列空位。这个策略优先保证路由器 7x24
运行时的低延迟和稳定性。生产环境建议配合 `-s` 使用，减少逐包日志数量。

## nftables 与 iptables

默认 nftables 路径使用集合匹配，适合黑白名单规则较多的场景。iptables fallback
会保持相同的过滤语义，但规则是线性匹配，规则数量多时效率不如 nftables。

如果系统支持 nftables，建议使用默认路径。

## License

GNU General Public License v3.0
