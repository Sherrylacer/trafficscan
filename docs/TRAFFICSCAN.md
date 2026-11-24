# LLMSCAN Source-to-Traffic 分析（trafficscan）开发记录

需求依据：`Specification.md`。本文档记录已实现功能、实际运行结果、未解决问题与下一步任务。所有结果均由 LLMSCAN 自身运行得到（命令见下），未经抓包验证的结论一律标记为静态推导。

## 1. 运行入口

```sh
cd src
./run_trafficscan.sh                       # Xray-core（第一阶段验收对象）
./run_trafficscan.sh --use-llm             # 额外用 LLM 对前 8 个特征族做解释（标注为未验证）
../.venv/bin/python scan.py --language Go --project-path <Go 项目> --scanners trafficscan \
    [--go-version 1.27.3] [--goos linux --goarch arm64] [--package-filter <子串> ...] [--offline] [--use-llm]
```

输出：`log/trafficscan/<父目录>_<目录>/traffic_report.md` 与 `traffic_report.json`。
本地示例报告保存在 `docs/examples/xray-v26.11.9/` 与 `docs/examples/synthtunnel/`，不纳入代码提交。Xray 源码、Go 标准库与模块缓存也不随仓库发布，需自行获取目标工程；依赖由分析器自动下载。

测试：`.venv/bin/python -m unittest discover -s tests -v`（15 项，当前全部通过）。

## 2. 架构（全部集成在 LLMSCAN 内）

| 模块 | 作用 |
|---|---|
| `src/scan.py` | 原有入口；新增 `--language Go`、`--scanners trafficscan` 及相关参数 |
| `src/pipeline/trafficscan.py` | 新扫描器：调度语言前端 → 特征推导 → （可选）LLM 解释 → 报告 |
| `src/parser/program_parser.py` | 原有 TSParser/TSAnalyzer，**新增 Go 支持**（函数、参数、if/for、调用图），metascan 可直接用于 Go |
| `src/traffic/deps/go_resolver.py` | 解析 go.mod（require/replace/toolchain），按**锁定版本**获取模块 zip（GOPROXY 镜像自动探测排序）与对应版本 Go 标准库源码；记录每个包的来源与版本 |
| `src/traffic/lang/go_program.py` | 包级 Go 程序模型：构建约束（GOOS/GOARCH/`//go:build`）、导入别名、函数/方法、结构体/接口（字段、嵌入）、常量求值（iota、隐式重复、跨包） |
| `src/traffic/lang/go_symexec.py` | **核心**：路径敏感符号执行。整数与切片长度为 sympy 表达式，符号以规范化源码文本命名，跨函数同一量共享同一符号，从而可在调用边界间约简（TLS 记录长度即由此化简为常量）；过程间摘要、接收者/参数重命名、路径合并、发送点（net.Conn.Write 等）记录 |
| `src/traffic/lang/go_layers.py` | 结构化发现“包装连接的层”（含 net.Conn / io.Writer 字段的类型、发送点、发送闭包、入口方法） |
| `src/traffic/lang/go_domains.py` | 符号 getter（如 `Overhead()`）取值域：精确方法或接口实现；接口实现经 RTA（从层所在包可达的构造点）与接口方法集过滤；委托递归解析；携带取值条件以与路径条件做一致性检查 |
| `src/traffic/lang/go_knowledge.py` | 仅含**通用 API 语义**（AEAD.Seal 追加 Overhead、hash.Sum 追加 Size、rand.Intn 范围、crypto/rand.Int、big.NewInt 等），不含任何协议常量或预期特征 |
| `src/traffic/analysis/derive.py` | 语言无关的特征推导：单元分类（序列/固定/范围/仿射）、状态计数器识别与序列枚举、累计字节阈值截断、取值域组合与路径条件过滤、可信度标注 |
| `src/traffic/analysis/observability.py` | 单元 → 外部可观测对象映射与限制说明；从 Go 标准库源码收集运行时证据（如默认 TCP_NODELAY） |
| `src/traffic/analysis/llm_agent.py` | 复用原有 `model/llm.py`；LLM 只做解释与假设，结果单独存放并标注“未验证”，列出 LLM 提到但未被静态推导的数字 |
| `src/traffic/report/report.py` | JSON + Markdown 报告；按“发送点 × 入口”分特征族，列出各配置变体 |

每个候选特征输出规范要求的六项：特征内容、来源（含依赖版本与源码位置）、推导过程（公式、常量及其定义位置、调用路径）、触发条件（路径条件，按协议状态/配置/连接状态/输入大小分类）、可观测位置（及限制）、可信程度。

## 3. 第一阶段验收：Go TLS Dynamic Record Sizing（1208）

运行：`./run_trafficscan.sh --use-llm`（Xray-core v26.11.9，Go 1.27.3 标准库，linux/arm64；175 个项目包，554 个包，43 个依赖模块，28.6 s，无超时/错误）。

| 验收要求 | 结果 |
|---|---|
| 不预先硬编码 1208 | 生产代码中不含该值，`TestNoHardcodedTarget` 检查 |
| 找到构建与发送逻辑 | 自动发现层 `crypto/tls.Conn`，入口 `(*Conn).Write`（conn.go:1201），路径：`writeRecordLocked`（分片循环）→ `maxPayloadSizeForWrite` → `sliceForAppend` → `(*halfConn).encrypt` → `AEAD.Seal` → `(*Conn).write` → `c.conn.Write`（conn.go:953，类型 net.Conn） |
| 自动推导 1208 | 符号公式：k 个记录后长度 `1208 + k·(1202 − Overhead − ENL)`（TLS 1.3）；首个满记录长度中 `Overhead`、`explicitNonceLen` 在 `maxPayloadSizeForWrite`（减去开销）与 `encrypt`/`Seal`（加回开销）之间约去，得到与实现无关的精确值 **1208**（confidence: static-derived） |
| 解释条件与计算过程 | 常量来源：`tcpMSSEstimate = 1208`（conn.go:876）、`recordHeaderLen = 5`、`maxPlaintext = 16384`、`recordSizeBoostThreshold = 131072`；触发条件：`!c.config.DynamicRecordSizingDisabled`、`c.bytesSent < 131072`、`c.packetsSent <= 1000`、握手完成、非缓冲写、单次写入数据大于当前记录预算 |
| 外部表现与限制 | 每条记录为一次 `net.Conn.Write`；Go 默认开启 TCP_NODELAY（证据 net/tcpsock.go:290）；≤MSS 时通常对应一个 TCP 段的载荷长度；列出 TCP 字节流、拆段/合并、TSO/GRO、中间盒、外层封装等限制 |
| 准确源码引用 | 每个特征给出入口、发送点、常量定义的文件与行号，及依赖模块版本 |

主要推导结果（报告 Family 1，23 个变体中的代表）：

- TLS 1.3 + AEAD（`c.vers == VersionTLS13`、`aead`、`explicitNonceLen = 0`）：**1208, 2394, 3580, 4766, 5952, 7138, …**（`Overhead() = 16` 来自 gcm/chacha20poly1305 实现）
- TLS ≤ 1.2 + AEAD 无显式 nonce（ChaCha20-Poly1305 路径）：1208, 2395, 3582, …；带 8 字节显式 nonce（AES-GCM）：1208, 2387, …（含于多值集合中）
- TLS 1.1+ AES-CBC：首个满记录 **1205**（块对齐与 MAC 导致的不同取值）
- 达到 128 KiB 后的满记录：16406（TLS 1.3 AEAD）等
- 同一机制在 Xray 实际使用的 **uTLS**（客户端指纹）与 **REALITY** fork 中被独立发现（Family 2、3），并有项目构造点证据

## 4. 通用性验证（非 1208 / 非 TLS）

| 对象 | 机制 | LLMSCAN 推导结果 |
|---|---|---|
| Xray `proxy/vless/encryption.CommonConn`（项目代码） | 8192 分块 + 5 字节头 + 16 字节 AEAD 标签 | 满块单元 **8213** 字节，static-derived（common.go:73；条件：写入大于 8192 且无 PreWrite） |
| Xray `proxy/freedom.FragmentWriter`、`finalmask/fragment` | TLS ClientHello 随机分片 | 分片记录长度 ∈ **[LengthMin+5, LengthMax+4]**（依赖用户配置，符号形式），条件 `PacketsFrom == 0 && PacketsTo == 1`、首次写 |
| Xray `finalmask/noise.noiseConn` | UDP 噪声包 | 长度 ∈ [RandMin, RandMax−1]（配置参数） |
| 合成隧道协议 `tests/fixtures/go_synthtunnel`（与 TLS 无关的常量与机制） | MTU 预算分帧 + AEAD、随机填充 keepalive、UDP 探测 | 满帧 **1392**（Overhead 约去）、keepalive ∈ **[12, 75]**、UDP 探测 **46**、尾帧 = 输入 + 4 + Overhead |

## 5. 可信程度标注

- `static-derived`：仅由源码常量与符号化简得到，与实现选择无关
- `static-derived (value independent of implementation choices)`：使用了 getter 摘要，但结果与取值无关
- `static-derived (implementation-domain values)`：使用了接口实现取值域（RTA + 方法集过滤，属过近似）
- `static-derived (random range)` / `static-symbolic (unresolved symbols remain)`：随机范围 / 仍含未解析符号（如配置值）
- **所有结果均未经抓包或受控实验验证**；报告中明确写明。LLM 输出单独标注为 “LLM interpretation (unverified)”。

## 6. 未解决问题 / 已知局限

1. **未做流量验证**：没有 pcap 比对或受控实验（本机未安装 Go 工具链）。“实验观察 / 统计验证”两级可信度尚无实现。
2. **配置值未绑定**：fragment/noise 等特征依赖用户 JSON 配置（`LengthMin` 等），目前以符号形式输出，未从 `infra/conf` 映射配置键并代入具体值。
3. **层堆叠关系未静态恢复**：各层分别分析；“VLESS → TLS → TCP” 等组合目前仅有 LLM 给出的假设（标注未验证），未从构造点数据流确定。
4. **Xray 自有 `buf.Writer` / `MultiBuffer` 接口未覆盖**：VMess、XTLS Vision 填充、Mux 等通过 `WriteMultiBuffer` 写出，当前汇点种子只含 net.Conn / io.Writer 家族，故这些层未被分析（Vision 的随机填充范围是下一步重点）。
5. **取值域过近似**：接口实现按 RTA 与方法集过滤，仍可能包含该配置下不会使用的实现（例如 TLS 1.2 序列中的多值集合）；部分实现返回运行时字段（如 `GCM.tagSize`）未解析。
6. **符号执行的近似**：不探索 `err != nil` 分支；循环只执行一次抽象迭代；`go` 语句、闭包、反射、通道未建模；路径数上限与被调方路径预算可能截断。
7. **噪声层**：标准库通用编码器（gzip/base64/hex 等）被识别为层，已按“generic”从主表排除，但仍存在于 JSON。
8. **其他语言**：分析核心与 Go 无关，但目前只有 Go 前端；C/C++（OpenSSL、WireGuard 等）、Rust、Python 前端尚未实现。
9. **JSON 报告体积**：Xray 报告约 14 MB（包含完整推导轨迹）。

## 7. 下一步开发任务

1. 增加 `buf.Writer`/`WriteMultiBuffer` 等“项目自定义写接口”的自动识别（接口方法名 + 字节容器参数），覆盖 VMess / Vision / Mux。
2. 配置绑定：解析目标 JSON 配置与 `infra/conf` 中的字段映射，代入具体参数生成可直接检测的数值。
3. 层堆叠恢复：从项目中 `tls.Client(conn, …)`、`websocket.NewClient`、代理出站的构造链，跟踪 `net.Conn` 的数据流，静态确定封装顺序，并把内层单元长度传播为外层载荷长度。
4. 验证模块：读取 pcap（或在受控环境中运行目标程序）统计 TLS Record / TCP Payload 长度分布，与静态预测比对，引入 “experimentally observed / statistically validated” 可信度；可利用 `ccs-submission-4310` 中已有的 Xray 抓包场景。
5. 第二个语言前端（建议 C：OpenSSL `SSL_write`/`ssl3_write_bytes` 与 OpenVPN），并在 OpenVPN 等非 Go 代码库上测试。
6. 握手阶段特征：分析 ClientHello/ServerHello 构造（扩展长度、填充扩展）得到首包长度特征。
7. 性能与精度：对 `explicitNonceLen` 等关键 getter 按 cipher suite 构造点做更精细的指向分析，减少多值集合。
