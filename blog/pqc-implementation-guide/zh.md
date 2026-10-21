# PQC 方案实现工程教程：从 NIST 征集到实现陷阱、侧信道与测试

Sep 25, 2026 · @jieyu

## 0. 导读

结论先行：PQC 实现的绝大多数 bug 不在“数学”，而在 **spec 与代码的边界**（字节序、编码、边界检查、拒绝采样计数）和 **优化引入的语义漂移**（中间值溢出、惰性约简范围、编译器引入的分支/除法）。NIST 三轮、KpqC、NGCC 首轮暴露的问题高度同构。

本教程面向已经会写 AVX2/AVX-512/NEON 优化代码、但希望系统化“高保障实现方法论”的研究者。建议阅读路线：

1. 快速浏览第 1–2 节（历史 + 方案全景），建立坐标系。
2. 精读第 3–5 节（流程、算子、陷阱清单），对照自己的代码逐条排查。
3. 第 6–7 节（侧信道、测试）按需建立 CI。
4. 第 8 节资源索引按主题延伸阅读；第 9 节是提交前的自查清单。

说明：文中标注 \[source\] 的是本次检索核对过的链接；未标注的为领域常识或近似描述，引用前请复核原文。

后续文章：第 7.1 节测试分层中的第 6 层（性质与变异测试）在[《翻转一个比特：密码学感知测试在 PQC 实现里找到了什么》](../crypto-informed-testing/?lang=zh)中有详细介绍，其中给出了一个最小测试程序，可用于第 9 节清单 B、C 中的比特翻转检查。

## 1. 标准化历史回顾

NIST 从 2016 年征集到 2024 年发布 FIPS 203/204/205，用了 8 年；中间每一轮都有候选因实现或设计问题被淘汰。NGCC 首轮公开评审在几天内发现的问题数量，说明评审工具（尤其 AI 辅助）已使“提交即被审计”成为常态。

### 1.1 NIST PQC 主线时间线（新→旧）

| 时间 | 事件 | 对实现者的启示 |
| --- | --- | --- |
| 2026-07 | HAWK 团队在 AI 辅助攻击公布后撤回签名方案 [source](https://www.nist.gov/news-events/news/2026/05/nine-candidates-advance-third-round-additional-digital-signatures-pqc) | 设计层面的审计速度同样在加快 |
| 2026-05 | 附加签名第 3 轮：FAEST、HAWK、MAYO、MQOM、QR-UOV、SDitH、SNOVA、SQIsign、UOV；CROSS、LESS、Mirath、PERK、RYDE 淘汰 [NIST IR 8610](https://csrc.nist.gov/pubs/ir/8610/final) | 多变量、MPCitH/VOLEitH、同源实现要求将快速收紧（恒定时间、物理攻击） |
| 2025-09 | 第 6 届 NIST PQC 会议；FIPS 206 (FN-DSA) 草案进展报告 [slides](https://csrc.nist.gov/presentations/2025/fips-206-fn-dsa-falcon) | FN-DSA 的浮点/定点问题仍在讨论 |
| 2025-03 | HQC 被选为第二个 KEM（代码基、多样性备份） | HQC 标准文本尚未定稿，实现需跟踪草案 |
| 2024-10 | 附加签名第 2 轮（14 个） | — |
| 2024-08-13 | FIPS 203 ML-KEM、FIPS 204 ML-DSA、FIPS 205 SLH-DSA 定稿 | 从 Kyber/Dilithium 到 ML-\* 有隐蔽差异（见 3.3） |
| 2023-08 | FIPS 203/204/205 初始公开草案；附加签名第 1 轮 40 个候选 | 草案期内广泛出现“草案与终稿不兼容”的实现 |
| 2022-07 | 第 3 轮结束：选定 Kyber、Dilithium、Falcon、SPHINCS+；BIKE/HQC/McEliece/SIKE 进入第 4 轮 | — |
| 2022-07/08 | SIKE 被 Castryck–Decru 攻破；Rainbow 被 Beullens 攻破（同年 2 月） | 数学结构可能整体崩塌，实现要有算法敏捷性 |
| 2020-07 | 第 3 轮：7 个决赛 + 8 个备选 | NIST 明确将 pqm4 等嵌入式数据纳入评估 |
| 2019-01 | 第 2 轮 26 个候选 | — |
| 2017-12 | 第 1 轮：82 份提交中 69 个入围 [NIST IR 8240](https://nvlpubs.nist.gov/nistpubs/ir/2019/NIST.IR.8240.pdf) | 首轮公开后也快速出现大量实现 bug 和攻破 |
| 2016-12 | NIST 正式征集（FRN） | — |

状态说明（截至 2026-09）：FIPS 206 FN-DSA 仍未定稿，HQC 已被选定但标准文本仍待发布；引用前请到 [NIST PQC 项目页](https://csrc.nist.gov/projects/post-quantum-cryptography) 复核。

### 1.2 其他标准化进程

- **中国 NGCC（ICCS 主办）**：2025 年 2 月启动，2026-09-20 公布首轮候选。公钥赛道含签名 34、KEM 41、密钥交换 9 个候选，另有哈希赛道 35 个。ICCS 公开了全部材料、要求英文 spec、提供统一 API，并运营公开论坛 [source](https://postquantum.com/security-pqc/china-ngcc-candidate-flaws/)。
- **NGCC 首轮公开审计**：Saarinen 维护的 [ngcc.dev](https://ngcc.dev/reports/index.html) 截至 2026-09-25 列出 147 条有效发现：实现 65、设计 53、侧信道 29。Saarinen 称其撰写的发现均使用了 AI 辅助。
- **韩国 KpqC**：2021 年起，从 Round 0 开始；2025 年 1 月公布胜出者 HAETAE、AIMer（签名）与 SMAUG-T、NTRU+（KEM）。其首轮同样有工作系统地对候选跑了 Valgrind 恒定时间检测、内存泄漏和 metamorphic testing [ePrint 2023/1437](https://eprint.iacr.org/2023/1437.pdf)，是 NGCC 很好的参照。
- **ISO/IEC 18033-2 修订**：纳入 FrodoKEM、Classic McEliece、ML-KEM 等；欧洲（BSI、ANSSI）对 FrodoKEM/McEliece 推荐力度高于 NIST。
- **IETF**：TLS 混合密钥交换（X25519MLKEM768）、LAMPS 证书 OID、CFRG 的 X-Wing 和 ML-KEM 规范化文档。实现者需要留意密钥编码（seed 格式 vs 展开格式）的决议。
- **其他国家/行业**：CNSA 2.0（美国国家安全系统）、中国密码行业标准中的格基方案（如 CTRU 行标起草）等。

## 2. 方案全景：KEM / 签名 / KEX

按数学基础分类记忆比按名字记忆更有用：同一家族的实现坑几乎相同（格→NTT/采样/FO，码→译码器恒定时间，多变量→高斯消元主元，哈希→地址/索引编码，MPCitH→种子树与承诺）。

### 2.1 NIST 标准与主要候选

| 方案 | 类型 | 数学基础 | 状态（2026-09） | 实现难点 |
| --- | --- | --- | --- | --- |
| ML-KEM (Kyber) | KEM | Module-LWE | FIPS 203 | NTT、压缩除法、FO 隐式拒绝、公钥模检查 |
| HQC | KEM | QC 汉明距离码 | 已选定，标准待发布 | 恒定时间 RS/RM 译码、定重采样、大多项式乘法 |
| Classic McEliece | KEM | Goppa 码 | ISO 路线，NIST 未选 | 巨大公钥、恒定时间高斯消元、bitslice 根查找 |
| FrodoKEM | KEM | 无结构 LWE | ISO 路线 | 矩阵生成带宽、CDF 采样 |
| BIKE | KEM | QC-MDPC | 第 4 轮未选 | BGF 迭代译码恒定时间、失败率 |
| NTRU / NTRU Prime (sntrup761) | KEM | NTRU 格 | 第 3 轮未选；OpenSSH 默认使用 sntrup761 | 非 NTT 友好环、求逆、恒定时间排序 |
| ML-DSA (Dilithium) | 签名 | Module-LWE/SIS | FIPS 204 | 拒绝采样循环、hint 编解码、强不可伪造性 |
| FN-DSA (Falcon) | 签名 | NTRU 格陷门 | FIPS 206 草案 | 浮点 FFT/离散高斯采样恒定时间、平台浮点一致性 |
| SLH-DSA (SPHINCS+) | 签名 | 哈希 | FIPS 205 | ADRS 地址编码、索引截断、故障攻击 |
| LMS / XMSS | 有状态签名 | 哈希 | SP 800-208 | 状态管理（绝不能重用索引） |
| UOV / MAYO / QR-UOV / SNOVA | 签名 | 多变量 | 附加签名第 3 轮 | GF(16)/GF(256) 查表、消元恒定时间 |
| FAEST / MQOM / SDitH | 签名 | VOLEitH / MPCitH | 附加签名第 3 轮 | GGM 树、承诺、AES/域运算恒定时间 |
| SQIsign | 签名 | 同源 | 附加签名第 3 轮 | 大数/四元数运算、验证器输入校验 |

### 2.2 韩国 KpqC 胜出方案

HAETAE（格签名，超球面均匀分布 + 拒绝采样）、AIMer（对称 + MPCitH）、SMAUG-T（MLWE/MLWR 混合 KEM）、NTRU+（NTRU KEM）。

### 2.3 NGCC 首轮候选（按家族归纳）

来源：[ngcc.dev 报告索引](https://ngcc.dev/reports/index.html) 中的家族标注。每个名称后是其官方编号。

**KEM（41 个）**

- 格（MLWE/RLWE/MLWR/LWE）：Aigis-Enc+（kem-01）、Amoeba（02）、BW-KEM（08）、CheetahKEM（09）、COMPASS-KEM（11）、CTL（12）、DKEM（13）、FLIT（15）、LoongKEM（18）、Lore（19）、MAMBA-Frost/Viper（20/21）、Mithril（22）、MORNING-Scabbard（24）、NEV（25）、Polar-KEM（29）、PolarLAC（30）、Rudraksh2（34）、Scloud+（35）、WeaverKEM（39）、ZEN（41）
- 格（NTRU）：DTRU（14）、NTRE（27）、OAEP-NTRU（28）、YuanYang.KEM（40）
- 码（秩度量）：BAG-Loong/Piglet（03/04）、BRA（06）、BRQC（07）、C-Multi-UR-AG（10）
- 码（汉明/QC/其他）：BIKE-MLThre（05）、HARE（16）、HEP-QC（17）、Mito（23）、NSS-HQC（26）、QCTM（32）、QUBE（33）、TRIKE（36）、TriQ-KEM（37）、UVW KEM（38）
- 同源：QIMEN-PIKE（31）

**签名（34 个）**

- 格（Fiat-Shamir）：Aigis-Sig+、CS、MORNING-ATLAS，及 BiT、COMPASS-SIG、DARTS、Octarine、OPS、Rhyme、Shuttle
- 格（hash-and-sign）：YuanYang.DSA
- 哈希：CEDRUS+C、CEDRUS-alpha、FlexTree、Phoenix
- 多变量：DOVE、Facto-DSA、Origami、TSUOV、UVW、VDOO
- MPCitH / VOLEitH：Chinith、Galas、GreatWall、Lynxer、Sigurd、Tins、TRINE、SYDO、ReSolveD-ɑ
- 码：Qing Luan
- 同源：SQIsign2D2、SQIsign2D-push1/2、SQIsignTriangle

**密钥交换（9 个）**

ADKEX、AFS-KEX、CreTAKE、DKEX、Loom、MAMBA-NIKE、NEV-AKE（格 AKE/NIKE），NIIKE（同源 NIKE），TriQ-KEX（码 AKE）。

### 2.4 KEX 的历史脉络

NIST 只征集 KEM，没有独立的 KEX 赛道；这是 NGCC 与 NIST 的一个明显差异。值得了解的经典工作：Ding 密钥交换（2012）、BCNS（2015）、NewHope（2016，Google CECPQ1 实验）、Frodo 密钥交换（2016）、CSIDH（2018，同源 NIKE）、SWOOSH（2023，格 NIKE）。实践中 AKE 多由 KEM + 签名在协议层组合（TLS 1.3、KEMTLS、PQ-Noise）。

## 3. 一般实现流程

成熟团队（PQ Code Package、PQClean、pqm4、liboqs、BoringSSL/AWS-LC）的共同做法是：**可执行规范 → 清晰参考实现 → 多层测试钉死行为 → 再做优化**，每个优化实现都以参考实现为差分基准。顺序颠倒（先写快的、再补测试）是 NGCC 问题的主要来源。

### 3.1 阶段划分

1. **Spec 精读与形式化摘要**
   - 把每个算法改写成伪代码，标注每个变量的类型、长度（bit 还是 byte）、取值范围、字节序。
   - 列出所有“输入校验”步骤（公钥模检查、密文长度、hint 格式、填充位为零）和所有域分离常量。
   - 对参数集做一遍“安全性预算核对”：种子长度、哈希输出长度、挑战空间、盐长度是否覆盖声称安全级别（NGCC 大量 critical 问题就死在这里）。
2. **可执行规范（executable spec）**
   - 用 Python/SageMath 或 hacspec/Rust 写一个不追求性能、逐行对应 spec 的模型，独立于 C 代码。
   - 这是之后所有差分测试的“真值”，最好由不同人撰写。
3. **参考实现（C99, portable）**
   - 按 [PQClean 要求](https://github.com/PQClean/PQClean)：合法 C99、`-Wall -Wextra -Wpedantic -Werror`、API 不越界写、大小端与 32/64 位输出一致、Valgrind 与 ASan 无报错。
   - 参考实现也必须恒定时间——评审者首先看的就是它。
4. **测试向量与测试框架（见第 7 节）**
   - KAT、中间值向量、负向测试向量、跨平台一致性。
5. **优化实现（AVX2/AVX-512/NEON/Cortex-M4/RISC-V V）**
   - 每个内核单独与参考函数做随机差分（包括边界输入）。
   - 记录每个内核的输入/输出系数范围不变式，并用断言或范围分析工具检查。
6. **验证与加固**
   - 恒定时间检测、fuzz、形式化验证（如 Jasmin/EasyCrypt、CBMC、HOL-Light）、第三方审计。
7. **发布与维护**
   - 明确标注对应 spec 版本；每次 tweak 同步更新向量；开放 issue。

### 3.2 参照项目

| 项目 | 定位 | 学什么 |
| --- | --- | --- |
| [PQ Code Package](https://github.com/pq-code-package) (mlkem-native, mldsa-native) | Linux Foundation PQCA 下的生产级 ML-KEM/ML-DSA | CBMC 证明内存安全 + HOL-Light 证明汇编内核功能正确；系数范围的契约式注释 |
| [PQClean](https://github.com/PQClean/PQClean) | 干净可移植实现集合，2026-07 起计划归档 | 自动化质量门禁清单；配套论文 [ePrint 2022/337](https://eprint.iacr.org/2022/337) 总结了提交代码的典型问题 |
| pqm4 / pqmx | Cortex-M4/M55 基准与测试 | 栈用量、嵌入式内核、硬件 RNG 接口 |
| liboqs / oqs-provider | 统一 API + OpenSSL provider | 跨方案测试、CI、实际集成问题 |
| libjade / formosa-crypto | Jasmin 高保障实现 | 功能正确性 + 恒定时间 + Spectre 防护证明 |
| SUPERCOP | 大规模基准 | 多编译器多选项对比；暴露未定义行为 |

### 3.3 “论文版”与“标准版”的隐蔽差异（以 NIST 为例）

- **ML-KEM vs Kyber r3**：K-PKE 密钥生成中 G 的输入增加了 k 作为域分离；封装不再对 m 哈希，共享密钥不再混入 H(c)；增加了封装输入（公钥模检查）和解封装输入（私钥哈希检查）校验。
- **ML-DSA vs Dilithium r3**：增加 context 字符串与 pre-hash 模式；tr 变为 64 字节；挑战哈希 c\~ 长度随安全级别变化；hint 解码增加了防止可塑性的检查。
- **SLH-DSA vs SPHINCS+ r3.1**：消息哈希与地址处理的细节修改、增加 context。

同理，NGCC 进入第 2 轮后的 tweak 也会产生“旧向量、新 spec”的不一致，建议每次改动都在 spec 中加“变更记录”小节。

## 4. 核心算子实现要点

性能瓶颈几乎总是多项式乘法和哈希/XOF，而正确性瓶颈几乎总是范围分析、采样和编码。下面按算子列出“必须明确的不变式”。

### 4.1 多项式乘法

- **NTT 友好环**（ML-KEM q=3329、ML-DSA q=8380417）
  - 明确表示：有符号 \[-q, q\] 还是无符号 \[0, q)，Montgomery 域还是普通域。每一层蝶形后写下系数绝对值上界。
  - 惰性约简（lazy reduction）是性能关键，也是溢出重灾区：int16 存储下每层范围翻倍，必须计算哪层必须插入 Barrett。
  - Kyber 的“不完全 NTT”（7 层 + 二次基乘法）、twiddle 的 bit-reversal 顺序、逆 NTT 最后的 n^-1 与 Montgomery 因子合并——这些常数最好由脚本生成并与模型比对。
  - 替代约简：Montgomery、Barrett、Plantard（Huang 等在 Cortex-M4 上的工作），对应不同的输入输出范围，混用时尤其要逐层核对。
- **NTT 不友好环**（NTRU、sntrup761、Saber、多数 NGCC NTRU/LWR 候选）
  - 路线：Toom-Cook/Karatsuba；在大模数上做 NTT 后映射回（需要输出范围不超过大模数的一半）；多模数 + CRT；Good's trick、Rader、混合基。参考 Chung 等 “NTT Multiplication for NTT-unfriendly Rings”（TCHES 2021）。
  - 关键潜在错误：乘积系数的最大可能值是否真的小于所选模数的一半——对私钥系数范围的假设一旦被恶意密文/公钥打破，就会得到错误但“看起来正常”的结果。
  - 多项式求逆（NTRU 密钥生成）：用恒定时间 divstep（Bernstein–Yang）或指数逆，避免扩展欧几里得的数据相关分支。
- **码基方案**：GF(2)\[x\] 乘法用 PCLMULQDQ/VPCLMULQDQ 或 bitslice；稀疏×稠密乘法若按秘密支撑位置访问内存就是缓存侧信道（NGCC kem-33 即此类）。

### 4.2 采样

- **均匀拒绝采样**（SampleNTT/ExpandA）：输入是公开种子时可变时间；但必须处理“XOF 输出不够”的情况，且向量化版本的尾部处理要与标量版本对一个字节一个字节地对齐。
- **中心二项分布 CBD**：恒定时间 popcount；注意 η=3 时跨字节读取。
- **秘密输入的拒绝采样**：如 HQC 的定重向量采样，拒绝次数泄露种子信息，已被 Guo 等用于实际计时攻击（“Don't Reject This”，TCHES 2022）。正确做法是恒定时间采样（如 Sendrier 的方法、排序网络随机置换）。NGCC kem-33/kem-37/kex-09 都是解封装时用可变长度采样器重新展开私密种子。
- **离散高斯**（Falcon/FN-DSA、YuanYang.DSA）：恒定时间 CDT 或 Bernoulli 拒绝；浮点运算在不同平台（x87/FMA/软浮点）上的一致性与恒定时间性都要验证；协方差错误会直接泄露秘密基（NGCC sign-34-1）。
- **签名的掩码向量 y**：每次拒绝循环的 nonce/计数器必须递增且不会回绕；重复的掩码系数会泄露私钥（NGCC sign-15-4）。

### 4.3 编码、压缩与解码

- 压缩 round(2^d/q · x) 中的除法是 KyberSlash 的根源：用乘法 + 移位替代并穷举验证。
- **解码必须是单射的**：解码后再编码应得到原字节串。对公钥是“模检查”，对签名是“强不可伪造性”，对密文是 FO 重加密比对的前提。NGCC 中大量“签名可塑性”和“公钥别名”问题（sign-01-1、sign-15-2、sign-34-2）都属于这一类。
- 填充位、未使用的高位、hint 位置的单调性——每一个都要显式检查。

### 4.4 哈希 / XOF

- 对输出长度做“生日界”核对：256 位安全级别的签名如果消息代表只有 512 位，其抵抗碰撞的强度仅 256 位；种子长度同理。NGCC 有十几个候选在此类问题上被判 critical。
- 域分离：每次调用的前缀/后缀常量、nonce 字节位置、长度编码；多路并行 Keccak（x4/x8）的每一路必须与单路实现逐字节对比。
- 增量式 squeeze 在 rate 边界（SHAKE128 168 字节、SHAKE256 136 字节）处最容易出错；另外 SM3 等 Merkle–Damgård 哈希不能直接当 XOF 用。

## 5. 容易忽略的实现问题（含真实案例）

NGCC 首轮的 65 条实现类发现可以归入 9 类，几乎每一类在 NIST 进程或生产库中都有前例。前 5 类与“优化”无关，是参考实现就已存在的问题；第 5.2 节专门列出优化实现引入的问题。

### 5.1 问题分类表

编号指向 [ngcc.dev 报告](https://ngcc.dev/reports/index.html)。

| 类别 | 典型表现 | NGCC 实例 | 防御手段 |
| --- | --- | --- | --- |
| 1. 安全预算被代码截断 | 384/512 位级别用 256 位种子；消息代表或 prehash 长度不足；挑战空间小于声称级别；bit/byte 混淆 | kem-11-1、kem-21-1、kem-27-1、kex-06-1、sign-06-1/2、sign-15-3、kex-03-1（临时秘密降到 64 位） | 参数头文件中用静态断言检查每个长度 ≥ 对应安全预算；命名中带单位（`_BYTES`/`_BITS`） |
| 2. FO 变换实现错误 | 隐式拒绝无效；掩码只覆盖部分字节；重加密比对只比较部分密文；拒绝密钥未绑定完整密文 | kem-01-1、kem-09-1、kem-18-1、kem-02-1（只比较每第 4 字节）、kem-13-1 | 错误密文负向测试：对密文每一位翻转后，解封装必须输出确定性伪随机密钥且不等于正确密钥 |
| 3. 随机数问题 | KAT 用确定性 RNG 遗留在实际路径；进程内第一次封装可复现；临时密钥只生成一次；签名随机性可预测 | kem-17-1/3、sign-12-1、sign-33-1/4、kex-02-1、kex-08-2 | KAT RNG 与生产 RNG 在编译期隔离；测试“两次调用输出必须不同” |
| 4. 输入解析与内存安全 | 恶意 hint 计数导致栈写；调用者声明长度溢出栈缓冲区；全零签名崩溃或触发 assert；验证结果取决于未初始化栈数据；分配失败却返回成功 | sign-01-2、kem-14-1（DTRU）、sign-25-1、sign-27-1、sign-32-1/2、kem-10-1、kem-31-1、hash-02-1 | fuzz + ASan/UBSan/MSan；所有外部长度与常量比对；失败路径默认返回错误码并清零输出 |
| 5. 编码非单射 / 可塑性 | 签名填充位未检查；hint 编码存在多种合法表示；公钥打包存在别名 | sign-01-1、sign-07-1、sign-15-2、sign-11-5、sign-34-2 | “解码 → 再编码 → 逐字节相等”作为验证前置条件；针对 SUF-CMA 的变异测试（[详见后续文章](../crypto-informed-testing/?lang=zh)） |
| 6. 代码与 spec 不一致 | 遗漏舍入常数；丢弃误差多项式；缺少一层纠错译码；地址截断为 8 位；哈希实例化不同 | kem-24-1、kem-40-1、kem-39-2、kem-23-1、sign-04-2/3、sign-03-1 | 独立可执行规范 + 中间值差分（不只是最终输出） |
| 7. 状态管理 | 协议状态可重置；状态重用泄露密钥 | kex-05-2；此外有 Threshold ML-DSA 参考代码的状态重用问题 [source](https://www.projecteleven.com/blog/nine-schemes-advance-to-round-3-of-nists-additional-digital-signatures-process) | 状态机显式化，使用后即销毁 |
| 8. 协议级遗漏 | 身份硬编码为零；恶意公钥破坏贡献性；原始共享值未经 KDF | kex-07-1、kem-13-2、kex-08-1 | KDF 输入包含完整 transcript；对恶意对等方建模 |
| 9. 遗留调试代码 | 调试路径保留秘密误差向量；提交包自带完整攻击脚本 | kem-32-1、kem-29-1 | 发布前 `grep` printf/DEBUG/全局变量；审查包内每一个文件 |

历史前例：FrodoKEM 等多个 NIST 候选的 FO 密文比对曾用非恒定时间 memcmp（Guo–Johansson–Nilsson，CRYPTO 2020）；Falcon 参考实现 2019 年曾因采样器 bug 产生分布错误的签名。

### 5.2 优化实现引入的问题（重点）

1. **范围溢出**：惰性约简、延迟的 Barrett、`vpmulhw` 仅取高 16 位、`vpmaddwd` 的饱和/累加——正常输入下永远不出错，恶意密文或极端秘密才触发。必须用“最大绝对值输入”测试每个内核。
2. **尾部与越界访问**：n 不是向量宽度整数倍时（如 sntrup761 的 761、NTRU 的素数维度）会多读/多写一个向量。对齐填充的缓冲区要保证填充区是零且不被写入输出（参见 sign-01-4、kem-06-2 一类“多写一个多项式/一个 limb”）。
3. **向量化拒绝采样**：基于查表的 shuffle 压缩会在缓冲区末尾写入超出有效系数数量的元素；要分配余量并与标量版本对比“消耗的 XOF 字节数”。
4. **系数排列顺序**：AVX2 实现常用非标准顺序（shuffle 后的 NTT 域），在序列化/反序列化前必须恢复。如果整套实现内部自洽，KAT 仍会失败；但如果只有某个内部函数被外部调用，错误就会被掩盖。
5. **编译器引入的分支**：Kyber 参考代码的 `poly_frommsg` 在源码层是恒定时间的，但 Clang 15–18 在 `-Os` 等选项下生成秘密相关分支，可在约 10 分钟内恢复 ML-KEM-512 私钥（CVE-2024-37880）[source](https://github.com/antoonpurnal/clangover)。三元运算符、布尔转整数、`x ? a : b` 形式的 cmov 都不可靠。
6. **可变时间指令**：除法、取模（KyberSlash1/2，在 Cortex-A7/M4 上分别数小时和数分钟恢复密钥 [ePrint 2024/1049](https://eprint.iacr.org/2024/1049)）；部分嵌入式平台的乘法（Cortex-M3 `UMULL` 提前退出）；浮点次正规数。
7. **未定义行为**：有符号溢出、负数左移、按字节访问对齐不足的 `uint32_t*`（strict aliasing）。编译器会据此“优化”出语义不同的代码，且表现随编译器版本变化。
8. **清零被删除**：`memset` 秘密缓冲区会被 dead-store elimination 消除；用 `explicit_bzero`/volatile 函数指针/编译屏障。寄存器与栈上残留的 ymm/zmm 内容也应考虑。
9. **运行时分发不一致**：按 CPUID 选择 AVX2/AVX-512 路径时，不同路径对恶意输入的行为必须逐字节一致（包括返回码），否则是跨平台互操作性与安全问题。内存别名（输入输出是同一缓冲区）在向量化代码中经常没有被测试。
10. **嵌入式专属**：栈空间超限（M4 上大约几十 KB）、`randombytes` 返回值未检查、硬件 TRNG 健康检测、带 cache 的 M7/M55 上查表仍有泄露。
11. **浮点**（FN-DSA 类）：FMA 收缩、x87 扩展精度、`-ffast-math` 会改变结果或计时；跨平台必须比对签名字节。

## 6. 侧信道防护

软件实现的最低要求是“恒定时间”（更准确地说是**秘密无关的控制流、内存地址和可变时间指令操作数**），且要在**二进制层**验证。ngcc.dev 对全部 119 个候选做了源码级恒定时间审查，其中 29 条侧信道发现几乎全是这三类 [source](https://ngcc.dev/constant-time/index.html)。

### 6.1 三类泄露源与对应的 NGCC 实例

| 泄露源 | 典型代码模式 | NGCC 实例 | 安全写法 |
| --- | --- | --- | --- |
| 秘密相关分支 | 解密系数的符号分支；多变量消元的主元选择；按秘密中心映射系数分支；哈希按消息尾位分支 | kem-08-1（BW-KEM）、kex-02-2、sign-31-2、sign-33-5、kem-03-1、hash-01-1 | 算术掩码 + 条件交换；恒定时间高斯消元（对每行做掩码加法、不提前退出） |
| 秘密相关内存地址 | S-box/T-table 查表；稀疏多项式按支撑位置访问；译码器按校验子查表；秘密置换 | hash-05/11/21/22/27、kem-02-2、kem-06-3、kem-17-5、kem-33-2、kem-40-2、sign-18-4 | bitslice；全表扫描 + 掩码选择；排序网络（djbsort）实现置换 |
| 可变时间指令 / 可变工作量 | 除法、取模；秘密种子驱动的拒绝采样；迭代次数依赖秘密的译码 | kem-33-1、kem-37-1、kex-09-1、hash-35-1 | 乘法+移位替代除法；固定次数迭代；恒定时间定重采样 |

### 6.2 对 KEM 最致命的模式：明文检查预言机

对 FO 变换的 KEM，任何与“解密出的 m”有关的微小泄露（一个分支、一次除法、一次不恒定时间比较、一次解密失败后的重试）都能构成 plaintext-checking oracle，在几千到几万次查询内恢复私钥。Clangover 和 KyberSlash 均属此类。NGCC kem-38-2/3 的“列表译码失败预言机”、“重试行为泄露会话密钥”也是同一机制。

实践原则：解封装中从“解密”到“输出密钥”的整条路径必须是直线代码；解密失败不能有任何可观测的不同行为（包括返回码和耗时）。

### 6.3 编译器与微架构

- **对抗编译器**：对关键掩码值使用 value barrier（如 `__asm__("" : "+r"(x))` 或 volatile 全局变量异或），这是 Kyber 修复 Clangover 后采用的思路。Peter Schwabe 的 [Kyber 实现 slides](https://cryptojedi.org/peter/data/cmmrs-20240801.pdf) 对此有很好的演示。
- **在多个编译器×优化级别矩阵上测试**：gcc/clang 各主版本 × `-O0/-O1/-O2/-O3/-Os` × `-fno-vectorize` × LTO。
- **微架构泄露**：Spectre v1（越界推测读）、Hertzbleed（功耗→频率→时间，对 SIKE 实际有效）、数据相关预取器。Jasmin/libjade 项目有针对 Spectre 的类型系统。Intel DOIT、Arm DIT 标志位可以保证部分指令的数据无关计时。

### 6.4 物理侧信道与故障攻击（嵌入式）

- **功耗/电磁**：单条轨迹攻击（针对 NTT 的 belief propagation、针对 CBD/消息编码的模板攻击）、选择密文 + 侧信道的密钥恢复（Ravi、Primas、Pessl 等大量工作）。
- **掩码防护**：算术/布尔掩码转换是格基方案的瓶颈（压缩、比较、CBD、拒绝采样）。参考 Bos 等 “Masking Kyber: First- and Higher-Order Implementations”（TCHES 2021）、Coron 等高阶掩码 Kyber/Dilithium、以及为掩码设计的 Raccoon。
- **故障攻击**：确定性签名（Dilithium 确定性模式、SPHINCS+ 的 WOTS 链）上的差分故障攻击、跳过 FO 重加密比较。防护：随机化签名、重复计算校验、关键比较双重化。
- **评估方法**：TVLA（基于 t 检验的泄露评估）、ChipWhisperer 等开源平台。注意国家密码管理局已开设面向候选硬件实现侧信道评估的研究项目 [source](https://postquantum.com/security-pqc/china-ngcc-candidate-flaws/)，后续轮次物理安全的权重很可能上升。

### 6.5 延伸阅读

- Jancar 等，“They're not that hard to mitigate: What Cryptographic Library Developers Think About Timing Attacks”，IEEE S&P 2022：开发者为何不用恒定时间工具。
- 针对 NIST 附加签名候选的系统性计时泄露分析与工具链 [arXiv 2509.04010](https://arxiv.org/pdf/2509.04010)。
- Ravi、Chattopadhyay 等关于格基 KEM 侧信道辅助选择密文攻击的系列工作（含 HQC 的 “Et tu, Brute?”）。

## 7. 测试、鲁棒性与 spec 一致性

KAT 通过只证明“在 NIST DRBG 生成的 100 组随机输入上与参考实现一致”，几乎覆盖不到任何恶意输入或低概率边界。NGCC 暴露的问题大多数都能通过 KAT。建议按下表分层建设。

### 7.1 测试分层

| 层次 | 检查什么 | 工具 / 资源 |
| --- | --- | --- |
| 1. KAT | 正常输入下与参考实现一致 | NIST `PQCgenKAT`（AES-256-CTR DRBG，只用于测试） |
| 2. 内部函数 / 中间值向量 | 逐步定位分歧；KeyGen/Encaps 的确定性内部接口 | NIST ACVP；[C2SP CCTV](https://c2sp.org/CCTV/ML-KEM) 的 intermediate 向量 |
| 3. 负向与边界向量 | 公钥超模、密文错误长度、私钥哈希被篡改、XOF 读取极多的“unlucky”向量、用 strcmp 比较就会失败的向量 | CCTV、[Wycheproof](https://github.com/C2SP/wycheproof)、AWS-LC 的解封装校验向量 [source](https://pkg.go.dev/github.com/aws/aws-lc/util/vecgen) |
| 4. 累积向量 | 百万级随机测试只提交一个哈希值 | [Accumulated Test Vectors](https://words.filippo.io/accumulated/)：确定性 SHAKE128 生成输入，所有输出吸收进一个哈希 |
| 5. 差分测试 | 优化实现 vs 参考实现 vs 独立可执行规范；单个内核级别 + 整体 API 级别 | 自建框架；Sage/Python 模型 |
| 6. 性质与变异测试 | Decaps(Encaps) 一致；解码再编码不变；密文/签名逐位翻转必须被拒绝；两次 keygen 输出不同 | 变异测试（metamorphic）在 KpqC 上的应用 [ePrint 2023/1437](https://eprint.iacr.org/2023/1437.pdf)；方法的完整介绍见[后续文章](../crypto-informed-testing/?lang=zh) |
| 7. Fuzz | 解析器、验证器、解封装对任意字节串的鲁棒性；多实现差分 fuzz | libFuzzer、AFL++、honggfuzz；配合 ASan/UBSan/MSan |
| 8. 内存与未定义行为 | 越界、未初始化读、整数溢出 | Valgrind memcheck、各 Sanitizer、`-fsanitize=integer`；栈用量测量（M4） |
| 9. 跨平台一致性 | 大/小端、32/64 位、不同编译器 | QEMU 运行 s390x（大端）、i386、ARM；QEMU mps2-an386 运行 Cortex-M4 |
| 10. 恒定时间 | 秘密相关分支/地址/可变延迟指令 | 见 7.2 |
| 11. 形式化验证 | 功能正确性、内存安全、恒定时间的证明 | 见 7.3 |

### 7.2 恒定时间检测工具

- **Valgrind 秘密标记法（ctgrind / TIMECOP）**：用 `VALGRIND_MAKE_MEM_UNDEFINED` 把私钥和随机数标记为“未初始化”，任何依赖它的分支或地址都会报错。最便宜、最应该第一个接入 CI。注意必须对公开值（如拒绝采样循环次数、验证结果）显式“解除标记”，并在文档中论证其公开性。
- **KyberSlash 补丁版 Valgrind**：额外检测操作数为秘密的除法等可变延迟指令，补丁在 [TCHES 2025 工件](https://artifacts.iacr.org/tches/2025/a9/readme.html) 中公开。
- **统计型：dudect**：黑盒计时 + t 检验，适合最终二进制抽检，但覆盖率依赖输入类别设计。
- **二进制级静态/符号分析**：Binsec/Rel、Microwalk（动态二进制插桩）、ct-verif（LLVM 层）。
- **编译器矩阵**：上述工具必须在多个编译器和优化级别下运行，否则会漏掉 Clangover 这类问题。

### 7.3 形式化验证工具链

- **Jasmin + EasyCrypt**（libjade/formosa）：功能正确性、恒定时间、推测恒定时间，已覆盖 ML-KEM 的 AVX2 实现。
- **CBMC + HOL Light**（mlkem-native）：C 代码用 CBMC 证明无越界和无溢出，汇编内核用 HOL Light（s2n-bignum 风格）证明功能正确。其函数契约写法（前置/后置条件标注系数范围）即使不跑证明也值得学习。
- **hax / hacspec + F\***（Cryspen libcrux）：Rust 实现的验证。
- **Cryptol + SAW**（Galois）：可执行规范与 C 代码的等价性证明。
- **saferewrite**（Bernstein）：基于符号执行检查优化实现与参考实现的等价性，适合小内核。

### 7.4 “与 spec 一致”的实操方法

1. 由**非代码作者**按 spec 独立写可执行模型。与代码不一致时，先判断是代码错还是 spec 错，并在 spec 勘误表中记录。
2. 导出每个子步骤的中间值（种子展开、矩阵 A、噪声、压缩前后、哈希输入），逐步比对。ngcc.dev 发现的“遗漏舍入常数”“丢弃误差多项式”这类问题，只有中间值对比才能发现。
3. 对 spec 中每一条“MUST/拒绝”语句写一个负向测试，建立需求到测试的追踪表。
4. 用解密失败率统计校验参数：对小参数或放大噪声的变体实测失败率，与理论值对比（可发现 kem-22-1、kem-09-3 这类失败率分析错误）。
5. 让 AI 助手按 spec 逐条审查代码——评审者已经在这么做，提交者应该先做。

## 8. 资源索引：人、论文、博客、slides、论坛

如果只看三样：PQClean 经验论文 [ePrint 2022/337](https://eprint.iacr.org/2022/337)、Peter Schwabe 的 [Kyber 实现要点 slides](https://cryptojedi.org/peter/data/cmmrs-20240801.pdf)、[ngcc.dev 报告](https://ngcc.dev/reports/index.html)逐条复现。

### 8.1 PQC 工程领域代表人物（按方向）

| 人物 | 机构（大致） | 代表工作 / 学什么 |
| --- | --- | --- |
| Daniel J. Bernstein | UIC / Academia Sinica | NTRU Prime、Classic McEliece、SUPERCOP、djbsort、KyberSlash、saferewrite；[博客](https://blog.cr.yp.to) 对安全性与工程权衡的长文 |
| Tanja Lange | TU/e | McEliece、同源、PQCRYPTO 教学材料 |
| Peter Schwabe | MPI-SP | Kyber/Dilithium/SPHINCS+ 共同设计者；PQClean、pqm4、Jasmin、高保障实现 |
| Matthias J. Kannwischer | Chelpis / PQCA | pqm4、PQClean、mlkem-native；嵌入式优化与测试基础设施 |
| Hanno Becker | AWS | mlkem-native、SLOTHY 汇编超优化器、HOL-Light 验证的 Arm 内核 |
| Bo-Yin Yang / Vincent Hwang / Ming-Shing Chen | Academia Sinica | NTT 不友好环乘法、Arm/AVX2 多项式乘法综述、McEliece/多变量优化 |
| Gilles Barthe / Manuel Barbosa / Benjamin Grégoire / François Dupressoir | MPI-SP / Porto / Inria / Bristol | Jasmin、EasyCrypt、libjade、形式化验证 ML-KEM |
| Karthikeyan Bhargavan / Franziskus Kiefer | Inria / Cryspen | hacspec、hax、libcrux（验证的 Rust ML-KEM） |
| Douglas Stebila / Thom Wiggers | Waterloo / PQShield | liboqs、OQS、KEMTLS、PQ 协议集成 |
| Markku-Juhani O. Saarinen | Tampere / PQShield | ngcc.dev、硬件与侧信道、标准化评论 |
| Thomas Prest / Thomas Pornin | PQShield / NCC | Falcon、掩码、Raccoon；Pornin 的浮点恒定时间实现经验 |
| Prasanna Ravi / Shivam Bhasin / Anupam Chattopadhyay | NTU | 格基/码基 KEM 的侧信道与故障攻击 |
| Peter Pessl / Thomas Pöppelmann / Joppe Bos | Infineon / NXP | 嵌入式掩码、单轨迹攻击、工业落地 |
| Filippo Valsorda / Sophie Schmieg / Bas Westerbaan | Geomys / Google / Cloudflare | Go/BoringSSL/Cloudflare 生产部署、测试向量、TLS 集成 |
| Antoon Purnal | PQShield | Clangover、编译器引入的泄露 |

### 8.2 必读论文（按主题）

- **软件质量与标准化**：Kannwischer–Schwabe–Stebila–Wiggers，“Improving Software Quality in Cryptography Standardization Projects”，SSR 2022 [ePrint 2022/337](https://eprint.iacr.org/2022/337)；KpqC 首轮实现安全分析 [ePrint 2023/1437](https://eprint.iacr.org/2023/1437.pdf)。
- **计时泄露**：KyberSlash [ePrint 2024/1049](https://eprint.iacr.org/2024/1049)；Guo–Johansson–Nilsson，FO 计时攻击（CRYPTO 2020）；Guo 等 HQC 定重采样计时攻击（TCHES 2022）；PQDSS 候选计时泄露工具链 [arXiv 2509.04010](https://arxiv.org/pdf/2509.04010)。
- **多项式乘法**：Chung 等，“NTT Multiplication for NTT-unfriendly Rings”（TCHES 2021）；Hwang 等关于向量化多项式乘法的算法视角综述；Seiler，AVX2 Kyber NTT（ePrint 2018/039）。
- **验证**：Almeida 等，“Formally Verifying Kyber”系列（Jasmin/EasyCrypt）；Barbosa 等，“SoK: Computer-Aided Cryptography”（S&P 2021）。
- **掩码**：Bos 等，“Masking Kyber”（TCHES 2021）；del Pino 等 Raccoon。
- **从开发者视角看恒定时间**：Jancar 等（S&P 2022）。

### 8.3 博客与技术文章

- Filippo Valsorda：[Enough Polynomials and Linear Algebra to Implement Kyber](https://words.filippo.io/kyber-math/)（已补充 ML-DSA 附录）、[Accumulated Test Vectors](https://words.filippo.io/accumulated/)。
- PQShield：[Clangover 原理解读](https://pqshield.com/pqshield-plugs-timing-leaks-in-kyber-ml-kem-to-improve-pqc-implementation-maturity/)，以及其他实现安全文章。
- [KyberSlash 页面](https://kyberslash.cr.yp.to/)：追踪各库修复状态，是“漏洞扩散到多少下游”的教科书案例。
- Cloudflare 博客（Bas Westerbaan 等）：PQ-TLS 部署、中间箱兼容性、性能实测。
- Project Eleven：[Threshold ML-DSA 状态重用问题的披露](https://www.projecteleven.com/blog/nine-schemes-advance-to-round-3-of-nists-additional-digital-signatures-process)。
- Giacomo Pope 的 [kyber-py](https://GitHub.com/GiacomoPope/kyber-py)：可作为“可执行规范”的写法参考。

### 8.4 Slides、课程与演讲

- Peter Schwabe，[Kyber – Implementation aspects](https://cryptojedi.org/peter/data/cmmrs-20240801.pdf)（CMMRS 2024）：含 Clangover 与查表泄露的逐步演示。cryptojedi.org 上有大量其他 PQC 工程课件。
- NIST 各届 PQC 标准化会议讲稿，如 [FIPS 206 FN-DSA 进展](https://csrc.nist.gov/presentations/2025/fips-206-fn-dsa-falcon)。
- Real World Crypto、CHES 的 PQC 实现与侧信道 tutorial（YouTube 有录像）。
- PQCRYPTO 暑期学校、Summer School on Real-World Crypto and Privacy 的课件。

### 8.5 论坛与社区

- [NIST pqc-forum](https://groups.google.com/a/list.nist.gov/g/pqc-forum)：实现问题讨论最集中的地方。推荐帖子：[Clangover 披露](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/hqbtIGFKIpU)、[ML-KEM 负向/中间值/边界测试向量](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/aCAX-2QrUFw/m/MuCObaS2AgAJ)、[FIPS 206 状态更新](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/1HXzjlMUU6Y)。该论坛已出现 NGCC 候选的公开评论。
- ICCS NGCC 官方公开论坛（两个赛道）与 [ngcc-harness GitHub issues](https://github.com/ngcc-dev/ngcc-harness/issues)。
- IETF CFRG / TLS / LAMPS 邮件列表：编码与协议集成决议。
- PQCA（Linux Foundation）与 Open Quantum Safe 的 GitHub Discussions。
- IACR ePrint：按“Implementation”分类订阅。

## 9. NGCC 提交前自查清单

下面每一项都对应首轮公开评审中至少一个候选被报告的问题。ngcc.dev 的 harness 只覆盖参考实现，所以 AVX2 / Cortex-M4 等优化版本需要自己跑同一套检查。

**A. 安全预算**

- [ ] 每个参数集的种子、哈希输出、挑战、盐、共享密钥长度都 ≥ 声称安全级别（碰撞相关的按 2 倍计），用 `_Static_assert` 固化
- [ ] 所有长度常量命名带单位，排查 bit/byte 混淆
- [ ] 解密失败率分析与实际实现（含公钥舍入、压缩误差）一致，有实测数据支撑

**B. KEM / FO**

- [ ] 密文逐位翻转：解封装输出确定性伪随机密钥，且不等于正确密钥（测试程序见[后续文章](../crypto-informed-testing/?lang=zh)第 9 节）
- [ ] 重加密比对覆盖全部密文字节，恒定时间，条件拷贝覆盖全部密钥字节
- [ ] 拒绝密钥的 KDF 输入绑定完整密文
- [ ] 解密→输出路径无任何秘密相关分支、除法、查表（对照 kem-08-1 的“解密系数分支”问题）
- [ ] 公钥模检查（或 spec 明确说明为何不需要）

**C. 签名**

- [ ] 解码→再编码逐字节相等，否则拒绝（填充位、hint、高位）
- [ ] hint 计数/索引范围检查先于任何写内存
- [ ] 全零、全 0xFF、截断、超长签名均返回错误且不崩溃
- [ ] 拒绝循环 nonce 不重复、不回绕

**D. 随机数与状态**

- [ ] KAT 用 DRBG 只在测试构建中链接；生产路径调用系统 RNG 并检查返回值
- [ ] 同一进程内连续两次 keygen/encaps/临时密钥输出不同
- [ ] 协议状态不可重置、不可重用；身份与 transcript 进入 KDF（KEX 赛道）

**E. API 与内存**

- [ ] 调用者声明的长度与常量比对，不匹配即返回错误（对照 kem-14-1 栈溢出问题）
- [ ] 分配失败、内部错误永不返回“成功”；失败时输出缓冲区清零
- [ ] 无 `assert`/`abort` 处理外部输入
- [ ] 秘密缓冲区用不可被优化掉的清零
- [ ] 删除调试路径、全局秘密、printf；审查提交包内每个文件

**F. 优化实现（AVX2 / AVX-512 / M4）**

- [ ] 每个内核与参考函数做随机 + 极值输入差分（含恶意密文导致的超范围系数）
- [ ] 每个内核的输入/输出范围不变式写进注释并有测试
- [ ] n 非向量宽度整数倍时的尾部读写被 ASan 覆盖（注意对齐填充会隐藏越界）
- [ ] ref / AVX2 / M4 对同一组恶意输入的输出与返回码逐字节一致
- [ ] M4：栈用量、硬件 RNG、可变延迟乘法指令

**G. 恒定时间与工具**

- [ ] Valgrind 秘密标记测试在 gcc/clang × `-O0`…`-O3`/`-Os` 矩阵下全部通过
- [ ] KyberSlash 补丁版 Valgrind 检查可变延迟指令
- [ ] 对公开的可变时间部分（如公开种子的拒绝采样）在 spec 中论证
- [ ] 解析入口持续 fuzz（解封装、验证、公钥导入）

**H. Spec 一致性**

- [ ] 独立可执行规范 + 中间值差分通过
- [ ] spec 中每条“必须拒绝”都有负向测试
- [ ] 公开变更记录与勘误表，每次修复附带回归测试

建议把 A–H 映射到自己的测试框架层次（基线 harness、独立模型差分、通用鲁棒性套件），并在 CI 中运行。

## 来源

- [ngcc.dev 报告索引](https://ngcc.dev/reports/index.html) 与 [恒定时间审查](https://ngcc.dev/constant-time/index.html)
- [PostQuantum.com：NGCC 首轮公开发现](https://postquantum.com/security-pqc/china-ngcc-candidate-flaws/)
- [NIST：附加签名第 3 轮公告](https://www.nist.gov/news-events/news/2026/05/nine-candidates-advance-third-round-additional-digital-signatures-pqc)、[NIST IR 8610](https://csrc.nist.gov/pubs/ir/8610/final)、[NIST IR 8240](https://nvlpubs.nist.gov/nistpubs/ir/2019/NIST.IR.8240.pdf)
- [PQClean](https://github.com/PQClean/PQClean)、[ePrint 2022/337](https://eprint.iacr.org/2022/337)、[ePrint 2023/1437](https://eprint.iacr.org/2023/1437.pdf)
- [KyberSlash ePrint 2024/1049](https://eprint.iacr.org/2024/1049)、[Clangover](https://github.com/antoonpurnal/clangover)、[Clangover pqc-forum 披露](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/hqbtIGFKIpU)
- [C2SP CCTV ML-KEM 向量公告](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/aCAX-2QrUFw/m/MuCObaS2AgAJ)、[Accumulated Test Vectors](https://words.filippo.io/accumulated/)
- [Peter Schwabe：Kyber – Implementation aspects](https://cryptojedi.org/peter/data/cmmrs-20240801.pdf)
