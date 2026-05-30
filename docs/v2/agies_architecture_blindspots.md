# agies 架构盲区分析：漏洞类型覆盖矩阵

> 基于 agies 当前架构（Director → Sourcer → Bulk Analysis → Verification → Report）的逐层分析。
> 分析对象为 `--new-pipeline`（Xint 风格）流水线。
> 日期：2026-05-23

---

## 架构能力总览

```
检测阶段    方法                             成本     能做什么
────────────────────────────────────────────────────────────────────
Director    tree-sitter + PageRank          $0       按 SAST 信号排序函数
Sourcer     tree-sitter 索引 + 调用图       $0       建函数索引、调用关系
Bulk        LLM 逐函数/逐块分析            $$$      "发现所有可疑 sink"
Verification LLM + 工具调用追踪             $$$$     "确认候选漏洞是否可利用"
Report      LLM 汇总                        $       格式化报告
```

架构的核心设计思路是 **数据流追踪**——找到"不安全的数据到达危险的函数"。这种设计对注入类、路径遍历类漏洞非常有效，但对"代码里没写什么东西"的漏洞类型几乎完全失效。

---

## 漏洞类型覆盖矩阵

### 类型一：注入类（SQLi、XSS、命令注入、模板注入）

| 维度 | 说明 |
|------|------|
| **架构覆盖** | ✅ **强** |
| **检测链路** | Director(`sql_sink=80`, `cmd_exec=80`, `dynamic_exec=80`) → Bulk 标记 sink → Verification 追踪输入流 |
| **已知检出** | vulpy 测试中的 SQLi、XSS ✅ |
| **盲区** | 跨语言注入链（如 JS 输入 → Python exec）需要跨文件追踪，依赖 Verification 能否通过 `find_callers` 找完整路径 |
| **根因** | 架构从设计之初就聚焦数据流跟踪——"不安全数据到达危险函数"是最自然匹配的漏洞模式 |

### 类型二：路径遍历 / 任意文件读写

| 维度 | 说明 |
|------|------|
| **架构覆盖** | ✅ **强** |
| **检测链路** | Director(`file_io=10`) → Bulk 发现路径拼接 → Verification 确认输入控制路径 |
| **已知检出** | zipp CVE-2024-5569 路径穿越 ✅（Verification Agent 有硬编码 override） |
| **盲区** | 需要跨多函数多文件调用链才能确认的路径穿越——Verification 的迭代限制可能导致来不及查全。当前 batch mode 每个 batch 只有 6 轮迭代 |
| **根因** | 这仍是数据流类漏洞，所以架构覆盖好 |

### 类型三：认证 / 授权缺失（IDOR、权限绕过、未授权访问）

| 维度 | 说明 |
|------|------|
| **架构覆盖** | 🟡 **靠 prompt 质量** |
| **检测链路** | Mapping(标注 trust_assumptions) → AttackSurface(标注 auth_required) → DataFlow → Vulnerability("读意图") |
| **盲区原因** | "缺了什么"比"多了什么"难检测一万倍。Vulnerability Agent 需要对比开发者"想的"和"写的"之间差距——这完全依赖 prompt 质量。Mapping Agent 虽然标注了 `"Prices arrive from client"` 这类 trust assumption，但下游没有系统性检查"每个 trust assumption 是否对应了一个 guard" |
| **典型漏检** | 一个 CRUD API 中 10 个端点里 9 个有 `@RequireAuth`，第 10 个忘记加——Bulk Analysis 看这个孤立端点时不会意识到"这里应该有一个 auth check" |

### 类型四：资源耗尽 / DoS（栈溢出、ReDoS、内存耗尽、无限循环）

| 维度 | 说明 |
|------|------|
| **架构覆盖** | 🔴 **架构盲区** |
| **检测链路** | 没有专项检测链路 |
| **已知例外** | zipp ReDoS 能检出是因为：`glob.py` 调用了 `re.compile()` + Verification Agent 有 CVE-2024-5569 的硬编码 override + exploit 触发了超时 |
| **原型案例** | **yaml_src CVE-2026-33532**：YAML 解析器的 composition/resolution 阶段使用递归函数且没有 depth bound。5000 层嵌套的 `[[[[...]]]` → `RangeError: Maximum call stack size exceeded` |
| **根因** | 此类漏洞的根因是 **"代码没写什么东西"**（没写深度限制、没写超时、没写次数限制），而不是 **"代码写了什么危险的东西"**。Bulk Analysis 看一个递归函数会说"这个函数递归调用了自己"，但不会说"没有 max_depth 检查"。架构中没有任何环节会问"这个操作有安全边界吗？" |
| **子类型列举** | 正则灾难性回溯（ReDoS）、递归深度无限制、输入大小无限制、并发量无限制、内存分配无限制、文件大小无限制 |

### 类型五：业务逻辑缺陷（价格篡改、步骤绕过、状态机错误、限额绕过）

| 维度 | 说明 |
|------|------|
| **架构覆盖** | 🟡 **靠 prompt 质量，不稳定** |
| **检测链路** | Mapping(标 trust assumptions) → Vulnerability("读意图" + "问 what if") |
| **盲区原因** | 真正的业务逻辑理解需要知道**"业务规则是什么"**。一个电商系统里"在创建订单后检查库存"和"在创建订单前检查库存"差别很大，但 LLM 只看代码不知道业务的预期顺序。Vulnerability Agent 的 prompt 虽然鼓励问 `"what if the user passes negative numbers?"` 之类的问题，但没有结构化的业务流输入 |
| **典型漏检** | 优惠券使用次数在 DB 列里做 `UPDATE ... SET count = count + 1` 没有锁 → 竞态条件。但如果攻击路径是"在 10ms 内并发发 100 个请求"，静态分析几乎不可能确认 |

### 类型六：加密 / 协议缺陷（弱算法、IV 重用、padding oracle、随机数可预测）

| 维度 | 说明 |
|------|------|
| **架构覆盖** | 🟡 **靠运气** |
| **检测链路** | Director(`crypto_operation=5`) → Bulk(看函数名和调用) → Verification |
| **盲区原因** | `AES-CBC` 和 `AES-GCM` 都是"加密操作"。Director 权重只有 **5**（全表最低），几乎不会因此进入 hot/warm 路径。Bulk Analysis 能识别 `Crypto.Cipher.AES.new(key, AES.MODE_CBC, iv)` 是一个加密调用，但不会说 "CBC 模式后续需要 HMAC 否则有 padding oracle 攻击"。Verification Agent prompt 没有加密审计专项知识 |
| **子类型列举** | ECB 模式（确定型加密）、CBC + 无 HMAC（padding oracle）、固定 IV、硬编码密钥、不安全随机数、证书验证跳过、弱哈希（MD5/SHA1） |

### 类型七：竞态条件 / TOCTOU（检查时间≠使用时间、并发变异、信号竞争）

| 维度 | 说明 |
|------|------|
| **架构覆盖** | 🔴 **架构盲区** |
| **检测链路** | 没有专项检测链路 |
| **盲区原因** | 需要理解"两个并发路径访问同一共享资源"。Bulk Analysis 看单个函数看不到并发；Verification 看单个 candidate 不会同时分析两个入口点。架构中没有"共享状态 → 锁 → 并发访问"的分析概念 |
| **子类型列举** | 文件 TOCTOU（检查存在后打开）、DB read-then-write 无锁、缓存未命中竞态、信号处理函数重入、延迟初始化竞态 |
| **为什么 LLM 也难** | 竞态条件的核心问题是**时序**——代码本身看起来完全正确，只是两段"正确"的代码在不同时序下交叉执行会产生意外状态。静态分析（无论 LLM 还是传统工具）对这类漏洞的检测率天然低 |

### 类型八：配置 / 部署漏洞（硬编码密钥、敏感信息泄露、debug 端点、缺安全头）

| 维度 | 说明 |
|------|------|
| **架构覆盖** | 🔴 **架构盲区** |
| **检测链路** | 没有专项检测链路 |
| **盲区原因** | Director 只**索引函数**，不扫描配置文件、Dockerfile、k8s yaml、.env 文件。Bulk Analysis 只分析源代码函数体。硬编码的 `API_KEY = "sk-xxx"` 如果在函数体外（模块级别），**根本进不了 function index** |
| **子类型列举** | 硬编码密钥/Token/P 在源码中、`.env` 提交到版本控制、debug 端点（`/debug/`）在生产环境可用、CORS 配成 `*`、HTTPS 不强制、HSTS 缺失、Docker 容器以 root 运行、k8s pod 权限过大 |

### 类型九：反序列化漏洞（pickle、yaml.load、XXE、不安全的 ObjectInputStream）

| 维度 | 说明 |
|------|------|
| **架构覆盖** | 🟡 **部分覆盖（易受类型十四噪音淹没影响）** |
| **检测链路** | Director(`serialization=20`) → Bulk(标记 `pickle.loads` 等 sink) → Verification(追踪输入) |
| **盲区原因** | 检测 `pickle.loads(user_input)` 本身在架构能力范围内。但 bentoml CVE-2024-9070 的测试表明：即使 `pickle.loads(request.body())` 这种教科书级的反序列化 RCE 存在于项目核心代码中，如果同时存在大型第三方打包 JS 文件，Pipeline 可能被噪音彻底淹没——Sourcer 索引了 7786 个函数（70% 来自 JS bundle），Bulk 的 58 个候选全是 JS 误报，Verification 上下文溢出，最终 `pickle.loads` 从未被标记为候选 |
| **分界线** | 调用已知危险函数（`pickle.loads`）+ 输入可控 → 理论上能检出，但需噪音不超标。解析器内部实现缺陷（栈溢出、无限循环）→ 不能检出 |

### 类型十：协议 / 状态机违规（JWT alg confusion、OAuth state 重用、SSRF、请求走私）

| 维度 | 说明 |
|------|------|
| **架构覆盖** | 🔴 **架构盲区** |
| **检测链路** | 没有专项检测链路 |
| **盲区原因** | 需要理解**多步骤协议流程**：Step 1 做了什么，Step 3 是否验证了 Step 1 的结果。当前架构所有 Agent 都是"单次一次性"的——一个 agent 实例分析一个文件或一个 candidate。黑板架构（P6）部分解决了跨函数知识共享，但远不够做协议流分析 |
| **典型漏检** | JWT 库代码中 `"alg": "none"` 的判断逻辑——需要在解析 token 的代码里找"是否忽略了 alg 头"。OAuth 流程中 state 参数是否校验——需要看重定向回来时的 state 检查 |

### 类型十一：编码 / 规范化攻击（Unicode 归一化绕过、双编码、大小写绕过、Null 字节注入）

| 维度 | 说明 |
|------|------|
| **架构覆盖** | 🔴 **架构盲区** |
| **盲区原因** | 需要理解"同一字符串在不同编码下的语义差异"。LLM 理论上知道 Unicode 归一化（NFD vs NFC），但 Bulk Analysis 不会把 `.lower()` 或 `.normalize()` 识别为安全问题。Verification 也没有相关的溯源能力 |
| **典型漏检** | `"admin"` vs `"a\x00dmin"` vs `"ａdmin"`（全角）绕过认证。路径中的 `..` vs `%2e%2e` vs `．．`（全角点）绕过路径过滤 |

### 类型十二：侧信道 / 时序攻击（常量时间比较、错误信息泄露、缓存侧信道）

| 维度 | 说明 |
|------|------|
| **架构覆盖** | 🔴 **架构盲区** |
| **盲区原因** | "对比 secret 时用了 `==` 而不是 `constant_time_compare()`"——Bulk Analysis 能看到 `==` 运算符，但不会识别为时序攻击。这类漏洞需要知道"这里比较的是密码/token"，需要类型系统或命名约定的支持 |
| **子类型列举** | 密码比较用 `==`（非常量时间）、错误信息区分"用户不存在" vs "密码错误"、调试堆栈返回给客户端、HTTP 响应时间可测量 |

### 类型十三：供应链（过时依赖、恶意包、typo-squatting、依赖混淆）

| 维度 | 说明 |
|------|------|
| **架构覆盖** | 🔴 **架构盲区** |
| **盲区原因** | Sourcer 索引函数但不解析依赖版本，不和 CVE 数据库做交叉引用。没有 `pip audit` / `npm audit` / `trivy` 的集成 |
| **子类型列举** | 使用已知有 CVE 的依赖版本、依赖包名 typosquatting（`requsts` vs `requests`）、私有包名与公开包名冲突（依赖混淆）、恶意 npm 包通过 postinstall 执行代码 |

### 类型十四：审计噪音淹没（第三方大型文件导致信号丢失）

| 维度 | 说明 |
|------|------|
| **架构覆盖** | 🔴 **架构盲区（破坏性盲区——不仅自身漏检，还会导致其他类型漏检）** |
| **检测链路** | Sourcer 无差别索引所有源文件 → Bulk Analysis 处理过多无用函数 → Verification 上下文被撑爆 |
| **原型案例** | **bentoml CVE-2024-9070**：`runner_app.py:301` 存在 `pickle.loads(request.body())`（反序列化 RCE，CWE-77，Severity 9.8）。但项目中含有 `swagger-ui-standalone-preset.js` 和 `swagger-ui-bundle.js` 两个大型第三方打包 JS 文件（数万行 minified 代码）。Sourcer 将它们也纳入了索引，导致 7786 个函数中约 70% 来自这两个 JS 文件。Bulk Analysis 产出的 58 个候选全部是 JS 误报（prototype pollution、buffer overflow 等），Python 侧的真实漏洞从未被标记。Verification 尝试处理这些候选时，system prompt + bulk 结果已达 **6M tokens**，远超 DeepSeek 的 1M 上限，所有验证任务全部失败，最终报告为空 |
| **根因** | 架构的设计假设是所有被索引的文件**价值均等**。Sourcer 没有区分"项目自有代码"和"第三方打包文件"的能力，Bulk Analysis 也没有优先级机制——它按顺序处理函数，不管这个函数来自 `app.py` 还是 `swagger-ui-bundle.js`。Verification 的上下文预算（context window）是**全局共享的**，被 JS 误报填满后，真正的 Python sink 候选即使被标记也没有剩余空间来验证。这是一种**二阶放大效应**：一个盲区（第三方文件被纳入分析）引爆了另一个问题（上下文溢出 → 所有验证失败） |
| **子类型列举** | 大型 minified JS bundle（swagger-ui、monaco-editor 等）、vendored 第三方库（项目内 `vendor/` 目录）、自动生成的 protobuf/thrift 代码、大型测试 fixture 数据、机器生成的 parser/lexer 代码 |
| **影响范围** | 非破坏性盲区最多只导致"某一类漏洞漏检"。类型十四是**破坏性盲区**——它能让整个 pipeline 对*所有*漏洞类型失效，无论该类型 agies 原本擅长与否 |

---

## 汇总：四类盲区的根本差异

```
盲区类别              根因                                   修复难度
─────────────────────────────────────────────────────────────────────
A. 架构意识盲区        架构不理解"缺少边界"是一种漏洞              中等
   （类型四：资源耗尽/DoS）                                      （需新增检测步骤）
   
B. 信息不足盲区        需要的输入不在当前分析范围内                 难
   （类型八：配置漏洞、                                        （需扩展扫描范围、
    类型十三：供应链）                                             新增工具集成）

C. 噪音淹没盲区        第三方大型文件污染了整条 pipeline           中等
   （类型十四：审计噪音淹没）                                    （Sourcer 加文件过滤器、
                                                                  Bulk 加来源优先级）
   
D. 时序/语义盲区       漏洞存在于代码执行的过程中或语义层面          最难
   （类型七：竞态条件、                                        （静态分析天然局限、
    类型十一：编码、                                             准确率上限低）
    类型十二：侧信道）
```

> 注：类型十四（噪音淹没）的特殊之处在于——它不是某一类漏洞的盲区，而是**整个 pipeline 的盲区**。当它被触发时，会级联放大为所有漏洞类型的漏检，包括 agies 原本"擅长"的注入类和路径遍历类。

---

## 每个脆弱类型的改善潜力评估

```
类型                 当前覆盖   改善潜力   建议方式
────────────────────────────────────────────────────
注入类                ✅ 强      微弱       无需改善（但注意类型十四噪音淹没可导致失效）
路径遍历              ✅ 强      微弱       无需改善（但注意类型十四噪音淹没可导致失效）
认证/授权缺失          🟡 靠prompt  中等   DataFlow 增加 auth gate 追踪
业务逻辑缺陷           🟡 靠prompt  中低   需要业务规则输入，架构级改动大
资源耗尽/DoS          🔴 盲区     高       新增 SafetyBoundary 检查（tree-sitter 扫描递归+边界缺失）
加密/协议缺陷          🟡 靠运气    中低    提高 crypto_operation 权重 + 专项 prompt
竞态条件/TOCTOU       🔴 盲区     低       LLM 静态分析上限就在这
配置/部署漏洞          🔴 盲区     高       Director 扩展扫描范围到非代码文件
反序列化              🟡 部分覆盖  中等     完善 Verification prompt（但注意类型十四可淹没）
协议/状态机违规        🔴 盲区     中低     需要跨 Agent 状态机建模
编码/规范化攻击        🔴 盲区     低       需要运行时输入，静态分析太难
侧信道/时序攻击        🔴 盲区     低       需要运行时测量，静态分析太难
供应链                🔴 盲区     高       集成 `pip audit` / `npm audit`
审计噪音淹没          🔴 破坏性盲区 高       Sourcer 加文件来源过滤 + 大型文件降权 + 语言优先级调度
```

---

## 关于 CVE-2026-33532（yaml_src）的专项分析

### 漏洞详情

| 字段 | 值 |
|------|-----|
| 包名 | `eemeli/yaml` v2.6.0 |
| GHSA | GHSA-48c2-rrv3-qjmp |
| CVE | CVE-2026-33532 |
| 严重度 | Medium |
| 修复版 | v2.8.3 (2026-03-21) |
| 漏洞类型 | 资源耗尽 / 栈溢出 |

### 触发路径

```
YAML.parse(input)
  → Composer.compose()
    → composeNode()              ← 递归，没有 depth 检查
      → composeNode()            ← 对嵌套集合再次递归
        → composeNode()          ← ...
          → RangeError: Maximum call stack size exceeded
```

### 构造 Payload

```yaml
[[[[[[[[[[[[[[[[[[[[...5000层嵌套...]]]]]]]]]]]]]]]]]]]]
```

仅 ~2-10KB 就能让 Node.js 进程崩溃。

### agies 漏检的根因追溯

| 阶段 | 发生了什么 | 为什么没用 |
|------|-----------|-----------|
| **Director** | `composeNode` 是递归函数，有 ref 标签 | 但 PageRank 只给了它普通的 centrality 分数，没有"递归函数需要深度限制"的标签类型 |
| **Bulk Analysis** | 看到 `composeNode()` 递归调用自身 | 输出可能是 `{"sinks": [], "vulnerabilities": []}` 因为没有外部调用 = 没有 sink |
| **Round 4 注入** | 对 critical 文件中未覆盖的函数注入 `cross_function_trace` 候选 | `composeNode` 被标记为 cross_function_trace, critical, 进入 verification |
| **Verification** | 检查 `composeNode`，发现它只是递归解析节点 | 没有 CVE 关键字在 reason 中，没有数据流路径可追踪 → 判定 false positive |
| **最终** | 0 triggerable | 架构没有任何环节会说"这个递归应该有深度限制" |

### 如果架构能检出，需要什么

新增一个 **SafetyBoundary 检查环节**（位置：在 Sourcer 和 Bulk Analysis 之间）：

```
tree-sitter 扫描所有函数 → 找出递归函数 → 检查函数体内是否有 depth/bound/limit 检查
  ├── 有 depth 检查 → 安全（如 if depth > MAX_NESTING: raise）
  ├── 无 depth 检查 → 标记为候选漏洞（"可能存在无限递归/栈溢出风险"）
  └── 无递归 → 跳过
```

这个检查是**确定性的**（tree-sitter），不需要 LLM 调用，成本为 $0。检查结果可以作为 Verification 的输入，让 verification agent 去验证"这个递归函数的 depth limit 是否足够、是否在正确的路径上"。

---

## 下一步优化方向

基于这个分析，收益最高的优化方向依次是：

1. **Sourcer 文件来源过滤**（区分项目自有代码 vs 第三方打包文件，覆盖类型十四——优先级最高，因为它是破坏性盲区，修复后还能释放被浪费的上下文预算）
2. **SafetyBoundary 检查**（新增 $0 的 tree-sitter 扫描步骤，覆盖类型四）
3. **配置/供应链扫描**（集成 pip audit、Dockerfile 检查，覆盖类型八、十三）
4. **Crypto 专项 prompt**（提高 crypto_operation 权重、给 Verification 添加加密模式分析知识）
5. **Auth gate 追踪**（在 DataFlow 层增加"敏感端点必须经过认证函数"的检查规则）
