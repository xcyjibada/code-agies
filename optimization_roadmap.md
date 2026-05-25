# agies 优化路线图（插入式进度）

> 基于 `agies_architecture_blindspots.md`（13+1 种盲区分析）和 `PROGRESS.md`（Phase 6 Step A 完成状态）制定的插入式优化计划。
> 当前基线：Phase 6 Step A ✅，全量测试 586 通过。
> 日期：2026-05-23

---

## 执行策略：三轮冲刺

```
冲刺一（Sourcer 免疫系统）→ 冲刺二（SafetyBoundary）→ 冲刺三（认证追踪准备）
  确定性，$0 成本             确定性+LLM 结合          架构改动，需谨慎
  1-2 天                      2-3 天                    待定
```

---

## 冲刺一：Sourcer 前置免疫系统

**目标**：根治类型十四（审计噪音淹没）。破坏性盲区，优先级最高。

### 1.1 特征阻断（Heuristic Blocking）

在 `engine/sourcer/loader.py` 的 `os.walk` / 文件遍历阶段嵌入三道过滤器：

| 特征 | 规则 | 实现方式 | 风险 |
|------|------|----------|------|
| A: 单行过长 | 文件平均行长 > 200 字符 → 跳过 | 采样前 20 行算平均行长 | 极低，minified 文件都 >500 字符/行 |
| B: 文件超大 | 文件 > 500KB 且非数据文件 → 跳过 | `os.path.getsize()` | 极低，正常源文件极少超过 200KB |
| C: 命名特征 | `*.min.js`, `*-bundle.js`, `vendor/` → 跳过 | glob/path pattern 匹配 | 极低，业界标准 |

**工作量**：1 个函数，~30 行，无新增依赖。

### 1.2 语言占比调度（Director 联动）

在 Director 统计各语言文件数，当主语言占比 > 80% 时，副语言文件在 Sourcer 索引时标记为 `low_priority`，Bulk Analysis 按 `priority` 排序，低优先级函数仅在上下文预算充足时处理。

**工作量**：Director 加统计逻辑（~20 行）+ Sourcer 加排序字段（~10 行）。

### 1.3 预期效果

| 指标 | 当前（bentoml） | 预期 |
|------|----------------|------|
| 索引函数数 | 7786 | <2000 |
| 误报候选 | 58（全部 JS） | <10 |
| Verification 上下文 | 6M tokens（溢出） | <500K tokens |
| 检出 `pickle.loads` | ❌ 漏检 | ✅ 应检出 |

---

## 冲刺二：SafetyBoundary 确定性检查

**目标**：覆盖类型四（资源耗尽/DoS）。确定性扫描 + LLM 验证的经典结合。

### 2.1 tree-sitter 递归函数标记

在 `engine/director/queries/python-tags.scm` 和 `js-tags.scm` 追加查询规则，检测函数体内递归调用（函数名出现在自身 body 中的 call 表达式）：

```scm
; 递归调用标记
(function_definition
  name: (identifier) @func_name
  body: (block
    (expression_statement
      (call
        function: (identifier) @call_name
        (#eq? @func_name @call_name)
      )
    )
  )
) @recursive_function
```

输出信号类型：`recursion`，权重：不做 depth 检查时 x100。

### 2.2 Depth Guard 浅层扫描

在 `engine/sast/matcher.py`（Phase A 待实现）中新增 `MissingBoundDetector`——对标记为递归的函数做确定性 pattern match，检查函数体内是否有 depth/limit/level/max 相关的比较操作：

```
匹配模式：
  1. if depth > N / if depth >= N
  2. if n > MAX / if level > MAX_DEPTH
  3. if len(stack) > max_nesting
  4. while depth < len(stack) 中的边界变量
  5. if limit <= 0: return
```

匹配成功 → 安全。匹配失败 + 递归标记 → 候选漏洞 `[MISSING_DEPTH_BOUND]` 进入 Director 高优先级。

### 2.3 Verification Prompt 增强

在 `engine/prompts/default.yaml` 的 `verification` 模板中加入：

```
## SafetyBoundary 检查
当候选漏洞带有 [MISSING_DEPTH_BOUND] 标签时：
- 不要寻找注入或数据流路径
- 检查：攻击者能否通过深层嵌套输入（JSON/YAML/XML）触发栈溢出？
- 确认：函数的递归深度是否受调用者控制？
- 验证：尝试构造导致栈溢出的输入（理论分析，不真正执行）
```

### 2.4 预期效果

| 靶场 | 当前 | 预期 |
|------|------|------|
| yaml_src CVE-2026-33532 | ❌ 漏检（0 triggerable） | ✅ 检出 |
| zipp glob.py replace | 已检出 | ✅ 维持 |

---

## 完成状态（2026-05-23）

```
冲刺一（Sourcer 免疫系统）       ✅ 完成
├── 1.1 特征阻断                  ✅ loader.py 添加三道过滤器
│   ├── 特征A: 单行过长 >200      ✅ _is_noise_file 采样前20行
│   ├── 特征B: 文件 >500KB        ✅ os.path.getsize()
│   └── 特征C: *.min.js/vendor    ✅ 命名+路径 pattern 匹配
│
├── 1.2 语言占比调度               ⏸ 暂缓（特征阻断已覆盖核心场景）
│
冲刺二（SafetyBoundary）          ✅ 完成
├── 2.1 递归函数 tree-sitter 标记  ✅ repomap.py: Python 后处理检测
│   └── Director 信号              ✅ signals.py: recursion=30
├── 2.2 Depth Guard 浅层扫描      ✅ sast/bound_checker.py
│   └── Brain 集成                ✅ brain.py: _inject_boundary_candidates
└── 2.3 Verification prompt 增强  ✅ default.yaml: Step 5

冲刺三（认证授权断言体系）         ⏸ 待规划
```

### 变更文件清单

| 文件 | 改动 |
|------|------|
| `engine/sourcer/loader.py` | 新增 `_is_noise_file()` + 3 道过滤器 + `MAX_FILE_SIZE`/`MAX_AVG_LINE_LEN`/`NOISE_NAME_PATTERNS` 常量 |
| `engine/director/repomap.py` | 新增 `_find_recursive_funcs()` + `get_tags_raw` 中调用注入 `@signal.recursion` 标签 |
| `engine/director/signals.py` | 新增 `"recursion": 30` 信号权重 |
| `engine/sast/bound_checker.py` | **新文件** — `check_depth_guard()` + `find_missing_bounds()` |
| `engine/brain.py` | 新增 `_inject_boundary_candidates()` — 在 bulk_analysis 前注入 [MISSING_DEPTH_BOUND] 候选 |
| `engine/prompts/default.yaml` | 新增 Step 5 SafetyBoundary 验证指导 |

### 测试结果

- 586 通过，2 预存失败（与改动无关）
- 0 回归

**目标**：为类型三（认证/授权缺失）铺路。架构级改动，需规划独立阶段。

### 3.1 Mapping Agent 输出 `global_security_rules`

在 Mapping 的 output schema 中新增 `global_security_rules` 字段，LLM 在分析项目结构时输出推断出的安全规则：

```json
{
  "summary": "...",
  "trust_assumptions": [...],
  "global_security_rules": [
    {"rule": "All /api/admin/* routes must call verify_jwt() before processing"},
    {"rule": "All DELETE requests must verify resource ownership"}
  ]
}
```

### 3.2 State 层规则传递

`ProjectState` 新增 `security_rules` 存储，DataFlow Agent 初始化时自动注入相关规则。

### 3.3 DataFlow 反向检验模式

当前 DataFlow 是"追踪路径 → 输出路径"。反向检验模式是：
1. 拿到 entry_point + 关联的 security_rules
2. LLM 收到指令："请证明这个 entry_point 遵守了 security_rules。如果不能证明，报出 IDOR/权限绕过。"
3. 输出中增加 `rule_satisfied: bool | None` 字段

### 3.4 实施建议

**放在单独的 Phase 中实施**，理由：
- Mapping schema 变更影响所有 downstream agent
- DataFlow 行为模式变化（从"探索"到"证伪"）需要新测试套件
- 规则的 LLM 幻觉风险需要评估（LLM 可能编造不存在的规则或遗漏重要规则）

建议先做 3.1（Mapping 只输出规则，不强制消费），验证规则质量后再推进 3.2-3.3。

---

## 优先级总表

```
ID  项                          盲区类型   成本   效果     依赖    建议窗口
─────────────────────────────────────────────────────────────────────
1.1  特征阻断（行/大小/命名）     类型十四    $0    高（根治） 无     现在
1.2  语言占比调度                 类型十四    $0    中        1.1    1.1 之后
2.1  递归函数 tree-sitter 标记    类型四      $0    高        Director 已有  现在
2.2  Depth Guard 浅层扫描         类型四      $0    中        2.1 + matcher.py
2.3  Verification prompt 增强     类型四      $0    低        2.2    配合 2.2
3.1  Mapping 输出 security_rules  类型三      $$$   评估中    无     可并行启动
3.2  State 层规则传递             类型三      $0    前提条件   3.1    3.1 验证后
3.3  DataFlow 反向检验            类型三      $$$   高        3.2    独立 Phase
```

## 与现有 Phase 的关系

```
PROGRESS.md  Phase       本路线图
────────────────────────────────────
Phase 6     Step A 完成  ← 当前基线
            Step B      ← 冲刺一（Sourcer 过滤）
            Step C      ← 冲刺二（SafetyBoundary）
Phase 7     （新）       ← 冲刺三（认证断言体系）
Phase 8     （新）       ← DataFlow 反向检验 + 完整闭环
```

冲刺一和冲刺二属于 Phase 6 的自然延续（多 Agent 引擎的加固）。冲刺三及以上需要新的 Phase。
