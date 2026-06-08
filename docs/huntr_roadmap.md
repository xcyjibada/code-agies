# huntr 路线图 — agies 真实漏洞检测能力提升

日期：2026-06-08

## P0：后期重分类 — Logic Agent 输出 actual_vuln_type

**问题**：PoC Agent 收到的 vuln_type 来自 sink 分类（如 `open` → LFI），导致 PoC 写错方向。
zipp 的 CVE-2024-5569（无限循环 DoS）被写成读 `/etc/passwd` 的路径遍历 PoC。

**方案**：Logic Agent 在 contradictions 之外，额外输出 `actual_vuln_type`，
让 LLM 根据完整代码链自由判断漏洞类型。PoC Agent 用这个字段替代原始 sink 分类。

**改动范围**：
- `agies/engine/v3/agents/logic_agent.py` — prompt 输出格式 + `run()` 返回字段
- `agies/engine/v3/aggregator/models.py` — `AgentPhaseResult` 增加 `actual_vuln_type`
- `agies/engine/v3/agents/poc_agent.py` — 接收 `actual_vuln_type` 替代 `vuln_type`
- `agies/engine/v3/agents/adversary_agent.py` — 同样接收 `actual_vuln_type`

**验证方式**：zipp 回归测试，确认 PoC 显示 DoS/infinite loop 而非路径遍历。

---

## P1：ML 漏洞检测扩展

**问题**：sink_patterns.py 只有 pickle/cloudpickle，完全没有 ML 框架感知。
PyTorch、HuggingFace、safetensors、ONNX、joblib 等 ML 特定 sink 全部盲区。

**方案**：新建 `agies/engine/v3/rules/ml/` 可插拔模块。

### ML sink patterns 需要覆盖：

```python
# PyTorch
("torch.load", VulnType.RCE),
("torch.hub.load", VulnType.RCE),
("torch.hub.download_url_to_file", VulnType.SSRF),
# HuggingFace
("transformers.pipeline", VulnType.RCE),
("AutoModel.from_pretrained", VulnType.RCE),
("AutoModelForSequenceClassification.from_pretrained", VulnType.RCE),
("pipeline", VulnType.RCE),
# safetensors（不是 pickle，但文件路径可被操控）
("safetensors.torch.load_file", VulnType.AFO),
# ONNX
("onnxruntime.InferenceSession", VulnType.RCE),
# joblib / skops（ML 模型序列化）
("joblib.load", VulnType.RCE),
("skops.load", VulnType.RCE),
# MLflow 自身
("mlflow.pyfunc.load_model", VulnType.RCE),
("mlflow.pytorch.load_model", VulnType.RCE),
("mlflow.huggingface.load_model", VulnType.RCE),
# TensorFlow / Keras
("tf.keras.models.load_model", VulnType.RCE),
("tensorflow.keras.models.load_model", VulnType.RCE),
```

### ML 专用 prompt 模板：
- `prompts/model_poisoning.py` — 模型投毒检测
- `prompts/prompt_injection.py` — Prompt 注入检测  
- `prompts/weights_theft.py` — 权重文件泄露
- `prompts/training_data_leakage.py` — 训练数据泄露

### 文件结构：
```
agies/engine/v3/rules/ml/
├── __init__.py
├── sinks_ml.py         # ML sink patterns + classify_ml_sink()
├── prompts_ml.py       # ML 专用 prompt 注册
└── examples/           # 参考 CVE 用例
```

---

## P2：CodeQL 数据流追踪

**问题**：tree-sitter 只能追"谁调用了谁"，不能回答"用户输入是否到达 sink"。
Lib mode 下几百条 SUSPICIOUS 路径被 rebutted 为"无外部输入"就是因为没有数据流证据。

**方案**：落地 CodeQL 查询，回答精确的 source→sink 数据流。

### 需要写的 QL 查询（每个漏洞类型一条）：
```
codeql_queries/
├── mlflow_unzip_path_traversal.ql
├── mlflow_pip_injection.ql
├── mlflow_exec_in_scorer.ql
├── generic_pickle_deserialize.ql
├── generic_path_traversal.ql
└── zipp_infinite_loop.ql     # CVE-2024-5569 专用
```

### QL 可以做到而 tree-sitter 做不到的事：
1. 追踪参数是否来自用户输入（HTTP request、CLI args、文件上传）
2. 检测 sanitizer 是否存在（`os.path.realpath`、`is_safe_path`）
3. 检测 sanitizer bypass（先 sanitize 后拼接、条件竞争）
4. 跨文件、跨模块数据流

### 前提：
- 需要安装 CodeQL CLI（约 200MB）
- 需要为每个项目类型写 QL 查询
- CodeQL 不能"发现未知漏洞"，只能验证已知模式

---

## 依赖关系

```
P0（重分类）→ 独立，无依赖
P1（ML 扩展）→ 独立，可并行
P2（CodeQL）→ 需要先知道要找什么（P0+P1 的产出驱动 QL 查询）
```

## 当前进度

- [ ] P0：后期重分类
- [ ] P1：ML 漏洞检测扩展
- [ ] P2：CodeQL 数据流追踪
