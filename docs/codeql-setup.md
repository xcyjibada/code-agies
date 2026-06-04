# CodeQL CLI 安装手册

> 用于 agies v3 `--v3` 管线的 CodeQL CLI + QL 查询库安装。

## 前提

- Linux amd64
- `curl`、`unzip` 已安装

## 安装步骤

```bash
cd /home/xcy/workSpace

# 1. 下载 CodeQL CLI v2.25.5
curl -L -o codeql-linux64.zip \
  "https://github.com/github/codeql-cli-binaries/releases/download/v2.25.5/codeql-linux64.zip"

# 2. 解压
unzip codeql-linux64.zip -d /home/xcy/workSpace/codeql/
rm codeql-linux64.zip

# 3. 验证
/home/xcy/workSpace/codeql/codeql/codeql --version

# 4. 加入 PATH（持久化到 bashrc）
echo 'export PATH="/home/xcy/workSpace/codeql/codeql:$PATH"' >> ~/.bashrc
source ~/.bashrc

# 5. 验证 PATH
which codeql && codeql --version
```

## 安装 QL 标准库（首次运行自动装）

不需要手动下载。首次 `agies audit --v3` 时会自动执行：

```bash
codeql pack install --search-path /home/xcy/workSpace/code-agies/agies/engine/v3/codeql/queries
```

这会安装 `codeql/python-all` 库。之后都是缓存。

## 测试

### 1. 手动测 CodeQL 建库

```bash
codeql database create --language=python /tmp/test-codeql-db --source-root /tmp/bounty_test/zipp_src
```

### 2. 测 agies v3 管线

```bash
cd /home/xcy/workSpace/code-agies
agies audit /tmp/bounty_test/zipp_src --v3
```

### 3. 测一个简单项目

```bash
mkdir -p /tmp/test-vuln && cat > /tmp/test-vuln/app.py << 'PYEOF'
import subprocess

def run_command(user_input):
    result = subprocess.check_output(user_input, shell=True)
    return result

def read_file(path):
    with open(path) as f:
        return f.read()

def fetch_url(url):
    import requests
    return requests.get(url)

def execute_code(code):
    exec(code)
PYEOF

agies audit /tmp/test-vuln --v3
```

预期输出：找到 3 个 sink（`subprocess.check_output`、`open`、`exec`）+ 可选的数据流路径。

## 文件结构

安装后：

```
/home/xcy/workSpace/
├── codeql/
│   └── codeql/              # CodeQL CLI 目录
│       ├── codeql            # 主二进制
│       ├── lib/              # QL 库缓存
│       └── ...
├── code-agies/
│   └── agies/engine/v3/
│       └── codeql/queries/   # agies 内置 QL 查询
│           ├── rce.ql
│           ├── lfi.ql
│           ├── ssrf.ql
│           ├── sqli.ql
│           ├── xss.ql
│           └── rce_dataflow.ql
```

## 版本说明

当前硬编码版本：`v2.25.5`（2025-06 最新稳定版）。

如果需要更新版本，修改 `agies/engine/graph/codeql.py` 中 `ensure_installed()` 的 URL 版本号，以及 `agies/engine/v3/codeql/queries/qlpack.yml` 中的 `codeql/python-all`。
