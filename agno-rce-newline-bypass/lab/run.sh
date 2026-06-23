#!/bin/bash
# 不使用 Docker 直接运行（需要先安装 agno）
# 确保 OPENAI_API_KEY 已设置

set -e

if [ -z "$OPENAI_API_KEY" ]; then
    echo "请先设置 OPENAI_API_KEY"
    echo "  export OPENAI_API_KEY='sk-...'"
    exit 1
fi

# 检查 agno 是否已安装
python3 -c "from agno.tools.coding import CodingTools" 2>/dev/null || {
    echo "需要安装 agno。先 cd 到 agno 源码目录并 pip install -e ."
    exit 1
}

pip install -q fastapi uvicorn jinja2 2>/dev/null

echo "[*] 启动 agno RCE 演示服务..."
echo "[*] 访问 http://localhost:8000"
echo "[*] 按 Ctrl+C 停止"
echo ""

OPENAI_API_KEY="$OPENAI_API_KEY" uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
