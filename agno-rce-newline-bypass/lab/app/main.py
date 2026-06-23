"""
FastAPI Web 服务 — agno RCE 漏洞演示

运行方式：
  cd lab
  docker-compose up

或者本地运行：
  pip install fastapi uvicorn
  uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

然后访问 http://localhost:8000
需要设置 OPENAI_API_KEY 环境变量
"""
import os
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

from app.agent_service import analyze_external_content

app = FastAPI(title="agno RCE Demo")

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

FLAG_PATH = Path("/app/workspace/FLAG.txt")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """主页面 — 粘贴外部内容给 agent 分析"""
    flag_exists = FLAG_PATH.exists()
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "result": None,
            "flag": flag_exists,
            "api_key_set": bool(os.environ.get("OPENAI_API_KEY")),
        },
    )


@app.post("/analyze", response_class=HTMLResponse)
async def analyze(request: Request, content: str = Form(...)):
    """处理用户提交的外部内容"""
    flag_exists_before = FLAG_PATH.exists()

    try:
        result = analyze_external_content(content)
    except Exception as e:
        result = f"[!] Agent 调用出错: {e}"

    flag_exists_after = FLAG_PATH.exists()
    rce_success = flag_exists_after and not flag_exists_before

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "result": result,
            "flag": flag_exists_after,
            "rce_success": rce_success,
            "api_key_set": bool(os.environ.get("OPENAI_API_KEY")),
        },
    )
