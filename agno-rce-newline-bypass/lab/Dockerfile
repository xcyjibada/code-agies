FROM python:3.11-slim

WORKDIR /app

# 安装 agno（从源码）
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/agno-agi/agno /tmp/agno
RUN pip install -e /tmp/agno/libs/agno

# 安装 FastAPI
RUN pip install fastapi uvicorn jinja2

# 复制应用代码
COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
