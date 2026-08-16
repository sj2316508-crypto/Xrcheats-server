# Bypass API

Render-ready FastAPI service for resolving supported short links.

## Run locally

```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

## Proxy configuration

Cloud hosts can be blocked by link shortener providers. The resolver supports
Webshare's `host:port:username:password` format.

For local development, copy `proxies.example.txt` to `proxies.txt`, add the
proxy lines, and set:

```bash
export BYPASS_PROXY_FILE=proxies.txt
```

For Render, do not commit the real proxy file. Set the secret environment
variable `BYPASS_PROXIES` to the ten proxy lines, one per line. The resolver
rotates one proxy per attempt without printing credentials.

## Render

Set the service Root Directory to `bypass-api`. The included `render.yaml`
contains the build, start, and health-check configuration.

## Endpoints

- `GET /health`
- `GET /api?bypass=<shortlink>`
- `GET /bypass?url=<shortlink>`
- `POST /bypass` with `{"url": "..."}`
- `GET /job?id=<job_id>`