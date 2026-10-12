FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

RUN useradd --create-home --uid 10001 app && chown -R app /app
USER app

ENV PORT=8000
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os,urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ.get('PORT','8000'), timeout=4).status == 200 else 1)"

# Single process on purpose: the background job worker runs inside the app.
# FORWARDED_ALLOW_IPS: which proxies may set X-Forwarded-For (client IPs feed the login/report rate limits).
# "*" suits platforms whose proxy addresses vary (Render); set your proxy's address when you run the image yourself.
ENV FORWARDED_ALLOW_IPS="*"
CMD ["sh", "-c", "uvicorn threatdesk.main:app --host 0.0.0.0 --port ${PORT} --workers 1 --proxy-headers --forwarded-allow-ips=\"${FORWARDED_ALLOW_IPS}\""]
