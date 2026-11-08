FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements-gateway.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && useradd --uid 10001 --create-home --shell /usr/sbin/nologin czts
EXPOSE 2222
USER 10001:10001
CMD ["python", "-m", "czt.gateway.server"]
