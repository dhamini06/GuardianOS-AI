# GuardianOS-AI container image (build from the repository root).
#   docker build -f packaging/Dockerfile -t guardian-os-ai:0.1.0 .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GUARDIAN_DATA_DIR=/var/lib/guardian-os

WORKDIR /opt/guardian-os

RUN mkdir -p /var/lib/guardian-os

COPY requirements.txt pyproject.toml README.md ./
COPY backend ./backend
COPY scripts ./scripts

RUN pip install --no-cache-dir -r requirements.txt \
 && pip install --no-cache-dir --no-deps .

USER nobody
EXPOSE 8000

CMD ["guardian-server", "--host", "0.0.0.0", "--port", "8000", "--auth"]
