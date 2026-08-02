# GuardianOS-AI container (Linux target)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# The MVP runs dry-run safe: no destructive action executes without approval.
CMD ["python", "scripts/run_mvp.py"]
