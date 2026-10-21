# ARTEX container image
#
# Runs under gunicorn instead of `python app.py`, so the Werkzeug debugger
# (debug=True in app.py) is never enabled. Scan state lives in process memory,
# so gunicorn must run a single worker; concurrency comes from threads.
#
# Build: docker build -t artex .
# Run:   docker run --rm -p 8000:8000 -e GROQ_API_KEY=... artex

FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# nmap is used for TCP connect scans (-sT), which need no extra capabilities.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install -r requirements.txt gunicorn==23.0.0

COPY app.py ./
COPY core/ core/
COPY modules/ modules/
COPY utils/ utils/
COPY templates/ templates/

RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin artex
USER 10001

EXPOSE 8000

CMD ["gunicorn", "app:app", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "1", \
     "--threads", "8", \
     "--timeout", "120", \
     "--worker-tmp-dir", "/dev/shm"]
