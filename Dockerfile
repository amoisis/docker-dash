FROM python:3.14-slim
WORKDIR /app

COPY ./src .
RUN pip install --no-cache-dir -r requirements.txt

# Expose the web UI port
EXPOSE 3445

# Health check to ensure service is running
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:3445/').read()" || exit 1

CMD ["python", "main.py"]
