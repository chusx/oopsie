FROM python:3.12-alpine
WORKDIR /app
COPY runner.py checks.py /app/
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 65534:65534
CMD ["python", "/app/runner.py"]
