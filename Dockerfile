
FROM python:3.12-slim

WORKDIR /app

COPY network_scanner.py .

ENTRYPOINT ["python", "network_scanner.py"]
