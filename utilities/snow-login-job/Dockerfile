FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

# Run as a non-root user
RUN useradd -r -u 1000 appuser
USER appuser

CMD ["python", "main.py"]