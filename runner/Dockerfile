FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY run_full_re.py /app/run_full_re.py

ENTRYPOINT ["python", "/app/run_full_re.py"]
