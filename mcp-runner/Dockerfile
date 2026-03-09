FROM python:3.12-slim

WORKDIR /app
COPY mcp-runner/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY mcp-runner/*.py /app/
COPY mcp-runner/*.sh /app/
RUN chmod +x /app/*.sh
ENTRYPOINT ["bash", "/app/run_full_analysis.sh"]
