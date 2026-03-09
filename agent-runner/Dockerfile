FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY structure-engine/requirements.txt structure-engine/
COPY agent-runner/requirements.txt agent-runner/
RUN pip install --no-cache-dir \
    -r structure-engine/requirements.txt \
    -r agent-runner/requirements.txt

# Copy source code
COPY structure-engine/ structure-engine/
COPY agent-runner/ agent-runner/
COPY mcp-runner/run_mcp_analysis.py mcp-runner/

# Create output directories
RUN mkdir -p /reports/game-sdk /samples

ENV PYTHONUNBUFFERED=1
ENV MCP_BASE=http://ghidrassist-mcp:8080

CMD ["python", "-m", "agent-runner.autonomous_analyzer"]
