FROM eclipse-temurin:21-jdk

ARG GHIDRA_VERSION=12.0.4
ARG GHIDRA_TAG=Ghidra_12.0.4_build
ARG GHIDRA_ZIP_NAME=ghidra_12.0.4_PUBLIC_20260303.zip
ARG GHIDRA_ZIP_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/${GHIDRA_TAG}/${GHIDRA_ZIP_NAME}

ARG GHIDRASSIST_MCP_RELEASE=2.3.0
ARG GHIDRASSIST_MCP_ZIP=ghidra_12.0_PUBLIC_20260307_GhidrAssistMCP.zip
ARG GHIDRASSIST_MCP_URL=https://github.com/symgraph/GhidrAssistMCP/releases/download/${GHIDRASSIST_MCP_RELEASE}/${GHIDRASSIST_MCP_ZIP}

ENV DEBIAN_FRONTEND=noninteractive \
    GHIDRA_INSTALL_DIR=/opt/ghidra \
    HOME=/tmp/ghidra \
    GHIDRA_USER_HOME=/tmp/ghidra \
    GHIDRA_USER_EXTENSIONS_DIR=/root/.config/ghidra/ghidra_12.0.4_PUBLIC/Extensions

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN curl -fL "${GHIDRA_ZIP_URL}" -o /tmp/ghidra.zip \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" "${GHIDRA_INSTALL_DIR}" \
    && rm -f /tmp/ghidra.zip

# Install prebuilt GhidrAssistMCP extension into Ghidra user extensions
RUN mkdir -p "${GHIDRA_USER_EXTENSIONS_DIR}" \
    && curl -fL "${GHIDRASSIST_MCP_URL}" -o /tmp/ghidrassistmcp.zip \
    && unzip -q /tmp/ghidrassistmcp.zip -d "${GHIDRA_USER_EXTENSIONS_DIR}" \
    && rm -f /tmp/ghidrassistmcp.zip

# Add script wrappers and custom hold script
RUN mkdir -p /opt/ghidra_scripts
COPY GhidrAssistMCP/src/main/java/ghidrassistmcp/scripts/GAMCPStartServerScript.java /opt/ghidra_scripts/GAMCPStartServerScript.java
COPY mcp-headless/scripts/HoldMcpServerScript.java /opt/ghidra_scripts/HoldMcpServerScript.java

COPY mcp-headless/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /
ENTRYPOINT ["/entrypoint.sh"]
