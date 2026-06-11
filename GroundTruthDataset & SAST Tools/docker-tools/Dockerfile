FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Installazione dipendenze di base
RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    openjdk-17-jdk golang-go \
    curl unzip wget git docker.io \
    && rm -rf /var/lib/apt/lists/*

# Installazione dipendenze Python
RUN pip3 install trueseeing --break-system-packages

# Installazione jadx
RUN curl -L -O https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip && \
    unzip jadx-1.5.0.zip -d /opt/jadx && rm jadx-1.5.0.zip
ENV PATH="$PATH:/opt/jadx/bin"

# Installazione dex2jar
RUN curl -L -O https://github.com/pxb1988/dex2jar/releases/download/v2.4/dex-tools-v2.4.zip && \
    unzip dex-tools-v2.4.zip -d dex2jar && \
    rm -f dex-tools-v2.4.zip && \
    mv dex2jar /usr/local/bin/dex2jar && \
    chmod +x /usr/local/bin/dex2jar/dex-tools-v2.4/*.sh && \
    ln -s /usr/local/bin/dex2jar/dex-tools-v2.4/d2j-dex2jar.sh /usr/local/bin/d2j-dex2jar

# Crea il mount point per il volume condiviso con SEBASTiAn
RUN mkdir -p /shared

WORKDIR /app
COPY ./APKHunt /app/APKHunt
COPY RunningScript.sh AddToCSV.py ToolParser.py GenerateMetricsCSV.py /app/
RUN chmod +x /app/*.sh /app/*.py /app/APKHunt/*
