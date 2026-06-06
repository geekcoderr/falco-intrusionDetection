FROM python:3.9-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    netcat-openbsd openssh-client iptables procps curl iproute2 \
    && rm -rf /var/lib/apt/lists/*
RUN pip install flask requests
COPY app.py index.html ./
EXPOSE 5000
CMD ["python", "app.py"]
