FROM python:3.12-slim
ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends tcpdump tshark \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir pyshark==0.6
WORKDIR /app
COPY analyze.py .
CMD ["python", "analyze.py"]
