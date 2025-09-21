FROM python:3.12-slim

WORKDIR /app

# pycryptodome 설치
RUN pip install --no-cache-dir pycryptodome

COPY app ./app