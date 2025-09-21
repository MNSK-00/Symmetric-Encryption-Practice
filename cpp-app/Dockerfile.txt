# g++가 포함된 Debian 기반 이미지
FROM gcc:14

WORKDIR /app

# 3DES 구현용 OpenSSL 헤더/라이브러리
RUN apt-get update && apt-get install -y --no-install-recommends libssl-dev

COPY src ./src

RUN g++ src/server.cpp src/KeyIO.cpp src/TextIO.cpp -lcrypto -o server \
 && g++ src/client.cpp src/KeyIO.cpp src/TextIO.cpp -lcrypto -o client