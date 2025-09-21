# g++가 포함된 Debian 기반 이미지
FROM gcc:14

# 작업 디렉토리 설정
WORKDIR /app

# OpenSSL 개발 라이브러리 설치
RUN apt-get update && apt-get install -y libssl-dev

# 'src' 디렉토리의 모든 소스 코드를 컨테이너의 'src' 디렉토리로 복사
COPY src ./src

# 서버와 클라이언트 컴파일
# -I./src: 컴파일러가 'src' 디렉토리에서 헤더 파일(utils.hpp)을 찾도록 경로를 추가
# src/utils.cpp: server.cpp와 client.cpp가 공통으로 사용하는 유틸리티 코드를 함께 컴파일
# -lssl -lcrypto: 컴파일된 코드에 OpenSSL 라이브러리를 링크
RUN g++ -I./src src/server.cpp src/utils.cpp -o server -lssl -lcrypto && \
    g++ -I./src src/client.cpp src/utils.cpp -o client -lssl -lcrypto