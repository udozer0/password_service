FROM ubuntu:24.04 AS build

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    ninja-build \
    git \
    pkg-config \
    libsodium-dev \
    libboost-dev \
    libboost-program-options-dev \
    libgtest-dev \
    nlohmann-json3-dev \
    && rm -rf /var/lib/apt/lists/*


WORKDIR /tmp

# RapidJSON
RUN git clone https://github.com/Tencent/rapidjson.git  \
 && cmake -S rapidjson -B rapidjson/build \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/usr/local \
      -DRAPIDJSON_BUILD_TESTS=OFF \
      -DRAPIDJSON_BUILD_EXAMPLES=OFF \
      -DRAPIDJSON_BUILD_DOC=OFF \
      -DRAPIDJSON_BUILD_THIRDPARTY_GTEST=OFF \
    && cmake --build rapidjson/build --target install


# cppgraphqlgen + сабмодули, без тестов и примеров
RUN git clone --recursive https://github.com/microsoft/cppgraphqlgen.git \
 && cmake -S cppgraphqlgen -B cppgraphqlgen/build \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/usr/local \
      -DBUILD_TESTS=OFF \
      -DCPPGRAPHQLGEN_INSTALL_EXAMPLES=OFF \
 && cmake --build cppgraphqlgen/build --target install

WORKDIR /src
COPY CMakeLists.txt /src/
COPY src/ /src/src/
COPY include/ /src/include/
COPY graphql/ /src/graphql/
COPY third_party/ /src/third_party/
COPY web/ /src/web/

RUN mkdir -p /data

RUN cmake -S /src -B /src/build -G Ninja \
 && cmake --build /src/build
WORKDIR /src/build
ENV MASTER_PASSWORD=changeme
EXPOSE 8000
CMD ["./password_service"]
