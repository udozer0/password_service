FROM ubuntu:24.04 AS build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git wget pkg-config libsodium-dev ca-certificates ninja-build \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY CMakeLists.txt /src/
COPY src/ /src/src/

RUN cmake -S /src -B /src/build -G Ninja && cmake --build /src/build

FROM ubuntu:24.04 AS runtime

RUN apt-get update && apt-get install -y libsodium23 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /src/build/password_service /app/password_service

VOLUME ["/data"]

ENTRYPOINT ["/app/password_service"]

