#pragma once
#include <string>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>

namespace metrics {

inline std::string statsd_host() {
    const char* h = std::getenv("STATSD_HOST");
    return h ? std::string(h) : "telegraf";
}

inline int statsd_port() {
    const char* p = std::getenv("STATSD_PORT");
    return p ? std::atoi(p) : 8125;
}

inline void send_statsd(const std::string& msg) {
    std::string host = statsd_host();
    std::string port = std::to_string(statsd_port());

    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0 || !res) {
        return;
    }

    for (addrinfo* p = res; p; p = p->ai_next) {
        int sock = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock < 0) continue;

        ::sendto(sock, msg.data(), msg.size(), 0, p->ai_addr, p->ai_addrlen);
        ::close(sock);
        break;
    }

    freeaddrinfo(res);
}

inline void track_request(const std::string& route,
                          int status_code,
                          std::size_t body_size)
{
    std::fprintf(stderr,
                 "[pw_metrics] route=%s status=%d body=%zu\n",
                 route.c_str(), status_code, body_size);

    std::fflush(stderr);
    {
        std::string m = "pw_requests,route=" + route +
                        ",status=" + std::to_string(status_code) +
                        ":1|c";
        send_statsd(m);
    }
    {
        std::string m = "pw_requests_total,route=" + route + ":1|c";
        send_statsd(m);
    }
    {
        std::string m = "pw_payload_bytes,route=" + route +
                        ",status=" + std::to_string(status_code) +
                        ":" + std::to_string(static_cast<long long>(body_size)) +
                        "|g";
        send_statsd(m);
    }
}

} // namespace metrics
