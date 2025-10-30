#include "otel.hpp"
#include <sstream>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <nlohmann/json.hpp>

OTELExporter::OTELExporter(const std::string &endpoint, bool verbose)
: endpoint_(endpoint), verbose_(verbose) {}

bool OTELExporter::parse_endpoint(const std::string &endpoint, std::string &host, int &port, std::string &path) {
    // support: http://host:port/path
    if (endpoint.rfind("http://",0) != 0) {
        if (verbose_) std::cout << "[WARNING] Only http:// endpoints supported in this implementation\n";
        return false;
    }
    size_t p = 7;
    size_t slash = endpoint.find('/', p);
    std::string hostport = (slash==std::string::npos) ? endpoint.substr(p) : endpoint.substr(p, slash - p);
    path = (slash==std::string::npos) ? "/" : endpoint.substr(slash);
    size_t colon = hostport.find(':');
    if (colon==std::string::npos) {
        host = hostport;
        port = 80;
    } else {
        host = hostport.substr(0, colon);
        port = std::stoi(hostport.substr(colon+1));
    }
    return true;
}

bool OTELExporter::http_post(const std::string &host, int port, const std::string &path, const std::string &body) {
    struct addrinfo hints{}, *res=nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int rc = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res);
    if (rc!=0) { if (verbose_) std::cerr << "[ERROR] getaddrinfo: " << gai_strerror(rc) << "\n"; return false; }
    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) { freeaddrinfo(res); if (verbose_) perror("socket"); return false; }
    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) { freeaddrinfo(res); close(sock); if (verbose_) perror("connect"); return false; }
    std::ostringstream req;
    req << "POST " << path << " HTTP/1.1\r\n";
    req << "Host: " << host << "\r\n";
    req << "User-Agent: snmp2otel/1.0\r\n";
    req << "Content-Type: application/json\r\n";
    req << "Content-Length: " << body.size() << "\r\n";
    req << "Connection: close\r\n\r\n";
    req << body;
    std::string reqs = req.str();
    ssize_t sent = send(sock, reqs.data(), reqs.size(), 0);
    if (sent < 0) { if (verbose_) perror("send"); close(sock); freeaddrinfo(res); return false; }
    // read response (but don't need full body)
    char buf[4096];
    ssize_t r = recv(sock, buf, sizeof(buf)-1, 0);
    if (r <= 0) { if (verbose_) perror("recv"); close(sock); freeaddrinfo(res); return false; }
    buf[r]=0;
    std::string resp(buf);
    if (verbose_) std::cerr << "[DEBUG] HTTP response start: " << resp.substr(0, std::min<size_t>(resp.size(),200)) << "\n";
    // parse status code
    if (resp.rfind("HTTP/1.",0)==0) {
        size_t sp = resp.find(' ');
        if (sp!=std::string::npos) {
            size_t sp2 = resp.find(' ', sp+1);
            if (sp2!=std::string::npos) {
                int code = atoi(resp.substr(sp+1, sp2-sp-1).c_str());
                close(sock); freeaddrinfo(res);
                return (code >= 200 && code < 300);
            }
        }
    }
    close(sock); freeaddrinfo(res);
    return false;
}

bool OTELExporter::export_gauge(
    const std::map<std::string, SNMPResult> &values,
    const std::map<std::string, OIDInfo> &mapping) 
{
    uint64_t ts = now_unix_nano();
    nlohmann::json metrics = nlohmann::json::array();

    for (const auto &kv : values) {
        const std::string &oid = kv.first;
        const SNMPResult &v = kv.second;

        const auto item = mapping.find(oid);
        std::string name = (item != mapping.end()) ? item->second.name : oid;
        std::string unit = (item != mapping.end()) ? item->second.unit : "";

        nlohmann::json dp; // datapoint
        dp["timeUnixNano"] = ts;
        dp["Int"] = v.value; // integer value

        nlohmann::json metric;
        metric["name"] = name;
        metric["unit"] = unit;
        metric["gauge"]["dataPoints"] = nlohmann::json::array({dp});

        metrics.push_back(metric);
    }

    nlohmann::json body;
    body["resourceMetrics"] = {
        {
            {"resource", {}},
            {"scopeMetrics", {{
                {"scope", {}},
                {"metrics", metrics}
            }}}
        }
    };

    std::string body_str = body.dump(); // compact JSON string

    if (verbose_) std::cout << "[DEBUG] OTLP JSON:\n" << body.dump(2) << "\n";

    std::string host; int port; std::string path;
    if (!parse_endpoint(endpoint_, host, port, path)) {
       if(verbose_) std::cerr << "[ERROR] Unsupported endpoint format\n";
        return false;
    }

    bool ok = http_post(host, port, path, body_str);
    if (!ok)
        if (verbose_) std::cerr << "[ERROR] Export failed for endpoint " << endpoint_ << "\n";

    return ok;
}