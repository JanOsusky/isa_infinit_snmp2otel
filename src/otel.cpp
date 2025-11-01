#include "otel.hpp"
#include <sstream>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <httplib.h>
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

bool OTELExporter::http_post(const std::string &host, int port,
                             const std::string &path,
                             const std::string &body) {

    httplib::Client cli(host, port);
    cli.set_keep_alive(false);

    auto res = cli.Post(path.c_str(),
                        body,
                        "application/json");

    if (!res) {
        if (verbose_) std::cerr << "[ERROR] HTTP request failed (network)\n";
        return false;
    }

    if (verbose_) {
        std::cout << "[DEBUG] HTTP status: " << res->status << "\n";
        std::cout << "[DEBUG] Response: " << res->body << "\n";
    }

    return (res->status >= 200 && res->status < 300);
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