#pragma once
#include <string>
#include <map>
#include "snmp.hpp"
#include "utils.hpp"

class OTELExporter {
public:
    OTELExporter(const std::string &endpoint, bool verbose=false);
    bool export_gauge(const std::map<std::string, SNMPValue> &values,
                      const std::map<std::string, OIDInfo> &mapping);
private:
    std::string endpoint_;
    bool verbose_;
    bool http_post(const std::string &host, int port, const std::string &path, const std::string &body);
    bool parse_endpoint(const std::string &endpoint, std::string &host, int &port, std::string &path);
};
