#include "utils.hpp"
#include <fstream>
#include <sstream>
#include <chrono>
#include <algorithm>
#include <iostream>


std::vector<std::string> load_oids_file(const std::string &path) {
    std::vector<std::string> oids;
    std::ifstream f(path);
    if (!f) return oids;
    std::string line;
    while (std::getline(f, line)) {
        // trim
        while (!line.empty() && isspace((unsigned char)line.back())) line.pop_back();
        size_t i=0; while (i<line.size() && isspace((unsigned char)line[i])) ++i;
        if (i>0) line = line.substr(i);
        if (line.empty()) continue;
        if (line[0]=='#') continue;
        oids.push_back(line);
    }
    return oids;
}

// Minimal JSON mapping stub (no external libs). Expects exact format with simple fields.
// If the file is missing or invalid, return empty map.
#include <cstdio>
std::map<std::string, OIDInfo> load_mapping_json(const std::string &path) {
    // For safety: return empty - implement later if needed
    (void)path;
    return {};
}

uint64_t now_unix_nano() {
    using namespace std::chrono;
    return (uint64_t)duration_cast<nanoseconds>(system_clock::now().time_since_epoch()).count();
}

std::string oid_to_name(const std::string &oid, const std::map<std::string, OIDInfo> &mapping) {
    auto it = mapping.find(oid);
    if (it != mapping.end() && !it->second.name.empty()) return it->second.name;
    return "snmp." + oid;
}
