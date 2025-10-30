#include "utils.hpp"
#include <fstream>
#include <sstream>
#include <chrono>
#include <algorithm>
#include <iostream>
#include <nlohmann/json.hpp>


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


std::map<std::string, OIDInfo> oad_oids_info(const std::string &file) {
    std::map<std::string, OIDInfo> mapping;
    std::ifstream map_file(file);
    if (!in) {
        std::cerr << "[ERROR] Cannot open mapping file: " << file << "\n";
        return false;
    }

    nlohmann::json j;
    try {
        map_file >> j;
    } catch () {
        std::cerr << "[ERROR] Invalid JSON in mapping file\n";
        return false;
    }

    for (auto &item : j.items()) {
        OIDInfo info;
        info.name = item.value().value("name", it.key()); 
        info.unit = item.value().value("unit", "");
        info.type = item.value().value("type", "gauge");
        mapping[item.key()] = info;
    }
    return mapping;
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

std::string getOIDtoString(netsnmp_variable_list * vars) {
    std::string oid;
    for(size_t i = 0; i < vars->name_length; i++)
    {
        if (i>0) oid += ".";
        oid += std::to_string(vars->name[i]);
    }
    return oid;
}