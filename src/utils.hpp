#pragma once
#include <string>
#include <vector>
#include <map>

struct OIDInfo {
    std::string name;
    std::string unit;
    std::string type; // gauge
};

std::vector<std::string> load_oids_file(const std::string &path);
std::map<std::string, OIDInfo> load_mapping_json(const std::string &path); // minimal stub; optional
uint64_t now_unix_nano();
std::string oid_to_name(const std::string &oid, const std::map<std::string, OIDInfo> &mapping);
