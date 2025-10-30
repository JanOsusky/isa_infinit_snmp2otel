#include <iostream>
#include <getopt.h>
#include <signal.h>
#include "snmp.hpp"
#include "otel.hpp"
#include "utils.hpp"
#include <thread>
#include <chrono>


volatile bool g_run = true;
void sigint_handler(int) { g_run = false; }

void usage() {
    std::cerr << "Usage: snmp2otel -t target [-C community] -o oids_file -e endpoint [-i interval] [-r retries] [-T timeout] [-p port] [-v] [-m] mapping_file\n";
}

int main(int argc, char **argv) {
    std::string target;
    std::string community = "public";
    std::string oids_file;
    std::string endpoint;
    int interval = 10;
    int retries = 2;
    int timeout_ms = 1000;
    int port = 161;
    bool verbose = false;
    std::string mapping_file;


    int opt;
    while ((opt = getopt(argc, argv, "t:C:o:e:i:r:T:p:m:vh")) != -1) {
        switch (opt) {
            case 't': target = optarg; break;
            case 'C': community = optarg; break;
            case 'o': oids_file = optarg; break;
            case 'e': endpoint = optarg; break;
            case 'i': interval = atoi(optarg); break;
            case 'r': retries = atoi(optarg); break;
            case 'T': timeout_ms = atoi(optarg); break;
            case 'p': port = atoi(optarg); break;
            case 'm': mapping_file = optarg; break;
            case 'v': verbose = true; break;
            default: usage(); return 1;
        }
    }
    if (target.empty() || oids_file.empty() || endpoint.empty()) {
        usage(); return 1;
    }
    if (interval <= 0) interval = 10;
    signal(SIGINT, sigint_handler);

    std::vector<std::string>  oids = load_oids_file(oids_file);
    if (oids.empty()) {
        std::cerr << "[ERROR] No OIDs loaded from " << oids_file << "\n";
        return 1;
    }
   
    std::map<std::string, OIDInfo> mapping;
    if(!mapping_file.empty()) {
        mapping = load_oids_info(mapping_file);
    }

    SNMPClient client(target, port, community, timeout_ms, retries, verbose);
    OTELExporter exporter(endpoint, verbose);

    while (g_run) {
        if (verbose) std::cout << "[INFO] Starting poll cycle\n";
        auto values = client.get(oids);
        if (!values.empty()) {
            exporter.export_gauge(values, mapping);
        } else {
            if (verbose) std::cout << "[WARNING] No values returned in this cycle\n";
        }
        for (int i=0;i<interval && g_run;++i) std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    if (verbose) std::cout << "[INFO] Exiting\n";
    return 0;
}
