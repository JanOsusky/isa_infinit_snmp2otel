#pragma once
#include <string>
#include <vector>
#include <map>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

// Struct holding the key information from SNMP response
struct SNMPResult {
    std::string name;
    std::string oid;
    int value;
};

// Client 
class SNMPClient {
public:
    SNMPClient(const std::string &target, int port, const std::string &community,
               int timeout_ms, int retries, bool verbose=false);
    ~SNMPClient();
    // Performs a GET for a list of scalar OIDs (e.g. "1.3.6.1.2.1.1.3.0")
    // returns map oid -> SNMPResult for values successfully decoded
    std::map<std::string, SNMPResult> get(const std::vector<std::string> &oids);

private:
    std::string target_;
    int port_;
    std::string community_;
    int timeout_ms_;
    int retries_;
    bool verbose_;
    // Variables required by net-snmp
    struct snmp_session session_, *ss_;
    struct snmp_pdu *pdu_;
    struct snmp_pdu *response_;
    struct variable_list *vars_;
           
    oid anOID_[MAX_OID_LEN]; 
    size_t anOID_len_ = MAX_OID_LEN;
   
   int status_;
    void init_net_snmp();
};
