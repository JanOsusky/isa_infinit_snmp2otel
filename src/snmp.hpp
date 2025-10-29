#pragma once
#include <string>
#include <vector>
#include <map>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>



struct SNMPValue {
    // support two simple types: INTEGER (as int64) and OCTET STRING (as string)
    bool isInt;
    int64_t intVal;
    std::string strVal;
     //std::string name;
    //int value; 
};

struct SNMPResult {
    std::string name;
    std::string oid;
    int value;
};

class SNMPClient {
public:
    SNMPClient(const std::string &target, int port, const std::string &community,
               int timeout_ms, int retries, bool verbose=false);
    ~SNMPClient();
    // Performs a GET for a list of scalar OIDs (e.g. "1.3.6.1.2.1.1.3.0")
    // returns map oid -> SNMPValue for values successfully decoded
    std::map<std::string, SNMPResult> get(const std::vector<std::string> &oids);

private:
    std::string target_;
    int port_;
    std::string community_;
    int timeout_ms_;
    int retries_;
    bool verbose_;

    struct snmp_session session_, *ss_;
    struct snmp_pdu *pdu_;
    struct snmp_pdu *response_;
    struct variable_list *vars_;
           
    oid anOID_[MAX_OID_LEN]; // TODO: redefine, quick error fix
    size_t anOID_len_ = MAX_OID_LEN;
   
   int status_;
    // helpers for BER encoding/decoding
    static std::vector<uint8_t> ber_encode_get_request(int request_id,
            const std::string &community, const std::vector<std::string> &oids);
    static bool ber_decode_response(const std::vector<uint8_t> &resp, std::map<std::string, SNMPValue> &out);

    // low-level UDP send/recv
    bool send_and_receive(const std::vector<uint8_t> &packet, std::vector<uint8_t> &response);

    void init_net_snmp();
};
