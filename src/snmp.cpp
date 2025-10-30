#include "snmp.hpp"
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <random>
#include <sstream>
#include "utils.hpp"
#include <iomanip>
#include <vector>


SNMPClient::SNMPClient(const std::string &target, int port, const std::string &community,
                       int timeout_ms, int retries, bool verbose)
: target_(target), port_(port), community_(community),
  timeout_ms_(timeout_ms), retries_(retries), verbose_(verbose) {
    // Initialize the Net-SNMP library
    init_net_snmp();
  }

SNMPClient::~SNMPClient() {}

void SNMPClient::init_net_snmp() {
    init_snmp("snmp2otel");
    snmp_sess_init(&session_);
    session_.peername = strdup((target_ + ":" + std::to_string(port_)).c_str());
    session_.version = SNMP_VERSION_2c;
    session_.community = (u_char*)community_.c_str();
    session_.community_len = community_.length();
    session_.retries = retries_;
    session_.timeout = timeout_ms_ * 1000; // Should be in qs
}

std::map<std::string, SNMPResult> SNMPClient::get(const std::vector<std::string> &oids) {
    std::map<std::string, SNMPResult> out;
    
    ss_ = snmp_open(&session_); 
    if (!ss_) {
        if(verbose_)  snmp_perror("[ERROR] SNMP session could not be opened\n");
        return out; // TODO: verify
    }
    pdu_ = snmp_pdu_create(SNMP_MSG_GET); // Creating pdu for get request

    for (auto oid : oids) {
        anOID_len_ = MAX_OID_LEN;
        if (oid.size() >= 2 && oid.substr(oid.size() - 2) == ".0") { // Filtering all non-scalar OIDs out
            if(!read_objid(oid.c_str(), anOID_, &anOID_len_)){
                if(verbose_) std::cerr << "[ERROR] Failed to convert OID: " << oid << std::endl;
                continue;
            } 
            if(!snmp_add_null_var(pdu_, anOID_,anOID_len_)){ // Adding oid to the PDU
                if(verbose_) std::cerr << "[ERROR] Failed to add OID " << oid << " to the PDU.\n";
            } 
        } else {
            if(verbose_) std::cerr << "[WARNING] OID: " << oid << " is not supported. Only scalar OID ending with .0 are.\n"; 
        }
    }
    // Send the request out
    status_ = snmp_synch_response(ss_, pdu_,  &response_);
    if(verbose_) std::cout << "[INFO] SNMP request send to " << session_.peername << ".\n";
    // Reply analysis
    if (status_ == STAT_SUCCESS && response_->errstat == SNMP_ERR_NOERROR) { 

        for (vars_ = response_->variables; vars_; vars_ = vars_->next_variable) {
            if(vars_->type == ASN_GAUGE)
            {
            char name[1024]; // Extracting the name, resulted value and oid
            snprint_objid(name, sizeof(name), vars_->name, vars_->name_length);
            std::string oid = get_oid_to_string(vars_);
            SNMPResult result;
            result.name = name;
            result.value = *vars_->val.integer;
            out[oid] = result;
            std::cout << oid << std::endl;
            } else {
                if(verbose_) std::cerr << "[WARNING] The OID " << get_oid_to_string(vars_) << " is not of type GAUGE. Other types are not supported.\n";
            }
        }

        return out; 
    }
    else {
        if(verbose_) std::cerr << "[ERROR] SNMP request failed.\n";
        return out; 
    }
}