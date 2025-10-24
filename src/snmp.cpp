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
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

// Helper functions for BER minimal encoding
static void append_len(std::vector<uint8_t>& out, size_t len) {
    if (len < 128) out.push_back((uint8_t)len);
    else {
        // long form
        std::vector<uint8_t> bytes;
        while (len) { bytes.push_back(len & 0xFF); len >>=8; }
        out.push_back(0x80 | (uint8_t)bytes.size());
        for (auto it = bytes.rbegin(); it != bytes.rend(); ++it) out.push_back(*it);
    }
}

static void append_tlv(std::vector<uint8_t>& out, uint8_t tag, const std::vector<uint8_t>& value) {
    out.push_back(tag);
    append_len(out, value.size());
    out.insert(out.end(), value.begin(), value.end());
}

static std::vector<uint8_t> encode_integer(int64_t v) {
    std::vector<uint8_t> b;
    // big-endian two's complement minimal
    bool negative = v < 0;
    uint64_t uv = (uint64_t)v;
    for (int i = 0; i < 8; ++i) {
        b.push_back((uv >> (56 - i*8)) & 0xFF);
    }
    // trim leading bytes
    size_t i = 0; while (i+1 < b.size() && ((b[i] == 0x00 && (b[i+1] & 0x80) == 0) || (b[i]==0xFF && (b[i+1] & 0x80)))) ++i;
    std::vector<uint8_t> out(b.begin()+i, b.end());
    return out;
}

static std::vector<uint8_t> encode_oid(const std::string &oid) {
    std::vector<uint8_t> out;
    // split by '.'
    std::vector<int> parts;
    size_t p=0;
    while (p<oid.size()) {
        size_t q = oid.find('.', p);
        if (q==std::string::npos) q = oid.size();
        std::string tok = oid.substr(p, q-p);
        if (!tok.empty()) parts.push_back(std::stoi(tok));
        p = q+1;
    }
    if (parts.size() < 2) return out;
    int first = parts[0], second = parts[1];
    out.push_back(40 * first + second);
    for (size_t i=2;i<parts.size();++i) {
        long v = parts[i];
        std::vector<uint8_t> tmp;
        do {
            tmp.insert(tmp.begin(), (uint8_t)(v & 0x7F));
            v >>= 7;
        } while (v);
        for (size_t j=0;j<tmp.size()-1;++j) tmp[j] |= 0x80;
        out.insert(out.end(), tmp.begin(), tmp.end());
    }
    return out;
}

static std::vector<uint8_t> encode_null() { return {}; }

std::vector<uint8_t> SNMPClient::ber_encode_get_request(int request_id,
        const std::string &community, const std::vector<std::string> &oids) {

    std::vector<uint8_t> varbinds_seq;
    for (const auto &oid : oids) {
        std::vector<uint8_t> vb;
        // name OID
        auto oid_enc = encode_oid(oid);
        append_tlv(vb, 0x06, oid_enc); // OID tag
        // value - NULL for GET request
        append_tlv(vb, 0x05, encode_null());
        // wrap VarBind sequence
        append_tlv(varbinds_seq, 0x30, vb); // but this appends to varbinds_seq incorrectly
    }

    // Warning: above we called append_tlv into varbinds_seq each iteration with tag 0x30 and vb,
    // but append_tlv expects the value bytes and handles length. So varbinds_seq contains concatenated VarBind SEQUENCEs.
    // Now wrap the sequence-of varbinds:
    std::vector<uint8_t> vb_all;
    // actually varbinds_seq currently contains already full VarBind TLVs; put them as the content of SEQUENCE
    vb_all.insert(vb_all.end(), varbinds_seq.begin(), varbinds_seq.end());
    std::vector<uint8_t> vbseq;
    append_tlv(vbseq, 0x30, vb_all);

    // PDU: GetRequest tag = 0xA0 (context-specific, constructed, tag 0)
    std::vector<uint8_t> pdu_content;
    // request-id
    auto rid = encode_integer(request_id);
    append_tlv(pdu_content, 0x02, rid);
    // error-status (0)
    auto zero = encode_integer(0);
    append_tlv(pdu_content, 0x02, zero);
    // error-index (0)
    append_tlv(pdu_content, 0x02, zero);
    // varbinds sequence
    pdu_content.insert(pdu_content.end(), vbseq.begin(), vbseq.end());
    std::vector<uint8_t> pdu;
    // tag 0xA0
    pdu.push_back(0xA0);
    append_len(pdu, pdu_content.size());
    pdu.insert(pdu.end(), pdu_content.begin(), pdu_content.end());

    // Full message: sequence { version(1), community, pdu }
    std::vector<uint8_t> msg;
    // version
    auto ver = encode_integer(1);
    std::vector<uint8_t> ver_tlv;
    append_tlv(ver_tlv, 0x02, ver);
    // community octet string
    std::vector<uint8_t> comm_bytes(community.begin(), community.end());
    std::vector<uint8_t> comm_tlv;
    append_tlv(comm_tlv, 0x04, comm_bytes);
    // assemble seq content
    std::vector<uint8_t> seq_content;
    seq_content.insert(seq_content.end(), ver_tlv.begin(), ver_tlv.end());
    seq_content.insert(seq_content.end(), comm_tlv.begin(), comm_tlv.end());
    seq_content.insert(seq_content.end(), pdu.begin(), pdu.end());
    // wrap entire message
    append_tlv(msg, 0x30, seq_content);
    return msg;
}

// Minimal decode helpers: we only try to extract OID names and simple INTEGER / OCTET STRING values
static bool read_tlv(const std::vector<uint8_t> &buf, size_t &pos, uint8_t &tag, size_t &len, size_t &value_pos) {
    if (pos >= buf.size()) return false;
    tag = buf[pos++];
    if (pos >= buf.size()) return false;
    uint8_t l = buf[pos++];
    if ((l & 0x80) == 0) {
        len = l;
    } else {
        int count = l & 0x7F;
        if (count == 0 || count > 4) return false;
        if (pos + count > buf.size()) return false;
        len = 0;
        for (int i=0;i<count;++i) { len = (len<<8) | buf[pos++]; }
    }
    value_pos = pos;
    pos += len;
    if (pos > buf.size()) return false;
    return true;
}

static std::string decode_oid(const std::vector<uint8_t> &buf, size_t pos, size_t len) {
    std::ostringstream oss;
    if (len == 0) return "";
    uint8_t first = buf[pos];
    int a = first / 40;
    int b = first % 40;
    oss << a << '.' << b;
    size_t i = pos+1;
    unsigned long value = 0;
    while (i < pos+len) {
        uint8_t c = buf[i++];
        value = (value<<7) | (c & 0x7F);
        if ((c & 0x80) == 0) {
            oss << '.' << value;
            value = 0;
        }
    }
    return oss.str();
}

bool SNMPClient::ber_decode_response(const std::vector<uint8_t> &resp, std::map<std::string, SNMPValue> &out) {
    size_t pos=0;
    uint8_t tag; size_t len; size_t vp;
    if (!read_tlv(resp, pos, tag, len, vp)) return false;
    if (tag != 0x30) return false; // sequence
    // inside: version, community, PDU
    size_t inner_pos = vp;
    // read version
    if (!read_tlv(resp, inner_pos, tag, len, vp)) return false;
    // skip community
    if (!read_tlv(resp, inner_pos, tag, len, vp)) return false;
    // PDU
    if (!read_tlv(resp, inner_pos, tag, len, vp)) return false;
    // tag should be 0xA2 (GetResponse is context-specific tag 2 -> 0xA2)
    if (tag != 0xA2) {
        return false;
    }
    size_t pdu_pos = vp;
    // request-id
    if (!read_tlv(resp, pdu_pos, tag, len, vp)) return false;
    // error-status
    if (!read_tlv(resp, pdu_pos, tag, len, vp)) return false;
    // error-index
    if (!read_tlv(resp, pdu_pos, tag, len, vp)) return false;
    // varbinds sequence
    if (!read_tlv(resp, pdu_pos, tag, len, vp)) return false;
    if (tag != 0x30) return false;
    size_t vbpos = vp;
    size_t vbend = vp + len;
    while (vbpos < vbend) {
        // each VarBind is a sequence
        if (!read_tlv(resp, vbpos, tag, len, vp)) return false;
        if (tag != 0x30) return false;
        size_t vbcontent = vp;
        size_t vbcontent_end = vp + len;
        // name OID
        if (!read_tlv(resp, vbcontent, tag, len, vp)) return false;
        if (tag != 0x06) return false;
        std::string oid = decode_oid(resp, vp, len);
        // value: read tag
        if (!read_tlv(resp, vbcontent, tag, len, vp)) return false;
        SNMPValue v;
        if (tag == 0x02) { // INTEGER
            int64_t val = 0;
            for (size_t i=0;i<len;++i) {
                val = (val<<8) | resp[vp+i];
            }
            v.isInt = true;
            v.intVal = val;
            out[oid] = v;
        } else if (tag == 0x04) { // OCTET STRING
            v.isInt = false;
            v.strVal = std::string((const char*)&resp[vp], (size_t)len);
            out[oid] = v;
        } else if (tag == 0x05) { // NULL
            // treat as empty string
            v.isInt = false; v.strVal = "";
            out[oid] = v;
        } else {
            // unsupported type -> skip but log?
            v.isInt = false; v.strVal = "";
            out[oid] = v;
        }
        // move to next varbind
    }
    return true;
}

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



}

bool SNMPClient::send_and_receive(const std::vector<uint8_t> &packet, std::vector<uint8_t> &response) {
    struct addrinfo hints{}, *res=nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    int rc = getaddrinfo(target_.c_str(), std::to_string(port_).c_str(), &hints, &res);
    if (rc!=0) {
        if (verbose_) std::cerr << "[ERROR] getaddrinfo failed: " << gai_strerror(rc) << "\n";
        return false;
    }
    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        freeaddrinfo(res);
        if (verbose_) perror("socket");
        return false;
    }
    // set recv timeout
    struct timeval tv;
    tv.tv_sec = timeout_ms_ / 1000;
    tv.tv_usec = (timeout_ms_ % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    ssize_t sent = sendto(sock, packet.data(), packet.size(), 0, res->ai_addr, res->ai_addrlen);
    if (sent < 0) {
        if (verbose_) perror("sendto");
        close(sock);
        freeaddrinfo(res);
        return false;
    }
    if (verbose_) std::cerr << "[DEBUG] Sent " << sent << " bytes to " << target_ << ":" << port_ << "\n";
    uint8_t buf[65536];
    ssize_t r = recvfrom(sock, buf, sizeof(buf), 0, nullptr, nullptr);
    if (r < 0) {
        if (verbose_) perror("recvfrom");
        close(sock);
        freeaddrinfo(res);
        return false;
    }
    response.assign(buf, buf + r);
    close(sock);
    freeaddrinfo(res);
    return true;
}

std::map<std::string, SNMPValue> SNMPClient::get(const std::vector<std::string> &oids) {
    std::map<std::string, SNMPValue> out;
    // build packet
    static std::mt19937 rng((unsigned)time(nullptr));
    int reqid = rng();
    auto pkt = ber_encode_get_request(reqid, community_, oids);
    // retry loop
    for (int attempt=0; attempt<=retries_; ++attempt) {
        std::vector<uint8_t> resp;
        if (verbose_) std::cerr << "[INFO] SNMP GET attempt " << attempt+1 << " to " << target_ << ":" << port_ << "\n";
        bool ok = send_and_receive(pkt, resp);
        if (!ok) {
            if (attempt == retries_) {
                if (verbose_) std::cerr << "[ERROR] SNMP request failed after retries\n";
                return out;
            } else continue;
        }
        std::cout << std::endl;
        bool dec = ber_decode_response(resp, out);
        for (uint8_t val : resp) {
            std::cout << static_cast<int>(val) << " ";
        }
        for (size_t i = 0; i < resp.size(); ++i) {
            if (i % 16 == 0) std::cout << std::endl; // new line every 16 bytes
            std::cout << std::setw(2) << std::setfill('0') 
                  << std::hex << std::uppercase 
                  << static_cast<int>(resp[i]) << " ";
        }
        std::cout << std::dec << std::endl; // reset formatting
        std::cout << std::endl;
        if (!dec) {
            if (verbose_) std::cerr << "[ERROR] Failed to parse SNMP response\n";
        }
        return out;
    }
    return out;
}
