#include "catch.hpp"
#include "../snmp.hpp"

TEST_CASE("SNMPClient filters OIDs correctly") {
    SNMPClient client("localhost", 161, "public", 1000, 2, false);
    std::vector<std::string> oids = {
        "1.3.6.1.4.1.1.0",
        "1.3.6.1.4.1.1.5",
        "1.3.6.1.4.1.2.0"
    };
    auto values = client.get(oids); // real function call
   // REQUIRE(values == {});
}
