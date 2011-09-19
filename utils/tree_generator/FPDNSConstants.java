
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author sjobe
 */
public final class FPDNSConstants {

  //Use a private constructor to make sure this class is not instantiated
  private FPDNSConstants(){}

  static final Map<String, String> OPCODES =
          Collections.unmodifiableMap(new HashMap<String, String>() {

    {
      put("0", "QUERY");
      put("1", "IQUERY");
      put("2", "STATUS");
      put("4", "NS_NOTIFY_OP");
      put("5", "UPDATE");
    }
  });

  static final Map<String, String> RCODES =
          Collections.unmodifiableMap(new HashMap<String, String>() {

    {
      put("0", "NOERROR");
      put("1", "FORMERR");
      put("2", "SERVFAIL");
      put("3", "NXDOMAIN");
      put("4", "NOTIMP");
      put("5", "REFUSED");
      put("6", "YXDOMAIN");
      put("7", "YXRRSET");
      put("8", "NXRRSET");
      put("9", "NOTAUTH");
      put("10", "NOTZONE");
    }
  });

  static final Map<String, String> CLASSES =
          Collections.unmodifiableMap(new HashMap<String, String>() {

    {
      put("1", "IN");
      put("3", "CH");
      put("4", "HS");
      put("254", "NONE");
      put("255", "ANY");
    }
  });

  static final Map<String, String> TYPES =
          Collections.unmodifiableMap(new HashMap<String, String>() {

    {
      put("1", "A");
      put("2", "NS");
      put("3", "MD");
      put("5", "CNAME");
      put("6", "SOA");
      put("13", "HINFO");
      put("28", "AAAA");
      put("30", "NTX");
      put("39", "DNAME");
      put("46", "RRSIG");
      put("47", "NSEC");
      put("48", "DNSKEY");
      put("249", "TKEY");
      put("250", "TSIG");
      put("251", "IXFR");
      put("252", "AXFR");
      // There are 8 types implemented in the collector that do not appear in the %typesbyname array of
      // the perl dns libray. Need to investigate what happens when these are used in queries
    }
  });

}
