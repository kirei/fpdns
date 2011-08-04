
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.commons.collections.map.MultiValueMap;

/**
 *
 * @author sjobe
 */
public class QueryTree {

  Node root;
  int queries[];
  Query[] allQueries;

  //TODO: Find a better place fot these constants 
  private static final Map<String, String> FPDNS_OPCODES =
          Collections.unmodifiableMap(new HashMap<String, String>() {

    {
      put("0", "QUERY");
      put("1", "IQUERY");
      put("2", "STATUS");
      put("4", "NS_NOTIFY_OP");
      put("5", "UPDATE");
    }
  });

  private static final Map<String, String> FPDNS_RCODES =
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

  private static final Map<String, String> FPDNS_CLASSES =
          Collections.unmodifiableMap(new HashMap<String, String>() {

    {
      put("1", "IN");
      put("3", "CH");
      put("4", "HS");
      put("254", "NONE");
      put("255", "ANY");
    }
  });

  private static final Map<String, String> FPDNS_TYPES =
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

  QueryTree(Node n, int qrs[]) {
    this.root = n;
    this.queries = qrs;
  }

  public void growTree() {
    this.growTree(root);
  }

  public String getXML() {
    ArrayList<String> responses = new ArrayList<String>();
    ArrayList<Integer> queryIndexes = new ArrayList<Integer>();
    String xml = "<?xml version=\"1.0\"?>\n";
    String rootNodeXML = this.root.getXML(responses, queryIndexes);
    xml += "<queries>\n";
    for (int i = 0; i < queryIndexes.size(); i++) {
      xml += "<query id=\"" + i + "\">\n";
      xml += "<header>" + allQueries[queryIndexes.get(i)].header + "</header>\n";
      xml += "<nct>" + allQueries[queryIndexes.get(i)].nameClassType + "</nct>\n";
      xml += "</query>\n";
    }
    xml += "</queries>\n";
    xml += "<responses>\n";
    for (int i = 0; i < responses.size(); i++) {
      xml += "<response id=\"" + i + "\">" + responses.get(i) + "</response>\n";
    }
    xml += "</responses>\n";
    xml += "<tree>\n";
    xml += rootNodeXML + "\n";
    xml += "</tree>\n";
    return xml;
  }

  public String getPerlFPDNSFormat() {
    ArrayList<String> responses = new ArrayList<String>();

    String initRule = "my %initrule = (header => $qy[0], query  => $nct[0], );\n";
    String ruleSet = "my @ruleset = (\n";
    ArrayList<Integer> queryIndexes = new ArrayList<Integer>();
    this.root.addQueryIndexToArrayList(queryIndexes, this.root.query);
    ruleSet += this.root.getPerlFPDNSFormat(responses, queryIndexes);
    ruleSet += ");\n";

    String iq = "my @iq = (\n";
    int count = 0;
    for (String response : responses) {
      iq += "\"" + getHeader(response, FPDNS_OPCODES, FPDNS_RCODES) + "\",    #iq" + count + "\n";
      count++;
    }
    iq += ");\n";

    count = 0;
    String qy = "my @qy = (\n";
    for (int j = 0; j < queryIndexes.size(); j++) {
      qy += "\"" + zeroHeaderCounts(getHeader(allQueries[queryIndexes.get(j)].header, FPDNS_OPCODES, FPDNS_RCODES)) + "\",    #qy" + count + "\n";
      count++;
    }
    qy += ");\n\n";

    count = 0;
    String nct = "my @nct = (\n";
    for (int j = 0; j < queryIndexes.size(); j++) {
      nct += "\"" + getNCT(allQueries[queryIndexes.get(j)].nameClassType, FPDNS_CLASSES, FPDNS_TYPES) + "\",    #nct" + count + "\n";
      count++;
    }
    nct += ");\n\n";

    return qy + nct + initRule + iq + ruleSet;
  }

  private void growTree(Node cur) {
    Set responses = cur.multipleHits.keySet();
    for (Object response : responses) {

      List serverList = ((List) cur.multipleHits.get(response));
      for (int queryIndex : this.queries) {
        if(this.allQueries[queryIndex].header.startsWith("0,6") || this.allQueries[queryIndex].header.startsWith("0,14")){
          //System.out.println("Found");
          continue;
        }
        MultiValueMap nodeChildrenGroupedByResponse = new MultiValueMap();
        for (Object server : serverList) {
          nodeChildrenGroupedByResponse.put(((DNSServer) server).responses[queryIndex], server);
        }
        //If query can split the group of servers, set up a new child node using the query
        //TODO: Instead of using the first query that can split the servers, use the best ?
        if (nodeChildrenGroupedByResponse.keySet().size() > 1) {
          //System.out.println("Query "+queryIndex+" splits response "+response+" of query "+cur.query+ " into "+nodeChildrenGroupedByResponse.keySet().size() + " parts");

          Node childNode = new Node();
          childNode.query = queryIndex;
          for (Object childResponse : nodeChildrenGroupedByResponse.keySet()) {
            List childServerList = (List) nodeChildrenGroupedByResponse.get(childResponse);
            if (childServerList.size() == 1) {
              childNode.uniqueHits.put((String) childResponse, (DNSServer) childServerList.get(0));
            }
          }

          //Remove the unique-hits from the list of all hits and what remains is multiple hits
          for (Object r : childNode.uniqueHits.keySet()) {
            nodeChildrenGroupedByResponse.remove(r);
          }

          childNode.multipleHits = nodeChildrenGroupedByResponse;
          //cur.multipleHits.remove(response);
          cur.children.put((String) response, childNode);
          this.growTree(childNode);
          break;
        }
      }
    }
    // Remove responses that can be split from multiple hits.
    // We do this here because doing it in the above loop breaks the iterator
    for (String r : cur.children.keySet()) {
      cur.multipleHits.remove(r);
    }
  }

  public static String getHeader(String header, Map<String, String> opcodes, Map<String, String> rcodes) {
    String h[] = header.split(",");
    if (opcodes.containsKey(h[1])) {
      h[1] = opcodes.get(h[1]);
    }

    if (rcodes.containsKey(h[8])) {
      h[8] = rcodes.get(h[8]);
    }

    return join(h, ",");
  }

    public static String getNCT(String nct, Map<String, String> classes, Map<String, String> types) {
    String nctArray[] = nct.split("\\s+");
    if (classes.containsKey(nctArray[1])) {
      nctArray[1] = classes.get(nctArray[1]);
    }

    if (types.containsKey(nctArray[2])) {
      nctArray[2] = types.get(nctArray[2]);
    }

    return join(nctArray, " ");
  }


  public static String join(String[] ary, String delim) {
    String out = "";
    for (int i = 0; i < ary.length; i++) {
      if (i != 0) {
        out += delim;
      }
      out += ary[i];
    }
    return out;
  }

  public static String zeroHeaderCounts(String header){
    String h[] = header.split(",");
    for(int i=1; i<=4; i++){
      h[h.length-i] = "0";
    }
    return join(h, ",");
  }
}
