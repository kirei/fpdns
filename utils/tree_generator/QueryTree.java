
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.collections.map.MultiValueMap;

/**
 *
 * @author sjobe
 */
public class QueryTree {

  Node root;
  int queries[];
  Query[] allQueries;   

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
    String state = "";
    ArrayList<Integer> queryIndexes = new ArrayList<Integer>();
    this.root.addQueryIndexToArrayList(queryIndexes, this.root.query);
    ruleSet += this.root.getPerlFPDNSFormat(responses, queryIndexes, state);
    ruleSet += ");\n";

    String iq = "my @iq = (\n";
    int count = 0;
    for (String response : responses) {
      iq += "\"" + getHeader(response, FPDNSConstants.OPCODES, FPDNSConstants.RCODES) + "\",    #iq" + count + "\n";
      count++;
    }
    iq += ");\n";

    count = 0;
    String qy = "my @qy = (\n";
    for (int j = 0; j < queryIndexes.size(); j++) {
      qy += "\"" + zeroHeaderCounts(getHeader(allQueries[queryIndexes.get(j)].header, FPDNSConstants.OPCODES, FPDNSConstants.RCODES)) + "\",    #qy" + count + "\n";
      count++;
    }
    qy += ");\n\n";

    count = 0;
    String nct = "my @nct = (\n";
    for (int j = 0; j < queryIndexes.size(); j++) {
      nct += "\"" + getNCT(allQueries[queryIndexes.get(j)].nameClassType, FPDNSConstants.CLASSES, FPDNSConstants.TYPES) + "\",    #nct" + count + "\n";
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
        //If an opcode is not supported by FPDNS, then skip it
        if(!FPDNSConstants.OPCODES.containsKey(this.allQueries[queryIndex].getOpcode())){
          continue;
        }
        
        MultiValueMap nodeChildrenGroupedByResponse = new MultiValueMap();
        for (Object server : serverList) {
          String rsp = ((DNSServer) server).responses[queryIndex];

          rsp = QueryTree.normalizeResponseString(rsp);
          
          nodeChildrenGroupedByResponse.put(rsp, server);
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

  public static String normalizeResponseString(String response){
    if(!response.matches(".*[10],[0],[0],[0]")){
      int pos = QueryTree.findNthIndexOf (response, ",", 9);
      response = response.substring(0,pos)+",.+,.+,.+,.+";
    }
    return response;
  }

  public static int findNthIndexOf (String str, String needle, int occurence)
            throws IndexOutOfBoundsException {
    int index = -1;
    Pattern p = Pattern.compile(needle, Pattern.MULTILINE);
    Matcher m = p.matcher(str);
    while(m.find()) {
        if (--occurence == 0) {
            index = m.start();
            break;
        }
    }
    if (index < 0) throw new IndexOutOfBoundsException();
    return index;
}

}
