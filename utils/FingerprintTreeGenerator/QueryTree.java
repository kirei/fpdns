
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import org.apache.commons.collections.map.MultiValueMap;

/**
 *
 * @author sjobe
 */
public class QueryTree {

  Node root;
  int queries[];

  QueryTree(Node n, int qrs[]) {
    this.root = n;
    this.queries = qrs;
  }

  public void growTree() {
    this.growTree(root);
  }

  public String getXML() {
    ArrayList<String> responses = new ArrayList<String>();
    String xml = "<?xml version=\"1.0\"?>\n";
    String rootNodeXML = this.root.getXML(responses);
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

  public String getPerlFPDNSFormat(Query[] allQueries) {
    ArrayList<String> responses = new ArrayList<String>();
    
    String initRule = "my %initrule = (header => $qy[0], query  => \". IN A\", );\n";
    String ruleSet = "my @ruleset = (\n";
    HashMap<Integer, Integer> queriesArrayMap = new HashMap<Integer, Integer>();
    ruleSet += this.root.getPerlFPDNSFormat(responses, queriesArrayMap);
    ruleSet += ");\n";

    String iq = "my @iq = (\n";
    int count = 0;
    for (String response : responses) {
      iq += "\"" + response + "\",    #iq" + count + "\n";
      count++;
    }
    iq += ");\n";

    Query qyArray[] = new Query[queriesArrayMap.size()];
    for (Integer allQueriesIndex : queriesArrayMap.keySet()) {
      qyArray[queriesArrayMap.get(allQueriesIndex)] = allQueries[allQueriesIndex];
    }

    count = 0;
    String qy = "my @qy = (\n";
    for (int j = 0; j < qyArray.length; j++) {
      qy += "\"" + qyArray[j].header + "\",    #qy" + count + "\n";
      count++;
    }
    qy += ");\n\n";

    count = 0;
    String ntc = "my @ntc = (\n";
    for (int j = 0; j < qyArray.length; j++) {
      ntc += "\"" + qyArray[j].nameTypeClass + "\",    #ntc" + count + "\n";
      count++;
    }
    ntc += ");\n\n";

    return qy + ntc + initRule + iq + ruleSet;
  }

  private void growTree(Node cur) {
    Set responses = cur.multipleHits.keySet();
    for (Object response : responses) {

      List serverList = ((List) cur.multipleHits.get(response));
      for (int queryIndex : this.queries) {
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
}
