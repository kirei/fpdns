
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.apache.commons.collections.map.MultiValueMap;

public class Main {

  public static final int NUM_RESPONSES = 4528;

  public static void main(String[] args) {
    if (args.length == 0) {
      System.out.println("Please pass in the path to the response folders as an argument.");
      return;
    }
    String responseFilesPath = args[0];
    String[] serverResponseFilePaths = getResponseFiles(responseFilesPath);
    int numServers = serverResponseFilePaths.length;
    ArrayList<QueryTree> queryTrees = new ArrayList<QueryTree>();
    DNSServer servers[] = initServers(numServers, serverResponseFilePaths);
    int queries[] = getUniqueQueries(numServers, servers);

    //Find queries that can identify a server in 1 try
    MultiValueMap serversGroupedByResponse;
    DNSServer s;
    DNSServer matched;
    List serverList;
    Set responses;
    Node node;
    for (int queryIndex : queries) {
      serversGroupedByResponse = new MultiValueMap();
      for (int i = 0; i < servers.length; i++) {
        s = servers[i];
        if (!s.isTreeNode) {
          serversGroupedByResponse.put(s.responses[queryIndex], s);
        }
      }
      responses = serversGroupedByResponse.keySet();
      for (Object response : responses) {
        serverList = ((List) serversGroupedByResponse.get(response));
        if (serverList.size() == 1) {
          matched = (DNSServer) serverList.get(0);
          //System.out.println("If Query # " + queryIndex + " returns " + response + " then server is " + matched.name);
          //TODO: If a query tree with that index already exists, add hit to that tree
          node = new Node();
          node.query = queryIndex;
          node.uniqueHits.put((String) response, matched);
          QueryTree qt = new QueryTree(node, queries);

          queryTrees.add(qt);
          matched.isTreeNode = true;
        }
      }
    }

    node = queryTrees.get(0).root;
    MultiValueMap nodeChildrenGroupedByResponse = new MultiValueMap();
    for (int i = 0; i < servers.length; i++) {
      s = servers[i];
      if (!s.isTreeNode) {
        nodeChildrenGroupedByResponse.put(s.responses[node.query], s);
      }
    }
    node.multipleHits = nodeChildrenGroupedByResponse;
    queryTrees.get(0).growTree();
    printXML(queryTrees);
  }

  static void printXML(List<QueryTree> queryTrees) {
    ArrayList<String> responses = new ArrayList<String>();
    String fingerprintTree = "";
    
    System.out.println("<?xml version=\"1.0\"?>");
    for (QueryTree tree : queryTrees) {
      fingerprintTree += tree.getXML(responses);
    }

    System.out.println("<responses>");
    for(int i=0; i<responses.size(); i++){
      System.out.println("<response id=\""+i+"\">"+responses.get(i)+"</response>");
    }
    System.out.println("</responses>");


    System.out.println("<tree>");
    System.out.println(fingerprintTree);
    System.out.println("</tree>");
  }

  static String[] getResponseFiles(String responseFilesPath) {
    ArrayList<String> paths = new ArrayList<String>();
    File folder = new File(responseFilesPath);
    File[] files = folder.listFiles();
    for (int i = 0; i < files.length; i++) {
      if (files[i].isFile() && files[i].getName().endsWith(".fpr")) {
        paths.add(files[i].getAbsolutePath());
      }
    }
    return paths.toArray(new String[paths.size()]);
  }

  static DNSServer[] initServers(int numServers, String[] serverResponseFilePaths) {
    DNSServer servers[] = new DNSServer[numServers];
    for (int i = 0; i < numServers; i++) {
      servers[i] = (new DNSServer(NUM_RESPONSES, serverResponseFilePaths[i]));
    }
    return servers;
  }

  static int[] getUniqueQueries(int numServers, DNSServer servers[]) {
    int queries[];
    //Group identical rows together
    MultiValueMap groupedMatrixRows = new MultiValueMap();
    StringBuilder sb = null;
    for (int i = 0; i < NUM_RESPONSES; i++) {
      sb = new StringBuilder(servers[0].responses[i]);
      for (int j = 1; j < numServers; j++) {
        sb.append(servers[j].responses[i]);
      }
      groupedMatrixRows.put(sb.toString(), i);
    }

    //Get the unique row indexes.
    Set matrixRows = groupedMatrixRows.keySet();
    queries = new int[matrixRows.size()];
    int curQ = 0;
    for (Object matrixRow : matrixRows) {
      queries[curQ] = (Integer) ((List) groupedMatrixRows.get((String) matrixRow)).get(0);
      curQ++;
    }

    return queries;
  }
}
