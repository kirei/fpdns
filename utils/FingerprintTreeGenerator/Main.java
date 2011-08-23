
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.apache.commons.collections.map.MultiValueMap;

public class Main {

  public static final int NUM_RESPONSES = 4528;
  // comma separated string of what versions of response collector output this generator can handle
  public static final String RESPONSE_COLLECTOR_VERSIONS = "0.1";

  public static void main(String[] args) {
    if (args.length == 0) {
      System.out.println("Missing arguments. Pass in path to response files and query file");
      return;
    }
    String queriesFilePath = args[0];
    String responseFilesPath = args[1];
    String[] serverResponseFilePaths = getResponseFiles(responseFilesPath);
    int numServers = serverResponseFilePaths.length;
    DNSServer servers[] = initServers(numServers, serverResponseFilePaths);
    int queryIndexes[] = getUniqueQueries(numServers, servers);

    DNSServer s;
    QueryTree queryTree = new QueryTree(new Node(), queryIndexes);
    queryTree.allQueries = getAllQueries(NUM_RESPONSES, queriesFilePath);

    Node rootNode = queryTree.root;
    for(int i=0; i<queryTree.allQueries.length; i++){
      if(queryTree.FPDNS_OPCODES.containsKey(queryTree.allQueries[i].getOpcode())){
        rootNode.query = i;
        break;
      }
    }
    for (int i = 0; i < servers.length; i++) {
      s = servers[i];
          String rsp = s.responses[rootNode.query];
          //TODO: This is dirty, clean up later
          if(rsp.startsWith("1,0,0,0,1,1,0,0,0")){
            rsp = "1,0,0,0,1,1,0,0,0,.+,.+,.+,.+";
          }else if(rsp.startsWith("1,0,0,0,0,1,0,0,0")){
            rsp="1,0,0,0,0,1,0,0,0,.+,.+,.+,.+";
          }else if(rsp.startsWith("1,0,0,0,0,1,0,1,0")){
            rsp="1,0,0,0,0,1,0,1,0,.+,.+,.+,.+";
          }else if(rsp.startsWith("1,0,0,1,1,1,0,0,0")){
            rsp="1,0,0,1,1,1,0,0,0,.+,.+,.+,.+";
          }


      rootNode.multipleHits.put(rsp, s);
    }
    queryTree.growTree();

    //System.out.println(queryTree.getXML());
    System.out.println(queryTree.getPerlFPDNSFormat());
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

  static Query[] getAllQueries(int numQueries, String queriesFilePath) {
    Query queries[] = new Query[numQueries];
    try {

      FileInputStream fstream = new FileInputStream(queriesFilePath);
      DataInputStream in = new DataInputStream(fstream);
      BufferedReader br = new BufferedReader(new InputStreamReader(in));
      String strLine;
      int lineNum = 0;
      int queryIndex = 0;
      while ((strLine = br.readLine()) != null) {
        if (lineNum == 0) {
          //TODO: Make sure the response file version is compatible with this collector
          lineNum++;
        } else {
          queries[queryIndex] = new Query();
          queries[queryIndex].header = strLine;
          queries[queryIndex].nameClassType = br.readLine();
          queryIndex++;
          lineNum += 2;
        }
      }

      in.close();
    } catch (Exception e) {

      System.err.println("Error: " + e.getMessage() + e.toString());
    }
    return queries;
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
