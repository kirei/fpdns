/*
Copyright (c) 2011 Verisign, Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.
3. The name of the authors may not be used to endorse or promote products
derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 */

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.commons.collections.map.MultiValueMap;

public class Main {

  public static final int NUM_RESPONSES = 4528;

  public static void main(String[] args) {
    String outputFormat = "perlFPDNS";
    String queriesFilePath;
    String responseFilesPath;
    String[] serverResponseFilePaths;
    int numServers;
    DNSServer servers[];
    int queryIndexes[];
    QueryTree queryTree;
    Node rootNode;
    DNSServer s;
    Map<String, Map<String, String>> DNS_LIB = LibConstants.PERL_LIB;

    if (args.length == 0) {
      System.out.println("Missing arguments. Specify paths to response files and query file");
      return;
    }

    if (args.length == 1) {
      System.out.println("Missing argument. Specify path to response files directory");
      return;
    }

    if (args.length >= 3) {
      if (args[2].equals("xml")) {
        outputFormat = "xml";
      }

      if (args.length >= 4){
        if(args[3].equals("ruby"))
        DNS_LIB = LibConstants.RUBY_LIB;
      }
    }

    queriesFilePath = args[0];
    responseFilesPath = args[1];
    serverResponseFilePaths = getResponseFiles(responseFilesPath);
    numServers = serverResponseFilePaths.length;
    servers = initServers(numServers, serverResponseFilePaths);
    queryIndexes = getUniqueQueries(numServers, servers);
    queryTree = new QueryTree(new Node(), queryIndexes, DNS_LIB);
    queryTree.allQueries = getAllQueries(NUM_RESPONSES, queriesFilePath);
    rootNode = queryTree.root;

    for (int i = 0; i < queryTree.allQueries.length; i++) {
      if (queryTree.allQueries[i].isSupportedByLibrary(DNS_LIB)) {
        rootNode.query = i;
        break;
      }
    }

    for (int i = 0; i < servers.length; i++) {
      s = servers[i];
      String rsp = s.responses[rootNode.query];
      rsp = QueryTree.normalizeResponseString(rsp);

      rootNode.multipleHits.put(rsp, s);
    }
    queryTree.growTree();

    if (outputFormat.equals("xml")) {
      System.out.println(queryTree.getXML());
    } else {
      System.out.println(queryTree.getPerlFPDNSFormat());
    }
  }

  /**
   * Get the file paths to each response file
   *
   * @param responseFilesPath
   * @return an array of strings representing response file paths
   */
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

  /**
   * Initialize the DNSServer objects
   *
   * @param numServers
   * @param serverResponseFilePaths
   * @return an array of DNSServer objects
   */
  private static DNSServer[] initServers(int numServers, String[] serverResponseFilePaths) {
    DNSServer servers[] = new DNSServer[numServers];
    for (int i = 0; i < numServers; i++) {
      servers[i] = (new DNSServer(NUM_RESPONSES, serverResponseFilePaths[i]));
    }
    return servers;
  }

  /**
   * Read all the queries from the query file and store them in an array
   *
   * @param numQueries
   * @param queriesFilePath
   * @return an array of Query objects
   */
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

  /**
   * Get the queries that will return unique responses
   *
   * @param numServers
   * @param servers
   * @return an array of queries that will return unique responses
   */
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
