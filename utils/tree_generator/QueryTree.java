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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.collections.map.MultiValueMap;

public class QueryTree {

  Node root;
  int queries[];
  Query[] allQueries;
  Map<String, Map<String, String>> DNS_LIB;

  QueryTree(Node n, int qrs[], Map<String, Map<String, String>> dns_lib) {
    this.root = n;
    this.queries = qrs;
    this.DNS_LIB = dns_lib;
  }

  public void growTree() {
    this.growTree(root);
  }

  /**
   * Get an xml representation of the query tree
   *
   * @return an xml representation of the query tree
   */
  public String getXML() {
    ArrayList<String> responses = new ArrayList<String>();
    ArrayList<Integer> queryIndexes = new ArrayList<Integer>();
    String xml = "<?xml version=\"1.0\"?>\n<fingerprint>\n";
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
    xml += "</tree>\n</fingerprint>\n";
    return xml;
  }

  /**
   * Get a perl representation of the query tree
   * 
   * @return a perl representation of the query tree
   */
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
      iq += "\"" + getPerlFPDNSHeaderString(response, LibConstants.PERL_LIB.get("opcodes"), LibConstants.PERL_LIB.get("rcodes")) + "\",    #iq" + count + "\n";
      count++;
    }
    iq += ");\n";

    count = 0;
    String qy = "my @qy = (\n";
    for (int j = 0; j < queryIndexes.size(); j++) {
      qy += "\"" + zeroPerlFPDNSHeaderCounts(getPerlFPDNSHeaderString(allQueries[queryIndexes.get(j)].header, LibConstants.PERL_LIB.get("opcodes"), LibConstants.PERL_LIB.get("rcodes"))) + "\",    #qy" + count + "\n";
      count++;
    }
    qy += ");\n\n";

    count = 0;
    String nct = "my @nct = (\n";
    for (int j = 0; j < queryIndexes.size(); j++) {
      nct += "\"" + getPerlFPDNSNCTString(allQueries[queryIndexes.get(j)].nameClassType, LibConstants.PERL_LIB.get("classes"), LibConstants.PERL_LIB.get("types")) + "\",    #nct" + count + "\n";
      count++;
    }
    nct += ");\n\n";

    return qy + nct + initRule + iq + ruleSet;
  }

  /**
   * A recursive method that is responsible for building out the tree from
   * the root node
   * 
   * @param cur
   */
  private void growTree(Node cur) {
    Set responses = cur.multipleHits.keySet();
    for (Object response : responses) {

      List serverList = ((List) cur.multipleHits.get(response));
      for (int queryIndex : this.queries) {
        //If a query is not supported, then skip it
        if (!this.allQueries[queryIndex].isSupportedByLibrary(this.DNS_LIB)) {
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

  /**
   *
   * @param header
   * @param opcodes
   * @param rcodes
   * @return a string representation of the header that's in a format compatible with the perl fpdns implementation
   */
  private static String getPerlFPDNSHeaderString(String header, Map<String, String> opcodes, Map<String, String> rcodes) {
    String h[] = header.split(",");
    if (opcodes.containsKey(h[1])) {
      h[1] = opcodes.get(h[1]);
    }

    if (rcodes.containsKey(h[8])) {
      h[8] = rcodes.get(h[8]);
    }

    return join(h, ",");
  }

  /**
   *
   * @param nct
   * @param classes
   * @param types
   * @return a string representation of the name/class/type that's in a format compatible with the perl fpdns implementation
   */
  private static String getPerlFPDNSNCTString(String nct, Map<String, String> classes, Map<String, String> types) {
    String nctArray[] = nct.split("\\s+");
    if (classes.containsKey(nctArray[1])) {
      nctArray[1] = classes.get(nctArray[1]);
    }

    if (types.containsKey(nctArray[2])) {
      nctArray[2] = types.get(nctArray[2]);
    }

    return join(nctArray, " ");
  }

  /**
   * Java Strings have a split method, but no join method.
   * This method takes an array of string and joins them separated by delim
   *
   * @param ary
   * @param delim
   * @return
   */
  private static String join(String[] ary, String delim) {
    String out = "";
    for (int i = 0; i < ary.length; i++) {
      if (i != 0) {
        out += delim;
      }
      out += ary[i];
    }
    return out;
  }

  /**
   * The perl implementation of fpdns fails to run when it tries to run a query
   * that doesnt have "qdcount","ancount","nscount","arcount" all set to 0.
   *
   * @param header
   * @return a string representation of the header with the 'counts' set to 0
   */
  private static String zeroPerlFPDNSHeaderCounts(String header) {
    String h[] = header.split(",");
    for (int i = 1; i <= 4; i++) {
      h[h.length - i] = "0";
    }
    return join(h, ",");
  }

  /**
   *
   * @param response
   * @return
   */
  public static String normalizeResponseString(String response) {
    if (!response.matches(".*[10],[0],[0],[0]")) {
      int pos = QueryTree.findNthIndexOf(response, ",", 9);
      response = response.substring(0, pos) + ",.+,.+,.+,.+";
    }
    return response;
  }

  /**
   * Find the nth occurrence of a substring within a string
   *
   * @param str
   * @param needle
   * @param occurrence
   * @return an int representing the start of nth occurrence of the specified string or -1 if it was not found
   * @throws IndexOutOfBoundsException
   */
  private static int findNthIndexOf(String str, String needle, int occurrence)
          throws IndexOutOfBoundsException {
    int index = -1;
    Pattern p = Pattern.compile(needle, Pattern.MULTILINE);
    Matcher m = p.matcher(str);
    while (m.find()) {
      if (--occurrence == 0) {
        index = m.start();
        break;
      }
    }
    if (index < 0) {
      throw new IndexOutOfBoundsException();
    }
    return index;
  }
}
