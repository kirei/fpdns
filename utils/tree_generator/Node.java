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
import java.util.HashMap;
import java.util.List;
import org.apache.commons.collections.map.MultiValueMap;


class Node {

  int query;
  HashMap<String, DNSServer> uniqueHits;
  MultiValueMap multipleHits;
  HashMap<String, Node> children;

  Node() {
    uniqueHits = new HashMap<String, DNSServer>();
    multipleHits = new MultiValueMap();
    children = new HashMap<String, Node>();
  }

  /**
   * Get an xml representation of the fingerprint tree
   * @param responses
   * @param queryIndexes
   * @return
   */
  @SuppressWarnings("unchecked") //Else we get a warning about an unchecked cast
  String getXML(ArrayList<String> responses, ArrayList<Integer> queryIndexes) {
    StringBuilder sb = new StringBuilder();
    sb.append("<query id=\"");
    sb.append(this.addQueryIndexToArrayList(queryIndexes, this.query));
    sb.append("\">\n");

    for (String r : this.uniqueHits.keySet()) {
      sb.append("<response id=\"");
      sb.append(this.addResponseToArrayList(responses, r));
      sb.append("\">");
      DNSServer serverInfo = this.uniqueHits.get(r);
      sb.append(serverInfo.vendor).append(" ").append(serverInfo.product).append(" ").append(serverInfo.version);
      sb.append("</response>\n");
    }

    for (Object r : this.multipleHits.keySet()) {
      DNSServer combinedInfo = DNSServer.getCombinedServerInformation((List<DNSServer>) this.multipleHits.get(r));
      sb.append("<response id=\"");
      sb.append(this.addResponseToArrayList(responses, (String) r));
      sb.append("\">");
      sb.append(combinedInfo.vendor).append(" ").append(combinedInfo.product).append(" ").append(combinedInfo.version);
      sb.append("</response>\n");
    }

    for (String r : children.keySet()) {
      sb.append("<response id=\"");
      sb.append(this.addResponseToArrayList(responses, r));
      sb.append("\">\n");
      sb.append(children.get(r).getXML(responses, queryIndexes));
      sb.append("  </response>\n");

    }

    sb.append("</query>\n");

    return sb.toString();
  }

  /**
   * Get a perl representation of the fingerprint tree
   * 
   * @param responses
   * @param queryIndexes
   * @param state
   * @return
   */
  String getPerlFPDNSFormat(ArrayList<String> responses, ArrayList<Integer> queryIndexes, String state) {
    StringBuilder sb = new StringBuilder();
    String s;
    int qi = this.addQueryIndexToArrayList(queryIndexes, this.query);
    state += "q"+qi;

    for (String r : this.uniqueHits.keySet()) {
      DNSServer serverInfo = this.uniqueHits.get(r);
      s = "{ fingerprint => $iq[" + this.addResponseToArrayList(responses, r) + "], result => { vendor =>\""+serverInfo.vendor+"\", product=>\"" + serverInfo.product + "\", version=>\""+serverInfo.version+"\"}, },\n";
      sb.append(s);
    }

    for (Object r : this.multipleHits.keySet()) {
      DNSServer combinedInfo = DNSServer.getCombinedServerInformation((List<DNSServer>) this.multipleHits.get(r));
      s = "{ fingerprint => $iq[" + this.addResponseToArrayList(responses, (String) r) + "], result => { vendor =>\""+combinedInfo.vendor+"\", product=>\"" + combinedInfo.product + "\", version=>\""+combinedInfo.version+"\"}, },\n";
      sb.append(s);
    }

    for (String r : children.keySet()) {
      int index = this.addQueryIndexToArrayList(queryIndexes, children.get(r).query);
      int ri = this.addResponseToArrayList(responses, r);
      state+="r"+ri;
      s = "{ fingerprint=>$iq[" + ri + "], header=>$qy[" + index + "], ";
      s += "query=>$nct[" + index + "], ";
      s += "ruleset => [\n";
      s += children.get(r).getPerlFPDNSFormat(responses, queryIndexes, state);
      s += "]},\n";
      sb.append(s);
    }
    if(state.matches(".+q[\\d]+$")){
      state+= "r?";
      s = "{ fingerprint => \".+\", state=>\""+state+"\" },\n";
      sb.append(s);
    }
    return sb.toString();
  }

  /**
   * Add a response to an array list if it doesn't already exist
   *
   * @param responses
   * @param response
   * @return the index of the response in the array list
   */
  int addResponseToArrayList(ArrayList<String> responses, String response) {
    if (!responses.contains(response)) {
      responses.add(response);
    }
    return responses.indexOf(response);
  }



  /**
   * Add a queryIndex to an array list of query indices if it isn't already in the array list
   *
   * @param queries
   * @param queryIndex
   * @return the array index of the newly added queryIndex
   */
  int addQueryIndexToArrayList(ArrayList<Integer> queries, int queryIndex) {
    if (!queries.contains(queryIndex)) {
      queries.add(queryIndex);
    }
    return queries.indexOf(queryIndex);
  }
}
