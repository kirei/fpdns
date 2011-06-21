package treegenerator;

import java.util.HashMap;
import java.util.List;
import org.apache.commons.collections.map.MultiValueMap;

/**
 *
 * @author sjobe
 */

class Node {
  int query;
  HashMap<String, DNSServer> uniqueHits;
  MultiValueMap multipleHits;
  HashMap<String, Node> children;

  Node(){
    uniqueHits = new HashMap<String, DNSServer>();
    multipleHits = new MultiValueMap();
    children = new HashMap<String, Node>();
  }

  void printXML(){
    System.out.println("<query num=\""+this.query+"\">");

    for(String r: this.uniqueHits.keySet()){
      System.out.println("  <response id=\""+r+"\">"+this.uniqueHits.get(r).name+"</response>");
    }

    for(Object r: this.multipleHits.keySet()){
      System.out.println("  <response id=\""+r+"\">"+getServersString((List<DNSServer>)this.multipleHits.get(r))+"</response>");
    }

    for(String r: children.keySet()){
      System.out.println("  <response id=\""+r+"\">");
      children.get(r).printXML();
      System.out.println("  </response>");

    }

    System.out.println("</query>");
  }

  String getServersString(List<DNSServer> servers){
    String s = "";
    for(DNSServer sv: servers){
      s+= sv.name+", ";//TODO: Use a stringbuilder here ?
    }
    return s;
  }
}