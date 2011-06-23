import java.util.ArrayList;
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

  @SuppressWarnings("unchecked") //Else we get a warning about unchecked cast
  String getXML(ArrayList<String> responses){
    StringBuilder sb = new StringBuilder();
    sb.append("<query num=\""+this.query+"\">\n");

    for(String r: this.uniqueHits.keySet()){
      sb.append("  <response id=\""+this.addResponseToArrayList(responses, r)+"\">"+this.uniqueHits.get(r).name+"</response>\n");
    }

    for(Object r: this.multipleHits.keySet()){

      sb.append("  <response id=\""+this.addResponseToArrayList(responses, (String)r)+"\">"+getServersString((List<DNSServer>)this.multipleHits.get(r))+"</response>\n");
    }

    for(String r: children.keySet()){
      sb.append("  <response id=\""+this.addResponseToArrayList(responses, r)+"\">\n");
      sb.append(children.get(r).getXML(responses));
      sb.append("  </response>\n");

    }

    sb.append("</query>\n");

    return sb.toString();
  }

  int addResponseToArrayList(ArrayList<String> responses, String response){
    if(!responses.contains(response)){
      responses.add(response);
    }
    return responses.indexOf(response);
  }

  String getServersString(List<DNSServer> servers){
    String s = "";
    for(DNSServer sv: servers){
      s+= sv.name+", ";//TODO: Use a stringbuilder here ?
    }
    return s;
  }
}