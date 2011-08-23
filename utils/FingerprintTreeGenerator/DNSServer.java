
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 *
 * @author sjobe
 */
class DNSServer {

  String vendor;
  String product;
  String version;
  String option;
  String[] responses;

  DNSServer(int numResponses, String filePath) {
    responses = new String[numResponses];
    try {

      FileInputStream fstream = new FileInputStream(filePath);
      // Get the object of DataInputStream
      DataInputStream in = new DataInputStream(fstream);
      BufferedReader br = new BufferedReader(new InputStreamReader(in));
      String strLine;
      int lineNum = 0;
      while ((strLine = br.readLine()) != null) {
        if (lineNum == 0) {
          this.setServerInformation(strLine);
        } else {
          this.responses[lineNum - 1] = strLine;
        }
        lineNum++;
      }

      in.close();
    } catch (Exception e) {
      System.err.println("Error: " + e.getMessage());
    }
  }

  DNSServer(){
    
  }

  private void setServerInformation(String information){
      if(information.contains("|")){
        String[] info = information.split(Pattern.quote("|"));
        this.vendor = info[0].replaceAll(" ", "");
        this.product = info[1].replaceAll(" ", "");
        this.version = info[2].replaceAll(" ", "");
    }else{
        this.vendor = "";
        this.product = information;
        this.version = "";
    }
  }

  public static DNSServer getCombinedServerInformation(List<DNSServer> servers){
    DNSServer d = new DNSServer();

    //If all the servers are from same vendor and are same product, group them together
    String vendor = null;
    String product = null;
    boolean singleVendorAndProduct = true;
    for (DNSServer sv : servers) {
      if(vendor != null && (!vendor.equalsIgnoreCase(sv.vendor) || !product.equalsIgnoreCase(sv.product))){
        singleVendorAndProduct = false;
        break;
      }
      vendor = sv.vendor;
      product = sv.product;
    }

    if(singleVendorAndProduct){
      d.vendor = vendor;
      d.product = product;
      if(servers.size() == 1){
        d.version = servers.get(0).version;
      }else{
        d.version = DNSServer.getCombinedVersionString(servers);
      }
      
    }else {
      d.vendor = "";
      d.product = "";
      d.version = "";
      for (DNSServer sv : servers) {
        d.version += sv.vendor+" "+sv.product+" "+sv.version+", ";
      }
    }

    return d;
  }

  public static String getCombinedVersionString(List<DNSServer> servers){
   String s = "";
   String versions[] = new String[servers.size()];
   int i = 0;
   for(DNSServer sv: servers){
    versions[i] = sv.version;
    i++;
   }
   Arrays.sort(versions);

   //TODO: Version strings with letters eg. "a", "b", "P1" might not be in the right order
   s = versions[0] + " -- " + versions[versions.length - 1];

   return s;
  }
}
