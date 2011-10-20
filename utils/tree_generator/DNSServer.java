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

  /**
   * Initialize a DNSServer object with the right responses
   *
   * @param numResponses
   * @param filePath
   */
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

  /**
   * Accepts a | delimited string and assigns the values to the right attributes
   *
   *
   * @param information should be in the format "$VENDOR | $PRODUCT | $VERSION"
   */
  private void setServerInformation(String information){
      if(information.contains("|")){
        String[] info = information.split(Pattern.quote("|"));
        this.vendor = info[0].trim();
        this.product = info[1].trim();
        this.version = info[2].trim();
    }else{
        this.vendor = "";
        this.product = information;
        this.version = "";
    }
  }

  /**
   * Returns a string that represent the range of server versions in servers
   *
   * @param servers
   * @return a shorter and friendlier string representation of the combined server versions
   */
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


  /**
   * Sorts and combines version numbers into a shorter range format
   *
   * @param servers
   * @return a string with the format oldest_version -- newest_version
   */
  private static String getCombinedVersionString(List<DNSServer> servers){
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
