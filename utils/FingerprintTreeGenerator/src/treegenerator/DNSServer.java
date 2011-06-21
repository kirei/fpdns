package treegenerator;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.InputStreamReader;

/**
 *
 * @author sjobe
 */
class DNSServer {
  String name;
  String[] responses;
  boolean isTreeNode;

  DNSServer(int numResponses, String filePath){
    responses = new String[numResponses];
    isTreeNode = false;
 try{

    FileInputStream fstream = new FileInputStream(filePath);
    // Get the object of DataInputStream
    DataInputStream in = new DataInputStream(fstream);
    BufferedReader br = new BufferedReader(new InputStreamReader(in));
    String strLine;
    int lineNum = 0;
    while ((strLine = br.readLine()) != null)   {
      if(lineNum == 0)
        this.name = strLine;
      else
        this.responses[lineNum - 1] = strLine;
      lineNum++;
    }

    in.close();
    }catch (Exception e){//Catch exception if any
      System.err.println("Error: " + e.getMessage());
    }
  }
}