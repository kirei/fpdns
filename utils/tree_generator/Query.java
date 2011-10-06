
import java.util.Map;


/**
 *
 * @author sjobe
 *
 * Is NOT meant to be an exact model of a DNS query,
 * please don't have my head for it. 
 *
 */
public class Query {

  String header;
  String nameClassType;
  String[] headerArray;
  String [] NCTArray;

  public String[] getHeaderArray() {
    if (headerArray == null) {
      this.headerArray = header.split(",");
    }
    return this.headerArray;
  }

  public String[] getNCTArray(){
    if(this.NCTArray == null) {
      this.NCTArray = nameClassType.split(" ");
    }
    return this.NCTArray;
  }

  public String getOpcode() {
    return this.getHeaderArray()[1].trim();
  }

  public String getRRClass() {
    return this.getNCTArray()[1].trim();
  }

  public String getRRType() {
    return this.getNCTArray()[2].trim();
  }

  public boolean isSupportedByLibrary(Map<String, Map<String, String>> lib){
    if(!(lib.get("opcodes")).containsKey(this.getOpcode())){
      return false;
    }

    if(!lib.get("classes").containsKey(this.getRRClass())){
      return false;
    }

    if(!lib.get("types").containsKey(this.getRRType())){
      return false;
    }

    return true;
  }

}
