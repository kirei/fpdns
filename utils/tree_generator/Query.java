
/**
 *
 * @author sjobe
 *
 * Is NOT meant to be an exact model of a DNS query,
 * please don't have my head for it. Think of it as
 * a way to avoid using multiple arrays with corresponding
 * indexes to keep track of some of the details of a query. 
 *
 */
public class Query {

  String header;
  String nameClassType;
  String[] headerArray;

  public String[] getHeaderArray() {
    if (headerArray == null) {
      this.headerArray = header.split(",");
    }
    return this.headerArray;
  }

  public String getOpcode() {
    return this.getHeaderArray()[1].trim();
  }
}
