/*
    Copyright (c) 2011 Verisign, Inc. All rights reserved.
    All rights reserved.

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
