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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author sjobe
 */
public final class LibConstants {

  //Using a private constructor to make sure this class is not instantiated
  private LibConstants() {
  }
  static final Map<String, Map<String, String>> PERL_LIB =
          Collections.unmodifiableMap(new HashMap<String, Map<String, String>>() {

    {
      put("opcodes", Collections.unmodifiableMap(new HashMap<String, String>() {

        {
          put("0", "QUERY");
          put("1", "IQUERY");
          put("2", "STATUS");
          put("4", "NS_NOTIFY_OP");
          put("5", "UPDATE");
        }
      }));

      put("rcodes", Collections.unmodifiableMap(new HashMap<String, String>() {

        {
          put("0", "NOERROR");
          put("1", "FORMERR");
          put("2", "SERVFAIL");
          put("3", "NXDOMAIN");
          put("4", "NOTIMP");
          put("5", "REFUSED");
          put("6", "YXDOMAIN");
          put("7", "YXRRSET");
          put("8", "NXRRSET");
          put("9", "NOTAUTH");
          put("10", "NOTZONE");
        }
      }));
      put("classes", Collections.unmodifiableMap(new HashMap<String, String>() {

        {
          put("1", "IN");
          put("3", "CH");
          put("4", "HS");
          put("254", "NONE");
          put("255", "ANY");
        }
      }));
      put("types", Collections.unmodifiableMap(new HashMap<String, String>() {

        {
          put("1", "A");
          put("2", "NS");
          put("3", "MD");
          put("5", "CNAME");
          put("6", "SOA");
          put("13", "HINFO");
          put("28", "AAAA");
          put("30", "NTX");
          put("39", "DNAME");
          put("46", "RRSIG");
          put("47", "NSEC");
          put("48", "DNSKEY");
          put("249", "TKEY");
          put("250", "TSIG");
          put("251", "IXFR");
          put("252", "AXFR");
        }
      }));
    }
  });
  static final Map<String, Map<String, String>> RUBY_LIB =
          Collections.unmodifiableMap(new HashMap<String, Map<String, String>>() {

    {
      put("opcodes", Collections.unmodifiableMap(new HashMap<String, String>() {

        {
          put("0", "QUERY");
          put("1", "IQUERY");
          put("2", "STATUS");
        }
      }));
      put("classes", Collections.unmodifiableMap(new HashMap<String, String>() {

        {
          put("1", "IN");
          put("3", "CH");
          put("4", "HS");
          put("254", "NONE");
          put("255", "ANY");
        }
      }));
      put("types", Collections.unmodifiableMap(new HashMap<String, String>() {

        {
          put("1", "A");
          put("2", "NS");
          put("5", "CNAME");
          put("6", "SOA");
          put("13", "HINFO");
          put("28", "AAAA");
        }
      }));
    }
  });
}
