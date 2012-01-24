
class HomeController < ApplicationController
  @debug_output
  @error
  def index
    @debug_output = ""
    @results = ""
    @error = ""
    if request.request_method == "POST"
      tree_nodes = read_xml_file.xpath("/fingerprint/tree/query")
      queries = read_xml_file.xpath("/fingerprint/queries")
      responses = read_xml_file.xpath("/fingerprint/responses")
      address = params[:server_address]
      begin

        if !IPAddress.valid? address
          require 'socket'
          address = IPSocket::getaddress(address)
        end
        resolver = Net::DNS::Resolver.new(:nameservers => address)

      rescue
        @error = "Invalid Address"
      end

      if @error.blank?
          @results = dfs_traverse(tree_nodes, queries, responses, resolver)
      end
    end
  end

  def read_xml_file
    f = File.open(Rails.root.to_s+"/public/fingerprint.xml")
    fingerprint_doc = Nokogiri::XML(f)
    f.close
    fingerprint_doc
  end

  def dfs_traverse(nodes, queries, responses, resolver)
    output = ""
    
    nodes.each do |node|
      # Find string for query id in tree
      # Build packet from it
      # Send query
      # If query response matches a response under current query, dfs_traverse

      if node.name == "query"
        query_header_string = queries.xpath("query[@id='#{node['id']}']/header").text
        query_nct = queries.xpath("query[@id='#{node['id']}']/nct").text
        #@debug_output += "Processing "+ query_header_string+ " " + query_nct
        @debug_output += "\nQuery Sent"
        query_packet = build_packet(query_header_string, query_nct)
        @debug_output += "\n"+ query_packet.to_s
        @debug_output += "\n"+ "\nResponse Received"

        begin
        response_packet = resolver.send(query_packet)
        response_header_string = get_formatted_header_string(response_packet.header)
        @debug_output += "\n"+ response_header_string
        @debug_output += "\n"+ response_packet.to_s

        rescue Net::DNS::Resolver::NoResponseError
          @debug_output += "\n"+ "query timed out"
          response_header_string = query_header_string
        end
        @debug_output += "\n"+ "****************************************************"
        @debug_output += "****************************************************"
        response_id = get_id_for_response(responses, response_header_string)
        
        if node.xpath("response[@id='#{response_id}']").length == 1
          output += dfs_traverse(node.xpath("response[@id='#{response_id}']"), queries, responses, resolver)
        end
      end

      if node.name == "response"
        # If there are more queries under current response, dfs_traverse queries
        # else return response text
        if node.xpath("query").length > 0
          output += dfs_traverse(node.xpath("query"), queries, responses, resolver)
        else
          output = node.text
        end

      end
    end
    output
  end

  def get_id_for_response(responses, response)
    responses.xpath("*").each do |node|
      if   /#{node.text}/ =~ response
        return node['id']
      end
    end
    -1
  end

  def get_formatted_header_string(header)
    formatted_header = "#{b2i(header.response?)},#{header.opCode},#{b2i(header.auth?)},#{b2i(header.truncated?)},"
    formatted_header += "#{b2i(header.recursive?)},#{b2i(header.r_available?)},#{b2i(header.verified?)},"
    formatted_header += "#{b2i(!header.checking?)},#{header.rCode},#{header.qdCount},#{header.anCount},#{header.nsCount},#{header.arCount}"
  end

  def build_packet(header_string, nct)
    nct_array = nct.split(" ")
    packet_name = nct_array[0]
    packet_class = Net::DNS::RR::Classes::Classes.invert[nct_array[1].to_i]
    packet_type = Net::DNS::RR::Types::TYPES.invert[nct_array[2].to_i]
    
    packet = Net::DNS::Packet.new(packet_name, packet_type, packet_class)
    
    header_array = header_string.split(",").collect{|s| s.to_i}
    
    header_response = header_array[0]
    header_opcode = header_array[1]
    header_aa = header_array[2]
    header_tc = header_array[3]
    header_rd = header_array[4]
    header_ra = header_array[5]
    header_ad = header_array[6]
    header_cd = header_array[7]
    header_rcode = header_array[8]
    header_qd_count = header_array[9]
    header_an_count = header_array[10]
    header_ns_count = header_array[11]
    header_ar_count = header_array[12]
    header = Net::DNS::Header.new(:qr => header_response, :opCode => header_opcode,
      :aa => header_aa, :tc => header_tc, :rd => header_rd, :ra => header_ra,
      :ad => header_ad, :cd => header_cd, :rCode => header_rcode,
      :qdCount => header_qd_count, :anCount => header_an_count, :nsCount => header_ns_count,
      :arCount => header_ar_count)

    packet.header = header;

    return packet
  end
    
  def b2i(bool_val)
    bool_val ? 1 : 0
  end

end
