-- create myproto protocol and its fields
p_alfred = Proto ("alfred","A.L.F.R.E.D")

local types = {[0] = "Push Data",
	       [1] = "Master Announcement",
	       [2] = "Request Data",
	       [3] = "Transaction finished",
	       [4] = "Error in Transaction",
	       [5] = "Modeswitch" } 
local modes = {[0] = "Slave" , [1] = "Master"  } 

local f_type = ProtoField.uint8("alfred.type", "Type", nil, types)
local f_version = ProtoField.uint8("alfred.version", "Version", base.DEC)
local f_length = ProtoField.uint16("alfred.length", "Length", base.DEC)
local f_rand = ProtoField.uint16("alfred.rand", "Random ID", base.HEX)
local f_counter = ProtoField.uint16("alfred.counter", "Number of packets", base.DEC)
local f_mac = ProtoField.ether("alfred.ether", "Source MAC Address")
local f_fact = ProtoField.uint8("alfred.fact", "Requested Fact", base.DEC)
local f_mode = ProtoField.uint8("alfred.mode", "Mode Switch", nil, modes)
local f_data = ProtoField.string("alfred.data", "Data", FT_STRING)

p_alfred.fields = {f_type, f_version, f_length, f_rand, f_counter, f_mac, f_fact, f_data}
 
function p_alfred.dissector (buf, pkt, root)
  -- validate packet length is adequate, otherwise quit
  if buf:len() == 0 then return end
  pkt.cols.protocol = p_alfred.name
  pkt.cols.info = "Type: "
  pkt.cols.info:append (types[buf(0,1):uint()])
 
  subtree = root:add(p_alfred, buf(0))
--- default TLV-Header / Master Announcement
  subtree:add(f_type, buf(0,1))
  subtree:add(f_version, buf(1,1))
  subtree:add(f_length, buf(2,2)):append_text(" Bytes")
--- Push Data
  if buf(0,1):uint() == 0 then
    subtree:add(f_rand, buf(4,2))
    subtree:add(f_mac, buf(8,6))
    subtree:add(f_fact, buf(14,1))
    subtree:add(f_data, buf(17))
  end
--- Request Data
  if buf(0,1):uint() == 2 then
    subtree:add(f_fact, buf(4,1))
    subtree:add(f_rand, buf(5,2))
  end
--- Finished Transaction 
  if buf(0,1):uint() == 3 then
    subtree:add(f_rand, buf(4,2))
    subtree:add(f_counter, buf(6,2))
  end
-- Error in Transaction
  if buf(0,1):uint() == 4 then
    subtree:add(f_rand, buf(4,2))
    subtree:add(f_counter, buf(6,2))
  end
--- TODO Modechange
  
  -- description of payload
--  subtree:append_text(", Command details here or in the tree below")
end
 
-- Initialization routine
function p_alfred.init()
end

-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port 7777
udp_table:add(16962,p_alfred)
-- register a chained dissector for port 8002
--local tcp_dissector_table = DissectorTable.get("tcp.port")
--dissector = tcp_dissector_table:get_dissector(8002)
  -- you can call dissector from function p_myproto.dissector above
  -- so that the previous dissector gets called
--tcp_dissector_table:add(8002, p_myproto)


