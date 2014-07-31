p_alfred = Proto ("alfred","A.L.F.R.E.D")

local types = {[0] = "Push Data",
	       [1] = "Master Announcement",
	       [2] = "Request Data",
	       [3] = "Transaction finished"}

local f_type = ProtoField.uint8("alfred.type", "Type", nil, types)
local f_version = ProtoField.uint8("alfred.version", "Version", base.DEC)
local f_length = ProtoField.uint16("alfred.length", "Length", base.DEC)
local f_txid = ProtoField.uint16("alfred.txid", "Transaction ID", base.HEX)
local f_counter = ProtoField.uint16("alfred.counter", "Number of packets", base.DEC)
local f_mac = ProtoField.ether("alfred.ether", "Source MAC Address")
local f_fact = ProtoField.uint8("alfred.fact", "Requested Fact", base.DEC)
local f_factlength = ProtoField.uint8("alfred.factlength", "Length of Fact", base.DEC)
local f_data = ProtoField.string("alfred.data", "Data", FT_STRING)

p_alfred.fields = {f_type, f_version, f_length, f_txid, f_counter, f_mac, f_fact, f_factlength, f_data}
 
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
    subtree:add(f_txid, buf(4,2))
    subtree:add(f_mac, buf(8,6))
    subtree:add(f_fact, buf(14,1))
    subtree:add(f_factlength, buf(16,2)):append_text(" Bytes")
    subtree:add(f_data, buf(18))
    pkt.cols.info:append ("\t\t\t Tx-ID: " .. (tostring(buf(4,2))))
  end
--- Request Data
  if buf(0,1):uint() == 2 then
    subtree:add(f_fact, buf(4,1))
    subtree:add(f_txid, buf(5,2))
    pkt.cols.info:append ("\t\t Tx-ID: " .. (tostring(buf(5,2))))
  end
--- Finished Transaction 
  if buf(0,1):uint() == 3 then
    subtree:add(f_txid, buf(4,2))
    subtree:add(f_counter, buf(6,2))
    pkt.cols.info:append ("\t Tx-ID: " .. (tostring(buf(4,2))))
  end
  
end
 
-- Initialization routine
function p_alfred.init()
end

-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port 0x4242
udp_table:add(16962,p_alfred)
