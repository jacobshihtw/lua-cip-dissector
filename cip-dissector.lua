------------------------------------------------------------------------------
-- cip_dissector.lua
--
-- https://github.com/jacobshihtw/lua-cip-dissector
--
-- Version: 0.9.01
--

local cip = Proto("crestron","control tcp cip protocol")

local debug_level = {
  DISABLED = 0,
  LEVEL_1  = 1,
  LEVEL_2  = 2
}

local DEBUG = debug_level.LEVEL_2

local default_settings = {
  debug_level  = DEBUG,
  port         = 41794,
}

local dprint = function() end
local dprint2 = function() end
local function reset_debug_level()
  if default_settings.debug_level > debug_level.DISABLED then
    dprint = function(...)
      print(table.concat({"Lua:", ...}," "))
    end

    if default_settings.debug_level > debug_level.LEVEL_1 then
      dprint2 = dprint
    end
  end
end
-- call it now
reset_debug_level()

----------------------------------------
-- packet types
local pkt_types = {
  [0x00] = "ack",
  [0x01] = "connection info",
  [0x02] = "register",
  [0x03] = "disconnecting",
  [0x04] = "disconnected",
  [0x05] = "data",
  [0x0B] = "unknown",
  [0x0D] = "heartbeat ping",
  [0x0E] = "heartbeat pong",
  [0x0F] = "query"
}

-- join types
local join_types = {
  [0x00] = "digital",
  [0x14] = "analog",
  [0x15] = "serial"
}

-- join numbers
local join_numbers = {
  [0x0001] = "help request",
  [0x0002] = "error message",
  [0x0003] = "data log",
  [0x0005] = "power on",
  [0x0006] = "power off",
  [0x0028] = "device id string",

  -- power
  [0x0005] = "power on",
  [0x0006] = "power off",
  [0x0009] = "power off warning",
  [0x1389] = "power status",
  [0x1428] = "warming up",
  [0x1392] = "warming up progress",
  [0x1429] = "cooling down",
  [0x1393] = "cooling down progress",

  -- emergency message
  [0x0016] = "emergency",

  -- lamp
  [0x0002] = "lamp hours integer",
  [0x0005] = "lamp hours text",
  [0x138c] = "lamp hours text",
  [0x138b] = "lamp mode text",
  [0x13b0] = "max lamp life",

  -- picture
  [0x1389] = "color",
  [0x138a] = "brightness",
  [0x138b] = "contrast",
  [0x138c] = "sharpness",
  [0x13f3] = "color +",
  [0x13f4] = "color -",
  [0x13f5] = "brightness +",
  [0x13f6] = "brightness -",
  [0x13f7] = "contrast +",
  [0x13f8] = "contrast -",
  [0x13f9] = "sharpness +",
  [0x13fa] = "sharpness -",

  -- audio
  [0x1394] = "volume",
  [0x13fb] = "volume +",
  [0x13fc] = "volume -",
  [0x13fd] = "mute on",
  [0x13fe] = "mute off",
  [0x13ff] = "mute toggle",

  -- network
  [0x13b0] = "ip address",
  [0x13b1] = "subnet mask",
  [0x13b2] = "default gateway",
  [0x13b3] = "dns server",
  [0x13b4] = "mac address",
  [0x13b5] = "control system ip address",
  [0x13b6] = "control system ip id",
  [0x13b7] = "control system port",
  [0x13af] = "host name",
  [0x145a] = "dhcp enable",
  [0x145b] = "dhcp disable",

  -- source
  [0x13ce] = "source 1",
  [0x13cf] = "source 2",
  [0x13d0] = "source 3",
  [0x13d1] = "source 4",
  [0x13d2] = "source 5",
  [0x13d3] = "source 6",
  [0x13d4] = "source 7",
  [0x13d5] = "source 8",
  [0x13d6] = "source 9",
  [0x13d7] = "source 10",
  [0x13d8] = "source 11",
  [0x13d9] = "source 12",
  [0x13da] = "source 13",
  [0x13db] = "source 14",
  [0x13dc] = "source 15",
  [0x1392] = "current source",
  [0x13e2] = "source search",

  -- password
  [0x145c] = "user password enabled",
  [0x145d] = "user password disabled",
  [0x145e] = "user password accepted",
  [0x145f] = "user password denied",
  [0x1460] = "admin password enabled",
  [0x1461] = "admin password disabled",
  [0x1462] = "admin password accepted",
  [0x1463] = "admin password denied",
  [0x13c5] = "user new password",
  [0x13c6] = "admin new password",
  [0x13c7] = "entered new password",

  -- non-classified
  [0x1395] = "feature disable feedback",

  -- temperature
  [0x139d] = "temperature 1",
  [0x139e] = "temperature 2",
  [0x139f] = "temperature 3",
  [0x13a0] = "temperature 4",
  [0x13a1] = "temperature 5",
  [0x1450] = "disable temperature report",
  [0x1451] = "temperature format",

  -- lamp - advanced
  [0x13a8] = "lamp 2 hours",
  [0x13a9] = "lamp 3 hours",
  [0x13aa] = "lamp 4 hours",
  [0x1464] = "lamp mode 1",
  [0x1465] = "lamp mode 2",
  [0x1466] = "lamp mode 3",
  [0x1467] = "lamp mode 4",
  [0x1468] = "lamp mode 5",

  -- info - advanced
  [0x13ba] = "projector name",
  [0x13bb] = "assigned to name",
  [0x13bc] = "location",
  [0x13bd] = "projector position",
  [0x13be] = "room name",
  [0x13bf] = "resolution",
  [0x13c0] = "preset mode",
  [0x13c1] = "firmware version",

  -- language
  [0x13c2] = "language code",
  [0x13c3] = "default language",

  -- picture - advanced
  [0x13ec] = "auto position",
  [0x13ed] = "aspect",
  [0x13ee] = "pip",
  [0x13ef] = "image mute on",
  [0x13f0] = "image mute off",
  [0x13f1] = "freeze on",
  [0x13f2] = "freeze off",
  [0x141e] = "menu",
  [0x142f] = "up",
  [0x1420] = "down",
  [0x1421] = "left",
  [0x1422] = "right",
  [0x1423] = "exit",
  [0x1424] = "enter",
  [0x1425] = "re-sync",
  [0x1432] = "busy",
  [0x1434] = "closed captioning on",
  [0x1435] = "closed captioning off",
  [0x1436] = "preset mode",
  [0x1437] = "color temperature",
  [0x1438] = "keystone plus",
  [0x1439] = "keystone minus",
  [0x143a] = "zoom plus",
  [0x143b] = "zoom minus",
  [0x143c] = "zoom position up",
  [0x143d] = "zoom position down",
  [0x143e] = "zoom position left",
  [0x143f] = "zoom position right",
  [0x1440] = "pincushion plus",
  [0x1441] = "pincushion minus",
  [0x1446] = "av mute off",
  [0x1447] = "av mute on",
  [0x146e] = "preset mode 1",
  [0x146e] = "preset mode 1",
  [0x146f] = "preset mode 2",
  [0x1470] = "preset mode 3",
  [0x1471] = "preset mode 4",
  [0x1472] = "preset mode 5",
  [0x1473] = "preset mode 6",
  [0x1474] = "preset mode 7",
  [0x1475] = "preset mode 8",
  [0x1476] = "preset mode 9",
  [0x1477] = "preset mode 10"
}

-- protocol fields (but not register it yet)
local pf_segment      = ProtoField.bytes ("cip.segment", "CIP")
local pf_pkt_type     = ProtoField.uint8 ("cip.pkt_type", "Packet Type", base.HEX, pkt_types, nil, "packet type")
local pf_pkt_len      = ProtoField.uint16("cip.pkt_len", "Packet Length")
local pf_payload      = ProtoField.bytes ("cip.payload", "Payload")
local pf_data_len     = ProtoField.uint8 ("cip.data_len", "Data Length")
local pf_join_type    = ProtoField.uint8 ("cip.join_type", "Join Type", base.HEX, join_types, nil, "join type")
local pf_join_number  = ProtoField.uint16("cip.join_number", "Join Number", base.HEX, join_numbers, nil, "join number")
local pf_value_uint16 = ProtoField.uint16("cip.value", "Value", base.HEX, nil, nil, "join value")
local pf_value_string = ProtoField.string("cip.value", "Value")
local pf_value_raw    = ProtoField.bytes ("cip.value", "Value")
local pf_data_raw     = ProtoField.bytes ("cip.data", "Data")
local pf_join         = ProtoField.bytes ("cip.join", "Join Number/Value")
local pf_summary      = ProtoField.string("cip.summary", "CIP")
local pf_string       = ProtoField.string("cip.string", "CIP")

-- to register the ProtoFields above into new Protocol
cip.fields = {
  pf_segment,
  pf_pkt_type,
  pf_pkt_len,
  pf_payload,
  pf_data_len,
  pf_join_type,
  pf_join_number,
  pf_join,
  pf_value_raw,
  pf_data_raw,
  pf_summary,
  pf_string
}

----------------------------------------
local HEADER_LEN = 3
local JOIN_TYPE_DIGITAL = 0x00
local JOIN_TYPE_ANALOG  = 0x14
local JOIN_TYPE_SERIAL  = 0x15

--
-- pkt_add_header
--  @brief
--    add header to tree.
--  @param buf, Tvb, packet’s buffer.
--  @param pinfo, Pinfo, packet information.
--  @param tree, TreeItem, information in the packet-details pane of Wireshark.
--  @return subtree, TreeItem object of the tree root.
function pkt_add_header(buf, pinfo, tree)
  subtree = tree:add(pf_segment, buf)
  subtree:add(pf_pkt_type, buf(0, 1))
  subtree:add(pf_pkt_len, buf(1, 2))
  return subtree
end

--
-- pkt_set_info
--  @brief
--    set the info column of packet list.
--  @param pinfo, Pinfo, packet information.
--  @param pkt_type, packet type.
--  @param text, additional text.
function pkt_set_info(pinfo, pkt_type, text)
  local info = string.format("%02x %s", pkt_type, pkt_types[pkt_type])
  if text and string.len(text) > 0 then
    info = info .. " - " .. text
  end
  pinfo.cols.info:set(info)
  pinfo.cols.protocol:set("CIP")
end

--
-- pkt_type_01_dissector
--  @brief
--    to dissect packet type 0x01
--  @param buf, Tvb, packet’s buffer.
--  @param pinfo, Pinfo, packet information.
--  @param tree, TreeItem, information in the packet-details pane of Wireshark.
function pkt_type_01_dissector(buf, pinfo, tree)
  local pkt_type, pkt_len = segment_header(buf(0, HEADER_LEN):tvb())
  local value = buf(3, 4):uint()
  local subtree = pkt_add_header(buf, pinfo, tree)
  local payload_tree = subtree:add(pf_value_raw, buf(HEADER_LEN, pkt_len))
  local controller =  (value == 0x00 and "falsh ui" or "roomview")
  if value ~= 0x00 then
    controller = string.format("%s - %d.%d.%d.%d", controller, buf(3,1):uint(), buf(4,1):uint(), buf(5,1):uint(), buf(6,1):uint())
  end
  payload_tree:add(buf(3, 4), "From: "..controller)
  payload_tree:add(pf_data_raw, buf(7))
  pkt_set_info(pinfo, pkt_type, controller)
end

--
-- pkt_type_02_dissector
--  @brief
--    to dissect packet type 0x02
--  @param buf, Tvb, packet’s buffer.
--  @param pinfo, Pinfo, packet information.
--  @param tree, TreeItem, information in the packet-details pane of Wireshark.
function pkt_type_02_dissector(buf, pinfo, tree)
  local pkt_type, pkt_len = segment_header(buf(0, HEADER_LEN):tvb())
  local value = buf(3, 4):uint()
  local subtree = pkt_add_header(buf, pinfo, tree)
  local payload_tree = subtree:add(pf_value_raw, buf(HEADER_LEN, pkt_len))
  ipid = string.format("ip id: %d", value)
  payload_tree:add(buf(3, 4), ipid)
  pkt_set_info(pinfo, pkt_type, ipid)
end


--
-- pkt_type_05_parse_payload
--  @brief
--    to parse type 05 packet into join number, value and readable name.
--  @param payload, TvbRange object
--  @return summary, summary of the payload.
--  @return join_number, join number.
--  @return join_value, join value.
--  @return join_string, readable name of join number.
function pkt_type_05_parse_payload(payload)
  --[[
    | payload layout      |
    |---------------------|
    | 00 | 01 | 02 | ...  |
    | 00   00 |len | data |
  ]]--
  --[[
    | data layout          |
    |----------------------|
    | 00 | 01 | 02 | ...   |
    |join|   join  | join  |
    |type|  number | value |
  ]]--
  local data_len = payload(2, 1):uint()
  local data = payload(3, data_len)
  local join_type = data(0, 1):uint()
  local join_number, join_value, join_string, summary, value_string
  if join_type == JOIN_TYPE_DIGITAL then
    join_number = bit.band(data(1, 2):le_uint() + 1, 0x7fff)
    join_value = bit.band(data(2, 1):uint(), 0x80)
    join_string = join_numbers[join_number]
    if join_string == nil then
      join_string = "unknown"
    end
    value_string = string.format("0x%02x", join_value)
  elseif join_type == JOIN_TYPE_ANALOG then
    join_number = data(1, 2):uint() + 1
    join_value = data(3, 2):uint()
    value_string = string.format("0x04x", join_value)
  elseif join_type == JOIN_TYPE_SERIAL then
    join_number = data(1, 2):uint() + 1
    -- skip the first byte \003 of the join value.
    --    03 31 30 2e 30 2e 30 2e 31 33
    -- to get the string value.
    --    10.0.0.13
    -- and remember the index of lua starts from 1.
    join_value = string.sub(data(3):string(), 2)
    value_string = join_value
  else
    join_number = data(1, 2):uint() + 1
    join_value = data(3):uint()
    value_string = join_value
  end
  join_string = join_numbers[join_number]
  if join_string == nil then
    join_string = "unknown"
  end
  join_type_abbrev = join_types[join_type]
  if join_type_abbrev == nil then
    join_type_abbrev = "?"
  else
    join_type_abbrev = string.upper(string.match(join_type_abbrev, "^%a"))
  end
  summary = string.format("%s %04x (%s) %s", join_type_abbrev, join_number, join_string, value_string)
  return summary, join_number, join_value, join_string
end

function pkt_type_05_dissector(buf, pinfo, tree)
  local pkt_type, pkt_len = segment_header(buf(0, HEADER_LEN):tvb())
  local data_len = buf(5, 1):uint()
  subtree = pkt_add_header(buf, pinfo, tree)
  local payload = buf(3, pkt_len)
  payload_tree = subtree:add(pf_payload, payload)
  payload_tree:add(pf_data_len, buf(5, 1))
  if data_len >= 3 then
    summary, join_number, join_value, join_string = pkt_type_05_parse_payload(payload)
    -- to display summary for cip segment. 
    subtree:append_text(" - "..summary)
    payload_tree:add(pf_join_type, payload(3, 1))
    data_tree = payload_tree:add(pf_join, payload(4, data_len-1), "", summary)
    data_tree:add(pf_join_number, join_number)
    data_tree:add(pf_value_uint16, join_value)
  else
    payload_tree:add(pf_data_raw, payload(3, data_len))
  end
  pkt_set_info(pinfo, pkt_type)
end

function pkt_generic_dissector(buf, pinfo, tree)
  local pkt_type, pkt_len = segment_header(buf(0, HEADER_LEN):tvb())
  subtree = pkt_add_header(buf, pinfo, tree)
  subtree:add(pf_value_raw, buf(HEADER_LEN, pkt_len))
  pkt_set_info(pinfo, pkt_type)
end

--
-- from_crestron
--  @brief
--    is the packet from crestron controller (roomview or flash ui).
--  @return true if the packet from crestron controller.
function from_crestron(pinfo)
  return default_settings.port == pinfo.dst_port
end

--
-- segment_header
--  @param buf, Tvb object
--  @return pkt_type, packet type.
--  @return pkt_len, packet length.
function segment_header(tvb)
  if tvb:reported_length_remaining() >= HEADER_LEN then
    --[[
      | segment                                          |
      | header       |                                   |
      | 00 | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | ... |
      |pky | pkt     | handler |data|join|   join  |     |
      |type| length  |         |len |type|  number |     |
    ]]--
    return tvb(0, 1):uint(), tvb(1, 2):uint()
  else
    return nil, nil
  end
end

local cip_dissector = {
  [0x01] = pkt_type_01_dissector,
  [0x02] = pkt_type_02_dissector,
  [0x03] = pkt_generic_dissector,
  [0x04] = pkt_generic_dissector,
  [0x05] = pkt_type_05_dissector,
  [0x0b] = pkt_generic_dissector,
  [0x0d] = pkt_generic_dissector, -- heartbeat
  [0x0e] = pkt_generic_dissector, -- heartbeat response
  [0x0f] = pkt_generic_dissector
}

function cip.dissector(buf, pinfo, tree)
  local total_len = buf:reported_length_remaining()
  local cip_tree = tree:add(cip, buf(0,total_len))
  local i = 0
  while i < total_len do
    local pkt_type, pkt_len = segment_header(buf(i, HEADER_LEN):tvb())
    local seg_len = HEADER_LEN + pkt_len
    local segment = buf(i, seg_len)
    i = i + seg_len
    if cip_dissector[pkt_type] ~= nil then
      cip_dissector[pkt_type](segment, pinfo, cip_tree)
    else
      pkt_generic_dissector(segment, pinfo, cip_tree)
    end
  end
end

if cip == nil then
  dprint("cip is nil")
end

local tcp_encap_table = DissectorTable.get("tcp.port")
if tcp_encap_table ~= nil then
  tcp_encap_table:add(default_settings.port, cip)
else
  dprint("tcp_encap_table is nil")
end
