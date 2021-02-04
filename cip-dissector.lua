------------------------------------------------------------------------------
-- cip_dissector.lua
--
-- https://github.com/jacobshihtw/lua-cip-dissector
--
-- Version: 0.9.02
--

local cip = Proto("crestron","control tcp cip protocol")

local debug_level = {
  DISABLED = 0,
  LEVEL_1  = 1,
  LEVEL_2  = 2
}

local DEBUG = debug_level.LEVEL_2

local HEADER_LEN = 3
local JOIN_TYPE_DIGITAL      = "digital"
local JOIN_TYPE_ANALOG       = "analog"
local JOIN_TYPE_SERIAL       = "serial"
local JOIN_TYPE_SERIAL_1     = "serial 1"
local JOIN_TYPE_SERIAL_2     = "serial 2"
local JOIN_TYPE_COMMAND      = "command"
local JOIN_TYPE_CALENDAR     = "calendar"
local JOIN_TYPE_SMART_OBJECT = "smart object"

local default_settings = {
  debug_level  = DEBUG,
  port         = 41794,
}

local dprint = function() end
local dprint2 = function() end
local function reset_debug_level()
  if default_settings.debug_level > debug_level.DISABLED then
    dprint = function(...)
      print(table.concat({"CIP:", ...}," "))
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
  [0x00] = "dummy",
  [0x01] = "connect",
  [0x02] = "connected",
  [0x03] = "disconnect",
  [0x04] = "disconnected",
  [0x05] = "data",
  [0x0A] = "connect dhcp",
  [0x0B] = "authenticate",
  [0x0C] = "authenticated",
  [0x0D] = "heartbeat ping",
  [0x0E] = "heartbeat pong",
  [0x0F] = "program ready"
}

-- command types
local command_types = {
  [0x00] = "clear all/program restart/update request",
  [0x02] = "sleep",
  [0x03] = "wake",
  [0x16] = "end of update",
  [0x1d] = "---",
  [0x1e] = "update request",
  [0x1f] = "all clear"
}

-- join types
local join_types = {
  [0x00] = JOIN_TYPE_DIGITAL,
  [0x27] = JOIN_TYPE_DIGITAL,

  [0x01] = JOIN_TYPE_ANALOG,
  [0x14] = JOIN_TYPE_ANALOG,

  [0x02] = JOIN_TYPE_SERIAL_1,
  [0x12] = JOIN_TYPE_SERIAL_2,
  [0x15] = JOIN_TYPE_SERIAL,

  [0x03] = JOIN_TYPE_COMMAND,
  [0x08] = JOIN_TYPE_CALENDAR,

  [0x38] = JOIN_TYPE_SMART_OBJECT
}

-- join numbers
local join_numbers_digital = {
  -- non-classified
  [0x0001] = "online",  -- undocemented
  [0x0003] = "log",     -- undocemented

  -- power
  [0x0005] = "power on",
  [0x0006] = "power off",
  [0x0009] = "power off warning",
  [0x1428] = "warming up",
  [0x1429] = "cooling down",

  -- emergency message
  [0x0016] = "emergency message supported",

  -- picture
  [0x13f3] = "color +",
  [0x13f4] = "color -",
  [0x13f5] = "brightness +",
  [0x13f6] = "brightness -",
  [0x13f7] = "contrast +",
  [0x13f8] = "contrast -",
  [0x13f9] = "sharpness +",
  [0x13fa] = "sharpness -",

  -- audio
  [0x13fb] = "volume +",
  [0x13fc] = "volume -",
  [0x13fd] = "mute on",
  [0x13fe] = "mute off",
  [0x13ff] = "mute toggle",

  -- network
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

  -- temperature
  [0x1450] = "disable temperature report",
  [0x1451] = "temperature format",

  -- lamp - advanced
  [0x1464] = "lamp mode 1",
  [0x1465] = "lamp mode 2",
  [0x1466] = "lamp mode 3",
  [0x1467] = "lamp mode 4",
  [0x1468] = "lamp mode 5",

  -- picture - advanced
  [0x13ec] = "auto position",
  [0x13ed] = "aspect",
  [0x13ee] = "pip",
  [0x13ef] = "image mute on",
  [0x13f0] = "image mute off",
  [0x13f1] = "freeze on",
  [0x13f2] = "freeze off",
  [0x141e] = "menu",
  [0x141f] = "up",
  [0x1420] = "down",
  [0x1421] = "left",
  [0x1422] = "right",
  [0x1423] = "exit",
  [0x1424] = "enter",
  [0x1433] = "re-sync",
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

local join_numbers_analog = {
  -- power
  [0x1392] = "warming up progress",
  [0x1393] = "cooling down progress",

  -- emergency message
  [0x0016] = "emergency message",
  [0x13ba] = "emergency message text format",

  -- lamp
  [0x0002] = "lamp hours integer",
  [0x13b0] = "max lamp life",

  -- picture
  [0x1389] = "color",
  [0x138a] = "brightness",
  [0x138b] = "contrast",
  [0x138c] = "sharpness",

  -- audio
  [0x1394] = "volume",

  -- non-classified
  [0x1395] = "feature disable feedback",

  -- temperature
  [0x139d] = "temperature 1",
  [0x139e] = "temperature 2",
  [0x139f] = "temperature 3",
  [0x13a0] = "temperature 4",
  [0x13a1] = "temperature 5",

  -- lamp - advanced
  [0x0002] = "lamp 1 hours",  -- undocemented
  [0x13a8] = "lamp 2 hours",
  [0x13a9] = "lamp 3 hours",
  [0x13aa] = "lamp 4 hours",
}

local join_numbers_serial = {
  -- non-classified
  [0x0001] = "help request",
  [0x0002] = "error message",
  [0x0003] = "data log",
  [0x0028] = "device id string",

  -- power
  [0x1389] = "power status message",
  [0x138a] = "power status text",

  -- emergency message
  [0x0016] = "emergency",
  [0x0018] = "jpeg path",

  -- lamp
  [0x0005] = "lamp hours text",
  [0x138c] = "lamp hours text",
  [0x138b] = "lamp mode text",

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

  -- password
  [0x13c5] = "user new password",
  [0x13c6] = "admin new password",
  [0x13c7] = "entered new password",

  -- lamp - advanced
  [0x0005] = "lamp 1 hours",  -- undocemented
  [0x13a8] = "lamp 2 hours",
  [0x13a9] = "lamp 3 hours",
  [0x13aa] = "lamp 4 hours",

  -- info - advanced
  [0x13ba] = "projector name",
  [0x13bb] = "assigned to name",
  [0x13bc] = "location",
  [0x13bd] = "projector position",
  [0x13c1] = "room name",
  [0x13be] = "resolution",
  [0x13bf] = "preset mode",
  [0x13c0] = "firmware version",

  -- language
  [0x13e2] = "language code",
  [0x13e3] = "default language",
}

-- protocol fields (but not register it yet)
local pf_segment      = ProtoField.bytes ("cip.segment", "CIP")
local pf_pkt_type     = ProtoField.uint8 ("cip.pkt_type", "Packet Type", base.HEX, pkt_types, nil, "packet type")
local pf_pkt_len      = ProtoField.uint16("cip.pkt_len", "Packet Length")
local pf_payload      = ProtoField.bytes ("cip.payload", "Payload")
local pf_data_len     = ProtoField.uint8 ("cip.data_len", "Data Length")
local pf_join_type    = ProtoField.uint8 ("cip.join_type", "Join Type", base.HEX, join_types, nil, "join type")
local pf_value_uint16 = ProtoField.uint16("cip.value", "Value", base.HEX, nil, nil, "join value")
local pf_value_string = ProtoField.string("cip.value", "Value")
local pf_data_raw     = ProtoField.bytes ("cip.data", "Data")

-- to register the ProtoFields above into new Protocol
cip.fields = {
  pf_segment,
  pf_pkt_type,
  pf_pkt_len,
  pf_payload,
  pf_data_len,
  pf_join_type,
  pf_data_raw
}

----------------------------------------

--
-- pkt_add_header
--  @brief
--    add cip segment to tree and header to subtree of segment.
--  @param buf, Tvb, packet’s buffer.
--  @param pinfo, Pinfo, packet information.
--  @param tree, TreeItem, information in the packet-details pane of Wireshark.
--  @return subtree, TreeItem object of cip segment.
function pkt_add_header(buf, pinfo, tree)
  subtree = tree:add(pf_segment, buf)
  subtree:add(pf_pkt_type, buf(0, 1))
  subtree:add(pf_pkt_len, buf(1, 2))
  return subtree
end

--
-- pkt_set_brief_info
--  @brief
--    set the brief information of the packet to the global variable pkt_info.
--  @param text, the brief information of the packet.
function pkt_set_brief_info(text)
  if pkt_info == nil or string.len(pkt_info) == 0 then
    pkt_info = text
  -- else
  --   pkt_info = pkt_info .. " ..."
  end
end

--
-- pkt_set_info
--  @brief
--    set the info column of packet list.
--  @param pinfo, Pinfo, packet information.
--  @param pkt_type, packet type.
--  @param text, additional text.
function pkt_set_info(pinfo, pkt_type)
  local info = string.format("%02x %s", pkt_type, pkt_types[pkt_type])
  if pkt_info and string.len(pkt_info) > 0 then
    info = info .. " - " .. pkt_info
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
  local subtree = pkt_add_header(buf, pinfo, tree)
  local payload = buf(HEADER_LEN, pkt_len)
  local payload_tree = subtree:add(pf_data_raw, payload)
  local value = payload(0, 4):uint()
  local dest_cid = payload(4, 2):uint()
  local flags = payload(6, 1):uint()
  local controller =  ""
  if value == 0x00 then
    controller = "falsh ui"
  else
    controller = dest_cid == 0x0003 and "roomview" or "xpanel"
    controller = string.format("%s - %s", controller, payload(0, 4):ipv4())
  end
  payload_tree:add(payload(0, 4), "From: "..controller)
  payload_tree:add(pf_value_string, string.format("DestCID: 0x%04x", dest_cid))
  payload_tree:add(pf_value_string, string.format("Flags: 0x%02x", flags))
  pkt_set_brief_info(controller)
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
  local subtree = pkt_add_header(buf, pinfo, tree)
  local payload = buf(HEADER_LEN, pkt_len)
  local payload_tree = subtree:add(pf_data_raw, payload)
  payload_tree:add(pf_value_string, string.format("Mode: 0x%02x", payload(2, 1):uint()))
  if pkt_len > 3 then
    payload_tree:add(pf_value_string, string.format("Flags: 0x%02x", payload(3, 1):uint()))
  end
  pkt_set_brief_info(ipid)
end

--
-- pkt_type_05_join_name
--  @brief
--    to get the name of the join number.
--  @param join_type, join type.
--  @param join_number, join number.
--  @return join_name, friendly name of join number.
function pkt_type_05_join_name(join_type, join_number)
  local join_numbers = {}
  if join_types[join_type] ~= nil then
    if string.match(join_types[join_type], JOIN_TYPE_DIGITAL) then
      join_numbers = join_numbers_digital
    elseif string.match(join_types[join_type], JOIN_TYPE_ANALOG) then
      join_numbers = join_numbers_analog
    elseif string.match(join_types[join_type], JOIN_TYPE_SERIAL) then
      join_numbers = join_numbers_serial
    end
  end
  if join_type == 0x08 then
    return JOIN_TYPE_CALENDAR
  end
  join_name = join_numbers[join_number]
  --[[
    if the join name cannot be resolved from the join number table and the
    join number is less than 256, the connection is from control box
    supposedly, try to shift the join number with offset 4970 and resolve again.
  ]]--
  if join_name == nil then
    if join_number < 256 and join_number > 0 then
      join_number = join_number + 4970
      join_name = join_numbers[join_number]
    end
  end
  return join_name == nil and "(?)" or string.format("(%s)", join_name)
end

--
-- pkt_type_05_parse_payload
--  @brief
--    to parse type 05 packet into join number, value and readable name.
--  @param payload, TvbRange object
--  @return summary, summary of the payload.
--  @return join_number, join number.
--  @return join_value, join value.
--  @return join_name, readable name of join number.
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
  local join_number, join_value, join_name, summary, value_string, flags
  local join_type_name = join_types[join_type]
  local join_type_abbrev = join_type_name == nil and "?" or join_type_name
  join_type_abbrev = string.upper(string.match(join_type_abbrev, "^%a"))
  if join_type_name == nil then
    join_number = 0
    join_value = ""
    value_string = join_value
  elseif string.match(join_type_name, JOIN_TYPE_CALENDAR) then
    join_number = 0
    join_value = ""
    value_string = string.format("%02d:%02d:%02d %02d/%02d/%02d", data(2, 1):uint(), data(3, 1):uint(), data(4, 1):uint(), data(5, 1):uint(), data(6, 1):uint(), data(7, 1):uint())
  elseif string.match(join_type_name, JOIN_TYPE_DIGITAL) then
    join_number = bit.band(data(1, 2):le_uint() + 1, 0x7fff)
    join_value = bit.band(data(2, 1):uint(), 0x80)
    value_string = string.format("0x%02x", join_value)
  elseif string.match(join_type_name, JOIN_TYPE_ANALOG) then
    join_number = data(1, 2):uint() + 1
    join_value = join_type == 0x01 and data(3, 1):uint() or data(3, 2):uint()
    value_string = string.format("0x%04x", join_value)
  elseif string.match(join_type_name, JOIN_TYPE_SERIAL) then
    join_number = data(1, 2):uint() + 1
    -- the first byte of value is flags defined as below:
    -- |                  |  7 |  6 |  5 |  4 |  3 |  2 |  1 |  0 |
    -- |                  |---:|---:|---:|---:|---:|---:|---:|---:|
    -- | end of message   |  - |  - |  - |  - |  - |  - |  0 |  1 |
    -- | start of message |  - |  - |  - |  - |  - |  - |  1 |  0 |
    -- | continuation     |  - |  - |  - |  - |  - |  - |  1 |  1 |
    -- | ascii            |  - |  - |  - |  0 |  0 |  0 |  - |  - |
    -- | utf16            |  - |  - |  - |  0 |  0 |  1 |  - |  - |
    -- skip the first byte (flags) to get the string value.
    -- and remember the index of lua starts from 1.
    END_OF_MESSAGE = 0x01
    flags = data(3, 1):uint()
    is_end_of_message = bit.band(flags, END_OF_MESSAGE) == END_OF_MESSAGE
    join_value = is_end_of_message and string.sub(data(3):string(), 2) or ""
    value_string = join_value
  end
  join_type_name = join_type_name == nil and "x" or join_type_name
  join_name = pkt_type_05_join_name(join_type, join_number)
  summary = string.format("%s %d %s %s", join_type_abbrev, join_number, join_name, value_string)
  return summary, join_number, join_value, join_name, flags
end

--
-- pkt_type_05_parse_command
--  @brief
--    to parse type 05 packet for command type.
--  @param payload, TvbRange object
--  @return summary, summary of the payload.
--  @return command, command.
--  @return command_name, readable name of command.
function pkt_type_05_parse_command(payload)
  --[[
    | payload layout      |
    |---------------------|
    | 00 | 01 | 02 | ...  |
    | 00   00 |len | data |
  ]]--
  --[[
    | data layout |
    |---------|
    | 00 | 01 |
    |join|sub |
    |type|type|
  ]]--
  local data_len = payload(2, 1):uint()
  local data = payload(3, data_len)
  local join_type = data(0, 1):uint()
  local command = data(1, 1):uint()
  local command_name = command_types[command]
  local join_type_name = join_types[join_type]
  local join_type_abbrev = string.upper(string.match(join_type_name, "^%a"))
  summary = string.format("%s 0x%02x - %s", join_type_abbrev, command, command_name)
  return summary, command, command_name
end

--
-- pkt_type_05_dissector
--  @brief
--    to dissect packet type 0x05
--  @param buf, Tvb, packet’s buffer.
--  @param pinfo, Pinfo, packet information.
--  @param tree, TreeItem, information in the packet-details pane of Wireshark.
function pkt_type_05_dissector(buf, pinfo, tree)
  local pkt_type, pkt_len = segment_header(buf(0, HEADER_LEN):tvb())
  local subtree = pkt_add_header(buf, pinfo, tree)
  local payload = buf(HEADER_LEN, pkt_len)
  local data_len = buf(5, 1):uint()
  payload_tree = subtree:add(pf_payload, payload)
  payload_tree:add(pf_data_len, buf(5, 1))
  if data_len >= 3 then
    local summary, join_number, join_value, join_name, flags = pkt_type_05_parse_payload(payload)
    -- to display summary for cip segment.
    subtree:append_text(" - "..summary)
    payload_tree:add(pf_join_type, payload(3, 1))
    local data_tree = payload_tree:add(pf_data_raw, payload(4, data_len-1), "", summary)
    local join_string = string.format("Join number: %d %s", join_number, join_name)
    data_tree:add(pf_value_string, join_string)
    if flags ~= nil then
      data_tree:add(pf_value_string, string.format("Flags: 0x%02x", flags))
    end
    data_tree:add(pf_value_uint16, "Value: "..join_value)
    pkt_set_brief_info(summary)
  else
    if payload(3, 1):uint() == 0x03 then
      local summary, command, command_name = pkt_type_05_parse_command(payload)
      subtree:append_text(" - "..summary)
      payload_tree:add(pf_join_type, payload(3, 1))
      local data_tree = payload_tree:add(pf_data_raw, payload(4, data_len-1), "", summary)
      local command_string = string.format("Command: %d %s", command, command_name)
      data_tree:add(pf_value_string, command_string)
      pkt_set_brief_info(summary)
    else
      payload_tree:add(pf_data_raw, payload(3, data_len))
    end
  end
end

--
-- pkt_generic_dissector
--  @brief
--    generic cip packet dissector
--  @param buf, Tvb, packet’s buffer.
--  @param pinfo, Pinfo, packet information.
--  @param tree, TreeItem, information in the packet-details pane of Wireshark.
function pkt_generic_dissector(buf, pinfo, tree)
  local pkt_type, pkt_len = segment_header(buf(0, HEADER_LEN):tvb())
  subtree = pkt_add_header(buf, pinfo, tree)
  subtree:add(pf_data_raw, buf(HEADER_LEN, pkt_len))
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
  [0x00] = pkt_generic_dissector, -- dummy
  [0x01] = pkt_type_01_dissector, -- connect
  [0x02] = pkt_type_02_dissector, -- connected
  [0x03] = pkt_generic_dissector, -- disconnect
  [0x04] = pkt_generic_dissector, -- disconnected
  [0x05] = pkt_type_05_dissector, -- data
  [0x0b] = pkt_generic_dissector, -- authenticate
  [0x0c] = pkt_generic_dissector, -- authenticated
  [0x0d] = pkt_generic_dissector, -- heartbeat ping
  [0x0e] = pkt_generic_dissector, -- heartbeat pong
  [0x0f] = pkt_generic_dissector  -- program ready
}

function cip.dissector(buf, pinfo, tree)
  local total_len = buf:reported_length_remaining()
  local cip_tree = tree:add(cip, buf(0,total_len))
  local i = 0
  pkt_info = nil
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
    pkt_set_info(pinfo, pkt_type)
  end
end

local tcp_encap_table = DissectorTable.get("tcp.port")
if tcp_encap_table ~= nil then
  tcp_encap_table:add(default_settings.port, cip)
else
  dprint("tcp_encap_table is nil")
end
