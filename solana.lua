if set_plugin_info then
    local my_info = {
        version = "0.1",
        author  = "Richard Patel",
        email   = "me@terorie.dev",
        license = "Apache-2.0",
        details = "Wireshark plugin for decoding Solana blockchain traffic",
    }
    set_plugin_info(my_info)
end

local gossip = Proto("Solana.Gossip", "Solana Gossip Protocol")

local gossip_message_id = ProtoField.uint32("solana.gossip.message_id", "Message ID", base.DEC)
local gossip_message_names = {
    [0] = "PullRequest",
    [1] = "PullResponse",
    [2] = "PushMessage",
    [3] = "PruneMessage",
    [4] = "PingMessage",
    [5] = "PongMessage",
}
local gossip_ping_from = ProtoField.bytes("solana.gossip.ping.from", "From")
local gossip_ping_token = ProtoField.bytes("solana.gossip.ping.token", "Token")
local gossip_ping_signature = ProtoField.bytes("solana.gossip.ping.signature", "Signature")
local gossip_pull_resp_pubkey = ProtoField.bytes("solana.gossip.pull_response.pubkey", "Pubkey")

local gossip_crds_value = ProtoField.none("solana.gossip.crds_value", "Value")
local gossip_crds_value_signature = ProtoField.bytes("solana.gossip.crds_value.signature", "Signature")

local GOSSIP_CRDS_CONTACT_INFO = 0
local GOSSIP_CRDS_VOTE = 1
local GOSSIP_CRDS_LOWEST_SLOT = 2

local gossip_crds_id = ProtoField.uint32("solana.gossip.crds.id", "Data ID", base.DEC)
local gossip_crds_names = {
    [GOSSIP_CRDS_CONTACT_INFO] = "ContactInfo",
    [GOSSIP_CRDS_VOTE]         = "Vote",
    [GOSSIP_CRDS_LOWEST_SLOT]  = "LowestSlot",
    [3] = "SnapshotHashes",
    [4] = "AccountsHashes",
    [5] = "EpochSlots",
    [6] = "LegacyVersion",
    [7] = "Version",
    [8] = "NodeInstance",
    [9] = "DuplicateShred",
    [10] = "IncrementalSnapshotHashes",
}

local gossip_contact_info_pubkey       = ProtoField.bytes("solana.gossip.contact_info.pubkey", "Pubkey")
local gossip_contact_info_gossip       = ProtoField.none("solana.gossip.contact_info.gossip", "Gossip Endpoint")
local gossip_contact_info_tvu          = ProtoField.none("solana.gossip.contact_info.tvu", "TVU Endpoint")
local gossip_contact_info_tvu_fwd      = ProtoField.none("solana.gossip.contact_info.tvu_fwd", "TVUfwd Endpoint")
local gossip_contact_info_repair       = ProtoField.none("solana.gossip.contact_info.repair", "Repair Endpoint")
local gossip_contact_info_tpu          = ProtoField.none("solana.gossip.contact_info.tpu", "TPU Endpoint")
local gossip_contact_info_tpu_fwd      = ProtoField.none("solana.gossip.contact_info.tpu_fwd", "TPUfwd Endpoint")
local gossip_contact_info_tpu_vote     = ProtoField.none("solana.gossip.contact_info.tpu_vote", "TPUvote Endpoint")
local gossip_contact_info_rpc          = ProtoField.none("solana.gossip.contact_info.rpc", "RPC Endpoint")
local gossip_contact_info_rpc_pubsub   = ProtoField.none("solana.gossip.contact_info.rpc_pubsub", "RPC PubSub Endpoint")
local gossip_contact_info_serve_repair = ProtoField.none("solana.gossip.contact_info.serve_repair", "Serve Repair Endpoint")

local gossip_ip4 = ProtoField.ipv4("solana.gossip.ip4", "IP")
local gossip_ip6 = ProtoField.ipv6("solana.gossip.ip6", "IP")
local gossip_port = ProtoField.uint16("solana.gossip.port", "Port") -- TODO fix per-protocol port
local gossip_wallclock = ProtoField.uint64("solana.gossip.wallclock", "Wall clock")
local gossip_shred_version = ProtoField.uint16("solana.shred_version")

gossip.fields = {
    ------- Messages
    gossip_message_id,
    -- Pull response
    gossip_pull_resp_pubkey,
    -- Ping
    gossip_ping_from,
    gossip_ping_token,
    gossip_ping_signature,
    -------- Types
    -- Basic
    gossip_ip4,
    gossip_ip6,
    gossip_port,
    gossip_wallclock,
    gossip_shred_version,
    -- CRDS
    gossip_crds_value,
    gossip_crds_value_signature,
    gossip_crds_id,
    -- CRDS ContactInfo
    gossip_contact_info_pubkey,
    gossip_contact_info_gossip,
    gossip_contact_info_tvu,
    gossip_contact_info_tvu_fwd,
    gossip_contact_info_repair,
    gossip_contact_info_tpu,
    gossip_contact_info_tpu_fwd,
    gossip_contact_info_tpu_vote,
    gossip_contact_info_rpc,
    gossip_contact_info_rpc_pubsub,
    gossip_contact_info_serve_repair,
}

function gossip.dissector (tvb, pinfo, tree)
    local subtree = tree:add(gossip, tvb(), "Solana Gossip Message")

    local message_id = tvb(0,4):le_uint()
    local message_name = gossip_message_names[message_id] or "Unknown"
    subtree:add_le(gossip_message_id, tvb(0,4)):append_text(" (" .. message_name .. ")")
    tvb = tvb(4)

    if message_id == 0 then
        -- disect_crds_filter(tvb, subtree)
    elseif message_id == 1 then
        subtree:add(gossip_pull_resp_pubkey, tvb(0,32))
        local num_values = tvb(32,4):le_uint() -- 8 bytes broken
        tvb = tvb(40)
        for i=1,num_values,1 do
            local value = subtree:add(gossip_crds_value, tvb(0,64)):append_text(" #" .. i-1)
            value:add(gossip_crds_value_signature, tvb(0,64))
            tvb = disect_crds_data(tvb(64), value)
        end
    elseif message_id == 4 or message_id == 5 then
        subtree:add(gossip_ping_from, tvb(0,32))
        subtree:add(gossip_ping_token, tvb(32,32))
        subtree:add(gossip_ping_signature, tvb(64,64))
    end
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(8000, gossip)

---------------------------------------
-- Data types                        --
---------------------------------------

function disect_crds_data (tvb, tree)
    local data_id = tvb(0,4):le_uint()
    local data_name = gossip_crds_names[data_id] or "Unknown"
    tree:add_le(gossip_crds_id, tvb(0,4)):append_text(" (" .. data_name .. ")")
    tvb = tvb(4)

    if data_id == GOSSIP_CRDS_CONTACT_INFO then
        tree:add(gossip_contact_info_pubkey, tvb(0,32))
        tvb = disect_socket_addr(gossip_contact_info_gossip, tvb(32), tree)
        tvb = disect_socket_addr(gossip_contact_info_tvu, tvb, tree)
        tvb = disect_socket_addr(gossip_contact_info_tvu_fwd, tvb, tree)
        tvb = disect_socket_addr(gossip_contact_info_repair, tvb, tree)
        tvb = disect_socket_addr(gossip_contact_info_tpu, tvb, tree)
        tvb = disect_socket_addr(gossip_contact_info_tpu_fwd, tvb, tree)
        tvb = disect_socket_addr(gossip_contact_info_tpu_vote, tvb, tree)
        tvb = disect_socket_addr(gossip_contact_info_rpc, tvb, tree)
        tvb = disect_socket_addr(gossip_contact_info_rpc_pubsub, tvb, tree)
        tvb = disect_socket_addr(gossip_contact_info_serve_repair, tvb, tree)
        tree:add_le(gossip_wallclock, tvb(0,8))
        tree:add_le(gossip_shred_version, tvb(8,2))
    end

    return tvb
end

function tvbs (tvb, ...)
    ret = {}
    local split = nil
    for i,v in ipairs({...}) do
        if split ~= nil then
            local size = v - split
            if v == -1 then
                size = nil
            end
            table.insert(ret, tvb(split, size))
        end
        split = v
    end
    return unpack(ret)
end

function disect_socket_addr (entry, tvb, tree)
    local ip_type = tvb(0,4):le_uint()
    local return_tvb, ip_entry, ip_tvb, port_tvb
    if ip_type == 0 then
        tvb, return_tvb = tvbs(tvb,0,10,-1)
        ip_tvb, port_tvb = tvbs(tvb,4,8,10)
        ip_entry = gossip_ip4
    elseif ip_type == 1 then
        tvb, return_tvb = tvbs(tvb,0,22,-1)
        ip_tvb, port_tvb = tvbs(tvb,4,20,22)
        ip_entry = gossip_ip6
    else
        error("invalid ip type: " .. ip_type)
    end

    local subtree = tree:add(entry, tvb)
    subtree:add(ip_entry, ip_tvb)
    subtree:add_le(gossip_port, port_tvb)

    return return_tvb
end
