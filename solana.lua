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

---------------------------------------
-- Protocols                         --
---------------------------------------

local gossip = Proto("Solana.Gossip", "Solana Gossip Protocol")

---------------------------------------
-- Data Types                        --
---------------------------------------

local GOSSIP_MSG_PULL_REQ  = 0
local GOSSIP_MSG_PULL_RESP = 1
local GOSSIP_MSG_PUSH      = 2
local GOSSIP_MSG_PRUNE     = 3
local GOSSIP_MSG_PING      = 4
local GOSSIP_MSG_PONG      = 5

local gossip_message_id = ProtoField.uint32("solana.gossip.message_id", "Message ID", base.DEC)
local gossip_message_names = {
    [GOSSIP_MSG_PULL_REQ]  = "PullRequest",
    [GOSSIP_MSG_PULL_RESP] = "PullResponse",
    [GOSSIP_MSG_PUSH]      = "PushMessage",
    [GOSSIP_MSG_PRUNE]     = "PruneMessage",
    [GOSSIP_MSG_PING]      = "PingMessage",
    [GOSSIP_MSG_PONG]      = "PongMessage",
}
local gossip_ping_from = ProtoField.bytes("solana.gossip.ping.from", "From")
local gossip_ping_token = ProtoField.bytes("solana.gossip.ping.token", "Token")
local gossip_ping_signature = ProtoField.bytes("solana.gossip.ping.signature", "Signature")
local gossip_pull_resp_pubkey = ProtoField.bytes("solana.gossip.pull_response.pubkey", "Pubkey")

local gossip_crds_value = ProtoField.none("solana.gossip.crds_value", "Value")
local gossip_crds_value_signature = ProtoField.bytes("solana.gossip.crds_value.signature", "Signature")

local GOSSIP_CRDS_CONTACT_INFO        = 0
local GOSSIP_CRDS_VOTE                = 1
local GOSSIP_CRDS_LOWEST_SLOT         = 2
local GOSSIP_CRDS_SNAPSHOT_HASHES     = 3
local GOSSIP_CRDS_ACCOUNTS_HASHES     = 4
local GOSSIP_CRDS_EPOCH_SLOTS         = 5
local GOSSIP_CRDS_LEGACY_VERSION      = 6
local GOSSIP_CRDS_VERSION             = 7
local GOSSIP_CRDS_NODE_INSTANCE       = 8
local GOSSIP_CRDS_DUPLICATE_SHRED     = 9
local GOSSIP_CRDS_INC_SNAPSHOT_HASHES = 10

local gossip_crds_id = ProtoField.uint32("solana.gossip.crds.id", "Data ID", base.DEC)
local gossip_crds_names = {
    [GOSSIP_CRDS_CONTACT_INFO]        = "ContactInfo",
    [GOSSIP_CRDS_VOTE]                = "Vote",
    [GOSSIP_CRDS_LOWEST_SLOT]         = "LowestSlot",
    [GOSSIP_CRDS_SNAPSHOT_HASHES]     = "SnapshotHashes",
    [GOSSIP_CRDS_ACCOUNTS_HASHES]     = "AccountsHashes",
    [GOSSIP_CRDS_EPOCH_SLOTS]         = "EpochSlots",
    [GOSSIP_CRDS_LEGACY_VERSION]      = "LegacyVersion",
    [GOSSIP_CRDS_VERSION]             = "Version",
    [GOSSIP_CRDS_NODE_INSTANCE]       = "NodeInstance",
    [GOSSIP_CRDS_DUPLICATE_SHRED]     = "DuplicateShred",
    [GOSSIP_CRDS_INC_SNAPSHOT_HASHES] = "IncrementalSnapshotHashes",
}

local gossip_ip4            = ProtoField.ipv4  ("solana.gossip.ip4",         "IP")
local gossip_ip6            = ProtoField.ipv6  ("solana.gossip.ip6",         "IP")
local gossip_port           = ProtoField.uint16("solana.gossip.port",        "Port") -- TODO fix per-protocol port
local gossip_wallclock      = ProtoField.uint64("solana.gossip.wallclock",   "Wall clock")
local gossip_pubkey         = ProtoField.bytes ("solana.gossip.from",        "From")

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

local gossip_vote_index     = ProtoField.uint8 ("solana.gossip.vote.index",  "Index")
local gossip_vote_pubkey    = ProtoField.bytes ("solana.gossip.vote.pubkey", "Pubkey")
local gossip_vote_slot      = ProtoField.uint64("solana.gossip.vote.slot",   "Slot")

local gossip_lowest_slot_index  = ProtoField.uint8 ("solana.gossip.lowest_slot.index",  "Index")
local gossip_lowest_slot_root   = ProtoField.uint64("solana.gossip.lowest_slot.root",   "Root Slot")
local gossip_lowest_slot_lowest = ProtoField.uint64("solana.gossip.lowest_slot.lowest", "Lowest Slot")
local gossip_lowest_slot_slots  = ProtoField.none  ("solana.gossip.lowest_slots.slots", "Slots")
local gossip_lowest_slot_slot   = ProtoField.uint64("solana.gossip.lowest_slots.slot",  "Slot")

local gossip_hash_event = ProtoField.none  ("solana.gossip.hash_event")
local gossip_hash_slot  = ProtoField.uint64("solana.gossip.hash_event.slot", "Slot", base.DEC)
local gossip_hash_hash  = ProtoField.bytes ("solana.gossip.hash_event.hash", "Hash")

local gossip_version_major    = ProtoField.uint16("solana.gossip.version.major",    "Major",       base.DEC)
local gossip_version_minor    = ProtoField.uint16("solana.gossip.version.minor",    "Minor",       base.DEC)
local gossip_version_patch    = ProtoField.uint16("solana.gossip.version.patch",    "Patch",       base.DEC)
local gossip_version_commit   = ProtoField.uint32("solana.gossip.version.commit",   "Commit Hash", base.HEX)
local gossip_version_features = ProtoField.uint32("solana.gossip.version.features", "Feature Set", base.HEX)

local gossip_node_instance_timestamp = ProtoField.uint64("solana.gossip.node_instance.timestamp", "Instance Creation Timestamp", base.DEC)
local gossip_node_instance_token     = ProtoField.uint64("solana.gossip.node_instance.token",     "Instance Token",              base.HEX)

local gossip_prune_pubkey      = ProtoField.bytes("solana.gossip.prune.pubkey", "Pubkey")
local gossip_prune_target      = ProtoField.bytes("solana.gossip.prune.target", "Target")
local gossip_prune_destination = ProtoField.bytes("solana.gossip.prune.dest",   "Destination")

local gossip_filter_mask      = ProtoField.uint64("solana.gossip.filter.mask",      "Mask",  base.HEX)
local gossip_filter_mask_bits = ProtoField.uint32("solana.gossip.filter.mask_bits", "Mask bits")

local gossip_bloom_filter = ProtoField.none  ("solana.gossip.bloom",       "Bloom filter")
local gossip_bloom_key    = ProtoField.uint64("solana.gossip.bloom.key",   "Key", base.HEX)
local gossip_bloom_bits   = ProtoField.bytes ("solana.gossip.bloom.bits",  "Bit vector")
local gossip_bloom_size   = ProtoField.uint64("solana.gossip.bloom.size",  "Size in bits")
local gossip_bloom_ones   = ProtoField.uint64("solana.gossip.bloom.ones",  "Number of one bits")

local sol_transaction       = ProtoField.none  ("solana.tx",                  "Transaction")
local sol_signature         = ProtoField.bytes ("solana.sig",                 "Signature")
local sol_pubkey            = ProtoField.bytes ("solana.pubkey",              "Pubkey")
local sol_tx_sigs_req       = ProtoField.uint8 ("solana.tx.sigs_req",         "Required Signatures",      base.DEC)
local sol_tx_signed_ro      = ProtoField.uint8 ("solana.tx.sigs.ro",          "Signed read-only count",   base.DEC)
local sol_tx_unsigned_ro    = ProtoField.uint8 ("solana.tx.sigs.rw",          "Unsigned read-only count", base.DEC)
local sol_recent_blockhash  = ProtoField.bytes ("solana.tx.recent_blockhash", "Recent blockhash")
local sol_shred_version     = ProtoField.uint16("solana.shred_version")
local sol_invoc             = ProtoField.none  ("solana.insn",                "Instruction")
local sol_invoc_program_idx = ProtoField.uint8 ("solana.insn.program_index",  "Program Index", base.DEC)
local sol_invoc_account_idx = ProtoField.uint8 ("solana.insn.account_index",  "Account Index", base.DEC)
local sol_invoc_data        = ProtoField.bytes ("solana.insn.data",           "Data")

gossip.fields = {
    ------- Solana Core
    sol_transaction,
    sol_signature,
    sol_pubkey,
    sol_tx_sigs_req,
    sol_tx_signed_ro,
    sol_tx_unsigned_ro,
    sol_recent_blockhash,
    sol_shred_version,
    sol_invoc,
    sol_invoc_program_idx,
    sol_invoc_account_idx,
    sol_invoc_data,
    ------- Messages
    gossip_message_id,
    -- Pull request
    -- Pull response
    gossip_pull_resp_pubkey,
    -- Prune
    gossip_prune_pubkey,
    gossip_prune_target,
    gossip_prune_destination,
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
    gossip_pubkey,
    -- Bloom
    gossip_bloom_filter,
    gossip_bloom_key,
    gossip_bloom_bits,
    gossip_bloom_size,
    gossip_bloom_ones,
    -- CRDS Filter
    gossip_filter_mask,
    gossip_filter_mask_bits,
    -- CRDS
    gossip_crds_value,
    gossip_crds_value_signature,
    gossip_crds_id,
    -- CRDS ContactInfo
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
    -- CRDS Vote
    gossip_vote_index,
    gossip_vote_pubkey,
    gossip_vote_slot,
    -- CRDS Lowest Slot
    gossip_lowest_slot_index,
    gossip_lowest_slot_root,
    gossip_lowest_slot_lowest,
    gossip_lowest_slot_slots,
    gossip_lowest_slot_slot,
    -- CRDS Snapshot/Accounts/Incremental Hashes
    gossip_hash_event,
    gossip_hash_slot,
    gossip_hash_hash,
    -- CRDS Version
    gossip_version_major,
    gossip_version_minor,
    gossip_version_patch,
    gossip_version_commit,
    gossip_version_features,
    -- CRDS NodeInstance
    gossip_node_instance_timestamp,
    gossip_node_instance_token,
}

function gossip.dissector (tvb, pinfo, tree)
    local subtree = tree:add(gossip, tvb(), "Solana Gossip Message")

    local message_id = tvb(0,4):le_uint()
    local message_name = gossip_message_names[message_id] or "Unknown"
    subtree:add_le(gossip_message_id, tvb(0,4)):append_text(" (" .. message_name .. ")")
    tvb = tvb(4)

    local disect
    if message_id == GOSSIP_MSG_PULL_REQ then
        disect = solana_gossip_disect_pull_req
    elseif message_id == GOSSIP_MSG_PULL_RESP or message_id == GOSSIP_MSG_PUSH then
        disect = solana_gossip_disect_pull_resp
    elseif message_id == GOSSIP_MSG_PRUNE then
        disect = solana_gossip_disect_prune
    elseif message_id == GOSSIP_MSG_PING or message_id == GOSSIP_MSG_PONG then
        disect = solana_gossip_disect_ping
    end
    if disect then
        disect(tvb, subtree)
    end
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(8000, gossip)

---------------------------------------
-- Helpers                           --
---------------------------------------

-- Splits a Tvb into TvbRange.
-- Takes indexes as variadic args.
-- Finish args with -1 to return remaining TvbRange.
local function tvbs (tvb, ...)
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

---------------------------------------
-- Data types                        --
---------------------------------------

function solana_gossip_disect_ping (tvb, subtree)
    subtree:add(gossip_ping_from, tvb(0,32))
    subtree:add(gossip_ping_token, tvb(32,32))
    subtree:add(gossip_ping_signature, tvb(64,64))
end

function solana_gossip_disect_pull_req (tvb, subtree)
    tvb = solana_gossip_disect_crds_filter(tvb, subtree)
    tvb = solana_gossip_disect_crds_value (tvb, subtree)
    return tvb
end

function solana_gossip_disect_pull_resp (tvb, subtree)
    subtree:add(gossip_pull_resp_pubkey, tvb(0,32))
    local num_values = tvb(32,4):le_uint() -- 8 bytes broken
    tvb = tvb(40)
    for i=1,num_values,1 do
        local value
        tvb, value = solana_gossip_disect_crds_value(tvb, subtree)
        value:append_text(" #" .. i-1)
    end
end

function solana_gossip_disect_prune (tvb, subtree)
    subtree:add(gossip_prune_pubkey, tvb(0,32))
    subtree:add(gossip_prune_pubkey, tvb(32,32))
    local num_prune = tvb(64,4):le_uint()
    tvb = tvb(72)
    for i=1,num_prune,1 do
        subtree:add(gossip_prune_target, tvb(0,32))
        tvb = tvb(32)
    end
    subtree:add(sol_signature, tvb(0,64))
    subtree:add(gossip_prune_destination, tvb(64,32))
    subtree:add_le(gossip_wallclock, tvb(96,8))
end

-- Pops a gossip CrdsFilter off tvb and appends items to tree.
function solana_gossip_disect_crds_filter (tvb, tree)
    tvb = solana_gossip_disect_bloom_filter(tvb, tree)
    tree:add_le(gossip_filter_mask,      tvb(0,8))
    tree:add_le(gossip_filter_mask_bits, tvb(8,4))
    return tvb(12)
end

-- Pops a gossip Bloom filter off tvb and appends it as an opaque object to tree.
function solana_gossip_disect_bloom_filter (tvb, tree)
    local before_len = tvb:len()
    local bloom = tree:add(gossip_bloom_filter, tvb)

    local num_keys = tvb(0,4):le_uint()
    tvb = tvb(8)
    for i=1,num_keys,1 do
        bloom:add(gossip_bloom_key, tvb(0,8))
        tvb = tvb(8)
    end

    local has_bits = tvb(0,1):uint() == 1
    tvb = tvb(1)
    if has_bits then
        local count = tvb(0,4):le_uint()
        local bits = bloom:add(gossip_bloom_bits, tvb(8,count*8))
        tvb = tvb(8+count*8)
    end

    bloom:add_le(gossip_bloom_size, tvb(0,8))
    bloom:add_le(gossip_bloom_ones, tvb(8,8))
    tvb = tvb(16)

    bloom:set_len(before_len - tvb:len())
    return tvb
end

-- Pops a gossip CrdsValue off tvb and appends items to tree.
function solana_gossip_disect_crds_value (tvb, tree, i)
    local before_len = tvb:len()
    local value = tree:add(gossip_crds_value, tvb)
    value:add(gossip_crds_value_signature, tvb(0,64))
    tvb = solana_gossip_disect_crds_data(tvb(64), value)
    value:set_len(before_len - tvb:len())
    return tvb, value
end

-- Pops a gossip CrdsData off tvb and appends items to tree.
function solana_gossip_disect_crds_data (tvb, tree)
    local data_id = tvb(0,4):le_uint()
    local data_name = gossip_crds_names[data_id] or "Unknown"
    tree:add_le(gossip_crds_id, tvb(0,4)):append_text(" (" .. data_name .. ")")
    tvb = tvb(4)

    if data_id == GOSSIP_CRDS_CONTACT_INFO then
        tree:add(gossip_pubkey, tvb(0,32))
        tvb = solana_gossip_disect_socket_addr(gossip_contact_info_gossip, tvb(32), tree)
        tvb = solana_gossip_disect_socket_addr(gossip_contact_info_tvu, tvb, tree)
        tvb = solana_gossip_disect_socket_addr(gossip_contact_info_tvu_fwd, tvb, tree)
        tvb = solana_gossip_disect_socket_addr(gossip_contact_info_repair, tvb, tree)
        tvb = solana_gossip_disect_socket_addr(gossip_contact_info_tpu, tvb, tree)
        tvb = solana_gossip_disect_socket_addr(gossip_contact_info_tpu_fwd, tvb, tree)
        tvb = solana_gossip_disect_socket_addr(gossip_contact_info_tpu_vote, tvb, tree)
        tvb = solana_gossip_disect_socket_addr(gossip_contact_info_rpc, tvb, tree)
        tvb = solana_gossip_disect_socket_addr(gossip_contact_info_rpc_pubsub, tvb, tree)
        tvb = solana_gossip_disect_socket_addr(gossip_contact_info_serve_repair, tvb, tree)
        tree:add_le(gossip_wallclock, tvb(0,8))
        tree:add_le(sol_shred_version, tvb(8,2))
    elseif data_id == GOSSIP_CRDS_VOTE then
        tree:add(gossip_vote_index, tvb(0,1))
        tree:add(gossip_vote_pubkey, tvb(1,32))
        tvb, tx = solana_gossip_disect_transaction(tvb(33), tree)
        tx:set_text("Vote Transaction")
        tree:add_le(gossip_wallclock, tvb(0,8))
        if tvb:len() > 8 then tvb = tvb(8) end
    elseif data_id == GOSSIP_CRDS_LOWEST_SLOT then
        tree:add_le(gossip_lowest_slot_index, tvb(0,1))
        tree:add   (gossip_pubkey, tvb(1,32))
        tree:add_le(gossip_lowest_slot_root, tvb(33,8))
        tree:add_le(gossip_lowest_slot_lowest, tvb(41,8))
        local num_slots = tvb(49,4):le_uint() -- uint64 broken

        local subtree = tree:add(gossip_lowest_slot_slots, tvb(49,8+8*num_slots))
        tvb = tvb(57)
        for i=1,num_slots,1 do
            subtree:add_le(gossip_lowest_slot_slot, tvb(0,8)):append_text(" #" .. i-1)
            tvb = tvb(8)
        end
        -- TODO Stash and wall clock
    elseif data_id == GOSSIP_CRDS_SNAPSHOT_HASHES or data_id == GOSSIP_CRDS_ACCOUNTS_HASHES then
        local event_name
        if data_id == GOSSIP_CRDS_SNAPSHOT_HASHES then
            event_name = "Snapshot Hash"
        else
            event_name = "Accounts Hash"
        end
        tree:add(gossip_vote_pubkey, tvb(0,32))
        local num_hashes = tvb(32,4):le_uint() -- uint64 broken
        tvb = tvb(40)
        for i=1,num_hashes,1 do
            local subtree = tree:add(gossip_hash_event, tvb(0,40))
            subtree:set_text(event_name)
            subtree:add_le(gossip_hash_slot, tvb(0,8))
            subtree:add   (gossip_hash_hash, tvb(8,32))
            tvb = tvb(40)
        end
        tree:add_le(gossip_wallclock, tvb(0,8))
    elseif data_id == GOSSIP_CRDS_LEGACY_VERSION or data_id == GOSSIP_CRDS_VERSION then
        tree:add(sol_pubkey, tvb(0,32))
        tree:add_le(gossip_wallclock,     tvb(32,8))
        tree:add_le(gossip_version_major, tvb(40,2))
        tree:add_le(gossip_version_minor, tvb(42,2))
        tree:add_le(gossip_version_patch, tvb(44,2))
        if tvb(46,1) == 1 then
            tree:add_le(gossip_version_commit, tvb(47,4))
            tvb = tvb(51)
        else
            tvb = tvb(47)
        end
        if data_id == GOSSIP_CRDS_VERSION then
            tree:add_le(gossip_version_features, tvb(0,4))
        end
    elseif data_id == GOSSIP_CRDS_NODE_INSTANCE then
        tree:add   (gossip_pubkey,    tvb(0,32))
        tree:add_le(gossip_wallclock, tvb(32,8))
        tree:add_le(gossip_node_instance_timestamp, tvb(40,8))
        tree:add_le(gossip_node_instance_token,     tvb(48,8))
    else
        error("unsupported data ID")
    end

    return tvb
end

-- Pops a gossip SocketAddr off tvb and appends a subtree to tree.
function solana_gossip_disect_socket_addr (entry, tvb, tree)
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

    return return_tvb, subtree
end

-- Pops a transaction off tvb and appends a subtree to tree.
function solana_gossip_disect_transaction (tvb, tree, name)
    local before_len = tvb:len()
    local subtree = tree:add(sol_transaction, tvb)

    local num_sigs = tvb(0,1):le_uint()
    tvb = tvb(1)
    for i=1,num_sigs,1 do
        subtree:add(sol_signature, tvb(0,64)):append_text(" #" .. i-1)
        tvb = tvb(64)
    end

    -- TODO support txn v0
    subtree:add_le(sol_tx_sigs_req,    tvb(0,1))
    subtree:add_le(sol_tx_signed_ro,   tvb(1,1))
    subtree:add_le(sol_tx_unsigned_ro, tvb(2,1))
    tvb = tvb(3)

    local num_keys = tvb(0,1):le_uint()
    tvb = tvb(1)
    for i=1,num_keys,1 do
        subtree:add(sol_pubkey, tvb(0,32)):append_text(" #" .. i-1)
        tvb = tvb(32)
    end

    subtree:add(sol_recent_blockhash, tvb(0,32))
    tvb = tvb(32)

    local num_invocs = tvb(0,1):le_uint()
    tvb = tvb(1)
    for i=1,num_invocs,1 do
        local invoc
        tvb, invoc = solana_disect_invoc (tvb, subtree)
        invoc:append_text(" #" .. i-1)
    end

    subtree:set_len(before_len - tvb:len())
    return tvb, subtree
end

-- Pops a transaction instruction off tvb and appends a subtree to tree.
function solana_disect_invoc (tvb, tree)
    local before_len = tvb:len()
    local subtree = tree:add(sol_invoc, tvb)

    subtree:add_le(sol_invoc_program_idx, tvb(0,1))
    tvb = tvb(1)

    local num_accs = tvb(0,1):le_uint()
    tvb = tvb(1)
    for i=1,num_accs,1 do
        subtree:add_le(sol_invoc_account_idx, tvb(0,1))
        tvb = tvb(1)
    end

    local data_len = tvb(0,1):le_uint()
    subtree:add(sol_invoc_data, tvb(1,data_len))
    tvb = tvb(1+data_len)

    subtree:set_len(before_len - tvb:len())
    return tvb, subtree
end
