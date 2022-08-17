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

local solana_proto = Proto("Solana.Core",    "Solana Core Protocol")
local gossip       = Proto("Solana.Gossip",  "Solana Gossip Protocol")
local shreds_proto = Proto("Solana.Shreds",  "Solana Shreds Protocol")
local entry_proto  = Proto("Solana.Entry",   "Solana Block Entries")
local repair_proto = Proto("Solana.Repair",  "Solana Repair Protocol")
local tpu_proto    = Proto("Solana.TPU.UDP", "Solana TPU Protocol (UDP)")

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

local gossip_epoch_slots_index        = ProtoField.uint8 ("solana.gossip.epoch_slots.index",        "Index")
local gossip_epoch_slots_slots        = ProtoField.none  ("solana.gossip.epoch_slots.slots",        "Slots")
local gossip_epoch_slots_first_slot   = ProtoField.uint64("solana.gossip.epoch_slots.first_slot",   "First Slot")
local gossip_epoch_slots_count        = ProtoField.uint64("solana.gossip.epoch_slots.count",        "Slot Count")
local gossip_epoch_slots_uncompressed = ProtoField.bytes ("solana.gossip.epoch_slots.uncompressed", "Uncompressed Data")
local gossip_epoch_slots_bitvec       = ProtoField.bytes ("solana.gossip.epoch_slots.bitvec",       "Bit vector")
local gossip_epoch_slots_bitvec_size  = ProtoField.uint64("solana.gossip.epoch_slots.bitvec",       "Bit vector size")
local gossip_epoch_slots_bitvec_ones  = ProtoField.uint64("solana.gossip.epoch_slots.bitvec",       "Bit vector ones")
local gossip_epoch_slots_flate2       = ProtoField.bytes ("solana.gossip.epoch_slots.flate2",       "Flate2 Data")

local sol_slot              = ProtoField.uint64("solana.slot",                "Slot")
local sol_transaction       = ProtoField.none  ("solana.tx",                  "Transaction")
local sol_signature         = ProtoField.bytes ("solana.sig",                 "Signature")
local sol_pubkey            = ProtoField.bytes ("solana.pubkey",              "Pubkey")
local sol_tx_sigs_req       = ProtoField.uint8 ("solana.tx.sigs_req",         "Required Signatures",      base.DEC)
local sol_tx_signed_ro      = ProtoField.uint8 ("solana.tx.sigs.ro",          "Signed read-only count",   base.DEC)
local sol_tx_unsigned_ro    = ProtoField.uint8 ("solana.tx.sigs.rw",          "Unsigned read-only count", base.DEC)
local sol_recent_blockhash  = ProtoField.bytes ("solana.tx.recent_blockhash", "Recent blockhash")
local sol_shred_version     = ProtoField.uint16("solana.shred_version",       "Shred Version")
local sol_invoc             = ProtoField.none  ("solana.insn",                "Instruction")
local sol_invoc_program_idx = ProtoField.uint8 ("solana.insn.program_index",  "Program Index", base.DEC)
local sol_invoc_account_idx = ProtoField.uint8 ("solana.insn.account_index",  "Account Index", base.DEC)
local sol_invoc_data        = ProtoField.bytes ("solana.insn.data",           "Data")

local shred_variant       = ProtoField.uint8 ("solana.shred.variant", "Shred Variant", base.HEX)
local shred_coding        = ProtoField.none  ("solana.shred.coding",  "Coding Shred")
local shred_data          = ProtoField.none  ("solana.shred.data",    "Data Shred")
local shred_index         = ProtoField.uint32("solana.shred.index",   "Shred Index")
local shred_version       = ProtoField.uint16("solana.shred.version", "Shred Version")
local shred_fec_set_index = ProtoField.uint32("solana.shred.fec_set", "FEC Set Index")

local shred_coding_num_data    = ProtoField.uint16("solana.shred.coding.num_data",   "Data Shred Count")
local shred_coding_num_coding  = ProtoField.uint16("solana.shred.coding.num_coding", "Coding Shred Count")
local shred_coding_position    = ProtoField.uint16("solana.shred.coding.position",   "Position")

local shred_data_parent_offset = ProtoField.uint16("solana.shred.data.parent_offset", "Parent Offset")
local shred_data_flags         = ProtoField.uint8 ("solana.shred.data.flags",         "Flags", base.HEX)
local shred_data_tick_ref      = ProtoField.uint8 ("solana.shred.data.ref_tick",      "Reference Tick")
local shred_data_complete      = ProtoField.bool  ("solana.shred.data.completed",     "Complete")
local shred_data_last          = ProtoField.bool  ("solana.shred.data.last",          "Last Shred in Slot")
local shred_data_size          = ProtoField.uint16("solana.shred.data.size",          "Size")
local shred_data_content       = ProtoField.bytes ("solana.shred.data.contents",      "Content")

local REPAIR_LEGACY_WINDOW_INDEX                    = 0
local REPAIR_LEGACY_HIGHEST_WINDOW_INDEX            = 1
local REPAIR_LEGACY_ORPHAN                          = 2
local REPAIR_LEGACY_WINDOW_INDEX_WITH_NONCE         = 3
local REPAIR_LEGACY_HIGHEST_WINDOW_INDEX_WITH_NONCE = 4
local REPAIR_LEGACY_ORPHAN_WITH_NONCE               = 5
local REPAIR_LEGACY_ANCESTOR_HASHES                 = 6
local REPAIR_PONG                                   = 7
local REPAIR_WINDOW_INDEX                           = 8
local REPAIR_HIGHEST_WINDOW_INDEX                   = 9
local REPAIR_ORPHAN                                 = 10
local REPAIR_ANCESTOR_HASHES                        = 11

local repair_message_id = ProtoField.uint32("solana.repair.message_id", "Message ID", base.DEC)
local repair_message_names = {
    [REPAIR_LEGACY_WINDOW_INDEX]                    = "LegacyWindowIndex",
    [REPAIR_LEGACY_HIGHEST_WINDOW_INDEX]            = "LegacyHighestWindowIndex",
    [REPAIR_LEGACY_ORPHAN]                          = "LegacyOrphan",
    [REPAIR_LEGACY_WINDOW_INDEX_WITH_NONCE]         = "LegacyWindowIndexWithNonce",
    [REPAIR_LEGACY_HIGHEST_WINDOW_INDEX_WITH_NONCE] = "LegacyHighestWindowIndexWithNonce",
    [REPAIR_LEGACY_ORPHAN_WITH_NONCE]               = "LegacyOrphanWithNonce",
    [REPAIR_LEGACY_ANCESTOR_HASHES]                 = "LegacyAncestorHashes",
    [REPAIR_PONG]                                   = "Pong",
    [REPAIR_WINDOW_INDEX]                           = "WindowIndex",
    [REPAIR_HIGHEST_WINDOW_INDEX]                   = "HighestWindowIndex",
    [REPAIR_ORPHAN]                                 = "Orphan",
    [REPAIR_ANCESTOR_HASHES]                        = "AncestorHashes",
}

local repair_shred_index = ProtoField.uint64("solana.repair.shred_index", "Shred Index")
local repair_nonce       = ProtoField.uint32("solana.repair.nonce",       "Nonce", base.HEX)
local repair_sender      = ProtoField.bytes ("solana.repair.sender",      "Sender")
local repair_recipient   = ProtoField.bytes ("solana.repair.recipient",   "Recipient")
local repair_timestamp   = ProtoField.uint64("solana.repair.timestamp",   "Timestamp")

local entry_hashes = ProtoField.uint64("solana.entry.num_hashes", "SHA-256 Iterations")
local entry_hash   = ProtoField.bytes ("solana.entry.hash",       "Entry Hash")

solana_proto.fields = {
    sol_slot,
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
}

gossip.fields = {
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
    -- CRDS EpochSlots
    gossip_epoch_slots_index,
    gossip_epoch_slots_slots,
    gossip_epoch_slots_first_slot,
    gossip_epoch_slots_count,
    gossip_epoch_slots_uncompressed,
    gossip_epoch_slots_bitvec,
    gossip_epoch_slots_bitvec_size,
    gossip_epoch_slots_bitvec_ones,
    gossip_epoch_slots_flate2,
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

shreds_proto.fields = {
    ------- Common Header
    shred_variant,
    shred_coding,
    shred_data,
    shred_index,
    shred_version,
    shred_fec_set_index,
    ------- Coding Header
    shred_coding_num_data,
    shred_coding_num_coding,
    shred_coding_position,
    ------- Data Header
    shred_data_parent_offset,
    shred_data_flags,
    shred_data_tick_ref,
    shred_data_complete,
    shred_data_last,
    shred_data_size,
    shred_data_content,
}

repair_proto.fields = {
    repair_message_id,
    repair_shred_index,
    repair_nonce,
    repair_sender,
    repair_recipient,
    repair_timestamp,
}

function gossip.dissector (tvb, pinfo, tree)
    pinfo.cols.protocol:set("SolGossip")
    local subtree = tree:add(gossip, tvb())

    local message_id = tvb(0,4):le_uint()
    local message_name = gossip_message_names[message_id] or "Unknown"
    subtree:add_le(gossip_message_id, tvb(0,4)):append_text(" (" .. message_name .. ")")
    tvb = tvb(4)

    subtree:set_text("Solana Gossip " .. message_name)

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

function shreds_proto.init ()
    -- Serves to reassemble messages
    --   table<slot, either<bool, table<index, msg>>>
    --
    -- table<3, true> means that slot 3 has been reassembled already
    -- msg is {bytes: <Data> off: <number>}
    fragments = {}
end

function shreds_proto.dissector (tvb, pinfo, tree)
    pinfo.cols.protocol:set("SolShred")
    local subtree = tree:add(gossip, tvb(), "Solana Shred")

    subtree:add(sol_signature, tvb(0,64))
    local variant_node = subtree:add(shred_variant, tvb(64,1))
    local variant = tvb(64,1):uint()
    subtree:add_le(sol_slot,            tvb(65,8))
    subtree:add_le(shred_index,         tvb(73,4))
    subtree:add_le(shred_version,       tvb(77,2))
    subtree:add_le(shred_fec_set_index, tvb(79,4))

    local _slot  = tvb(65,8):le_uint64()
    local _index = tvb(73,4):le_uint()
    local shred_desc = "Slot="  .. _slot ..
        " Index=" .. string.format("%04d", _index)

    tvb = tvb(83)
    if variant == 0xA5 then
        variant_node:append_text(" (Data)")
        pinfo.cols.info:set("Data Shred   " .. shred_desc)
        solana_disect_data_shred(tvb, pinfo, subtree, _slot, _index)
    elseif variant == 0x5A then
        variant_node:append_text(" (Coding)")
        pinfo.cols.info:set("Coding Shred " .. shred_desc)
        solana_disect_coding_shred(tvb, pinfo, subtree)
    else
        error("unsupported shred variant")
    end
end

function repair_proto.dissector (tvb, pinfo, tree)
    pinfo.cols.protocol:set("SolRepair")
    local subtree = tree:add(repair_proto, tvb())

    local message_id = tvb(0,4):le_uint()
    local message_name = repair_message_names[message_id] or "Unknown"
    subtree:add_le(repair_message_id, tvb(0,4)):append_text(" (" .. message_name .. ")")
    tvb = tvb(4)
    subtree:set_text("Solana Repair " .. message_name)

    if message_id == REPAIR_LEGACY_WINDOW_INDEX or message_id == REPAIR_LEGACY_HIGHEST_WINDOW_INDEX then
        tvb = solana_gossip_disect_contact_info(tvb, subtree)
        subtree:add_le(sol_slot,           tvb(0,8))
        subtree:add_le(repair_shred_index, tvb(8,8))
    elseif message_id == REPAIR_LEGACY_ORPHAN then
        tvb = solana_gossip_disect_contact_info(tvb, subtree)
        subtree:add_le(sol_slot,           tvb(0,8))
    elseif message_id == REPAIR_LEGACY_WINDOW_INDEX_WITH_NONCE or message_id == REPAIR_LEGACY_HIGHEST_WINDOW_INDEX_WITH_NONCE then
        tvb = solana_gossip_disect_contact_info(tvb, subtree)
        subtree:add_le(sol_slot,           tvb(0,8))
        subtree:add_le(repair_shred_index, tvb(8,8))
        subtree:add_le(repair_nonce,       tvb(16,4))
    elseif message_id == REPAIR_LEGACY_ORPHAN_WITH_NONCE or message_id == REPAIR_LEGACY_ANCESTOR_HASHES then
        tvb = solana_gossip_disect_contact_info(tvb, subtree)
        subtree:add_le(sol_slot,           tvb(0,8))
        subtree:add_le(repair_nonce,       tvb(8,4))
    elseif message_id == REPAIR_PONG then
        solana_gossip_disect_ping(tvb, subtree)
    elseif message_id == REPAIR_WINDOW_INDEX or message_id == REPAIR_HIGHEST_WINDOW_INDEX then
        tvb = solana_repair_disect_header(tvb, subtree)
        subtree:add_le(sol_slot,           tvb(0,8))
        subtree:add_le(repair_shred_index, tvb(8,8))
    elseif message_id == REPAIR_ORPHAN or message_id == REPAIR_ANCESTOR_HASHES then
        tvb = solana_repair_disect_header(tvb, subtree)
        subtree:add_le(sol_slot,           tvb(0,8))
    else
        error("unsupported repair request: " .. message_id)
    end
end

function tpu_proto.dissector (tvb, pinfo, tree)
    local subtree = tree:add(tpu_proto, tvb())
    solana_disect_transaction(tvb, tree)
end

function entry_proto.dissector (tvb, pinfo, tree)
    local tree = tree:add(entry_proto, tvb())

    pinfo.cols.protocol:set("SolEntry")
    tree:add(entry_hashes, tvb(0,8))
    if tvb(4,4):le_uint() ~= 0 then
        -- >2^32 serial SHA-256 hashes in double-digit milliseconds is probably impossible
        error("extreme hash count in entry, probably misaligned")
    end
    tree:add(entry_hash,   tvb(8,32))
    local num_txns = tvb(40,4):le_uint()
    if tvb(44,4):le_uint() ~= 0 or num_txns > 500000 then
        error("extreme tx count in entry, probably misaligned")
    end
    tvb = tvb(48)
    for i=1,num_txns,1 do
        local tx
        tvb, tx = solana_disect_transaction(tvb, tree)
        tvb:append_text(" #" .. i-1)
    end
end

-- Assuming base port 8000
local udp_port = DissectorTable.get("udp.port")
udp_port:add(8000, gossip)
udp_port:add(8001, shreds_proto)
udp_port:add(8002, shreds_proto)
udp_port:add(8003, tpu_proto)

-- Most nodes use these repair ports. Not reliable
udp_port:add(8008, repair_proto)
udp_port:add(8009, repair_proto)

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
        tvb = solana_gossip_disect_contact_info(tvb, tree)
    elseif data_id == GOSSIP_CRDS_VOTE then
        tree:add(gossip_vote_index, tvb(0,1))
        tree:add(gossip_vote_pubkey, tvb(1,32))
        tvb, tx = solana_disect_transaction(tvb(33), tree)
        tx:set_text("Vote Transaction")
        tree:add_le(gossip_wallclock, tvb(0,8))
        if tvb:len() > 8 then tvb = tvb(8) end
    elseif data_id == GOSSIP_CRDS_LOWEST_SLOT then
        tree:add_le(gossip_lowest_slot_index, tvb(0,1))
        tree:add   (gossip_pubkey, tvb(1,32))
        tree:add_le(gossip_lowest_slot_root, tvb(33,8))
        tree:add_le(gossip_lowest_slot_lowest, tvb(41,8))
        local num_slots = tvb(49,4):le_uint() -- uint64 broken
        local subtree
        if num_slots > 0 then
            subtree = tree:add(gossip_lowest_slot_slots, tvb(49,8+8*num_slots))
        end
        tvb = tvb(57)
        for i=1,num_slots,1 do
            subtree:add_le(gossip_lowest_slot_slot, tvb(0,8)):append_text(" #" .. i-1)
            tvb = tvb(8)
        end
        -- Skipping 8 bytes of Vec<deprecated::EpochIncompleteSlots>, which is deprecated
        tree:add_le(gossip_wallclock, tvb(8,8))
        if tvb:len() > 16 then tvb = tvb(16) end
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
            local subtree
            tvb, subtree = solana_gossip_disect_hash_event(tvb, tree)
            subtree:set_text(event_name)
        end
        tree:add_le(gossip_wallclock, tvb(0,8))
        if tvb:len() > 8 then tvb = tvb(8) end
    elseif data_id == GOSSIP_CRDS_EPOCH_SLOTS then
        tree:add(gossip_epoch_slots_index, tvb(0,1))
        tree:add(gossip_pubkey,            tvb(1,32))

        local num_entries = tvb(33,4):le_uint()
        tvb = tvb(41)
        for i=1,num_entries,1 do
            tvb, entry = solana_gossip_disect_compressed_slots(tvb, tree)
            entry:append_text(" #" .. i-1)
        end

        tree:add_le(gossip_wallclock, tvb(0,8))
        if tvb:len() > 8 then tvb = tvb(8) end
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
        if tvb:len() > 56 then tvb = tvb(56) end
    elseif data_id == GOSSIP_CRDS_INC_SNAPSHOT_HASHES then
        tree:add   (gossip_pubkey,    tvb(0,32))
        local event
        tvb, event = solana_gossip_disect_hash_event(tvb, tree)
        event:set_text("Base Snapshot")

        local num_hashes = tvb(0,4):le_uint()
        tvb = tvb(8)
        for i=1,num_hashes,1 do
            local event
            tvb, event = solana_gossip_disect_hash_event(tvb, tree)
            event:set_text("Incremental Snapshot #" .. i-1)
        end

        tree:add_le(gossip_wallclock, tvb(0,8))
        if tvb:len() > 8 then tvb = tvb(8) end
    else
        error("unsupported data ID")
    end

    return tvb
end

function solana_gossip_disect_contact_info (tvb, tree)
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
    if tvb:len() > 10 then tvb = tvb(10) end
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

function solana_gossip_disect_compressed_slots (tvb, tree)
    local before_len = tvb:len()
    local entry = tree:add(gossip_epoch_slots_slots, tvb)

    local compression_type = tvb(0,4):le_uint()
    entry:add_le(gossip_epoch_slots_first_slot, tvb(4,8))
    entry:add_le(gossip_epoch_slots_count,      tvb(12,8))
    tvb = tvb(20)

    if compression_type == 0 then
        -- Flate2-compressed
        local stream_len = tvb(0,4):le_uint()
        entry:add(gossip_epoch_slots_flate2, tvb(8,stream_len))
        tvb = tvb(8+stream_len)
    elseif compression_type == 1 then
        -- Uncompressed, BitVec with 1-byte blocks
        tvb = solana_gossip_disect_uncompressed_slots(tvb, entry)
    else
        error("unsupported compression type: " .. compression_type)
    end

    entry:set_len(before_len - tvb:len())
    return tvb, entry
end

function solana_gossip_disect_uncompressed_slots (tvb, tree)
    local before_len = tvb:len()
    local subtree = tree:add(gossip_epoch_slots_uncompressed, tvb)

    local has_bits = tvb(0,1):uint() == 1
    tvb = tvb(1)
    if has_bits then
        local count = tvb(0,4):le_uint()
        local bits = subtree:add(gossip_epoch_slots_bitvec, tvb(8,count))
        tvb = tvb(8+count)
    end
    subtree:add_le(gossip_epoch_slots_bitvec_size, tvb(0,8))
    subtree:add_le(gossip_epoch_slots_bitvec_ones, tvb(8,8))
    tvb = tvb(16)

    subtree:set_len(before_len - tvb:len())
    return tvb, subtree
end

function solana_gossip_disect_hash_event (tvb, tree)
    local subtree = tree:add(gossip_hash_event, tvb(0,40))
    subtree:add_le(gossip_hash_slot, tvb(0,8))
    subtree:add   (gossip_hash_hash, tvb(8,32))
    tvb = tvb(40)
    return tvb, subtree
end

-- Pops a transaction off tvb and appends a subtree to tree.
function solana_disect_transaction (tvb, tree, name)
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

function solana_disect_coding_shred (tvb, pinfo, tree)
    local subtree = tree:add(shred_coding, tvb)
    subtree:add_le(shred_coding_num_data,   tvb(0,2))
    subtree:add_le(shred_coding_num_coding, tvb(2,2))
    subtree:add_le(shred_coding_position,   tvb(4,2))
end

function solana_disect_data_shred (tvb, pinfo, tree, slot, index)
    local subtree = tree:add(shred_data, tvb)
    subtree:add_le(shred_data_parent_offset, tvb(0,2))
    local flags_node = subtree:add(shred_data_flags, tvb(2,1))
    subtree:add_le(shred_data_size,          tvb(3,2))
    local content_size = tvb(3,2):le_uint() - 88
    subtree:add_le(shred_data_content,       tvb(5,content_size))

    local flags       = tvb(2,1):uint()
    local tick_ref    = bit.band(flags, 0x3F)
    local is_complete = bit.band(flags, 0x40) ~= 0
    local is_last     = bit.band(flags, 0xC0) == 0xC0
    flags_node
        :add(shred_data_tick_ref, tvb(2,1), tick_ref)
        :set_generated()
    flags_node
        :add(shred_data_complete, tvb(2,1), is_complete)
        :set_generated()
    flags_node
        :add(shred_data_last, tvb(2,1), is_last)
        :set_generated()

    -- Do block reassembly
    if pinfo.visited then
        return
    end
    if fragments[slot] == nil then
        fragments[slot] = {}
    elseif fragments[slot] == true then
        return
    end
    if fragments[slot][index] == nil then
        fragments[slot][index] = {}
    else
        return
    end
    local frag = fragments[slot][index]
    frag.data = tvb(5,content_size):bytes()
    frag.off  = tvb(0,2):le_uint()

    if is_last then
        local message = ByteArray.new()
        local ptr = 0
        local frags = fragments[slot]
        fragments[slot] = true -- drop table and set placeholder
        for i=0,index,1 do
            local frag = frags[i]
            if frag ~= nil then
                if frag.off > ptr then
                    local zeros = ByteArray.new()
                    zeros:set_size(frag.off - ptr)
                    ptr = ptr + zeros:len()
                    message:append(zeros)
                end
                ptr = ptr + frag.data:len()
                message:append(frag.data)
            end
        end
        print("Reassembled slot " .. slot)
        entry_proto.dissector(message:tvb(), pinfo, tree)
    end
end

function solana_repair_disect_header (tvb, tree)
    tree:add   (sol_signature,    tvb(0,64))
    tree:add   (repair_sender,    tvb(64,32))
    tree:add   (repair_recipient, tvb(96,32))
    tree:add_le(repair_timestamp, tvb(128,8))
    tree:add_le(repair_nonce,     tvb(136,4))
    return tvb(140)
end
