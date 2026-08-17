#pragma once
// ============================================================================
// PSEUDO-GROUP PROTOCOL ON TOP OF TOX (current implementation)
// ============================================================================
//
// This is NOT a real Tox group chat (tox_group_*) - this is a protocol built
// on top of ordinary 1:1 Tox friendships (friend_number), where "group" is
// merely a convention maintained only by the logic of this file and by the
// admin_id field matching for all participants. The protocol below is
// described exactly as it is implemented NOW, including its deliberate
// limitations.
//
// ---- Identifiers ----
// - Full Tox ID = 76 hex characters (32 bytes of public key + 2 bytes of
//   NOSPAM + 2 bytes of checksum). It is used both as the participant ID
//   and as "the person being added" to join the group.
// - Until the full address is known (for example, an incoming friend request
//   provides only the public key), the participant is temporarily stored
//   under the 64-character pubkey; the full address is learned later
//   (update_peer_real_id) and is always verified against the already known
//   pubkey prefix rather than simply overwritten.
//
// ---- Wire message format ----
// One type byte + payload:
//   MSG_REQUEST_PEER_LIST = 2  -- payload: JSON {sender, admin_id}
//                                  (admin_id may be empty - meaning
//                                  "I don't have a group yet, I want to join")
//   MSG_PEER_LIST          = 3  -- payload: JSON {type, admin_id, sender, peers[]}
//   MSG_ADMIN_QUERY        = 4  -- payload: empty
//   MSG_ADMIN_RESPONSE     = 5  -- payload: 76-byte admin_tox_id
//   MSG_GROUP_MESSAGE      = 6  -- payload: JSON {type, message_id, sender,
//                                  time, message|cmd, admin_id, path[]}
//
// ---- Joining the group ----
// 1. A "group" = all nodes with the same admin_tox_id. Joining = an ordinary
//    Tox friend request to the tox_id of any group participant
//    (send_friend_request_to_peer, menu 5 / join_tox_id command-line argument).
// 2. Incoming friend requests (friend_request_callback) are ACCEPTED
//    AUTOMATICALLY, without asking the user, BUT only if the node already
//    has an admin_tox_id (i.e. the node already belongs to someone - it
//    founded the group via menu 6 or has already successfully joined one).
//    While admin_tox_id is empty, any unsolicited (not initiated by us)
//    friend requests are rejected - otherwise, whoever contacted us first
//    would win the race for the right to become "our" admin_id instead of
//    the actual target of the join operation.
// 3. After the friend connection is established, if should_request_list=true
//    (set for both outgoing and accepted incoming friends), the node
//    automatically sends MSG_REQUEST_PEER_LIST with its tox_id and its
//    (possibly empty) admin_id.
// 4. The request recipient (process_friend_message):
//    - verifies the tox_id claimed in the request against the actual,
//      cryptographically authenticated identity of the friend_number that
//      physically sent it (does not take the field at face value);
//    - responds with MSG_PEER_LIST only if the requester's admin_id is empty
//      (this is a genuine attempt to join) OR matches ours - if it already
//      claims a DIFFERENT, foreign admin_id from ours, then it already
//      belongs to another established group and has no reason to request
//      our list - such a request is simply ignored;
//    - in all other cases, responds with MSG_PEER_LIST - JSON containing
//      its own admin_id, its own sender (own tox_id), and a list of up to 10
//      known peers (sorted by XOR distance to the requester).
// 5. Processing an incoming peer_list (process_peer_list):
//    - The "sender" field is verified against the actual, cryptographically
//      authenticated tox_id of the friend_number that physically delivered
//      the message (rather than simply being trusted).
//    - If we do not yet have an admin_tox_id - take it from the list (this
//      is the moment of actual "joining the group").
//    - If admin_tox_id ALREADY exists and does NOT match the admin_id from
//      this list - the list is completely ignored (this is a foreign group;
//      we neither cache it nor send friend requests to its participants).
//    - Only if the list passes these checks - send our own friend request
//      for each new peer_id from it (cascading discovery of the remaining
//      group participants).
//
// ---- Group message exchange ----
// - send_group_message: builds a group_message JSON with message_id =
//   hash(sender + time_rounded_to_the_minute + text), path=[self],
//   and broadcasts it to 3 randomly selected connected friends (simple
//   gossip flooding, not a tree and not a centralized relay).
// - process_group_message on each node:
//   - message_id is used for deduplication (seen_message_ids, TTL
//     60s) - messages seen previously are not processed or
//     forwarded again.
//   - A message with a foreign admin_id (when ours is already set) is dropped
//     (rule 8) - this separates different groups from each other at the chat
//     level.
//   - The message is forwarded to all connected friends who are in neither
//     path nor blacklist, with self added to path (protection against
//     repeated forwarding in a loop).
//
// ---- Moderation (bans) ----
// - send_ban_command: only the current admin (ctx.admin_tox_id == own
//   tox_id) may initiate it; applies the ban locally immediately and
//   broadcasts a group_message with cmd="ban_id:<target>" to 3 random friends.
// - process_group_message on the recipient of the ban_id command:
//   - A "direct" ban = the message was delivered OVER THE TOX FRIENDSHIP
//     whose actual, cryptographically authenticated tox_id (found via
//     find_peer_by_friend_number using the actual friend_number, NOT the
//     sender string from the JSON) matches ctx.admin_tox_id. Only in this
//     case is the ban applied immediately.
//   - Otherwise (relay through someone else), the node does not trust it and
//     directly asks the real admin_id (via a Tox friend message) for
//     confirmation using cmd="checkban_id:<target>".
//   - The admin, upon receiving checkban_id, makes the decision itself and
//     sends the ban_id confirmation back to EXACTLY the friend_number that
//     physically sent the request (rather than to whoever claimed to be the
//     sender in the JSON).
//
// ---- Known limitations (deliberately not addressed at this stage) ----
// - There are no cryptographic signatures over any commands (ban_id,
//   admin assignment, etc.) - all protection is based on authentication at
//   the Tox connection level (friend_number <-> public key), rather than on
//   signatures over message contents.
// - blacklist is not explicitly synchronized when a new participant joins -
//   they learn about bans only from those group_message messages that reach
//   them after they come online.
// ============================================================================

#include <string>
#include <vector>
#include <set>
#include <map>
#include <sstream>
#include <algorithm>
#include <random>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <ctime>

#include <toxcore/tox.h>
#include "mini_json.h"

// Wire message types
enum MessageType {
    MSG_REQUEST_PEER_LIST = 2,
    MSG_PEER_LIST         = 3,
    MSG_ADMIN_QUERY       = 4,
    MSG_ADMIN_RESPONSE    = 5,
    MSG_GROUP_MESSAGE     = 6
};

struct PeerInfo {
    uint32_t friend_number = 0;
    std::string tox_id;  // FULL address (76 hex chars with NOSPAM)
    std::string name;
    uint32_t hash_distance = 0;
    bool connected = false;
    bool should_request_list = false;
    bool request_sent = false;
};

struct GroupContext {
    Tox *tox = nullptr;
    std::string admin_tox_id;
    std::vector<PeerInfo> peers;
    
    // message_id -> timestamp (for 60 second TTL)
    std::map<std::string, time_t> seen_message_ids;
    
    // Blacklist for moderation
    std::set<std::string> blacklist;
};

// ===== Hash/ID utilities =====

inline std::string get_own_tox_id(Tox *tox) {
    uint8_t bytes[TOX_ADDRESS_SIZE];
    tox_self_get_address(tox, bytes);
    char id_str[TOX_ADDRESS_SIZE * 2 + 1];
    for (int i = 0; i < TOX_ADDRESS_SIZE; i++) {
        sprintf(id_str + i * 2, "%02X", bytes[i]);
    }
    id_str[TOX_ADDRESS_SIZE * 2] = '\0';
    return std::string(id_str);
}

inline int tox_id_to_bytes(const std::string &id_str, uint8_t *bytes) {
    if (id_str.length() != (size_t)TOX_ADDRESS_SIZE * 2) {
        return -1;
    }
    for (int i = 0; i < TOX_ADDRESS_SIZE; i++) {
        unsigned int value = 0;
        if (sscanf(id_str.c_str() + i * 2, "%2x", &value) != 1) {
            return -1;
        }
        bytes[i] = (uint8_t)value;
    }
    return 0;
}

inline uint32_t calculate_hash_distance(const std::string &id1, const std::string &id2) {
    uint8_t bytes1[TOX_ADDRESS_SIZE];
    uint8_t bytes2[TOX_ADDRESS_SIZE];
    if (tox_id_to_bytes(id1, bytes1) != 0 || tox_id_to_bytes(id2, bytes2) != 0) {
        return UINT32_MAX;
    }
    uint32_t distance = 0;
    for (int i = 0; i < TOX_ADDRESS_SIZE; i++) {
        uint8_t value = bytes1[i] ^ bytes2[i];
        for (int bit = 0; bit < 8; bit++) {
            if (value & (1 << bit)) distance++;
        }
    }
    return distance;
}

// rule 4: message_id = hash(sender_id + time_truncated_to_minute + message text)
inline std::string compute_message_id(const std::string &sender_id, const std::string &message_text,
                                       time_t now = -1) {
    if (now == (time_t)-1) now = time(nullptr);
    time_t truncated = now - (now % 60);
    std::string hash_input = sender_id + std::to_string((long long)truncated) + message_text;
    uint8_t hash[TOX_HASH_LENGTH];
    tox_hash(hash, (const uint8_t *)hash_input.c_str(), hash_input.length());
    char hash_str[TOX_HASH_LENGTH * 2 + 1];
    for (int i = 0; i < TOX_HASH_LENGTH; i++) {
        sprintf(hash_str + i * 2, "%02X", hash[i]);
    }
    hash_str[TOX_HASH_LENGTH * 2] = '\0';
    return std::string(hash_str);
}

// ===== Peer management =====

inline PeerInfo *find_peer_by_friend_number(GroupContext &ctx, uint32_t friend_number) {
    for (auto &peer : ctx.peers) {
        if (peer.friend_number == friend_number) return &peer;
    }
    return nullptr;
}

inline PeerInfo *find_peer_by_tox_id(GroupContext &ctx, const std::string &tox_id) {
    for (auto &peer : ctx.peers) {
        if (peer.tox_id == tox_id) return &peer;
    }
    return nullptr;
}

inline PeerInfo *find_peer_by_public_key(GroupContext &ctx, const std::string &public_key_64chars) {
    if ((int)public_key_64chars.length() != TOX_PUBLIC_KEY_SIZE * 2) return nullptr;
    for (auto &peer : ctx.peers) {
        if ((int)peer.tox_id.length() >= TOX_PUBLIC_KEY_SIZE * 2) {
            if (peer.tox_id.substr(0, TOX_PUBLIC_KEY_SIZE * 2) == public_key_64chars) {
                return &peer;
            }
        }
    }
    return nullptr;
}

inline void add_peer(GroupContext &ctx, uint32_t friend_number, const std::string &tox_id,
                      const std::string &name, bool should_request_list = false) {
    if ((int)tox_id.length() != TOX_PUBLIC_KEY_SIZE * 2 && (int)tox_id.length() != TOX_ADDRESS_SIZE * 2) {
        printf("[ERROR] Invalid peer ID length: %zu (expected %d or %d)\n", 
               tox_id.length(), TOX_PUBLIC_KEY_SIZE * 2, TOX_ADDRESS_SIZE * 2);
        return;
    }

    if (find_peer_by_tox_id(ctx, tox_id)) {
        return;
    }

    PeerInfo peer;
    peer.friend_number = friend_number;
    peer.tox_id = tox_id;
    peer.name = name;
    peer.hash_distance = calculate_hash_distance(get_own_tox_id(ctx.tox), tox_id);
    peer.connected = false;
    peer.should_request_list = should_request_list;
    peer.request_sent = false;

    ctx.peers.push_back(peer);
}

// Update peer with real full Tox ID (containing NOSPAM) - called from MSG_ANNOUNCE_ID handler
inline void update_peer_real_id(GroupContext &ctx, uint32_t friend_number, const std::string &real_id) {
    if ((int)real_id.length() != TOX_ADDRESS_SIZE * 2) {
        printf("[WARN] update_peer_real_id: invalid ID length %zu\n", real_id.length());
        return;
    }

    PeerInfo *peer = find_peer_by_friend_number(ctx, friend_number);
    if (!peer) {
        // Add new peer with full address
        add_peer(ctx, friend_number, real_id, "Unknown", false);
        return;
    }

    if (peer->tox_id != real_id) {
        printf("[INFO] Updating peer %u address from %s to %s\n", friend_number, peer->tox_id.c_str(), real_id.c_str());
        peer->tox_id = real_id;
        peer->hash_distance = calculate_hash_distance(get_own_tox_id(ctx.tox), real_id);
    }
}

inline void remove_peer(GroupContext &ctx, uint32_t friend_number) {
    for (auto it = ctx.peers.begin(); it != ctx.peers.end(); ++it) {
        if (it->friend_number == friend_number) {
            ctx.peers.erase(it);
            return;
        }
    }
}

// ===== Message expiration (TTL = 60 seconds) =====

inline void purge_expired_message_ids(GroupContext &ctx) {
    time_t now = time(nullptr);
    for (auto it = ctx.seen_message_ids.begin(); it != ctx.seen_message_ids.end();) {
        if (now - it->second > 60) {
            it = ctx.seen_message_ids.erase(it);
        } else {
            ++it;
        }
    }
}

// ===== JSON builders =====

inline std::string build_peer_request(Tox *tox, const std::string &own_admin_tox_id) {
    JsonValue root = JsonValue::makeObject();
    root["sender"] = JsonValue::makeString(get_own_tox_id(tox));
    // May be empty - an empty admin_id means "I don't belong to a group
    // yet, I'm trying to join yours", which is the legitimate join case.
    root["admin_id"] = JsonValue::makeString(own_admin_tox_id);
    std::string json = root.dump();

    std::stringstream ss;
    ss << (char)MSG_REQUEST_PEER_LIST;
    ss << json;
    return ss.str();
}

// Peer list as JSON (not plain text like other responses)
inline std::string build_peer_list_message(GroupContext &ctx, const std::string &target_tox_id) {
    if ((int)target_tox_id.length() != TOX_ADDRESS_SIZE * 2) {
        printf("[ERROR] build_peer_list_message: invalid target ID length\n");
        return std::string(1, (char)MSG_PEER_LIST);
    }

    // Sort by hash distance to target
    std::vector<PeerInfo> sorted_peers = ctx.peers;
    std::sort(sorted_peers.begin(), sorted_peers.end(),
              [&target_tox_id](const PeerInfo &a, const PeerInfo &b) {
                  uint32_t dist_a = calculate_hash_distance(a.tox_id, target_tox_id);
                  uint32_t dist_b = calculate_hash_distance(b.tox_id, target_tox_id);
                  return dist_a < dist_b;
              });

    JsonValue root = JsonValue::makeObject();
    root["type"] = JsonValue::makeString("peer_list");
    root["admin_id"] = JsonValue::makeString(ctx.admin_tox_id);
    root["sender"] = JsonValue::makeString(get_own_tox_id(ctx.tox));

    JsonValue peersArray = JsonValue::makeArray();
    int count = 0;
    for (const auto &peer : sorted_peers) {
        if (count >= 10) break;
        if (peer.tox_id == target_tox_id) continue;
        // Only include peers with full address (76 chars)
        if ((int)peer.tox_id.length() != TOX_ADDRESS_SIZE * 2) continue;

        JsonValue peerObj = JsonValue::makeObject();
        peerObj["tox_id"] = JsonValue::makeString(peer.tox_id);
        peerObj["name"] = JsonValue::makeString(peer.name);
        peerObj["online"] = JsonValue::makeBool(peer.connected);
        peersArray.arr.push_back(peerObj);
        count++;
    }
    root["peers"] = peersArray;

    std::string json = root.dump();
    std::stringstream ss;
    ss << (char)MSG_PEER_LIST;
    ss << json;
    return ss.str();
}

inline std::string build_admin_response(const GroupContext &ctx) {
    std::stringstream ss;
    ss << (char)MSG_ADMIN_RESPONSE;
    ss << ctx.admin_tox_id;
    return ss.str();
}

// Group message JSON - time is NUMBER (double timestamp), NOT string
inline std::string build_group_message_json(const std::string &message_id, const std::string &sender,
                                             const std::string &message, const std::vector<std::string> &path,
                                             const std::string &admin_id, time_t timestamp) {
    JsonValue root = JsonValue::makeObject();
    root["type"] = JsonValue::makeString("group_message");
    root["message_id"] = JsonValue::makeString(message_id);
    root["sender"] = JsonValue::makeString(sender);
    root["time"] = JsonValue::makeNumber((double)timestamp);  // NUMBER, not string
    root["message"] = JsonValue::makeString(message);
    root["admin_id"] = JsonValue::makeString(admin_id);

    JsonValue pathArray = JsonValue::makeArray();
    for (const auto &p : path) {
        pathArray.arr.push_back(JsonValue::makeString(p));
    }
    root["path"] = pathArray;

    return root.dump();
}

// Group message with command (ban_id, checkban_id, etc)
inline std::string build_group_command_json(const std::string &message_id, const std::string &sender,
                                             const std::string &cmd, const std::vector<std::string> &path,
                                             const std::string &admin_id, time_t timestamp) {
    JsonValue root = JsonValue::makeObject();
    root["type"] = JsonValue::makeString("group_message");
    root["message_id"] = JsonValue::makeString(message_id);
    root["sender"] = JsonValue::makeString(sender);
    root["time"] = JsonValue::makeNumber((double)timestamp);
    root["cmd"] = JsonValue::makeString(cmd);
    root["admin_id"] = JsonValue::makeString(admin_id);

    JsonValue pathArray = JsonValue::makeArray();
    for (const auto &p : path) {
        pathArray.arr.push_back(JsonValue::makeString(p));
    }
    root["path"] = pathArray;

    return root.dump();
}

// ===== Outbound actions =====

inline void send_friend_request_to_peer(GroupContext &ctx, const std::string &tox_id) {
    if ((int)tox_id.length() != TOX_ADDRESS_SIZE * 2) {
        printf("[ERROR] send_friend_request_to_peer: Invalid ID length %zu\n", tox_id.length());
        return;
    }

    if (find_peer_by_tox_id(ctx, tox_id)) {
        return;
    }

    uint8_t bytes[TOX_ADDRESS_SIZE];
    if (tox_id_to_bytes(tox_id, bytes) != 0) {
        printf("[ERROR] Invalid Tox ID format\n");
        return;
    }

    Tox_Err_Friend_Add err;
    uint32_t friend_number = tox_friend_add(ctx.tox, bytes, (const uint8_t *)"Join group", 10, &err);

    if (err == TOX_ERR_FRIEND_ADD_OK) {
        add_peer(ctx, friend_number, tox_id, "Unknown", true);
        printf("[SEND] Friend request sent: %s\n", tox_id.c_str());
    } else {
        printf("[WARN] Could not add peer, error: %d\n", (int)err);
    }
}

inline void send_group_message(GroupContext &ctx, const std::string &text) {
    std::string own_tox_id = get_own_tox_id(ctx.tox);
    time_t now = time(nullptr);
    std::string message_id = compute_message_id(own_tox_id, text, now);

    std::vector<std::string> path;
    path.push_back(own_tox_id);

    ctx.seen_message_ids[message_id] = now;

    std::string json = build_group_message_json(message_id, own_tox_id, text, path, ctx.admin_tox_id, now);
    std::string payload;
    payload += (char)MSG_GROUP_MESSAGE;
    payload += json;

    // Send to up to 3 connected peers
    std::vector<PeerInfo *> connected_peers;
    for (auto &peer : ctx.peers) {
        if (peer.connected && (int)peer.tox_id.length() == TOX_ADDRESS_SIZE * 2) {
            connected_peers.push_back(&peer);
        }
    }

    if (connected_peers.empty()) {
        printf("[WARN] No connected peers\n");
        return;
    }

    std::random_device rd;
    std::mt19937 rng(rd());
    std::shuffle(connected_peers.begin(), connected_peers.end(), rng);

    int sent = 0;
    for (auto *peer : connected_peers) {
        if (sent >= 3) break;
        Tox_Err_Friend_Send_Message err;
        tox_friend_send_message(ctx.tox, peer->friend_number, TOX_MESSAGE_TYPE_NORMAL,
                                 (const uint8_t *)payload.c_str(), payload.length(), &err);
        if (err == TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
            sent++;
        }
    }
}

inline void request_admin_from_friend(GroupContext &ctx, uint32_t friend_number) {
    std::string request;
    request += (char)MSG_ADMIN_QUERY;
    Tox_Err_Friend_Send_Message err;
    tox_friend_send_message(ctx.tox, friend_number, TOX_MESSAGE_TYPE_NORMAL,
                             (const uint8_t *)request.c_str(), request.length(), &err);
}

inline void remove_peer_from_friends(GroupContext &ctx, uint32_t friend_number) {
    Tox_Err_Friend_Delete err;
    tox_friend_delete(ctx.tox, friend_number, &err);
    if (err == TOX_ERR_FRIEND_DELETE_OK) {
        printf("[MOD] Removed friend #%u\n", friend_number);
    }
}

// Admin sends ban command to group
inline void send_ban_command(GroupContext &ctx, const std::string &target_id) {
    // Only admin can ban
    if (ctx.admin_tox_id != get_own_tox_id(ctx.tox)) {
        printf("[ERROR] Only admin can ban\n");
        return;
    }

    if ((int)target_id.length() != TOX_ADDRESS_SIZE * 2) {
        printf("[ERROR] Invalid target ID length\n");
        return;
    }

    std::string own_id = get_own_tox_id(ctx.tox);
    time_t now = time(nullptr);
    std::string cmd = "ban_id:" + target_id;
    std::string message_id = compute_message_id(own_id, cmd, now);

    std::vector<std::string> path;
    path.push_back(own_id);

    ctx.seen_message_ids[message_id] = now;
    ctx.blacklist.insert(target_id);

    // Remove the banned peer from friends
    PeerInfo *peer = find_peer_by_tox_id(ctx, target_id);
    if (peer) {
        remove_peer_from_friends(ctx, peer->friend_number);
        remove_peer(ctx, peer->friend_number);
    }

    std::string json = build_group_command_json(message_id, own_id, cmd, path, ctx.admin_tox_id, now);
    std::string payload;
    payload += (char)MSG_GROUP_MESSAGE;
    payload += json;

    // Send to 3 connected peers
    std::vector<PeerInfo *> connected;
    for (auto &p : ctx.peers) {
        if (p.connected && (int)p.tox_id.length() == TOX_ADDRESS_SIZE * 2) {
            connected.push_back(&p);
        }
    }

    std::random_device rd;
    std::mt19937 rng(rd());
    std::shuffle(connected.begin(), connected.end(), rng);

    int sent = 0;
    for (auto *p : connected) {
        if (sent >= 3) break;
        Tox_Err_Friend_Send_Message err;
        tox_friend_send_message(ctx.tox, p->friend_number, TOX_MESSAGE_TYPE_NORMAL,
                                 (const uint8_t *)payload.c_str(), payload.length(), &err);
        if (err == TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
            sent++;
            printf("[SEND] Ban command sent to: %s\n", p->tox_id.c_str());
        }
    }
}

// ===== Inbound processing =====

inline void process_peer_list(GroupContext &ctx, uint32_t friend_number, const std::string &json_str) {
    JsonValue root = JsonValue::parse(json_str);
    if (!root.isObject()) {
        printf("[WARN] Malformed peer list\n");
        return;
    }

    std::string admin_id, sender;
    if (const JsonValue *v = root.find("admin_id"); v && v->isString()) admin_id = v->asString();
    if (const JsonValue *v = root.find("sender"); v && v->isString()) sender = v->asString();

    // Verify the declared "sender" against the real, Tox-authenticated
    // identity of whoever delivered this (friend_number), not just take
    // their word for it. If we only know them by 64-char pubkey so far,
    // a matching prefix lets us safely learn their full 76-char address
    // (that's them telling us their own NOSPAM suffix, which can't be
    // forged without the matching private key). If we already know their
    // full address and it conflicts with the declared sender, something
    // is wrong - drop the message.
    if ((int)sender.length() == TOX_ADDRESS_SIZE * 2) {
        PeerInfo *peer = find_peer_by_friend_number(ctx, friend_number);
        if (peer) {
            if ((int)peer->tox_id.length() == TOX_PUBLIC_KEY_SIZE * 2 &&
                sender.substr(0, TOX_PUBLIC_KEY_SIZE * 2) == peer->tox_id) {
                update_peer_real_id(ctx, friend_number, sender);
            } else if ((int)peer->tox_id.length() == TOX_ADDRESS_SIZE * 2 && peer->tox_id != sender) {
                printf("[WARN] peer_list sender field doesn't match the real connection identity, ignoring\n");
                return;
            }
        }
    }

    // A peer_list only speaks for ITS sender's own group. If we already
    // belong to one (admin_tox_id set), a list whose declared admin_id
    // doesn't match ours is from a different group entirely - accepting
    // it would leak our group's presence to strangers (we'd friend-request
    // every member of a group we're not part of, and they'd do the same
    // back at us). Only while we don't have an admin yet (i.e. we are
    // actively joining) is a fresh list allowed to establish one.
    if (!ctx.admin_tox_id.empty()) {
        if (admin_id != ctx.admin_tox_id) {
            printf("[INFO] Ignoring peer_list from a different group (admin mismatch)\n");
            return;
        }
    } else if ((int)admin_id.length() == TOX_ADDRESS_SIZE * 2) {
        ctx.admin_tox_id = admin_id;
        printf("[INFO] Admin ID: %s\n", admin_id.c_str());
    } else {
        // No admin declared and we don't have one yet - nothing
        // trustworthy to act on.
        return;
    }

    // Add peers from list
    if (const JsonValue *v = root.find("peers"); v && v->isArray()) {
        for (const auto &peer_obj : v->arr) {
            if (!peer_obj.isObject()) continue;

            std::string peer_id, peer_name;
            bool peer_online = false;

            if (const JsonValue *id = peer_obj.find("tox_id"); id && id->isString()) {
                peer_id = id->asString();
            }
            if (const JsonValue *name = peer_obj.find("name"); name && name->isString()) {
                peer_name = name->asString();
            }
            if (const JsonValue *online = peer_obj.find("online"); online && online->isBool()) {
                peer_online = online->asBool();
            }

            if ((int)peer_id.length() == TOX_ADDRESS_SIZE * 2) {
                if (!find_peer_by_tox_id(ctx, peer_id)) {
                    send_friend_request_to_peer(ctx, peer_id);
                }
            }
        }
    }
}

inline void process_group_message(GroupContext &ctx, uint32_t friend_number, const std::string &json_str) {
    JsonValue root = JsonValue::parse(json_str);
    if (!root.isObject()) {
        printf("[WARN] Malformed group message\n");
        return;
    }

    std::string message_id, sender, text, cmd, admin_id;
    time_t msg_time = 0;
    std::vector<std::string> path;

    if (const JsonValue *v = root.find("message_id"); v && v->isString()) message_id = v->asString();
    if (const JsonValue *v = root.find("sender"); v && v->isString()) sender = v->asString();
    if (const JsonValue *v = root.find("message"); v && v->isString()) text = v->asString();
    if (const JsonValue *v = root.find("cmd"); v && v->isString()) cmd = v->asString();
    if (const JsonValue *v = root.find("admin_id"); v && v->isString()) admin_id = v->asString();
    if (const JsonValue *v = root.find("time"); v && v->isNumber()) msg_time = (time_t)v->asNumber();

    if (const JsonValue *v = root.find("path"); v && v->isArray()) {
        for (const auto &p : v->arr) {
            if (p.isString()) path.push_back(p.asString());
        }
    }

    // Check if already seen
    purge_expired_message_ids(ctx);
    if (ctx.seen_message_ids.count(message_id) > 0) {
        return;
    }
    ctx.seen_message_ids[message_id] = time(nullptr);

    // Update peer with full address if in sender field
    if ((int)sender.length() == TOX_ADDRESS_SIZE * 2) {
        PeerInfo *peer = find_peer_by_tox_id(ctx, sender);
        if (!peer) {
            std::string pubkey = sender.substr(0, TOX_PUBLIC_KEY_SIZE * 2);
            peer = find_peer_by_public_key(ctx, pubkey);
            if (peer) {
                update_peer_real_id(ctx, peer->friend_number, sender);
            }
        }
    }

    // rule 8: only forward if admin_id matches ours (if we have one set)
    if (!ctx.admin_tox_id.empty() && admin_id != ctx.admin_tox_id) {
        printf("[INFO] Ignoring message with different admin_id\n");
        return;
    }

    // Who ACTUALLY delivered this message, per Tox's own crypto layer.
    // friend_number comes straight from tox_callback_friend_message and
    // cannot be spoofed without owning that friend's private key - unlike
    // the "sender"/"admin_id" fields above, which are just strings the
    // remote client typed into the JSON. All trust decisions must be based
    // on this, not on self-declared fields.
    PeerInfo *immediate_peer = find_peer_by_friend_number(ctx, friend_number);
    std::string real_sender = immediate_peer ? immediate_peer->tox_id : std::string();
    bool from_real_admin = !ctx.admin_tox_id.empty() &&
                           (int)real_sender.length() == TOX_ADDRESS_SIZE * 2 &&
                           real_sender == ctx.admin_tox_id;

    // ===== Moderation commands =====
    if (cmd.length() > 7 && cmd.substr(0, 7) == "ban_id:") {
        std::string target_id = cmd.substr(7);
        printf("[MOD] Ban command received for: %s (claimed sender: %s, real sender: %s)\n",
               target_id.c_str(), sender.c_str(), real_sender.c_str());

        // moderation rule 3: direct from admin = delivered over the Tox
        // friend connection whose OWN crypto identity is the admin's -
        // NOT a message that merely claims sender == admin_id in its JSON.
        if (from_real_admin) {
            // Direct from admin
            printf("[MOD] Ban is directly from admin (verified via Tox friend identity), applying immediately\n");
            
            ctx.blacklist.insert(target_id);
            
            // Remove banned peer from friends
            PeerInfo *peer = find_peer_by_tox_id(ctx, target_id);
            if (peer) {
                remove_peer_from_friends(ctx, peer->friend_number);
                remove_peer(ctx, peer->friend_number);
            }

            // Don't forward direct admin bans, just apply
            return;
        } else {
            // moderation rule 4: if relayed (not direct), ask admin to confirm
            printf("[MOD] Ban is relayed, asking admin to confirm\n");
            
            // Send checkban_id directly to admin
            std::string own_id = get_own_tox_id(ctx.tox);
            time_t now = time(nullptr);
            std::string check_cmd = "checkban_id:" + target_id;
            std::string check_msg_id = compute_message_id(own_id, check_cmd, now);

            std::vector<std::string> direct_path;
            direct_path.push_back(own_id);

            ctx.seen_message_ids[check_msg_id] = now;

            std::string check_json = build_group_command_json(check_msg_id, own_id, check_cmd, 
                                                               direct_path, admin_id, now);
            std::string check_payload;
            check_payload += (char)MSG_GROUP_MESSAGE;
            check_payload += check_json;

            // Send direct message to admin
            PeerInfo *admin_peer = nullptr;
            for (auto &p : ctx.peers) {
                if (p.tox_id == admin_id) {
                    admin_peer = &p;
                    break;
                }
            }

            if (admin_peer && admin_peer->connected) {
                Tox_Err_Friend_Send_Message err;
                tox_friend_send_message(ctx.tox, admin_peer->friend_number, TOX_MESSAGE_TYPE_NORMAL,
                                         (const uint8_t *)check_payload.c_str(), check_payload.length(), &err);
                printf("[SEND] checkban_id sent to admin\n");
            }

            // Still forward the ban to others for now (they will also ask admin)
        }
    }

    if (cmd.length() > 10 && cmd.substr(0, 10) == "checkban_id:") {
        std::string target_id = cmd.substr(10);
        printf("[MOD] Ban check requested for: %s by %s\n", target_id.c_str(), sender.c_str());

        // Only admin should respond
        if (ctx.admin_tox_id == get_own_tox_id(ctx.tox)) {
            printf("[MOD] We are admin, confirming ban\n");
            
            // Send confirmation back to requester
            std::string own_id = get_own_tox_id(ctx.tox);
            time_t now = time(nullptr);
            std::string ban_cmd = "ban_id:" + target_id;
            std::string ban_msg_id = compute_message_id(own_id, ban_cmd, now);

            std::vector<std::string> direct_path;
            direct_path.push_back(own_id);

            ctx.seen_message_ids[ban_msg_id] = now;

            // Apply ban locally
            ctx.blacklist.insert(target_id);
            PeerInfo *peer = find_peer_by_tox_id(ctx, target_id);
            if (peer) {
                remove_peer_from_friends(ctx, peer->friend_number);
                remove_peer(ctx, peer->friend_number);
            }

            std::string ban_json = build_group_command_json(ban_msg_id, own_id, ban_cmd, 
                                                             direct_path, ctx.admin_tox_id, now);
            std::string ban_payload;
            ban_payload += (char)MSG_GROUP_MESSAGE;
            ban_payload += ban_json;

            // Send ban confirmation directly back to whoever actually
            // delivered this checkban_id (friend_number), not to a peer
            // looked up via the self-declared "sender" field in the JSON.
            Tox_Err_Friend_Send_Message err;
            tox_friend_send_message(ctx.tox, friend_number, TOX_MESSAGE_TYPE_NORMAL,
                                     (const uint8_t *)ban_payload.c_str(), ban_payload.length(), &err);
            printf("[SEND] Ban confirmation sent\n");
        }

        // Don't display or forward checkban_id
        return;
    }

    // Regular message
    if (!text.empty()) {
        printf("\n[GROUP] %s: %s\n", sender.c_str(), text.c_str());
    }

    // Forward to connected peers not in path and not blacklisted
    std::string own_id = get_own_tox_id(ctx.tox);
    if (std::find(path.begin(), path.end(), own_id) == path.end()) {
        path.push_back(own_id);
    }

    std::string forward_json = text.empty()
        ? build_group_command_json(message_id, sender, cmd, path, admin_id, msg_time)
        : build_group_message_json(message_id, sender, text, path, admin_id, msg_time);

    std::string forward_payload;
    forward_payload += (char)MSG_GROUP_MESSAGE;
    forward_payload += forward_json;

    for (auto &peer : ctx.peers) {
        if (!peer.connected) continue;
        if (ctx.blacklist.count(peer.tox_id) > 0) continue;
        if (std::find(path.begin(), path.end(), peer.tox_id) != path.end()) continue;

        Tox_Err_Friend_Send_Message err;
        tox_friend_send_message(ctx.tox, peer.friend_number, TOX_MESSAGE_TYPE_NORMAL,
                                 (const uint8_t *)forward_payload.c_str(), forward_payload.length(), &err);
    }
}

inline void process_friend_message(GroupContext &ctx, uint32_t friend_number, const uint8_t *message, size_t length) {
    if (length < 1) return;

    MessageType type = (MessageType)message[0];
    const char *payload = (const char *)(message + 1);
    size_t payload_length = length - 1;

    // MSG_REQUEST_PEER_LIST: payload is JSON {sender, admin_id}
    if (type == MSG_REQUEST_PEER_LIST) {
        std::string json_str(payload, payload_length);
        JsonValue root = JsonValue::parse(json_str);
        if (!root.isObject()) return;

        std::string target_id, requester_admin_id;
        if (const JsonValue *v = root.find("sender"); v && v->isString()) target_id = v->asString();
        if (const JsonValue *v = root.find("admin_id"); v && v->isString()) requester_admin_id = v->asString();

        if ((int)target_id.length() != TOX_ADDRESS_SIZE * 2) return;

        // Verify the claimed sender against the real, Tox-authenticated
        // identity of friend_number - same pattern as everywhere else in
        // this file. Safe upgrade from pubkey to full address on a
        // matching prefix; reject on a conflicting full address.
        PeerInfo *peer = find_peer_by_friend_number(ctx, friend_number);
        if (peer) {
            if ((int)peer->tox_id.length() == TOX_PUBLIC_KEY_SIZE * 2 &&
                target_id.substr(0, TOX_PUBLIC_KEY_SIZE * 2) == peer->tox_id) {
                update_peer_real_id(ctx, friend_number, target_id);
            } else if ((int)peer->tox_id.length() == TOX_ADDRESS_SIZE * 2 && peer->tox_id != target_id) {
                printf("[WARN] peer_list request sender doesn't match the real connection identity, ignoring\n");
                return;
            }
        }

        // Only answer if the requester has no group yet (empty admin_id -
        // a genuine join attempt) or already declares OUR admin_id.
        // A requester who already belongs to a different, established
        // group has no legitimate reason to be asking for ours.
        if (!requester_admin_id.empty() && requester_admin_id != ctx.admin_tox_id) {
            printf("[INFO] Ignoring peer_list request from a different group (admin mismatch)\n");
            return;
        }

        printf("[RECV] Peer list request from: %s\n", target_id.c_str());

        std::string response = build_peer_list_message(ctx, target_id);
        Tox_Err_Friend_Send_Message err;
        tox_friend_send_message(ctx.tox, friend_number, TOX_MESSAGE_TYPE_NORMAL,
                                 (const uint8_t *)response.c_str(), response.length(), &err);
        return;
    }

    // MSG_PEER_LIST
    if (type == MSG_PEER_LIST) {
        std::string json_str(payload, payload_length);
        process_peer_list(ctx, friend_number, json_str);
        return;
    }

    // MSG_ADMIN_QUERY
    if (type == MSG_ADMIN_QUERY) {
        std::string response = build_admin_response(ctx);
        Tox_Err_Friend_Send_Message err;
        tox_friend_send_message(ctx.tox, friend_number, TOX_MESSAGE_TYPE_NORMAL,
                                 (const uint8_t *)response.c_str(), response.length(), &err);
        return;
    }

    // MSG_ADMIN_RESPONSE
    if (type == MSG_ADMIN_RESPONSE) {
        if (payload_length == (size_t)TOX_ADDRESS_SIZE * 2) {
            ctx.admin_tox_id.assign(payload, payload_length);
            printf("[INFO] Admin ID: %s\n", ctx.admin_tox_id.c_str());
        }
        return;
    }

    // MSG_GROUP_MESSAGE
    if (type == MSG_GROUP_MESSAGE) {
        std::string json_str(payload, payload_length);
        process_group_message(ctx, friend_number, json_str);
        return;
    }
}

// ===== Tox callbacks =====

inline void friend_request_callback(Tox *tox, const uint8_t *public_key, const uint8_t *message, size_t length, void *user_data) {
    GroupContext *ctx = static_cast<GroupContext *>(user_data);

    // Build temporary 64-char ID from public key
    char temp_id[TOX_PUBLIC_KEY_SIZE * 2 + 1];
    for (int i = 0; i < TOX_PUBLIC_KEY_SIZE; i++) {
        sprintf(temp_id + i * 2, "%02X", public_key[i]);
    }
    temp_id[TOX_PUBLIC_KEY_SIZE * 2] = '\0';

    // While we don't have an admin yet, we're either about to found a
    // group (admin gets set locally, before any network activity) or
    // mid-join, waiting on a peer_list from the one specific tox_id we
    // deliberately friended. In neither case is an UNSOLICITED incoming
    // friend request a legitimate source of group/admin info - accepting
    // it would let whoever friends us first win the admin_tox_id race,
    // regardless of whether they're the peer we actually meant to join.
    // So: no admin yet -> no auto-accept of requests we didn't initiate.
    if (ctx->admin_tox_id.empty()) {
        printf("[SECURITY] Rejecting unsolicited friend request from %s - no admin/group set yet\n", temp_id);
        return;
    }

    printf("[RECV] Friend request from (public key): %s\n", temp_id);

    Tox_Err_Friend_Add err;
    uint32_t friend_number = tox_friend_add_norequest(tox, public_key, &err);

    if (err == TOX_ERR_FRIEND_ADD_OK) {
        add_peer(*ctx, friend_number, std::string(temp_id), "Unknown", true);
    }
}

inline void friend_message_callback(Tox *, uint32_t friend_number, Tox_Message_Type type, const uint8_t *message, size_t length, void *user_data) {
    GroupContext *ctx = static_cast<GroupContext *>(user_data);
    if (type != TOX_MESSAGE_TYPE_NORMAL) return;
    process_friend_message(*ctx, friend_number, message, length);
}

inline void friend_connection_status_callback(Tox *tox, uint32_t friend_number, Tox_Connection connection_status, void *user_data) {
    GroupContext *ctx = static_cast<GroupContext *>(user_data);
    PeerInfo *peer = find_peer_by_friend_number(*ctx, friend_number);

    if (connection_status != TOX_CONNECTION_NONE) {
        printf("[EVENT] Friend %u connected\n", friend_number);

        if (peer) {
            peer->connected = true;

            // Send peer list request if needed (will receive full address in response)
            if (peer->should_request_list && !peer->request_sent) {
                std::string request = build_peer_request(tox, ctx->admin_tox_id);
                Tox_Err_Friend_Send_Message err;
                tox_friend_send_message(tox, friend_number, TOX_MESSAGE_TYPE_NORMAL,
                                         (const uint8_t *)request.c_str(), request.length(), &err);
                peer->request_sent = true;
            }
        }
    } else {
        printf("[EVENT] Friend %u disconnected\n", friend_number);
        if (peer) peer->connected = false;
    }
}

inline void self_connection_status_callback(Tox *, Tox_Connection connection_status, void *) {
    if (connection_status != TOX_CONNECTION_NONE) {
        printf("[EVENT] Connected to Tox DHT\n");
    } else {
        printf("[EVENT] Disconnected from Tox DHT\n");
    }
}