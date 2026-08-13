/*
PROTOCOL - THESE POINTS MUST BE FOLLOWED WHEN MODIFYING THE CODE
1) Every node has a standard tox_id - this will be the ID for joining the group
2) That is, when someone sends a friend request (node A), we automatically accept it (node B)
3) After accepting a friend (node A), the friend (node B) sends a message request to node A asking for a list of others and the known admin name
4) In response to the request (node A), we send it our list of friends (online if possible) and the known admin name (up to 10 people, if there are that many) with the closest hash-distance to this joined friend (node B) - we add this list as a friend and set the received admin name
5) B itself should not be considered a friend of A, which should be Include in this list.
6) When node B has added a friend, it begins adding other friends from the list.
7) Each participant can request information from any other participant about who the admin is and receive their ID in response.
8) Each participant has the right to consider any other participant or themselves as the admin.
Mechanism for sending messages to a group
0) All messages in JSON format {"type":"group_message","message_id":"...","sender":"...","time":"...","message":"...","path":["...","..."],"admin_id":"..."}
or {"type":"group_message","message_id":"...","sender":"...","time":"...","cmd":"...","path":["...","..."],"admin_id":"..."}
1) admin_id is required when sending
2) time - sending time
3) When sending a message to a group, it is sent to any 3 known nodes in the group
4) The JSON message packet must contain the sender ID, the message itself, a list of nodes the message passed through, and a unique message ID
5) The unique message ID is the hash of the sum of the sender ID, the current time without seconds, and the message itself )
*6) Each node stores all forwarded message IDs for one minute. When forwarding, the uniqueness of the message ID is checked and it is not forwarded if there has already been a message with the same ID.
7) When a node receives a message, it forwards it to those nodes not on the list containing the message itself, adding its own ID to the list.
8) If the admin_id in the forwarded message does not match the one known to the node, the message is not forwarded.
Moderation
1) All nodes have their own list of node IDs from which messages are not forwarded and to which they are not forwarded (blacklist).
2) To ban someone, the admin in the group sends {...,"cmd":"ban_id:xxxxxxxxxx",...}
3) Everyone who received {...,"cmd":"ban_id:xxxxxxxxxx",...} must add the admin as a friend directly if they haven't already. 4) If {...,"cmd":"ban_id:xxxxxxxxxx",...} didn't come directly from the admin, send the admin a message directly {...,"cmd":"checkban_id:xxxxxxxxxx",...}
5) The admin checks their blacklist and, if a ban is indeed necessary, sends a direct message back {...,"cmd":"ban_id:xxxxxxxxxx",...}
6) After the admin sends the ban command, removes the user from their friends list, ignoring any subsequent attempts to join with that user.
7) The node that received "ban_id:xxxxxxxxxx" directly from the admin also blacklists that user and removes them from their friends list, ignoring any subsequent attempts to join with that user.
*/
#include <thread>
#include <atomic>
#include <cstring>

#include <toxcore/tox.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <winsock2.h>
#include <windows.h>
#include <vector>
#include <string>
#include <algorithm>
#include <set>
#include <map>
#include <iostream>
#include <sstream>
#include <ctime>
#include <random>

#include "mini_json.h"

enum MessageType {
    MSG_REQUEST_PEER_LIST = 2,
    MSG_PEER_LIST = 3,
    MSG_ADMIN_QUERY = 4,
    MSG_ADMIN_RESPONSE = 5,
    MSG_GROUP_MESSAGE = 6,
    // Sent unconditionally to every friend the instant it connects, and
    // to nobody else - carries our own real, full Tox ID (correct
    // nospam+checksum, straight from get_own_tox_id/tox_self_get_address).
    // This is the ONLY id that is ever stored or forwarded anywhere in this
    // file from this point on: no node ever has to guess, reconstruct, or
    // placeholder another node's id - everyone always just announces their
    // own real id themselves the moment a connection exists.
    MSG_ANNOUNCE_ID = 7
};

struct PeerInfo {
    uint32_t friend_number;
    char tox_id[TOX_ADDRESS_SIZE * 2 + 1];
    char name[256];
    uint32_t hash_distance;

    bool connected = false;
    bool should_request_list = false;
    bool request_sent = false;

    bool should_request_admin = false;
    bool admin_request_sent = false;

    // guards MSG_ANNOUNCE_ID from being resent on every reconnect
    bool id_announced = false;

    std::vector<std::string> pending_direct_messages;
};

struct GroupContext {
    Tox *tox;
    char admin_tox_id[TOX_ADDRESS_SIZE * 2 + 1];
    std::vector<PeerInfo> peers;
    std::map<std::string, time_t> seen_message_ids;
    std::set<std::string> blacklist;
};

// Global context - avoid passing through all methods
static GroupContext g_ctx{nullptr, {0}, {}, {}, {}};
static std::atomic<bool> g_running{true};

// ===== JSON Message Utilities =====
std::string create_json_group_message(
    const std::string &message_id,
    const std::string &sender,
    const std::string &message,
    const std::vector<std::string> &path,
    const std::string &admin_id,
    time_t timestamp
) {
    JsonValue root = JsonValue::makeObject();
    root["type"] = JsonValue::makeString("group_message");
    root["message_id"] = JsonValue::makeString(message_id);
    root["sender"] = JsonValue::makeString(sender);
    root["time"] = JsonValue::makeNumber((double)timestamp);
    root["message"] = JsonValue::makeString(message);
    root["admin_id"] = JsonValue::makeString(admin_id);
    
    JsonValue pathArray = JsonValue::makeArray();
    for (const auto &p : path) {
        pathArray.arr.push_back(JsonValue::makeString(p));
    }
    root["path"] = pathArray;
    
    return root.dump();
}

std::string create_json_peer_list(
    const std::vector<PeerInfo> &peers,
    const std::string &admin_id,
    const std::string &sender_id
) {
    JsonValue root = JsonValue::makeObject();
    root["type"] = JsonValue::makeString("peer_list");
    root["admin_id"] = JsonValue::makeString(admin_id);
    root["sender"] = JsonValue::makeString(sender_id);
    
    JsonValue peersArray = JsonValue::makeArray();
    for (const auto &peer : peers) {
        JsonValue peerObj = JsonValue::makeObject();
        peerObj["tox_id"] = JsonValue::makeString(peer.tox_id);
        peerObj["name"] = JsonValue::makeString(peer.name);
        peerObj["online"] = JsonValue::makeBool(peer.connected);
        peersArray.arr.push_back(peerObj);
    }
    root["peers"] = peersArray;
    
    return root.dump();
}

// Same schema as create_json_group_message, but carries a "cmd" field
// instead of "message" (spec: the two are mutually exclusive on the wire).
// Used for ban_id / checkban_id moderation commands.
std::string create_json_group_cmd(
    const std::string &message_id,
    const std::string &sender,
    const std::string &cmd,
    const std::vector<std::string> &path,
    const std::string &admin_id,
    time_t timestamp
) {
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

bool parse_json_message(const std::string &json_str, JsonValue &root) {
    root = JsonValue::parse(json_str);
    return root.isObject() || root.isArray();
}

// forward declaration: defined later in "Core Tox Utilities", but ConsoleUI
// (below) calls it before that point in the file.
void get_own_tox_id(Tox *tox, char *tox_id);

// ===== Console UI Abstraction =====
class ConsoleUI {
public:
    static void print_menu() {
        printf("\n=== Group Node Menu ===\n");
        printf("1. Print self info\n");
        printf("2. Print peers\n");
        printf("3. Print admin info\n");
        printf("4. Request admin info from friend\n");
        printf("5. Add friend by ID\n");
        printf("6. Set admin ID\n");
        printf("7. Send group message\n");
        printf("8. Ban peer\n");
        printf("9. Exit\n");
        printf("Choice: ");
    }
    
    static void print_self_info() {
        char own_id[TOX_ADDRESS_SIZE * 2 + 1];
        get_own_tox_id(g_ctx.tox, own_id);
        printf("\n[INFO] Self Tox ID: %s\n", own_id);
    }
    
    static void print_peers() {
        printf("\n=== Peers ===\n");
        if (g_ctx.peers.empty()) {
            printf("No peers\n");
            return;
        }
        
        for (size_t i = 0; i < g_ctx.peers.size(); i++) {
            const auto &peer = g_ctx.peers[i];
            printf("%zu. %s (ID: %s, %s)\n",
                   i + 1,
                   peer.name,
                   peer.tox_id,
                   peer.connected ? "online" : "offline");
        }
    }
    
    static void print_admin_info() {
        printf("\n[INFO] Admin ID: %s\n", g_ctx.admin_tox_id[0] != '\0' ? g_ctx.admin_tox_id : "Unknown");
    }
    
    static void print_input_prompt(const char *prompt, char *buffer, size_t size) {
        printf("%s", prompt);
        fgets(buffer, size, stdin);
        
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len - 1] == '\n') {
            buffer[len - 1] = '\0';
        }
    }
};

// ===== Core Tox Utilities =====
void tox_id_from_bytes(const uint8_t *bytes, char *id_str) {
    for (int i = 0; i < TOX_ADDRESS_SIZE; i++) {
        sprintf(id_str + i * 2, "%02X", bytes[i]);
    }
    id_str[TOX_ADDRESS_SIZE * 2] = '\0';
}

int tox_id_to_bytes(const char *id_str, uint8_t *bytes) {
    if (strlen(id_str) != TOX_ADDRESS_SIZE * 2) {
        return -1;
    }

    for (int i = 0; i < TOX_ADDRESS_SIZE; i++) {
        unsigned int value = 0;

        if (sscanf(id_str + i * 2, "%2x", &value) != 1) {
            return -1;
        }

        bytes[i] = (uint8_t)value;
    }

    return 0;
}

void get_own_tox_id(Tox *tox, char *tox_id) {
    uint8_t bytes[TOX_ADDRESS_SIZE];
    tox_self_get_address(tox, bytes);
    tox_id_from_bytes(bytes, tox_id);
}

uint32_t calculate_hash_distance(const char *id1, const char *id2) {
    uint8_t bytes1[TOX_ADDRESS_SIZE];
    uint8_t bytes2[TOX_ADDRESS_SIZE];

    if (tox_id_to_bytes(id1, bytes1) != 0 || tox_id_to_bytes(id2, bytes2) != 0) {
        return UINT32_MAX;
    }

    uint32_t distance = 0;

    for (int i = 0; i < TOX_ADDRESS_SIZE; i++) {
        uint8_t value = bytes1[i] ^ bytes2[i];

        for (int bit = 0; bit < 8; bit++) {
            if (value & (1 << bit)) {
                distance++;
            }
        }
    }

    return distance;
}

// ===== Peer Management =====
PeerInfo *find_peer_by_friend_number(uint32_t friend_number) {
    for (auto &peer : g_ctx.peers) {
        if (peer.friend_number == friend_number) {
            return &peer;
        }
    }
    return nullptr;
}

PeerInfo *find_peer_by_tox_id(const char *tox_id) {
    for (auto &peer : g_ctx.peers) {
        if (strcmp(peer.tox_id, tox_id) == 0) {
            return &peer;
        }
    }
    return nullptr;
}

void add_peer(uint32_t friend_number, const char *tox_id, const char *name,
              bool should_request_list = false) {
    if (find_peer_by_tox_id(tox_id)) {
        return;
    }

    char own_tox_id[TOX_ADDRESS_SIZE * 2 + 1];
    get_own_tox_id(g_ctx.tox, own_tox_id);

    PeerInfo peer;
    peer.friend_number = friend_number;
    strcpy(peer.tox_id, tox_id);
    strcpy(peer.name, name);
    peer.hash_distance = calculate_hash_distance(own_tox_id, tox_id);
    peer.connected = false;
    peer.should_request_list = should_request_list;
    peer.request_sent = false;
    peer.should_request_admin = false;
    peer.admin_request_sent = false;

    g_ctx.peers.push_back(peer);

    printf("[INFO] Peer added: %s (ID: %s)\n", name, tox_id);
}

void remove_peer_by_tox_id(const char *tox_id) {
    auto it = std::find_if(g_ctx.peers.begin(), g_ctx.peers.end(),
        [tox_id](const PeerInfo &p) { return strcmp(p.tox_id, tox_id) == 0; });
    
    if (it != g_ctx.peers.end()) {
        printf("[INFO] Peer removed: %s\n", it->name);
        g_ctx.peers.erase(it);
    }
}

void remove_peer(uint32_t friend_number) {
    auto it = std::find_if(g_ctx.peers.begin(), g_ctx.peers.end(),
        [friend_number](const PeerInfo &p) { return p.friend_number == friend_number; });

    if (it != g_ctx.peers.end()) {
        g_ctx.peers.erase(it);
    }
}

// ===== Time / hashing helpers (message_id computation, rule 4/5) =====
std::string bytes_to_hex_string(const uint8_t *bytes, size_t length) {
    std::string out;
    out.reserve(length * 2);
    char buf[3];
    for (size_t i = 0; i < length; i++) {
        sprintf(buf, "%02X", bytes[i]);
        out += buf;
    }
    return out;
}

// rule 1: full send time, used for display only (wire format stores a
// numeric unix timestamp - see create_json_group_message/create_json_group_cmd).
std::string format_time_string(time_t t) {
    char buf[32];
    struct tm *tm_info = localtime(&t);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info);
    return std::string(buf);
}

// rule 5: message_id = hash(sender_id + current time WITHOUT seconds + message text)
std::string compute_message_id(const std::string &sender_id, const std::string &message_text) {
    time_t now = time(nullptr);
    time_t truncated_to_minute = now - (now % 60);

    std::string hash_input = sender_id + std::to_string((long long)truncated_to_minute) + message_text;

    uint8_t hash[TOX_HASH_LENGTH];
    tox_hash(hash, (const uint8_t *)hash_input.c_str(), hash_input.length());

    return bytes_to_hex_string(hash, TOX_HASH_LENGTH);
}

// ===== Wire-format builders (peer discovery / admin query) =====
// These stay as plain header-byte + text, matching MSG_REQUEST_PEER_LIST /
// MSG_ADMIN_QUERY / MSG_ADMIN_RESPONSE - only the group-message channel
// (MSG_GROUP_MESSAGE) needs the full JSON schema from rule 0.
std::string build_peer_request() {
    char own_tox_id[TOX_ADDRESS_SIZE * 2 + 1];
    get_own_tox_id(g_ctx.tox, own_tox_id);

    std::string out;
    out += (char)MSG_REQUEST_PEER_LIST;
    out += own_tox_id;
    return out;
}

// rule 4: up to 10 peers, nearest by hash-distance to the requester, and the
// requester itself must never appear in its own list (rule 5).
std::string build_peer_list_message(const char *target_tox_id) {
    std::vector<PeerInfo> sorted_peers = g_ctx.peers;

    std::sort(sorted_peers.begin(), sorted_peers.end(),
        [target_tox_id](const PeerInfo &a, const PeerInfo &b) {
            uint32_t dist_a = calculate_hash_distance(a.tox_id, target_tox_id);
            uint32_t dist_b = calculate_hash_distance(b.tox_id, target_tox_id);
            return dist_a < dist_b;
        });

    std::vector<PeerInfo> selected;
    for (const auto &peer : sorted_peers) {
        if (selected.size() >= 10) break;
        if (strcmp(peer.tox_id, target_tox_id) == 0) continue; // rule 5
        selected.push_back(peer);
    }

    char own_tox_id[TOX_ADDRESS_SIZE * 2 + 1];
    get_own_tox_id(g_ctx.tox, own_tox_id);

    std::string json = create_json_peer_list(selected, g_ctx.admin_tox_id, own_tox_id);

    std::string out;
    out += (char)MSG_PEER_LIST;
    out += json;
    return out;
}

std::string build_admin_response() {
    std::string out;
    out += (char)MSG_ADMIN_RESPONSE;
    out += g_ctx.admin_tox_id;
    return out;
}

// Always carries OUR OWN real, full Tox ID - correct nospam+checksum
// included, because it's computed by ourselves via get_own_tox_id.
std::string build_announce_id() {
    char own_tox_id[TOX_ADDRESS_SIZE * 2 + 1];
    get_own_tox_id(g_ctx.tox, own_tox_id);

    std::string out;
    out += (char)MSG_ANNOUNCE_ID;
    out += own_tox_id;
    return out;
}

// Every place in this file that learns a peer's id from something THAT PEER
// told us about itself (never guessed/reconstructed from a public key)
// funnels through here, so the peer's local record - and everything we
// later forward about it in peer_list messages - always carries its real,
// full id with correct nospam+checksum.
void update_peer_real_id(uint32_t friend_number, const char *real_id) {
    if (strlen(real_id) != (size_t)(TOX_ADDRESS_SIZE * 2)) return;

    PeerInfo *peer = find_peer_by_friend_number(friend_number);
    if (!peer) return;
    if (strcmp(peer->tox_id, real_id) == 0) return;
    if (find_peer_by_tox_id(real_id)) return; // already known under this id elsewhere

    strcpy(peer->tox_id, real_id);

    char own_tox_id[TOX_ADDRESS_SIZE * 2 + 1];
    get_own_tox_id(g_ctx.tox, own_tox_id);
    peer->hash_distance = calculate_hash_distance(own_tox_id, real_id);
}

// ===== Message Callbacks =====
// Does NOT send the peer-list request directly here - the friend is not
// connected yet (no DHT handshake done), so sending now would almost always
// fail with FRIEND_NOT_CONNECTED. Instead the peer is marked with
// should_request_list=true, and the actual send happens in
// friend_connection_status_callback once the connection is really established.
void friend_request_callback(Tox *tox, const uint8_t *public_key, const uint8_t *friend_request_message, size_t length, void *user_data) {
    // public_key is 32 bytes (TOX_PUBLIC_KEY_SIZE), NOT the full 38-byte
    // Tox address. The full address's last 6 bytes (nospam + checksum) are
    // only known to the friend themselves - toxcore has no API to recover
    // them for someone who just friended us. We pad with a documented zero
    // placeholder rather than reading past the buffer or fabricating data,
    // so this id stays the right length (TOX_ADDRESS_SIZE*2 hex chars) for
    // tox_id_to_bytes/calculate_hash_distance, which are used everywhere
    // else in this file.
    char temp_tox_id[TOX_ADDRESS_SIZE * 2 + 1];
    for (int i = 0; i < TOX_PUBLIC_KEY_SIZE; i++) {
        sprintf(temp_tox_id + i * 2, "%02X", public_key[i]);
    }
    // nospam(4 bytes) + checksum(2 bytes) placeholder - unknown, zero-filled
    strcpy(temp_tox_id + TOX_PUBLIC_KEY_SIZE * 2, "000000000000");

    // Extract message
    std::string message(reinterpret_cast<const char*>(friend_request_message), length);
    printf("[FRIEND_REQUEST] From: %s, Message: %s\n", temp_tox_id, message.c_str());

    // moderation rule 6/7: never (re-)accept a friend request from a banned id
    if (g_ctx.blacklist.count(temp_tox_id) > 0) {
        printf("[MOD] Ignoring friend request from banned id: %s\n", temp_tox_id);
        return;
    }

    // Auto-accept the friend request per rule 2
    Tox_Err_Friend_Add add_err;
    uint32_t friend_number = tox_friend_add_norequest(tox, public_key, &add_err);

    if (add_err != TOX_ERR_FRIEND_ADD_OK) {
        printf("[ERROR] Failed to add friend, error: %d\n", add_err);
        return;
    }

    // rule 2: auto-accepted; rule 3: the accepting side (us) must request
    // the peer list -> should_request_list = true
    add_peer(friend_number, temp_tox_id, "Unknown", true);
    printf("[INFO] Friend accepted and added: %s\n", temp_tox_id);
}

// Registers the peer in g_ctx.peers right after the friend request is sent
// successfully, so this node's own peer list (rule 4/6) stays accurate for
// friends it added itself. peer_name can be set if we already know the
// peer's name from a received list.
void send_friend_request_to_peer(const char *tox_id, const char *peer_name = nullptr) {
    if (find_peer_by_tox_id(tox_id)) {
        return;
    }

    uint8_t bytes[TOX_ADDRESS_SIZE];
    if (tox_id_to_bytes(tox_id, bytes) != 0) {
        printf("[ERROR] Invalid Tox ID: %s\n", tox_id);
        return;
    }

    Tox_Err_Friend_Add err;
    uint32_t friend_number = tox_friend_add(g_ctx.tox, bytes, (const uint8_t *)"Join group", 10, &err);

    if (err == TOX_ERR_FRIEND_ADD_OK) {
        // We ourselves initiated joining this node - once connected, WE
        // request the peer list from it (rule 3 is the mirror case).
        const char *name = (peer_name && peer_name[0] != '\0') ? peer_name : "Unknown";
        add_peer(friend_number, tox_id, name, true);
        printf("[SEND] Friend request sent: %s (%s)\n", tox_id, name);
    } else {
        printf("[WARN] Could not add peer %s, error: %d\n", tox_id, err);
    }
}

// rule 4 (extended): process a received peer_list JSON payload, add unknown
// peers from it (rule 6), and set up admin discovery if we don't have one yet.
void process_peer_list(const std::string &json_payload) {
    JsonValue root;
    if (!parse_json_message(json_payload, root) || !root.isObject()) {
        printf("[WARN] Malformed peer_list message\n");
        return;
    }

    const JsonValue *admin_field = root.find("admin_id");
    std::string admin_id = admin_field ? admin_field->asString() : "";

    // rule 4: adopt the admin id from the list only if we don't have one yet
    if (admin_id.length() == TOX_ADDRESS_SIZE * 2 && strlen(g_ctx.admin_tox_id) == 0) {
        strcpy(g_ctx.admin_tox_id, admin_id.c_str());
        printf("[INFO] Admin ID from peer list: %s\n", g_ctx.admin_tox_id);
    }

    const JsonValue *peers_field = root.find("peers");
    if (!peers_field || !peers_field->isArray()) {
        return;
    }

    char own_tox_id[TOX_ADDRESS_SIZE * 2 + 1];
    get_own_tox_id(g_ctx.tox, own_tox_id);

    bool first_peer_processed = false;
    PeerInfo *first_peer = nullptr;

    for (const auto &peer_val : peers_field->arr) {
        const JsonValue *id_field = peer_val.find("tox_id");
        const JsonValue *name_field = peer_val.find("name");
        if (!id_field) continue;

        std::string peer_id = id_field->asString();
        std::string peer_name = name_field ? name_field->asString() : "Unknown";

        // rule 5: the requester itself must not appear in the list it gets back
        if (peer_id == own_tox_id) {
            continue;
        }

        PeerInfo *existing = find_peer_by_tox_id(peer_id.c_str());

        if (existing) {
            // rule 4: fill in the name if we only had "Unknown" so far
            if (!peer_name.empty() && strcmp(existing->name, "Unknown") == 0) {
                strcpy(existing->name, peer_name.c_str());
                printf("[INFO] Peer name updated: %s -> %s\n", peer_id.c_str(), peer_name.c_str());
            }
        } else {
            // rule 6: cascade - start adding the other peers from this list
            send_friend_request_to_peer(peer_id.c_str(), peer_name.c_str());
        }

        if (!first_peer_processed) {
            first_peer = find_peer_by_tox_id(peer_id.c_str());
            first_peer_processed = true;
        }
    }

    // rule 4 (extended): if admin is still unknown, ask the first peer once it connects
    if (strlen(g_ctx.admin_tox_id) == 0 && first_peer) {
        first_peer->should_request_admin = true;
        printf("[INFO] Will request admin from: %s (%s) when it connects\n", first_peer->tox_id, first_peer->name);
    }
}

// rule *6: entries older than one minute are dropped.
void purge_expired_message_ids() {
    time_t now = time(nullptr);
    for (auto it = g_ctx.seen_message_ids.begin(); it != g_ctx.seen_message_ids.end();) {
        if (now - it->second > 60) {
            it = g_ctx.seen_message_ids.erase(it);
        } else {
            ++it;
        }
    }
}

// Peers a message may still be forwarded to: connected, not already in the
// message's path, and not banned locally (moderation rule 1).
std::vector<PeerInfo *> get_eligible_peers(const std::vector<std::string> &path) {
    std::vector<PeerInfo *> result;

    for (auto &peer : g_ctx.peers) {
        if (!peer.connected) continue;
        if (g_ctx.blacklist.count(peer.tox_id) > 0) continue;

        bool in_path = std::find(path.begin(), path.end(), peer.tox_id) != path.end();
        if (in_path) continue;

        result.push_back(&peer);
    }

    return result;
}

// Sends a wire-format payload directly to a single peer. If not connected
// yet, the payload is queued and flushed from friend_connection_status_callback
// once it connects.
void send_direct_or_queue(PeerInfo *peer, const std::string &wire_payload) {
    if (!peer) return;

    if (peer->connected) {
        Tox_Err_Friend_Send_Message err;
        tox_friend_send_message(g_ctx.tox, peer->friend_number, TOX_MESSAGE_TYPE_NORMAL,
                                 (const uint8_t *)wire_payload.c_str(), wire_payload.length(), &err);
        if (err == TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
            return;
        }
    }

    peer->pending_direct_messages.push_back(wire_payload);
}

// moderation rule 6/7: blacklist a tox id, drop the Tox friendship with it
// if we have one, and forget its local peer entry.
void ban_peer(const std::string &target_id) {
    g_ctx.blacklist.insert(target_id);

    PeerInfo *peer = find_peer_by_tox_id(target_id.c_str());
    if (peer) {
        Tox_Err_Friend_Delete err;
        tox_friend_delete(g_ctx.tox, peer->friend_number, &err);
        remove_peer(peer->friend_number);
    }

    printf("[MOD] %s added to local blacklist\n", target_id.c_str());
}

// moderation rule 5: only meaningful if WE are the admin. Confirms the ban
// directly (not flooded) back to whoever asked, if it's genuinely on our list.
void handle_checkban_id_cmd(uint32_t friend_number, const std::string &target_id) {
    char own_tox_id[TOX_ADDRESS_SIZE * 2 + 1];
    get_own_tox_id(g_ctx.tox, own_tox_id);

    if (strlen(g_ctx.admin_tox_id) == 0 || strcmp(own_tox_id, g_ctx.admin_tox_id) != 0) {
        return; // we don't consider ourselves the admin
    }
    if (g_ctx.blacklist.count(target_id) == 0) {
        return; // not actually on our blacklist
    }

    PeerInfo *requester = find_peer_by_friend_number(friend_number);
    if (!requester) return;

    std::vector<std::string> path;
    path.push_back(own_tox_id);

    std::string cmd = "ban_id:" + target_id;
    std::string message_id = compute_message_id(own_tox_id, cmd);
    g_ctx.seen_message_ids[message_id] = time(nullptr);

    std::string json = create_json_group_cmd(message_id, own_tox_id, cmd, path, own_tox_id, time(nullptr));

    std::string wire_payload;
    wire_payload += (char)MSG_GROUP_MESSAGE;
    wire_payload += json;

    send_direct_or_queue(requester, wire_payload);
    printf("[MOD] Confirmed ban of %s directly to requester\n", target_id.c_str());
}

// moderation rules 3/4/6/7
void handle_ban_id_cmd(uint32_t friend_number, const std::string &admin_id,
                        const std::string &target_id, bool directly_from_admin) {
    if (admin_id.empty() || target_id.empty()) return;

    char own_tox_id[TOX_ADDRESS_SIZE * 2 + 1];
    get_own_tox_id(g_ctx.tox, own_tox_id);

    // rule 3: everyone who receives a ban_id command must have the admin
    // as a direct friend, adding them now if that is not the case yet
    if (admin_id != own_tox_id && !find_peer_by_tox_id(admin_id.c_str())) {
        send_friend_request_to_peer(admin_id.c_str());
    }

    if (!directly_from_admin) {
        // rule 4: only relayed, not received first-hand - ask the admin to confirm
        PeerInfo *admin_peer = find_peer_by_tox_id(admin_id.c_str());
        if (admin_peer) {
            std::vector<std::string> path;
            path.push_back(own_tox_id);

            std::string cmd = "checkban_id:" + target_id;
            std::string message_id = compute_message_id(own_tox_id, cmd);
            g_ctx.seen_message_ids[message_id] = time(nullptr);

            std::string json = create_json_group_cmd(message_id, own_tox_id, cmd, path, admin_id, time(nullptr));

            std::string wire_payload;
            wire_payload += (char)MSG_GROUP_MESSAGE;
            wire_payload += json;

            send_direct_or_queue(admin_peer, wire_payload);
            printf("[MOD] ban_id for %s was relayed, asking admin to confirm directly\n", target_id.c_str());
        }
        return;
    }

    // rule 7: received directly from the admin - trust it and apply locally
    ban_peer(target_id);
}

void handle_group_cmd(uint32_t friend_number, const std::string &admin_id,
                       const std::string &cmd, bool directly_from_admin) {
    size_t colon = cmd.find(':');
    if (colon == std::string::npos) return;

    std::string cmd_name = cmd.substr(0, colon);
    std::string target_id = cmd.substr(colon + 1);

    if (cmd_name == "ban_id") {
        handle_ban_id_cmd(friend_number, admin_id, target_id, directly_from_admin);
    } else if (cmd_name == "checkban_id") {
        handle_checkban_id_cmd(friend_number, target_id);
    }
}

// rule 7/8: when a node receives a group message, it forwards it to known
// nodes not already in the message's path, adding its own id first.
// seen_message_ids (with the *6 TTL purge) makes sure the same message
// reaching a node twice via overlapping flood paths is only handled once.
void process_group_message(uint32_t friend_number, const std::string &json_payload) {
    JsonValue root;
    if (!parse_json_message(json_payload, root) || !root.isObject()) {
        printf("[WARN] Malformed group message received\n");
        return;
    }

    const JsonValue *id_field = root.find("message_id");
    std::string message_id = id_field ? id_field->asString() : "";
    if (message_id.empty()) {
        printf("[WARN] Malformed group message received\n");
        return;
    }

    purge_expired_message_ids();
    if (g_ctx.seen_message_ids.count(message_id) > 0) {
        return;
    }
    g_ctx.seen_message_ids[message_id] = time(nullptr);

    const JsonValue *sender_field = root.find("sender");
    std::string sender = sender_field ? sender_field->asString() : "";

    // moderation rule 1: messages from a banned sender are dropped entirely
    if (g_ctx.blacklist.count(sender) > 0) {
        return;
    }

    const JsonValue *time_field = root.find("time");
    time_t msg_time = time_field ? (time_t)time_field->asNumber() : time(nullptr);

    const JsonValue *admin_field = root.find("admin_id");
    std::string admin_id = admin_field ? admin_field->asString() : "";

    const JsonValue *text_field = root.find("message");
    std::string text = text_field ? text_field->asString() : "";

    const JsonValue *cmd_field = root.find("cmd");
    std::string cmd = cmd_field ? cmd_field->asString() : "";

    std::vector<std::string> path;
    const JsonValue *path_field = root.find("path");
    if (path_field && path_field->isArray()) {
        for (const auto &p : path_field->arr) path.push_back(p.asString());
    }

    bool is_cmd = !cmd.empty();

    if (is_cmd) {
        printf("\n[GROUP CMD %s] %s: %s\n", format_time_string(msg_time).c_str(), sender.c_str(), cmd.c_str());
    } else {
        printf("\n[GROUP %s] %s: %s\n", format_time_string(msg_time).c_str(), sender.c_str(), text.c_str());
    }

    // was this handed to us directly by the admin we know, or relayed?
    PeerInfo *from_peer = find_peer_by_friend_number(friend_number);
    bool directly_from_admin = from_peer
        && strlen(g_ctx.admin_tox_id) > 0
        && strcmp(from_peer->tox_id, g_ctx.admin_tox_id) == 0;

    if (is_cmd) {
        handle_group_cmd(friend_number, admin_id, cmd, directly_from_admin);
    }

    char own_tox_id[TOX_ADDRESS_SIZE * 2 + 1];
    get_own_tox_id(g_ctx.tox, own_tox_id);

    if (std::find(path.begin(), path.end(), std::string(own_tox_id)) == path.end()) {
        path.push_back(own_tox_id);
    }

    // rule 8: only forward if the message's claimed admin matches ours.
    // If we don't have an admin set yet, there's nothing to validate against.
    if (strlen(g_ctx.admin_tox_id) > 0 && admin_id != g_ctx.admin_tox_id) {
        return;
    }

    std::string forward_json = is_cmd
        ? create_json_group_cmd(message_id, sender, cmd, path, admin_id, msg_time)
        : create_json_group_message(message_id, sender, text, path, admin_id, msg_time);

    std::string forward_payload;
    forward_payload += (char)MSG_GROUP_MESSAGE;
    forward_payload += forward_json;

    for (auto *peer : get_eligible_peers(path)) {
        Tox_Err_Friend_Send_Message err;
        tox_friend_send_message(g_ctx.tox, peer->friend_number, TOX_MESSAGE_TYPE_NORMAL,
                                 (const uint8_t *)forward_payload.c_str(), forward_payload.length(), &err);
        if (err == TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
            printf("[SEND] Group message forwarded to: %s\n", peer->tox_id);
        }
    }
}

// Dispatches on the single MessageType header byte, matching build_peer_request /
// build_peer_list_message / build_admin_response above.
void process_friend_message(uint32_t friend_number, const uint8_t *message, size_t length) {
    if (length < 1) return;

    MessageType type = (MessageType)message[0];
    const char *payload = (const char *)(message + 1);
    size_t payload_length = length - 1;

    if (type == MSG_REQUEST_PEER_LIST) {
        if (payload_length < (size_t)(TOX_ADDRESS_SIZE * 2)) return;

        char target_tox_id[TOX_ADDRESS_SIZE * 2 + 1];
        memcpy(target_tox_id, payload, TOX_ADDRESS_SIZE * 2);
        target_tox_id[TOX_ADDRESS_SIZE * 2] = '\0';

        printf("[RECV] Peer list request from: %s\n", target_tox_id);

        // This payload is the sender's own real Tox ID - keep our record in sync.
        update_peer_real_id(friend_number, target_tox_id);

        std::string response = build_peer_list_message(target_tox_id);

        Tox_Err_Friend_Send_Message err;
        tox_friend_send_message(g_ctx.tox, friend_number, TOX_MESSAGE_TYPE_NORMAL,
                                 (const uint8_t *)response.c_str(), response.length(), &err);

        if (err == TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
            printf("[SEND] Peer list sent to: %s\n", target_tox_id);
        }
        return;
    }

    if (type == MSG_PEER_LIST) {
        process_peer_list(std::string(payload, payload_length));
        return;
    }

    if (type == MSG_ADMIN_QUERY) {
        std::string response = build_admin_response();
        Tox_Err_Friend_Send_Message err;
        tox_friend_send_message(g_ctx.tox, friend_number, TOX_MESSAGE_TYPE_NORMAL,
                                 (const uint8_t *)response.c_str(), response.length(), &err);
        return;
    }

    if (type == MSG_ADMIN_RESPONSE) {
        std::string admin_id(payload, payload_length);
        if (admin_id.length() == (size_t)(TOX_ADDRESS_SIZE * 2)) {
            strcpy(g_ctx.admin_tox_id, admin_id.c_str());
            printf("[INFO] Admin ID received: %s\n", g_ctx.admin_tox_id);
        }
        return;
    }

    if (type == MSG_GROUP_MESSAGE) {
        process_group_message(friend_number, std::string(payload, payload_length));
        return;
    }

    if (type == MSG_ANNOUNCE_ID) {
        std::string real_id(payload, payload_length);
        printf("[RECV] Real Tox ID announced: %s\n", real_id.c_str());
        update_peer_real_id(friend_number, real_id.c_str());
        return;
    }
}

void friend_message_callback(Tox *tox, uint32_t friend_number, Tox_Message_Type type, const uint8_t *message, size_t length, void *user_data) {
    if (type != TOX_MESSAGE_TYPE_NORMAL) {
        return;
    }
    process_friend_message(friend_number, message, length);
}

// Once the connection to a friend is actually established, and if this is a
// friend we accepted (should_request_list) and haven't requested the list
// yet, send the request now (rule 3). request_sent guards duplicate sends
// on reconnects. Also handles admin discovery (rule 4 extended) and flushes
// any direct messages (checkban_id/ban_id confirmations) queued while offline.
void friend_connection_status_callback(Tox *tox, uint32_t friend_number, Tox_Connection connection_status, void *user_data) {
    PeerInfo *peer = find_peer_by_friend_number(friend_number);

    if (connection_status != TOX_CONNECTION_NONE) {
        printf("[EVENT] Friend %u connected\n", friend_number);

        if (peer) {
            printf("[INFO] Peer ID: %s\n", peer->tox_id);
            peer->connected = true;

            // Always announce our own real id to every friend as soon as a
            // connection exists - regardless of who accepted whom, so no
            // node ever has to work with a guessed/placeholder id for any
            // peer, whether it originated the connection or accepted it.
            if (!peer->id_announced) {
                std::string announce = build_announce_id();
                Tox_Err_Friend_Send_Message announce_err;
                tox_friend_send_message(tox, friend_number, TOX_MESSAGE_TYPE_NORMAL,
                                         (const uint8_t *)announce.c_str(), announce.length(), &announce_err);

                if (announce_err == TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
                    peer->id_announced = true;
                } else {
                    printf("[WARN] Failed to announce id to %s, error: %d\n", peer->tox_id, announce_err);
                }
            }

            if (peer->should_request_list && !peer->request_sent) {
                std::string request = build_peer_request();
                Tox_Err_Friend_Send_Message send_err;
                tox_friend_send_message(tox, friend_number, TOX_MESSAGE_TYPE_NORMAL,
                                         (const uint8_t *)request.c_str(), request.length(), &send_err);

                if (send_err == TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
                    peer->request_sent = true;
                    printf("[SEND] Peer list request sent to: %s\n", peer->tox_id);
                } else {
                    printf("[WARN] Failed to send peer list request to %s, error: %d\n", peer->tox_id, send_err);
                }
            }

            if (peer->should_request_admin && !peer->admin_request_sent) {
                std::string request;
                request += (char)MSG_ADMIN_QUERY;

                Tox_Err_Friend_Send_Message admin_err;
                tox_friend_send_message(tox, friend_number, TOX_MESSAGE_TYPE_NORMAL,
                                         (const uint8_t *)request.c_str(), request.length(), &admin_err);

                if (admin_err == TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
                    peer->admin_request_sent = true;
                    printf("[SEND] Admin query sent to: %s\n", peer->tox_id);
                } else {
                    printf("[WARN] Failed to send admin query to %s, error: %d\n", peer->tox_id, admin_err);
                }
            }

            if (!peer->pending_direct_messages.empty()) {
                std::vector<std::string> pending = peer->pending_direct_messages;
                peer->pending_direct_messages.clear();

                for (const auto &wire_payload : pending) {
                    Tox_Err_Friend_Send_Message pending_err;
                    tox_friend_send_message(tox, friend_number, TOX_MESSAGE_TYPE_NORMAL,
                                             (const uint8_t *)wire_payload.c_str(), wire_payload.length(), &pending_err);

                    if (pending_err != TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
                        peer->pending_direct_messages.push_back(wire_payload);
                    }
                }
            }
        }
    } else {
        printf("[EVENT] Friend %u disconnected\n", friend_number);
        if (peer) {
            peer->connected = false;
        }
    }
}

void self_connection_status_callback(Tox *tox, Tox_Connection connection_status, void *user_data) {
    if (connection_status != TOX_CONNECTION_NONE) {
        printf("[INFO] Connected to Tox network\n");
    } else {
        printf("[INFO] Disconnected from Tox network\n");
    }
}

// ===== Tox Initialization =====
Tox *initialize_tox(const char *node_name, const char *save_file) {
    Tox_Options *options = tox_options_new(nullptr);
    if (!options) {
        printf("[ERROR] Failed to create Tox options\n");
        return nullptr;
    }

    // Try to load existing profile
    FILE *f = fopen(save_file, "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        size_t size = ftell(f);
        fseek(f, 0, SEEK_SET);

        std::vector<uint8_t> data(size);
        if (fread(data.data(), 1, size, f) == size) {
            tox_options_set_savedata_data(options, data.data(), size);
            tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_TOX_SAVE);
        }
        fclose(f);
    }

    tox_options_set_local_discovery_enabled(options, true);

    Tox_Err_New tox_err;
    Tox *tox = tox_new(options, &tox_err);
    tox_options_free(options);

    if (!tox) {
        printf("[ERROR] Failed to create Tox instance, error: %d\n", tox_err);
        return nullptr;
    }

    tox_self_set_name(tox, (const uint8_t *)node_name, strlen(node_name), nullptr);

    return tox;
}

void save_tox_data(Tox *tox, const char *save_file) {
    size_t size = tox_get_savedata_size(tox);
    std::vector<uint8_t> data(size);
    tox_get_savedata(tox, data.data());

    FILE *f = fopen(save_file, "wb");
    if (f) {
        fwrite(data.data(), 1, size, f);
        fclose(f);
        printf("[INFO] Tox data saved to %s\n", save_file);
    } else {
        printf("[ERROR] Failed to save Tox data\n");
    }
}

// ===== Console Commands =====
void request_admin_from_friend() {
    if (g_ctx.peers.empty()) {
        printf("[WARN] No friends\n");
        return;
    }

    PeerInfo &peer = g_ctx.peers[0];

    std::string request;
    request += (char)MSG_ADMIN_QUERY;

    Tox_Err_Friend_Send_Message err;
    tox_friend_send_message(g_ctx.tox, peer.friend_number, TOX_MESSAGE_TYPE_NORMAL,
                             (const uint8_t *)request.c_str(), request.length(), &err);

    if (err == TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
        printf("[SEND] Admin request sent to %s\n", peer.tox_id);
    } else {
        printf("[ERROR] Failed to send admin request: %d\n", err);
    }
}

void add_friend_by_id(const char *tox_id) {
    if (strlen(tox_id) != (size_t)(TOX_ADDRESS_SIZE * 2)) {
        printf("[ERROR] Invalid Tox ID\n");
        return;
    }

    uint8_t bytes[TOX_ADDRESS_SIZE];
    if (tox_id_to_bytes(tox_id, bytes) != 0) {
        printf("[ERROR] Invalid Tox ID\n");
        return;
    }

    send_friend_request_to_peer(tox_id);
}

void set_admin_id(const char *tox_id) {
    if (strlen(tox_id) != (size_t)(TOX_ADDRESS_SIZE * 2)) {
        printf("[ERROR] Invalid Tox ID\n");
        return;
    }

    uint8_t bytes[TOX_ADDRESS_SIZE];
    if (tox_id_to_bytes(tox_id, bytes) != 0) {
        printf("[ERROR] Invalid Tox ID\n");
        return;
    }

    strcpy(g_ctx.admin_tox_id, tox_id);
    printf("[INFO] Admin ID set to: %s\n", g_ctx.admin_tox_id);
}

// rule 3: a newly originated message is sent to any 3 known nodes of the group
void send_group_message(const std::string &text) {
    // rule 1: admin_id is mandatory on every outgoing message
    if (strlen(g_ctx.admin_tox_id) == 0) {
        printf("[ERROR] No admin ID set - set one first (option 6, you may set yourself)\n");
        return;
    }

    char own_tox_id[TOX_ADDRESS_SIZE * 2 + 1];
    get_own_tox_id(g_ctx.tox, own_tox_id);

    std::string message_id = compute_message_id(own_tox_id, text);
    time_t now = time(nullptr);

    // the originator is already part of the path so the message never
    // gets forwarded back to itself once it starts flooding out
    std::vector<std::string> path;
    path.push_back(own_tox_id);

    g_ctx.seen_message_ids[message_id] = now;

    std::string json = create_json_group_message(message_id, own_tox_id, text, path, g_ctx.admin_tox_id, now);

    std::string payload;
    payload += (char)MSG_GROUP_MESSAGE;
    payload += json;

    std::vector<PeerInfo *> connected_peers = get_eligible_peers(path);
    if (connected_peers.empty()) {
        printf("[WARN] No connected peers to send the message to\n");
        return;
    }

    std::random_device rd;
    std::mt19937 rng(rd());
    std::shuffle(connected_peers.begin(), connected_peers.end(), rng);

    int sent_count = 0;
    for (auto *peer : connected_peers) {
        if (sent_count >= 3) break;

        Tox_Err_Friend_Send_Message err;
        tox_friend_send_message(g_ctx.tox, peer->friend_number, TOX_MESSAGE_TYPE_NORMAL,
                                 (const uint8_t *)payload.c_str(), payload.length(), &err);

        if (err == TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
            sent_count++;
            printf("[SEND] Group message sent to: %s\n", peer->tox_id);
        }
    }

    if (sent_count == 0) {
        printf("[ERROR] Failed to send the group message to any peer\n");
    }
}

// moderation rule 2/6: admin broadcasts a ban_id cmd to any 3 known nodes,
// then immediately applies the ban locally too (unfriend + blacklist).
void send_ban_id_broadcast(const std::string &target_id) {
    char own_tox_id[TOX_ADDRESS_SIZE * 2 + 1];
    get_own_tox_id(g_ctx.tox, own_tox_id);

    if (strlen(g_ctx.admin_tox_id) == 0 || strcmp(own_tox_id, g_ctx.admin_tox_id) != 0) {
        printf("[ERROR] Only the admin can ban - set yourself as admin first (option 6)\n");
        return;
    }

    std::vector<std::string> path;
    path.push_back(own_tox_id);

    std::string cmd = "ban_id:" + target_id;
    std::string message_id = compute_message_id(own_tox_id, cmd);
    time_t now = time(nullptr);

    g_ctx.seen_message_ids[message_id] = now;

    std::string json = create_json_group_cmd(message_id, own_tox_id, cmd, path, own_tox_id, now);

    std::string payload;
    payload += (char)MSG_GROUP_MESSAGE;
    payload += json;

    std::vector<PeerInfo *> connected_peers = get_eligible_peers(path);

    std::random_device rd;
    std::mt19937 rng(rd());
    std::shuffle(connected_peers.begin(), connected_peers.end(), rng);

    int sent_count = 0;
    for (auto *peer : connected_peers) {
        if (sent_count >= 3) break;

        Tox_Err_Friend_Send_Message err;
        tox_friend_send_message(g_ctx.tox, peer->friend_number, TOX_MESSAGE_TYPE_NORMAL,
                                 (const uint8_t *)payload.c_str(), payload.length(), &err);

        if (err == TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
            sent_count++;
            printf("[SEND] Ban command sent to: %s\n", peer->tox_id);
        }
    }

    // rule 6: the admin also applies the ban locally right away
    ban_peer(target_id);

    printf("[MOD] Broadcast ban for %s (sent to %d known peer(s))\n", target_id.c_str(), sent_count);
}

// ===== Console Input Handler =====
void console_input_thread_func() {
    char input[256];
    
    while (g_running.load()) {
        if (fgets(input, sizeof(input), stdin)) {
            int choice = atoi(input);
            
            switch (choice) {
                case 1:
                    ConsoleUI::print_self_info();
                    break;
                case 2:
                    ConsoleUI::print_peers();
                    break;
                case 3:
                    ConsoleUI::print_admin_info();
                    break;
                case 4:
                    request_admin_from_friend();
                    break;
                case 5: {
                    char friend_id[TOX_ADDRESS_SIZE * 2 + 1];
                    ConsoleUI::print_input_prompt("Enter friend Tox ID: ", friend_id, sizeof(friend_id));
                    add_friend_by_id(friend_id);
                    break;
                }
                case 6: {
                    char admin_id[TOX_ADDRESS_SIZE * 2 + 1];
                    ConsoleUI::print_input_prompt("Enter admin Tox ID: ", admin_id, sizeof(admin_id));
                    set_admin_id(admin_id);
                    break;
                }
                case 7: {
                    char message[512];
                    ConsoleUI::print_input_prompt("Enter message: ", message, sizeof(message));
                    if (message[0] == '\0') {
                        printf("[ERROR] Empty message\n");
                        break;
                    }
                    send_group_message(message);
                    break;
                }
                case 8: {
                    char ban_id[TOX_ADDRESS_SIZE * 2 + 1];
                    ConsoleUI::print_input_prompt("Enter Tox ID to ban: ", ban_id, sizeof(ban_id));
                    if (strlen(ban_id) != (size_t)(TOX_ADDRESS_SIZE * 2)) {
                        printf("[ERROR] Invalid Tox ID\n");
                        break;
                    }
                    send_ban_id_broadcast(ban_id);
                    break;
                }
                case 9:
                    g_running.store(false);
                    break;
                default:
                    ConsoleUI::print_menu();
            }
        }
        
        Sleep(100);
    }
}

// ===== Main =====
int main() {
    printf("[INIT] Group Node Test\n");

    int mode = 0;
    printf("1. Start new group\n");
    printf("2. Join existing group\n");
    printf("Choice: ");
    scanf("%d", &mode);
    getchar();

    char join_tox_id[TOX_ADDRESS_SIZE * 2 + 1];
    join_tox_id[0] = '\0';

    if (mode == 2) {
        printf("Enter Tox ID of a node already in the group: ");
        if (fgets(join_tox_id, sizeof(join_tox_id), stdin)) {
            size_t jlen = strlen(join_tox_id);
            while (jlen > 0 && (join_tox_id[jlen - 1] == '\n' || join_tox_id[jlen - 1] == '\r')) {
                join_tox_id[--jlen] = '\0';
            }
        }

        if (strlen(join_tox_id) != TOX_ADDRESS_SIZE * 2) {
            printf("[ERROR] Invalid Tox ID, starting as a standalone node instead\n");
            join_tox_id[0] = '\0';
        }
    }

    char save_file[256];
    char node_name[256];

    DWORD pid = GetCurrentProcessId();
    srand((unsigned int)time(nullptr) ^ (unsigned int)pid);

    sprintf(node_name, "GroupNode_%lu_%d", (unsigned long)pid, rand() % 10000);
    sprintf(save_file, "node_%lu_%d.tox", (unsigned long)pid, rand() % 10000);

    printf("\n[INIT] Starting Tox node...\n");

    g_ctx.tox = initialize_tox(node_name, save_file);

    if (!g_ctx.tox) {
        printf("[ERROR] Tox initialization failed\n");
        return 1;
    }

    char own_tox_id[TOX_ADDRESS_SIZE * 2 + 1];
    get_own_tox_id(g_ctx.tox, own_tox_id);

    if (mode == 1) {
        strcpy(g_ctx.admin_tox_id, own_tox_id);
        printf("\n[INFO] Admin ID set to: %s\n", g_ctx.admin_tox_id);
    }

    printf("\nNode ready\n");
    printf("Tox ID: %s\n", own_tox_id);

    tox_callback_friend_request(g_ctx.tox, friend_request_callback);
    tox_callback_friend_message(g_ctx.tox, friend_message_callback);
    tox_callback_friend_connection_status(g_ctx.tox, friend_connection_status_callback);
    tox_callback_self_connection_status(g_ctx.tox, self_connection_status_callback);

    struct BootstrapNode {
        const char *address;
        uint16_t port;
        const char *public_key;
    };

    BootstrapNode bootstrap_nodes[] = {
        { "144.217.167.73",  33445, "7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A2A2FD34C" },
        { "3.0.24.15",       33445, "E20ABCF38CDBFFD7D04B29C956B33F7B27A3BB7AF0618101617B036E4AEA402D" },
        { "139.162.110.188", 33445, "F76A11284547163889DDC89A7738CF271797BF5E5E220643E97AD3C7E7903D55" },
        { "172.104.215.182", 33445, "DA2BD927E01CD05EBCC2574EBE5BEBB10FF59AE0B2105A7D1E2B40E49BB20239" },
    };

    int bootstrap_ok_count = 0;

    for (const auto &node : bootstrap_nodes) {
        uint8_t bootstrap_key_bytes[TOX_PUBLIC_KEY_SIZE];

        for (int i = 0; i < TOX_PUBLIC_KEY_SIZE; i++) {
            unsigned int value = 0;
            sscanf(node.public_key + i * 2, "%2x", &value);
            bootstrap_key_bytes[i] = (uint8_t)value;
        }

        Tox_Err_Bootstrap bootstrap_err;
        tox_bootstrap(g_ctx.tox, node.address, node.port, bootstrap_key_bytes, &bootstrap_err);

        if (bootstrap_err == TOX_ERR_BOOTSTRAP_OK) {
            bootstrap_ok_count++;
        } else {
            printf("[WARN] Bootstrap to %s failed, error: %d\n", node.address, bootstrap_err);
        }
    }

    if (bootstrap_ok_count > 0) {
        printf("[INFO] Bootstrap requests sent to %d node(s)\n", bootstrap_ok_count);
    } else {
        printf("[ERROR] Could not reach any bootstrap node - check your network settings\n");
    }

    // rule 1: any node's regular Tox ID is also the id used to join the
    // group - joining means simply sending it a friend request. From there
    // rules 2-6 (auto-accept, peer-list request/response, cascading adds)
    // take over automatically.
    if (join_tox_id[0] != '\0') {
        printf("[INIT] Joining group via node: %s\n", join_tox_id);
        send_friend_request_to_peer(join_tox_id);
    }

    ConsoleUI::print_menu();

    std::thread input_thread(console_input_thread_func);

    while (g_running.load()) {
        tox_iterate(g_ctx.tox, nullptr);

        uint32_t interval = tox_iteration_interval(g_ctx.tox);
        if (interval == 0) {
            interval = 10;
        }

        Sleep(interval);
    }

    if (input_thread.joinable()) {
        input_thread.join();
    }

    printf("\n[CLEANUP] Saving node...\n");
    save_tox_data(g_ctx.tox, save_file);
    tox_kill(g_ctx.tox);

    printf("[INFO] Node stopped\n");

    return 0;
}