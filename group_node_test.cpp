/* PROTOCOL - THESE POINTS MUST BE FOLLOWED WHEN MODIFYING THE CODE 
1) Any node has a regular tox_id - this will be the id for joining the group 
2) That is, when someone sends a friend request (node A) - we automatically accept it (node B) 
3) After we have accepted a friend (node A) - the friend (node B) sends a request by message to node A to be given a list of others 
4) In response to the request (node A), we send him our list of friends (up to 10 people, if there are that many) with the closest hash-distance to this joined friend (node B) 
5) B itself should not be considered a friend of A, who should be included in this list. 
6) When node B has added a friend, it starts adding other friends from the list. 
7) Each participant can request information from any other participant about who the admin is - and receive their ID in response. 
8) Each participant has the right to consider any other participant or themselves as the admin. 
Mechanism for sending messages to a group 
0) All messages in json format {"type":"group_message","message_id":"...","sender":"...","time":"...","message":"...","path":["...","..."],"admin_id":"..."} or {"type":"group_message","message_id":"...","sender":"...","time":"...","сmd":"...","path":["...","..."],"admin_id":"..."} 
1) admin_id must be specified when sending 
2) time - time of sending 
3) When sending a message to a group, it is sent to any 3 known nodes of the group 
4) the json message package must contain the sender's id, the message itself, and a list of nodes through which the message passed, a unique message id 
5) a unique message id is (a hash of the sum of the sender's id, the current time without seconds + the message 
*6) each The node stores all forwarded message IDs for a minute - when forwarding, the uniqueness of the message ID is checked and it is not forwarded further if there has already been a message with the same ID 
7) when a node receives a message, it forwards it further to those nodes that are not in the list of the message itself, while adding its ID to the list 
8) if the admin_id in the forwarded message does not match the one known to the node, we do not forward the message 
Moderation 
1) All nodes have their own list of node IDs from which messages are not forwarded and to which they are not forwarded (black list) 
2) to ban someone, the admin in the group sends {...,"cmd":"ban_id:xxxxxxxxxx",...} 
3) everyone who received {...,"cmd":"ban_id:xxxxxxxxxx",...} should add the admin as a friend directly if they have not already done so. 
4) If {...,"cmd":"ban_id:xxxxxxxxxx",...} did not come directly from the admin, we send a message directly to the admin {...,"cmd":"checkban_id:xxxxxxxxxx",...} 
5) The admin checks his blacklist and if a ban is really necessary, he sends it back directly this time {...,"cmd":"ban_id:xxxxxxxxxx",...} 
*/

#include <thread>
#include <atomic>

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
#include <iostream>
#include <sstream>
#include <ctime>
#include <random>

enum MessageType {
    MSG_REQUEST_PEER_LIST = 2,
    MSG_PEER_LIST = 3,
    MSG_ADMIN_QUERY = 4,
    MSG_ADMIN_RESPONSE = 5,
    MSG_GROUP_MESSAGE = 6
};

struct PeerInfo {
    uint32_t friend_number;
    char tox_id[TOX_ADDRESS_SIZE * 2 + 1];
    char name[256];
    uint32_t hash_distance;

    // --- connection state and who must initiate the peer-list exchange ---
    // true if the tox connection to this friend is currently established
    bool connected = false;
    // true if WE accepted an incoming friend request from this node
    // (rule 2/3: the accepting side is the one required to request the list).
    // false if WE added this friend ourselves (manually, or cascading from
    // someone else's list, rule 6) - in that case the OTHER side will
    // request the list once it accepts us, not us.
    bool should_request_list = false;
    // true once the peer-list request has actually been sent to this friend
    // (prevents re-sending on reconnects)
    bool request_sent = false;
};

struct GroupContext {
    Tox *tox;
    char admin_tox_id[TOX_ADDRESS_SIZE * 2 + 1];
    std::vector<PeerInfo> peers;

    // message_id values already seen (either sent by us or received/forwarded),
    // so a flooded message is displayed and relayed at most once
    std::set<std::string> seen_message_ids;
};

static std::atomic<bool> g_running{true};

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

PeerInfo *find_peer_by_friend_number(GroupContext *ctx, uint32_t friend_number) {
    for (auto &peer : ctx->peers) {
        if (peer.friend_number == friend_number) {
            return &peer;
        }
    }

    return nullptr;
}

PeerInfo *find_peer_by_tox_id(GroupContext *ctx, const char *tox_id) {
    for (auto &peer : ctx->peers) {
        if (strcmp(peer.tox_id, tox_id) == 0) {
            return &peer;
        }
    }

    return nullptr;
}

// should_request_list marks which of the two sides must initiate the
// peer-list request (rule 3).
void add_peer(GroupContext *ctx, uint32_t friend_number, const char *tox_id, const char *name,
              bool should_request_list = false) {
    if (find_peer_by_tox_id(ctx, tox_id)) {
        return;
    }

    char own_tox_id[TOX_ADDRESS_SIZE * 2 + 1];
    get_own_tox_id(ctx->tox, own_tox_id);

    PeerInfo peer;
    peer.friend_number = friend_number;
    strcpy(peer.tox_id, tox_id);
    strcpy(peer.name, name);
    peer.hash_distance = calculate_hash_distance(own_tox_id, tox_id);
    peer.connected = false;
    peer.should_request_list = should_request_list;
    peer.request_sent = false;

    ctx->peers.push_back(peer);

    printf("[INFO] Peer added: %s\n", tox_id);
}

void remove_peer(GroupContext *ctx, uint32_t friend_number) {
    for (auto it = ctx->peers.begin(); it != ctx->peers.end(); ++it) {
        if (it->friend_number == friend_number) {
            ctx->peers.erase(it);
            return;
        }
    }
}

std::string build_peer_request(Tox *tox) {
    char own_tox_id[TOX_ADDRESS_SIZE * 2 + 1];
    get_own_tox_id(tox, own_tox_id);

    std::stringstream ss;
    ss << (char)MSG_REQUEST_PEER_LIST;
    ss << own_tox_id;

    return ss.str();
}

std::string build_peer_list_message(GroupContext *ctx, const char *target_tox_id) {
    std::vector<PeerInfo> sorted_peers = ctx->peers;

    std::sort(sorted_peers.begin(), sorted_peers.end(),
        [target_tox_id](const PeerInfo &a, const PeerInfo &b) {
            uint32_t dist_a = calculate_hash_distance(a.tox_id, target_tox_id);
            uint32_t dist_b = calculate_hash_distance(b.tox_id, target_tox_id);
            return dist_a < dist_b;
        });

    std::stringstream ss;

    ss << (char)MSG_PEER_LIST;
    ss << ctx->admin_tox_id;
    ss << "|";

    int count = 0;

    for (const auto &peer : sorted_peers) {
        if (count >= 10) {
            break;
        }

        // rule 5: the requester itself (target) must not appear in the list we send back
        if (strcmp(peer.tox_id, target_tox_id) == 0) {
            continue;
        }

        ss << peer.tox_id << ":" << peer.name << ";";
        count++;
    }

    return ss.str();
}

std::string build_admin_response(GroupContext *ctx) {
    std::stringstream ss;
    ss << (char)MSG_ADMIN_RESPONSE;
    ss << ctx->admin_tox_id;
    return ss.str();
}

// --- group message protocol: minimal hand-written JSON, matching the exact
// schema required by rule 0:
// {"type":"group_message","message_id":"...","sender":"...","time":"...","message":"...","path":["...","..."]}
// A full JSON library is not linked in this project, so parsing/building is
// done manually here, the same way the rest of this file builds its own
// wire format (see build_peer_list_message / process_peer_list above).

std::string json_escape(const std::string &input) {
    std::string output;

    for (char c : input) {
        switch (c) {
            case '"':  output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\n': output += "\\n"; break;
            case '\r': output += "\\r"; break;
            case '\t': output += "\\t"; break;
            default:   output += c; break;
        }
    }

    return output;
}

// Extracts the value of a top-level "key":"value" string field.
std::string json_get_string(const std::string &json, const std::string &key) {
    std::string pattern = "\"" + key + "\":\"";
    size_t pos = json.find(pattern);

    if (pos == std::string::npos) {
        return "";
    }

    pos += pattern.length();

    std::string result;

    while (pos < json.length() && json[pos] != '"') {
        if (json[pos] == '\\' && pos + 1 < json.length()) {
            pos++;

            switch (json[pos]) {
                case 'n':  result += '\n'; break;
                case 't':  result += '\t'; break;
                case 'r':  result += '\r'; break;
                case '"':  result += '"'; break;
                case '\\': result += '\\'; break;
                default:   result += json[pos]; break;
            }
        } else {
            result += json[pos];
        }

        pos++;
    }

    return result;
}

// Extracts a top-level "key":["a","b",...] string array field.
std::vector<std::string> json_get_string_array(const std::string &json, const std::string &key) {
    std::vector<std::string> result;

    std::string pattern = "\"" + key + "\":[";
    size_t pos = json.find(pattern);

    if (pos == std::string::npos) {
        return result;
    }

    pos += pattern.length();

    size_t end = json.find(']', pos);

    if (end == std::string::npos) {
        return result;
    }

    std::string array_content = json.substr(pos, end - pos);

    size_t i = 0;

    while (i < array_content.length()) {
        if (array_content[i] == '"') {
            i++;

            std::string item;

            while (i < array_content.length() && array_content[i] != '"') {
                if (array_content[i] == '\\' && i + 1 < array_content.length()) {
                    i++;
                }

                item += array_content[i];
                i++;
            }

            result.push_back(item);
        }

        i++;
    }

    return result;
}

std::string build_path_json_array(const std::vector<std::string> &path) {
    std::stringstream ss;

    ss << "[";

    for (size_t i = 0; i < path.size(); i++) {
        if (i > 0) {
            ss << ",";
        }

        ss << "\"" << json_escape(path[i]) << "\"";
    }

    ss << "]";

    return ss.str();
}

// rule 0/3: builds the full group_message JSON payload
std::string build_group_message_json(const std::string &message_id, const std::string &sender,
                                      const std::string &time_str, const std::string &text,
                                      const std::vector<std::string> &path) {
    std::stringstream ss;

    ss << "{";
    ss << "\"type\":\"group_message\",";
    ss << "\"message_id\":\"" << json_escape(message_id) << "\",";
    ss << "\"sender\":\"" << json_escape(sender) << "\",";
    ss << "\"time\":\"" << json_escape(time_str) << "\",";
    ss << "\"message\":\"" << json_escape(text) << "\",";
    ss << "\"path\":" << build_path_json_array(path);
    ss << "}";

    return ss.str();
}

std::string bytes_to_hex_string(const uint8_t *bytes, size_t length) {
    std::stringstream ss;

    for (size_t i = 0; i < length; i++) {
        char buf[3];
        sprintf(buf, "%02X", bytes[i]);
        ss << buf;
    }

    return ss.str();
}

// rule 1: full send time, kept in the JSON "time" field
std::string current_time_string() {
    time_t now = time(nullptr);
    char buf[32];

    struct tm *tm_info = localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info);

    return std::string(buf);
}

// rule 4: message_id = hash(sender_id + current time WITHOUT seconds + message text)
// Uses tox_hash() (SHA-256 based, part of the public toxcore API used for
// file-transfer hashes) so no extra hashing dependency is needed.
std::string compute_message_id(const std::string &sender_id, const std::string &message_text) {
    time_t now = time(nullptr);
    time_t truncated_to_minute = now - (now % 60);

    std::string hash_input = sender_id + std::to_string((long long)truncated_to_minute) + message_text;

    uint8_t hash[TOX_HASH_LENGTH];

    tox_hash(hash, (const uint8_t *)hash_input.c_str(), hash_input.length());

    return bytes_to_hex_string(hash, TOX_HASH_LENGTH);
}

// Registers the peer in ctx->peers right after the friend request is sent
// successfully, so this node's own peer list (rule 4/6) stays accurate for
// friends it added itself.
void send_friend_request_to_peer(GroupContext *ctx, const char *tox_id) {
    if (find_peer_by_tox_id(ctx, tox_id)) {
        return;
    }

    uint8_t bytes[TOX_ADDRESS_SIZE];

    if (tox_id_to_bytes(tox_id, bytes) != 0) {
        printf("[ERROR] Invalid Tox ID: %s\n", tox_id);
        return;
    }

    Tox_Err_Friend_Add err;

    uint32_t friend_number = tox_friend_add(
        ctx->tox,
        bytes,
        (const uint8_t *)"Join group",
        10,
        &err
    );

    if (err == TOX_ERR_FRIEND_ADD_OK) {
        // We initiated this friendship ourselves, so WE do not request the list;
        // the other side will do it once it accepts us (rule 2/3)
        add_peer(ctx, friend_number, tox_id, "Unknown", false);
        printf("[SEND] Friend request sent: %s\n", tox_id);
    } else {
        printf("[WARN] Could not add peer %s, error: %d\n", tox_id, err);
    }
}

void process_peer_list(GroupContext *ctx, const char *data) {
    std::string message(data);

    size_t admin_separator = message.find('|');

    if (admin_separator == std::string::npos) {
        return;
    }

    std::string admin_id = message.substr(0, admin_separator);

    if (admin_id.length() == TOX_ADDRESS_SIZE * 2) {
        strcpy(ctx->admin_tox_id, admin_id.c_str());
        printf("[INFO] Admin ID: %s\n", ctx->admin_tox_id);
    }

    std::string peers = message.substr(admin_separator + 1);

    size_t position = 0;

    while (position < peers.length()) {
        size_t separator = peers.find(';', position);

        if (separator == std::string::npos) {
            break;
        }

        std::string entry = peers.substr(position, separator - position);

        size_t colon = entry.find(':');

        if (colon != std::string::npos) {
            std::string peer_id = entry.substr(0, colon);
            std::string peer_name = entry.substr(colon + 1);

            char own_tox_id[TOX_ADDRESS_SIZE * 2 + 1];
            get_own_tox_id(ctx->tox, own_tox_id);

            // rule 6: once we have the list, start adding the other peers from it
            if (peer_id != own_tox_id && !find_peer_by_tox_id(ctx, peer_id.c_str())) {
                send_friend_request_to_peer(ctx, peer_id.c_str());
            }
        }

        position = separator + 1;
    }
}

// rule 5: when a node receives a group message, it forwards it further to
// the known nodes that are NOT already in the message's own path, adding
// its own id to that path first. seen_message_ids additionally makes sure
// a message that reaches the same node twice (overlapping flood paths) is
// only shown/relayed once, instead of forwarded again in a loop.
void process_group_message(GroupContext *ctx, uint32_t friend_number, const char *payload, size_t payload_length) {
    std::string json(payload, payload_length);

    std::string message_id = json_get_string(json, "message_id");

    if (message_id.empty()) {
        printf("[WARN] Malformed group message received\n");
        return;
    }

    if (ctx->seen_message_ids.count(message_id) > 0) {
        return;
    }

    ctx->seen_message_ids.insert(message_id);

    std::string sender = json_get_string(json, "sender");
    std::string time_str = json_get_string(json, "time");
    std::string text = json_get_string(json, "message");
    std::vector<std::string> path = json_get_string_array(json, "path");

    printf("\n[GROUP %s] %s: %s\n", time_str.c_str(), sender.c_str(), text.c_str());

    char own_tox_id[TOX_ADDRESS_SIZE * 2 + 1];
    get_own_tox_id(ctx->tox, own_tox_id);

    bool already_in_path = false;

    for (const auto &id : path) {
        if (id == own_tox_id) {
            already_in_path = true;
            break;
        }
    }

    if (!already_in_path) {
        path.push_back(own_tox_id);
    }

    std::string forward_json = build_group_message_json(message_id, sender, time_str, text, path);

    std::string forward_payload;
    forward_payload += (char)MSG_GROUP_MESSAGE;
    forward_payload += forward_json;

    for (const auto &peer : ctx->peers) {
        if (!peer.connected) {
            continue;
        }

        bool peer_in_path = false;

        for (const auto &id : path) {
            if (id == peer.tox_id) {
                peer_in_path = true;
                break;
            }
        }

        if (peer_in_path) {
            continue;
        }

        Tox_Err_Friend_Send_Message err;

        tox_friend_send_message(
            ctx->tox,
            peer.friend_number,
            TOX_MESSAGE_TYPE_NORMAL,
            (const uint8_t *)forward_payload.c_str(),
            forward_payload.length(),
            &err
        );

        if (err == TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
            printf("[SEND] Group message forwarded to: %s\n", peer.tox_id);
        }
    }
}

void process_friend_message(GroupContext *ctx, uint32_t friend_number, const uint8_t *message, size_t length) {
    if (length < 1) {
        return;
    }

    MessageType type = (MessageType)message[0];
    const char *payload = (const char *)(message + 1);

    if (type == MSG_REQUEST_PEER_LIST) {
        if (length < 1 + TOX_ADDRESS_SIZE * 2) {
            return;
        }

        char target_tox_id[TOX_ADDRESS_SIZE * 2 + 1];

        memcpy(
            target_tox_id,
            payload,
            TOX_ADDRESS_SIZE * 2
        );

        target_tox_id[TOX_ADDRESS_SIZE * 2] = '\0';

        printf("[RECV] Peer list request from: %s\n", target_tox_id);

        std::string response = build_peer_list_message(ctx, target_tox_id);

        Tox_Err_Friend_Send_Message err;

        tox_friend_send_message(
            ctx->tox,
            friend_number,
            TOX_MESSAGE_TYPE_NORMAL,
            (const uint8_t *)response.c_str(),
            response.length(),
            &err
        );

        if (err == TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
            printf("[SEND] Peer list sent to: %s\n", target_tox_id);
        }

        return;
    }

    if (type == MSG_PEER_LIST) {
        process_peer_list(ctx, payload);
        return;
    }

    if (type == MSG_ADMIN_QUERY) {
        std::string response = build_admin_response(ctx);

        Tox_Err_Friend_Send_Message err;

        tox_friend_send_message(
            ctx->tox,
            friend_number,
            TOX_MESSAGE_TYPE_NORMAL,
            (const uint8_t *)response.c_str(),
            response.length(),
            &err
        );

        return;
    }

    if (type == MSG_ADMIN_RESPONSE) {
        if (strlen(payload) == TOX_ADDRESS_SIZE * 2) {
            strcpy(ctx->admin_tox_id, payload);
            printf("[INFO] Admin ID: %s\n", ctx->admin_tox_id);
        }

        return;
    }

    if (type == MSG_GROUP_MESSAGE) {
        // payload length is passed explicitly (length - 1 header byte)
        // instead of relying on null-termination, since a raw tox message
        // buffer is not guaranteed to be null-terminated
        process_group_message(ctx, friend_number, payload, length - 1);
        return;
    }
}

// Does NOT send the peer-list request directly here - the friend is not
// connected yet (no DHT handshake done), so sending now would almost always
// fail with FRIEND_NOT_CONNECTED and rule 3 would never actually happen.
// Instead the peer is marked with should_request_list=true, and the actual
// send happens in friend_connection_status_callback once the connection is
// really established.
void friend_request_callback(Tox *tox, const uint8_t *public_key, const uint8_t *message, size_t length, void *user_data) {
    GroupContext *ctx = static_cast<GroupContext *>(user_data);

    char tox_id[TOX_ADDRESS_SIZE * 2 + 1];
    tox_id_from_bytes(public_key, tox_id);

    printf("[RECV] Friend request from: %s\n", tox_id);

    Tox_Err_Friend_Add err;

    uint32_t friend_number = tox_friend_add_norequest(
        tox,
        public_key,
        &err
    );

    if (err != TOX_ERR_FRIEND_ADD_OK) {
        printf("[ERROR] Could not accept friend request: %d\n", err);
        return;
    }

    // rule 2: auto-accepted; rule 3: the accepting side (us) must request
    // the peer list -> should_request_list = true
    add_peer(ctx, friend_number, tox_id, "Unknown", true);
}

void friend_message_callback(Tox *tox, uint32_t friend_number, Tox_Message_Type type, const uint8_t *message, size_t length, void *user_data) {
    GroupContext *ctx = static_cast<GroupContext *>(user_data);

    if (type != TOX_MESSAGE_TYPE_NORMAL) {
        return;
    }

    process_friend_message(
        ctx,
        friend_number,
        message,
        length
    );
}

// Once the connection to a friend is actually established, and if this is
// a friend we accepted (should_request_list) and we haven't requested the
// list yet, send the request now (rule 3). request_sent guards against
// duplicate sends on reconnects.
void friend_connection_status_callback(Tox *tox, uint32_t friend_number, Tox_Connection connection_status, void *user_data) {
    GroupContext *ctx = static_cast<GroupContext *>(user_data);

    PeerInfo *peer = find_peer_by_friend_number(ctx, friend_number);

    if (connection_status != TOX_CONNECTION_NONE) {
        printf("[EVENT] Friend %u connected\n", friend_number);

        if (peer) {
            printf("[INFO] Peer ID: %s\n", peer->tox_id);

            peer->connected = true;

            if (peer->should_request_list && !peer->request_sent) {
                std::string request = build_peer_request(tox);

                Tox_Err_Friend_Send_Message send_err;

                tox_friend_send_message(
                    tox,
                    friend_number,
                    TOX_MESSAGE_TYPE_NORMAL,
                    (const uint8_t *)request.c_str(),
                    request.length(),
                    &send_err
                );

                if (send_err == TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
                    peer->request_sent = true;
                    printf("[SEND] Peer list request sent to: %s\n", peer->tox_id);
                } else {
                    printf("[WARN] Failed to send peer list request to %s, error: %d\n", peer->tox_id, send_err);
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
        printf("[EVENT] Connected to Tox DHT\n");
    } else {
        printf("[EVENT] Disconnected from Tox DHT\n");
    }
}

Tox *initialize_tox(const char *name, const char *save_data_file) {
    Tox_Options *options = tox_options_new(NULL);

    FILE *f = fopen(save_data_file, "rb");

    if (f) {
        fseek(f, 0, SEEK_END);
        size_t size = ftell(f);
        fseek(f, 0, SEEK_SET);

        uint8_t *data = (uint8_t *)malloc(size);

        if (data) {
            fread(data, 1, size, f);
            fclose(f);

            tox_options_set_savedata_data(options, data, size);
            tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_TOX_SAVE);

            free(data);

            printf("[INFO] Saved Tox data loaded\n");
        } else {
            fclose(f);
        }
    }

    Tox_Err_New err;

    Tox *tox = tox_new(options, &err);

    tox_options_free(options);

    if (err != TOX_ERR_NEW_OK) {
        printf("[ERROR] Tox initialization failed: %d\n", err);
        return NULL;
    }

    Tox_Err_Set_Info name_err;

    tox_self_set_name(
        tox,
        (const uint8_t *)name,
        strlen(name),
        &name_err
    );

    return tox;
}

void save_tox_data(Tox *tox, const char *save_data_file) {
    size_t size = tox_get_savedata_size(tox);

    uint8_t *data = (uint8_t *)malloc(size);

    if (!data) {
        return;
    }

    tox_get_savedata(tox, data);

    FILE *f = fopen(save_data_file, "wb");

    if (f) {
        fwrite(data, 1, size, f);
        fclose(f);
        printf("[INFO] Tox data saved\n");
    }

    free(data);
}

void print_self_info(Tox *tox) {
    char tox_id[TOX_ADDRESS_SIZE * 2 + 1];
    get_own_tox_id(tox, tox_id);

    printf("\nTox ID:\n%s\n\n", tox_id);
}

void print_menu() {
    printf("\n");
    printf("1 - Show own Tox ID\n");
    printf("2 - Show friends\n");
    printf("3 - Show admin ID\n");
    printf("4 - Request admin ID\n");
    printf("5 - Add friend by Tox ID\n");
    printf("6 - Set admin ID\n");
    printf("7 - Send group message\n");
    printf("9 - Exit\n");
}

void print_peers(GroupContext *ctx) {
    printf("\nFriends: %zu\n", ctx->peers.size());

    for (size_t i = 0; i < ctx->peers.size(); i++) {
        PeerInfo &peer = ctx->peers[i];

        printf(
            "%zu. %s | %s | distance: %u | %s\n",
            i + 1,
            peer.tox_id,
            peer.name,
            peer.hash_distance,
            peer.connected ? "online" : "offline"
        );
    }

    if (ctx->peers.empty()) {
        printf("No friends\n");
    }
}

void print_admin_info(GroupContext *ctx) {
    if (strlen(ctx->admin_tox_id) == 0) {
        printf("\nAdmin ID is not set\n");
    } else {
        printf("\nAdmin ID: %s\n", ctx->admin_tox_id);
    }
}

void request_admin_from_friend(GroupContext *ctx) {
    if (ctx->peers.empty()) {
        printf("[WARN] No friends\n");
        return;
    }

    PeerInfo &peer = ctx->peers[0];

    std::string request;
    request += (char)MSG_ADMIN_QUERY;

    Tox_Err_Friend_Send_Message err;

    tox_friend_send_message(
        ctx->tox,
        peer.friend_number,
        TOX_MESSAGE_TYPE_NORMAL,
        (const uint8_t *)request.c_str(),
        request.length(),
        &err
    );

    if (err == TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
        printf("[SEND] Admin request sent to %s\n", peer.tox_id);
    } else {
        printf("[ERROR] Failed to send admin request: %d\n", err);
    }
}

void set_admin_id(GroupContext *ctx) {
    char tox_id[TOX_ADDRESS_SIZE * 2 + 1];

    printf("Enter admin Tox ID: ");

    if (!fgets(tox_id, sizeof(tox_id), stdin)) {
        return;
    }

    size_t len = strlen(tox_id);

    while (len > 0 && (tox_id[len - 1] == '\n' || tox_id[len - 1] == '\r')) {
        tox_id[--len] = '\0';
    }

    if (strlen(tox_id) != TOX_ADDRESS_SIZE * 2) {
        printf("[ERROR] Invalid Tox ID\n");
        return;
    }

    uint8_t bytes[TOX_ADDRESS_SIZE];

    if (tox_id_to_bytes(tox_id, bytes) != 0) {
        printf("[ERROR] Invalid Tox ID\n");
        return;
    }

    strcpy(ctx->admin_tox_id, tox_id);

    printf("[INFO] Admin ID set to: %s\n", ctx->admin_tox_id);
}

// rule 2: a newly originated message is sent to any 3 known nodes of the group
void send_group_message(GroupContext *ctx, const std::string &text) {
    char own_tox_id[TOX_ADDRESS_SIZE * 2 + 1];
    get_own_tox_id(ctx->tox, own_tox_id);

    std::string message_id = compute_message_id(own_tox_id, text);
    std::string time_str = current_time_string();

    // the originator is already part of the path so the message never
    // gets forwarded back to itself once it starts flooding out
    std::vector<std::string> path;
    path.push_back(own_tox_id);

    ctx->seen_message_ids.insert(message_id);

    std::string json = build_group_message_json(message_id, own_tox_id, time_str, text, path);

    std::string payload;
    payload += (char)MSG_GROUP_MESSAGE;
    payload += json;

    std::vector<PeerInfo *> connected_peers;

    for (auto &peer : ctx->peers) {
        if (peer.connected) {
            connected_peers.push_back(&peer);
        }
    }

    if (connected_peers.empty()) {
        printf("[WARN] No connected peers to send the message to\n");
        return;
    }

    std::random_device rd;
    std::mt19937 rng(rd());
    std::shuffle(connected_peers.begin(), connected_peers.end(), rng);

    int sent_count = 0;

    for (auto *peer : connected_peers) {
        if (sent_count >= 3) {
            break;
        }

        Tox_Err_Friend_Send_Message err;

        tox_friend_send_message(
            ctx->tox,
            peer->friend_number,
            TOX_MESSAGE_TYPE_NORMAL,
            (const uint8_t *)payload.c_str(),
            payload.length(),
            &err
        );

        if (err == TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
            sent_count++;
            printf("[SEND] Group message sent to: %s\n", peer->tox_id);
        }
    }

    if (sent_count == 0) {
        printf("[ERROR] Failed to send the group message to any peer\n");
    }
}

void send_group_message_console(GroupContext *ctx) {
    char text[1024];

    printf("Enter message: ");

    if (!fgets(text, sizeof(text), stdin)) {
        return;
    }

    size_t len = strlen(text);

    while (len > 0 && (text[len - 1] == '\n' || text[len - 1] == '\r')) {
        text[--len] = '\0';
    }

    if (len == 0) {
        printf("[ERROR] Empty message\n");
        return;
    }

    send_group_message(ctx, std::string(text));
}

void add_friend_by_id(GroupContext *ctx) {
    char tox_id[TOX_ADDRESS_SIZE * 2 + 1];

    printf("Enter Tox ID: ");

    if (!fgets(tox_id, sizeof(tox_id), stdin)) {
        return;
    }

    size_t len = strlen(tox_id);

    while (len > 0 && (tox_id[len - 1] == '\n' || tox_id[len - 1] == '\r')) {
        tox_id[--len] = '\0';
    }

    if (strlen(tox_id) != TOX_ADDRESS_SIZE * 2) {
        printf("[ERROR] Invalid Tox ID\n");
        return;
    }

    uint8_t bytes[TOX_ADDRESS_SIZE];

    if (tox_id_to_bytes(tox_id, bytes) != 0) {
        printf("[ERROR] Invalid Tox ID\n");
        return;
    }

    send_friend_request_to_peer(ctx, tox_id);
}

void console_input_thread(GroupContext *ctx) {
    char input[256];

    while (g_running.load()) {
        printf("\n> ");
        fflush(stdout);

        if (!fgets(input, sizeof(input), stdin)) {
            g_running.store(false);
            break;
        }

        int cmd = atoi(input);

        switch (cmd) {
            case 1:
                print_self_info(ctx->tox);
                break;

            case 2:
                print_peers(ctx);
                break;

            case 3:
                print_admin_info(ctx);
                break;

            case 4:
                request_admin_from_friend(ctx);
                break;

            case 5:
                add_friend_by_id(ctx);
                break;

            case 6:
                set_admin_id(ctx);
                break;

            case 7:
                send_group_message_console(ctx);
                break;

            case 9:
                g_running.store(false);
                break;

            case 0:
                print_menu();
                break;

            default:
                printf("[INFO] Unknown command. Enter 0 for menu.\n");
                break;
        }
    }
}

int main(int argc, char *argv[]) {
    printf("Thauon GROUP NODE\n");
    printf("Tox pseudo-public group\n\n");

    GroupContext ctx;

    ctx.tox = NULL;
    ctx.admin_tox_id[0] = '\0';

    printf("1 - Create new group (start as founding node)\n");
    printf("2 - Join existing group (enter a node's Tox ID)\n");
    printf("Choice: ");

    int mode = 0;

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

    // Bug: rand() was never seeded, so every freshly started process produced
    // the exact same deterministic sequence of "random" numbers (libc's
    // default seed is 1). That means every node instance computed the SAME
    // node_name and, critically, the SAME save_file name - so launching
    // several nodes at once made them all read/write the same .tox file,
    // racing each other. One instance would see a half-written or otherwise
    // mismatched file and tox_new() would fail with
    // TOX_ERR_NEW_LOAD_BAD_FORMAT (error code 9).
    //
    // Fix: seed with time + the OS process id, and also fold the process id
    // directly into the filename. Two different processes always have
    // different PIDs, so this guarantees a unique save file even if several
    // nodes are started in the very same second.
    DWORD pid = GetCurrentProcessId();

    srand((unsigned int)time(nullptr) ^ (unsigned int)pid);

    sprintf(
        node_name,
        "GroupNode_%lu_%d",
        (unsigned long)pid,
        rand() % 10000
    );

    sprintf(
        save_file,
        "node_%lu_%d.tox",
        (unsigned long)pid,
        rand() % 10000
    );

    printf("\n[INIT] Starting Tox node...\n");

    ctx.tox = initialize_tox(
        node_name,
        save_file
    );

    if (!ctx.tox) {
        printf("[ERROR] Tox initialization failed\n");
        return 1;
    }

    char own_tox_id[TOX_ADDRESS_SIZE * 2 + 1];

    get_own_tox_id(
        ctx.tox,
        own_tox_id
    );

    printf("\nNode ready\n");
    printf("Tox ID: %s\n", own_tox_id);

    tox_callback_friend_request(
        ctx.tox,
        friend_request_callback
    );

    tox_callback_friend_message(
        ctx.tox,
        friend_message_callback
    );

    tox_callback_friend_connection_status(
        ctx.tox,
        friend_connection_status_callback
    );

    tox_callback_self_connection_status(
        ctx.tox,
        self_connection_status_callback
    );

    // Use IP addresses instead of a hostname: tox_bootstrap resolves the
    // host itself, and on networks without working DNS that resolution
    // fails with TOX_ERR_BOOTSTRAP_BAD_HOST (error code 2) before a single
    // UDP packet is even sent. A short list of well-known nodes, tried by
    // IP, avoids depending on DNS and also avoids a single point of failure.
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

            sscanf(
                node.public_key + i * 2,
                "%2x",
                &value
            );

            bootstrap_key_bytes[i] = (uint8_t)value;
        }

        Tox_Err_Bootstrap bootstrap_err;

        tox_bootstrap(
            ctx.tox,
            node.address,
            node.port,
            bootstrap_key_bytes,
            &bootstrap_err
        );

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
    // on rules 2-6 (auto-accept, peer-list request/response, cascading
    // adds) take over automatically.
    if (join_tox_id[0] != '\0') {
        printf("[INIT] Joining group via node: %s\n", join_tox_id);
        send_friend_request_to_peer(&ctx, join_tox_id);
    }

    print_menu();

    std::thread input_thread(
        console_input_thread,
        &ctx
    );

    while (g_running.load()) {
        tox_iterate(
            ctx.tox,
            &ctx
        );

        uint32_t interval = tox_iteration_interval(ctx.tox);

        if (interval == 0) {
            interval = 10;
        }

        Sleep(interval);
    }

    if (input_thread.joinable()) {
        input_thread.join();
    }

    printf("\n[CLEANUP] Saving node...\n");

    save_tox_data(
        ctx.tox,
        save_file
    );

    tox_kill(ctx.tox);

    printf("[INFO] Node stopped\n");

    return 0;
}