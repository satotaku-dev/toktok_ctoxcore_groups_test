// Real Tox group-protocol test node.
//
// This opens an actual Tox instance, bootstraps into the DHT, and talks
// the exact same wire protocol as group_node_test.cpp (which must not be
// modified) via the shared callbacks in link_groups.h. It is meant to be
// run alongside real group_node_test.cpp-based nodes (or other instances
// of this program) to verify real interoperability - it is not an offline
// simulator.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <atomic>
#include <iostream>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "mini_json.h"
#include "link_groups.h"

static void sleep_ms(unsigned ms) {
#ifdef _WIN32
    Sleep(ms);
#else
    usleep(ms * 1000);
#endif
}

// A handful of well-known public Tox bootstrap nodes.
struct BootstrapNode {
    const char *address;
    uint16_t port;
    const char *public_key_hex;
};

static const BootstrapNode BOOTSTRAP_NODES[] = { //Just for test
    {"144.217.167.73",  33445, "7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A2A2FD34C"},
    {"3.0.24.15",       33445, "E20ABCF38CDBFFD7D04B29C956B33F7B27A3BB7AF0618101617B036E4AEA402D"},
    {"139.162.110.188", 33445, "F76A11284547163889DDC89A7738CF271797BF5E5E220643E97AD3C7E7903D55"},
    {"172.104.215.182", 33445, "DA2BD927E01CD05EBCC2574EBE5BEBB10FF59AE0B2105A7D1E2B40E49BB20239"},
};

static bool hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    if (strlen(hex) != out_len * 2) return false;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int value = 0;
        if (sscanf(hex + i * 2, "%2x", &value) != 1) return false;
        out[i] = (uint8_t)value;
    }
    return true;
}

static void bootstrap(Tox *tox) {
    for (const auto &node : BOOTSTRAP_NODES) {
        uint8_t pubkey[TOX_PUBLIC_KEY_SIZE];
        if (!hex_to_bytes(node.public_key_hex, pubkey, TOX_PUBLIC_KEY_SIZE)) continue;

        Tox_Err_Bootstrap err;
        tox_bootstrap(tox, node.address, node.port, pubkey, &err);
        if (err == TOX_ERR_BOOTSTRAP_OK) {
            printf("[INFO] Bootstrapped via %s\n", node.address);
        }
    }
}

static Tox *initialize_tox(const std::string &savefile) {
    Tox_Options *options = tox_options_new(nullptr);

    std::vector<uint8_t> savedata;
    FILE *f = fopen(savefile.c_str(), "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        long size = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (size > 0) {
            savedata.resize((size_t)size);
            if (fread(savedata.data(), 1, (size_t)size, f) != (size_t)size) savedata.clear();
        }
        fclose(f);
    }

    if (!savedata.empty()) {
        tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_TOX_SAVE);
        tox_options_set_savedata_data(options, savedata.data(), savedata.size());
        printf("[INFO] Loaded save file: %s\n", savefile.c_str());
    }

    Tox_Err_New err;
    Tox *tox = tox_new(options, &err);
    tox_options_free(options);

    if (err != TOX_ERR_NEW_OK || !tox) {
        printf("[ERROR] tox_new failed: %d\n", (int)err);
        return nullptr;
    }

    tox_self_set_name(tox, (const uint8_t *)"GroupTestNode", 13, nullptr);
    return tox;
}

static void save_tox_data(Tox *tox, const std::string &savefile) {
    size_t size = tox_get_savedata_size(tox);
    if (size == 0) return;

    std::vector<uint8_t> data(size);
    tox_get_savedata(tox, data.data());

    FILE *f = fopen(savefile.c_str(), "wb");
    if (f) {
        fwrite(data.data(), 1, size, f);
        fclose(f);
    }
}

static std::atomic<bool> running{true};
static GroupContext group;

static void print_menu() {
    printf("\n=== Group Protocol Node ===\n");
    printf("1. Show my Tox ID\n");
    printf("2. Show friends\n");
    printf("3. Show admin ID\n");
    printf("4. Request admin ID from a friend\n");
    printf("5. Add friend by Tox ID\n");
    printf("6. Set admin ID (type your own ID to found a group as admin)\n");
    printf("7. Send group message\n");
    printf("8. Ban peer by Tox ID\n");
    printf("9. Show blacklist\n");
    printf("10. Save & exit\n");
    printf("Choice: ");
}

static std::string prompt_line() {
    std::string line;
    if (!std::getline(std::cin, line)) return "";
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
    return line;
}

static void console_thread_fn(const std::string &savefile) {
    while (running) {
        print_menu();
        std::string choice_str = prompt_line();
        int choice = atoi(choice_str.c_str());

        switch (choice) {
            case 1: {
                printf("\n[MY ID] %s\n", get_own_tox_id(group.tox).c_str());
                break;
            }
            case 2: {
                printf("\n[FRIENDS] Total: %zu\n", group.peers.size());
                for (const auto &p : group.peers) {
                    printf("  #%u %s | name=%s | connected=%d | should_request_list=%d | request_sent=%d\n",
                           p.friend_number, p.tox_id.c_str(), p.name.c_str(), p.connected,
                           p.should_request_list, p.request_sent);
                }
                break;
            }
            case 3: {
                if (group.admin_tox_id.empty()) {
                    printf("\n[ADMIN] not set\n");
                } else {
                    printf("\n[ADMIN] %s\n", group.admin_tox_id.c_str());
                    printf("[IS_ADMIN] %s\n", group.admin_tox_id == get_own_tox_id(group.tox) ? "YES" : "NO");
                }
                break;
            }
            case 4: {
                printf("Friend number: ");
                uint32_t fn = (uint32_t)atoi(prompt_line().c_str());
                request_admin_from_friend(group, fn);
                break;
            }
            case 5: {
                printf("Enter Tox ID (%d hex chars): ", TOX_ADDRESS_SIZE * 2);
                std::string tox_id = prompt_line();
                if ((int)tox_id.length() != TOX_ADDRESS_SIZE * 2) {
                    printf("[ERROR] invalid length\n");
                    break;
                }
                send_friend_request_to_peer(group, tox_id);
                break;
            }
            case 6: {
                printf("Enter admin Tox ID (%d hex chars): ", TOX_ADDRESS_SIZE * 2);
                std::string admin_id = prompt_line();
                if ((int)admin_id.length() != TOX_ADDRESS_SIZE * 2) {
                    printf("[ERROR] invalid length\n");
                    break;
                }
                uint8_t bytes[TOX_ADDRESS_SIZE];
                if (tox_id_to_bytes(admin_id, bytes) != 0) {
                    printf("[ERROR] invalid Tox ID\n");
                    break;
                }
                group.admin_tox_id = admin_id;
                printf("\n[INFO] Admin ID set to: %s\n", group.admin_tox_id.c_str());
                break;
            }
            case 7: {
                printf("Enter message: ");
                std::string msg = prompt_line();
                if (!msg.empty()) send_group_message(group, msg);
                break;
            }
            case 8: {
                if (group.admin_tox_id != get_own_tox_id(group.tox)) {
                    printf("\n[ERROR] Only admin can ban peers\n");
                    break;
                }
                printf("Enter peer Tox ID to ban (%d hex chars): ", TOX_ADDRESS_SIZE * 2);
                std::string ban_id = prompt_line();
                if ((int)ban_id.length() != TOX_ADDRESS_SIZE * 2) {
                    printf("[ERROR] invalid length\n");
                    break;
                }
                uint8_t bytes[TOX_ADDRESS_SIZE];
                if (tox_id_to_bytes(ban_id, bytes) != 0) {
                    printf("[ERROR] invalid Tox ID\n");
                    break;
                }
                send_ban_command(group, ban_id);
                break;
            }
            case 9: {
                printf("\n[BLACKLIST] Total banned: %zu\n", group.blacklist.size());
                for (const auto &id : group.blacklist) {
                    printf("  %s\n", id.c_str());
                }
                break;
            }
            case 10: {
                save_tox_data(group.tox, savefile);
                printf("\n[EXIT] Saved to %s\n", savefile.c_str());
                running = false;
                break;
            }
            default:
                printf("[ERROR] unknown command\n");
        }
    }
}

int main(int argc, char **argv) {
    std::string savefile = "group_node.tox";
    std::string join_tox_id;

    if (argc > 1) savefile = argv[1];
    if (argc > 2) join_tox_id = argv[2];

    printf("Group Protocol Node\n\n");

    Tox *tox = initialize_tox(savefile);
    if (!tox) return 1;

    group.tox = tox;

    tox_callback_friend_request(tox, friend_request_callback);
    tox_callback_friend_message(tox, friend_message_callback);
    tox_callback_friend_connection_status(tox, friend_connection_status_callback);
    tox_callback_self_connection_status(tox, self_connection_status_callback);

    bootstrap(tox);

    printf("[MY ID] %s\n\n", get_own_tox_id(tox).c_str());

    // rule 1: any node's regular Tox ID is also the id used to join the
    // group - joining means simply sending it a friend request. From there
    // on rules 2-6 (auto-accept, peer-list request/response, cascading
    // adds) take over automatically. Can be done here at startup by passing
    // the target's Tox ID as a second command-line argument, or later from
    // the menu via option 5.
    if (!join_tox_id.empty()) {
        if ((int)join_tox_id.length() != TOX_ADDRESS_SIZE * 2) {
            printf("[ERROR] join Tox ID has invalid length, ignoring\n");
        } else {
            printf("[INIT] Joining group via node: %s\n", join_tox_id.c_str());
            send_friend_request_to_peer(group, join_tox_id);
        }
    } else {
        printf("Type '6' at the menu to found a new group as admin, or '5' to join by adding an existing member's Tox ID.\n");
        printf("(You can also join directly at startup: %s <savefile> <founder_tox_id>)\n", argv[0]);
    }

    std::thread console_thread(console_thread_fn, savefile);

    while (running) {
        tox_iterate(tox, &group);
        sleep_ms(tox_iteration_interval(tox));
    }

    console_thread.join();
    tox_kill(tox);
    return 0;
}
