
 PSEUDO-GROUP PROTOCOL ON TOP OF TOX (current implementation)

 This is NOT a real Tox group chat (tox_group_*) - this is a protocol built
 on top of ordinary 1:1 Tox friendships (friend_number), where "group" is
 merely a convention maintained only by the logic of this file and by the
 admin_id field matching for all participants. The protocol below is
 described exactly as it is implemented NOW, including its deliberate
 limitations.

 ---- Identifiers ----
 - Full Tox ID = 76 hex characters (32 bytes of public key + 2 bytes of
   NOSPAM + 2 bytes of checksum). It is used both as the participant ID
   and as "the person being added" to join the group.
 - Until the full address is known (for example, an incoming friend request
   provides only the public key), the participant is temporarily stored
   under the 64-character pubkey; the full address is learned later
   (update_peer_real_id) and is always verified against the already known
   pubkey prefix rather than simply overwritten.

 ---- Wire message format ----
 One type byte + payload:
   MSG_REQUEST_PEER_LIST = 2  -- payload: JSON {sender, admin_id}
                                  (admin_id may be empty - meaning
                                  "I don't have a group yet, I want to join")
   MSG_PEER_LIST          = 3  -- payload: JSON {type, admin_id, sender, peers[]}
   MSG_ADMIN_QUERY        = 4  -- payload: empty
   MSG_ADMIN_RESPONSE     = 5  -- payload: 76-byte admin_tox_id
   MSG_GROUP_MESSAGE      = 6  -- payload: JSON {type, message_id, sender,
                                  time, message|cmd, admin_id, path[]}

 ---- Joining the group ----
 1. A "group" = all nodes with the same admin_tox_id. Joining = an ordinary
    Tox friend request to the tox_id of any group participant
    (send_friend_request_to_peer, menu 5 / join_tox_id command-line argument).
 2. Incoming friend requests (friend_request_callback) are ACCEPTED
    AUTOMATICALLY, without asking the user, BUT only if the node already
    has an admin_tox_id (i.e. the node already belongs to someone - it
    founded the group via menu 6 or has already successfully joined one).
    While admin_tox_id is empty, any unsolicited (not initiated by us)
    friend requests are rejected - otherwise, whoever contacted us first
    would win the race for the right to become "our" admin_id instead of
    the actual target of the join operation.
 3. After the friend connection is established, if should_request_list=true
    (set for both outgoing and accepted incoming friends), the node
    automatically sends MSG_REQUEST_PEER_LIST with its tox_id and its
    (possibly empty) admin_id.
 4. The request recipient (process_friend_message):
    - verifies the tox_id claimed in the request against the actual,
      cryptographically authenticated identity of the friend_number that
      physically sent it (does not take the field at face value);
    - responds with MSG_PEER_LIST only if the requester's admin_id is empty
      (this is a genuine attempt to join) OR matches ours - if it already
      claims a DIFFERENT, foreign admin_id from ours, then it already
      belongs to another established group and has no reason to request
      our list - such a request is simply ignored;
    - in all other cases, responds with MSG_PEER_LIST - JSON containing
      its own admin_id, its own sender (own tox_id), and a list of up to 10
      known peers (sorted by XOR distance to the requester).
 5. Processing an incoming peer_list (process_peer_list):
    - The "sender" field is verified against the actual, cryptographically
      authenticated tox_id of the friend_number that physically delivered
      the message (rather than simply being trusted).
    - If we do not yet have an admin_tox_id - take it from the list (this
      is the moment of actual "joining the group").
    - If admin_tox_id ALREADY exists and does NOT match the admin_id from
      this list - the list is completely ignored (this is a foreign group;
      we neither cache it nor send friend requests to its participants).
    - Only if the list passes these checks - send our own friend request
      for each new peer_id from it (cascading discovery of the remaining
      group participants).

 ---- Group message exchange ----
 - send_group_message: builds a group_message JSON with message_id =
   hash(sender + time_rounded_to_the_minute + text), path=[self],
   and broadcasts it to 3 randomly selected connected friends (simple
   gossip flooding, not a tree and not a centralized relay).
 - process_group_message on each node:
   - message_id is used for deduplication (seen_message_ids, TTL
     60s) - messages seen previously are not processed or
     forwarded again.
   - A message with a foreign admin_id (when ours is already set) is dropped
     (rule 8) - this separates different groups from each other at the chat
     level.
   - The message is forwarded to all connected friends who are in neither
     path nor blacklist, with self added to path (protection against
     repeated forwarding in a loop).

 ---- Moderation (bans) ----
 - send_ban_command: only the current admin (ctx.admin_tox_id == own
   tox_id) may initiate it; applies the ban locally immediately and
   broadcasts a group_message with cmd="ban_id:<target>" to 3 random friends.
 - process_group_message on the recipient of the ban_id command:
   - A "direct" ban = the message was delivered OVER THE TOX FRIENDSHIP
     whose actual, cryptographically authenticated tox_id (found via
     find_peer_by_friend_number using the actual friend_number, NOT the
     sender string from the JSON) matches ctx.admin_tox_id. Only in this
     case is the ban applied immediately.
   - Otherwise (relay through someone else), the node does not trust it and
     directly asks the real admin_id (via a Tox friend message) for
     confirmation using cmd="checkban_id:<target>".
   - The admin, upon receiving checkban_id, makes the decision itself and
     sends the ban_id confirmation back to EXACTLY the friend_number that
     physically sent the request (rather than to whoever claimed to be the
     sender in the JSON).

 ---- Known limitations (deliberately not addressed at this stage) ----
 - There are no cryptographic signatures over any commands (ban_id,
   admin assignment, etc.) - all protection is based on authentication at
   the Tox connection level (friend_number <-> public key), rather than on
   signatures over message contents.
 - blacklist is not explicitly synchronized when a new participant joins -
   they learn about bans only from those group_message messages that reach
   them after they come online.


 ## Pseudo-group vs. Native Tox Group

The current implementation is intentionally different from the native `tox_group_*` architecture. The main trade-offs are:

| Feature                                                                       |                      Pseudo-group on Tox friendships                     |            Native Tox Group            |
| ----------------------------------------------------------------------------- | :----------------------------------------------------------------------: | :------------------------------------: |
| **Join a public group without an invitation, using any participant's Tox ID** |                                🟢 **Yes**                                |                🔴 **No**               |
| **Public / discoverable group model**                                         |                                🟢 Possible                               |             🔴 Invite-based            |
| Built on ordinary 1:1 Tox friendships                                         |                                    🟢                                    | 🟡 Uses temporary `friend_connection`s |
| Requires changes to toxcore                                                   |                                   🟢 No                                  |                 🔴 Yes                 |
| Maximum direct connections per peer                                           |                     🟡 Depends on the implementation                     |                🟢 **4**                |
| Deterministic peer topology                                                   |                                   🔴 No                                  |                 🟢 Yes                 |
| Automatic topology recalculation                                              |                           🟡 Via peer discovery                          |                 🟢 Yes                 |
| Redundant paths between peers                                                 |                            🟢 Potentially many                           |               🟡 Limited               |
| Resilience to individual peer failures                                        |                            🟢 Potentially good                           |         🟡 Depends on topology         |
| Predictable routing                                                           |                                    🟡                                    |                   🟢                   |
| Best-effort message delivery                                                  |                                    🟢                                    |                   🟢                   |
| ACK + retry can be added                                                      |                                    🟢                                    |                   🟢                   |
| Retry through an alternative peer                                             |                                    🟢                                    |                   🟢                   |
| Message deduplication                                                         |                              🟢 `message_id`                             |                   🟢                   |
| Cryptographic message signatures                                              |                       🟡 Not currently implemented                       |      🟡 Depends on protocol layer      |
| Protection against relay modifying a message                                  | 🟡 Tox authenticates the connection, but there are no message signatures |                   🟡                   |
| Gossip / flooding                                                             |                                    🟢                                    |                   🟡                   |
| Traffic control                                                               |                                    🟡                                    |                   🟢                   |
| Scalability                                                                   |                                    🟡                                    |                   🟢                   |
| Bandwidth efficiency                                                          |                   🟡 Depends on flooding and group size                  |                   🟢                   |
| Dynamic membership                                                            |                                    🟢                                    |                   🟢                   |
| Implementation complexity                                                     |                                  🟢 Low                                  |                 🔴 High                |
| Easy to prototype without modifying toxcore                                   |                                    🟢                                    |                   🔴                   |
| Suitable as a native Tox group implementation                                 |                                   🔴 No                                  |                   🟢                   |

### Important reliability note

The current pseudo-group implementation uses gossip flooding and therefore does **not guarantee delivery**. A message is initially sent to 3 randomly selected connected friends, and recipients forward it to other eligible friends.

This provides redundant paths when the friendship graph is well connected, but it does not provide an end-to-end delivery guarantee.

A future reliable-delivery layer could add:

```text
MESSAGE(message_id)
        │
        ▼
     peer
        │
        ├── ACK(message_id)
        │
        └── timeout
              │
              ▼
       retry via another peer
```

Together with the existing `message_id` deduplication, this would provide an **at-least-once delivery** model while allowing duplicate transmissions to be safely ignored.

For stronger guarantees, ACKs could also be used to track which participants have received a particular message.

### Message authenticity

The current protocol relies on Tox connection-level authentication: a `friend_number` is associated with the authenticated Tox public key of the peer that actually delivered the message.

However, group messages themselves are **not cryptographically signed**.

Therefore, if a message is relayed through multiple peers, the protocol currently authenticates **the connection that delivered the message**, but does not provide a cryptographic proof inside the message itself that a particular participant originally authored its contents.

A future version could sign the original group message with the sender's long-term private key:

```text
sender_public_key
group_id / admin_id
message_id
timestamp
message_body
        │
        ▼
signature = Sign(sender_private_key, message_hash)
```

The original message and signature could then be forwarded unchanged through the gossip network. This would allow every recipient to independently verify the original author's identity and detect any modification by relay nodes.

