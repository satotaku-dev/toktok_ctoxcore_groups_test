PROTOCOL - THESE POINTS MUST BE FOLLOWED WHEN MODIFYING THE CODE 
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

