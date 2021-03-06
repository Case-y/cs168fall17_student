import wan_optimizer
import utils
import tcp_packet


class WanOptimizer(wan_optimizer.BaseWanOptimizer):
    """ WAN Optimizer that divides data into variable-sized
    blocks based on the contents of the file.

    This WAN optimizer should implement part 2 of project 4.
    """

    # The string of bits to compare the lower order 13 bits of hash to
    GLOBAL_MATCH_BITSTRING = '0111011001010'

    def __init__(self):
        wan_optimizer.BaseWanOptimizer.__init__(self)
        # Add any code that you like here (but do not add any constructor arguments).
        self.hash_data = dict()
        self.window_size = 48
        self.buffers = dict()               # (src, destination) <--> message so far
        self.receives = dict()

    def receive(self, packet):
        """ Handles receiving a packet.

        Right now, this function simply forwards packets to clients (if a packet
        is destined to one of the directly connected clients), or otherwise sends
        packets across the WAN. You should change this function to implement the
        functionality described in part 2.  You are welcome to implement private
        helper fuctions that you call here. You should *not* be calling any functions
        or directly accessing any variables in the other middlebox on the other side of
        the WAN; this WAN optimizer should operate based only on its own local state
        and packets that have been received.
        """

        buffer_key = (packet.src, packet.dest)

        if buffer_key not in self.buffers:
            self.buffers[buffer_key] = ""
        if packet.dest in self.address_to_port and buffer_key not in self.receives:
            self.receives[buffer_key] = ""

        packet_size = packet.size() + self.buffers[buffer_key].__len__()
        if packet_size > utils.MAX_PACKET_SIZE + self.buffers[buffer_key].__len__():
            # For all communication, the packet size should be less than or equal to utils.MAX_PACKET_SIZE
            return

        if not packet.is_raw_data and packet.payload in self.hash_data:
            # The packet got hashed and is a valid key. Send to the correct clients who are cached.
            message = self.hash_data[packet.payload]
            self.give_block(packet, message, self.address_to_port[packet.dest], packet.is_fin)

        elif packet.dest in self.address_to_port and packet.src in self.address_to_port:
            # Expected behavior for when a host sends a packet to a host on the same local network
            self.send(packet, self.address_to_port[packet.dest])

        elif packet.dest in self.address_to_port:
            # The packet is destined to one of the clients connected to this middle box;
            # send the packet there. Since bytes were sent from WAN to client, construct hash mapping here.
            self.receives[buffer_key] += packet.payload
            if not packet.is_raw_data or packet.is_fin:
                # set packet.is_raw_data to be intentionally False to terminate block
                message, self.receives[buffer_key] = self.receives[buffer_key], ""
                self.hash_data[utils.get_hash(message)] = message
                self.give_block(packet, message, self.address_to_port[packet.dest], packet.is_fin)

        else:
            # The packet must be destined to a host connected to the other middle box
            # so send it across the WAN. Bytes sent from client to WAN.

            # Set up scanning through the packet
            start = 0
            end_window = max(self.window_size, self.buffers[buffer_key].__len__())
            # Include hanging message from before
            copied_payload = self.buffers[buffer_key] + packet.payload
            while end_window <= packet_size:
                window_msg = copied_payload[end_window - self.window_size:end_window]
                hashed_msg = utils.get_hash(window_msg)
                if self.GLOBAL_MATCH_BITSTRING == utils.get_last_n_bits(hashed_msg, 13):
                    # New buffering :)
                    self.buffers[buffer_key] = ""
                    block_msg = copied_payload[start:end_window]
                    block_hash_msg = utils.get_hash(block_msg)

                    # Handle hashing, is_fin to False to handle other packets.
                    self.handle_hash(packet, block_msg, block_hash_msg, False)

                    # Restart block / window size
                    start = end_window
                    end_window += self.window_size
                else:
                    end_window += 1

            # Partake in storing these dangling damn messages...
            start = self.buffers[buffer_key].__len__() if start == 0 else start
            self.buffers[buffer_key] += copied_payload[start:]
            if packet.is_fin:
                self.handle_drop(packet) if self.buffers[buffer_key].__len__() else self.send(packet, self.wan_port)

    def handle_drop(self, packet):
        # Buffer Key
        buffer_key = (packet.src, packet.dest)

        # Find hanging message...
        hanging_msg = self.buffers[buffer_key]
        hashed_msg = utils.get_hash(hanging_msg)

        # Handle hashing
        self.handle_hash(packet, hanging_msg, hashed_msg, True)

        # Remove specific buffer pool information
        self.buffers[buffer_key] = ""

    def handle_hash(self, packet, message, hashed_message, is_fin):
        # Check for key...
        if hashed_message not in self.hash_data:
            self.hash_data[hashed_message] = message
            self.give_block(packet, message, self.wan_port, is_fin, False)
        else:
            self.send(tcp_packet.Packet(packet.src, packet.dest,
                                        False, is_fin, hashed_message), self.wan_port)

    def give_block(self, packet, message, port, is_fin, intent=True):
        # Give block to either Wan or client.
        # Intent being False means to terminate the message on the other Wan end.
        start_block = 0
        end_block = utils.MAX_PACKET_SIZE
        block_message_length = message.__len__()
        while end_block < block_message_length:
            split_msg = message[start_block:end_block]
            self.send(tcp_packet.Packet(packet.src, packet.dest,
                                        True, False, split_msg), port)
            start_block, end_block = end_block, end_block + utils.MAX_PACKET_SIZE
        carry_over_msg = message[start_block:]
        self.send(tcp_packet.Packet(packet.src, packet.dest,
                                    intent, is_fin, carry_over_msg), port)
