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
        self.buffered_hashes = set()
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
            self.give_client_block(packet, message)

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
                self.give_client_block(packet, message)

        else:
            # The packet must be destined to a host connected to the other middle box
            # so send it across the WAN. Bytes sent from client to WAN.

            # Set up scanning through the packet
            start = 0
            start_window = 0
            end_window = self.window_size
            # Include hanging message from before
            copied_payload = self.buffers[buffer_key] + packet.payload[:]
            while end_window <= packet_size:
                window_msg = copied_payload[start_window:end_window]
                hashed_msg = utils.get_hash(window_msg)
                if self.GLOBAL_MATCH_BITSTRING == utils.get_last_n_bits(hashed_msg, 13):
                    # New buffering :)
                    self.buffers[buffer_key] = ""
                    block_msg = copied_payload[start:end_window]
                    block_hash_msg = utils.get_hash(block_msg)
                    if block_hash_msg not in self.buffered_hashes:
                        self.buffered_hashes.add(block_hash_msg)
                        split_start = 0
                        split_end = utils.MAX_PACKET_SIZE
                        block_msg_size = block_msg.__len__()
                        # Split big block into block sized packets if necessary
                        while split_end < block_msg_size:
                            split_block_msg = block_msg[split_start:split_end]
                            self.send(tcp_packet.Packet(packet.src, packet.dest,
                                                        True, False, split_block_msg), self.wan_port)
                            split_start, split_end = split_end, split_end + utils.MAX_PACKET_SIZE
                        carry_over_msg = block_msg[split_start:]
                        # Intentionally, send the last packet message with is_raw_data = False
                        self.send(tcp_packet.Packet(packet.src,
                                                    packet.dest, False, packet.is_fin, carry_over_msg), self.wan_port)
                    else:
                        self.send(tcp_packet.Packet(packet.src, packet.dest,
                                                    False, packet.is_fin, block_hash_msg), self.wan_port)

                    # Restart block / window size
                    start, start_window = end_window, end_window
                    end_window += self.window_size
                else:
                    start_window += 1
                    end_window += 1

            # Partake in storing these dangling damn messages...
            start = self.buffers[buffer_key].__len__() if start == 0 else start
            self.buffers[buffer_key] += copied_payload[start:]
            if packet.is_fin:
                if self.buffers[buffer_key].__len__() == 0:
                    self.send(packet, self.wan_port)
                else:
                    self.handle_drop(packet)

    def handle_drop(self, packet):
        # Buffer Key
        buffer_key = (packet.src, packet.dest)

        # Find hanging message...
        hanging_msg = self.buffers[buffer_key]
        hanging_msg_size = hanging_msg.__len__()
        hashed_msg = utils.get_hash(hanging_msg)

        if hashed_msg not in self.buffered_hashes:
            self.buffered_hashes.add(hashed_msg)
            split_start = 0
            split_end = utils.MAX_PACKET_SIZE
            while split_end < hanging_msg_size:
                block_msg = hanging_msg[split_start:split_end]
                self.send(tcp_packet.Packet(packet.src, packet.dest,
                                            True, False, block_msg), self.wan_port)
                split_start, split_end = split_end, split_end + utils.MAX_PACKET_SIZE
            carry_over_msg = hanging_msg[split_start:]
            # Intentionally, send the last packet message with is_raw_data = False
            self.send(tcp_packet.Packet(packet.src,
                                        packet.dest, False, packet.is_fin, carry_over_msg), self.wan_port)
        else:
            self.send(tcp_packet.Packet(packet.src, packet.dest,
                                        False, packet.is_fin, hashed_msg), self.wan_port)
        # Remove specific buffer pool information
        self.buffers[buffer_key] = ""

    def give_client_block(self, packet, message):
        start_block = 0
        end_block = utils.MAX_PACKET_SIZE
        block_message_length = message.__len__()
        while end_block < block_message_length:
            split_msg = message[start_block:end_block]
            self.send(tcp_packet.Packet(packet.src, packet.dest,
                                        True, False, split_msg), self.address_to_port[packet.dest])
            start_block, end_block = end_block, end_block + utils.MAX_PACKET_SIZE
        carry_over_msg = message[start_block:]
        self.send(tcp_packet.Packet(packet.src, packet.dest,
                                    True, packet.is_fin, carry_over_msg), self.address_to_port[packet.dest])
