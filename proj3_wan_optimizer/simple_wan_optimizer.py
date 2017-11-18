import wan_optimizer
import utils
import tcp_packet


class WanOptimizer(wan_optimizer.BaseWanOptimizer):
    """ WAN Optimizer that divides data into fixed-size blocks.

    This WAN optimizer should implement part 1 of project 4.
    """

    # Size of blocks to store, and send only the hash when the block has been
    # sent previously
    BLOCK_SIZE = 8000

    def __init__(self):
        wan_optimizer.BaseWanOptimizer.__init__(self)
        # Add any code that you like here (but do not add any constructor arguments).
        self.hash_data = dict()
        self.receives = dict()    # (src, destination) <--> message received so far
        self.buffers = dict()     # (src, destination) <--> message so far

    def receive(self, packet):
        """ Handles receiving a packet.

        Right now, this function simply forwards packets to clients (if a packet
        is destined to one of the directly connected clients), or otherwise sends
        packets across the WAN. You should change this function to implement the
        functionality described in part 1.  You are welcome to implement private
        helper fuctions that you call here. You should *not* be calling any functions
        or directly accessing any variables in the other middlebox on the other side of
        the WAN; this WAN optimizer should operate based only on its own local state
        and packets that have been received.
        """

        packet_size = packet.size()
        buffer_key = (packet.src, packet.dest)

        if packet_size > utils.MAX_PACKET_SIZE:
            # For all communication, the packet size should be less than or equal to utils.MAX_PACKET_SIZE
            return

        if buffer_key not in self.buffers:
            self.buffers[buffer_key] = ""
        if packet.dest in self.address_to_port and buffer_key not in self.receives:
            self.receives[buffer_key] = ""
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
            # Should be block size.
            self.receives[buffer_key] += packet.payload
            received_length = self.receives[buffer_key].__len__()
            if received_length == self.BLOCK_SIZE or packet.is_fin:
                message, self.receives[buffer_key] = self.receives[buffer_key], ""
                hashed_message = utils.get_hash(message)
                self.hash_data[hashed_message] = message
                self.give_block(packet, message, self.address_to_port[packet.dest], packet.is_fin)

        else:
            # The packet must be destined to a host connected to the other middle box
            # so send it across the WAN. Bytes sent from client to WAN.
            buffered_length = self.buffers[buffer_key].__len__()
            total_bytes = packet_size + buffered_length
            if total_bytes >= self.BLOCK_SIZE:
                if total_bytes == self.BLOCK_SIZE:
                    self.buffers[buffer_key] += packet.payload
                    self.send_all_wan(packet, packet.is_fin)
                    return
                # Grab the bytes that made it, heh and don't :(
                squeezed_bytes = self.BLOCK_SIZE - buffered_length
                # Construct packets
                squeezed_msg = packet.payload[:squeezed_bytes]
                leftover_msg = packet.payload[squeezed_bytes:]
                self.buffers[buffer_key] += squeezed_msg
                # Send the first block of 8000 bytes: is_fin has to be False because leftover message.
                self.send_all_wan(packet, False)
                # Include leftover message
                self.buffers[buffer_key] = leftover_msg
                if packet.is_fin:
                    packet.payload = leftover_msg
                    self.handle_leftover_packet(packet, leftover_msg)

            else:
                # if total_bytes < self.BLOCK_SIZE:
                self.buffers[buffer_key] += packet.payload
                if packet.is_fin:
                    self.send(packet, self.wan_port) if total_bytes == 0 and self.buffers[buffer_key].__len__() == 0 else self.send_all_wan(packet, True)

    def send_all_wan(self, packet, is_fin):
        # Don't forget to Store hash and send to the other middle box
        # send_all_wan should only hash in self.BLOCK_SIZE
        buffer_key = (packet.src, packet.dest)
        message = self.buffers[buffer_key]
        hashed_msg = utils.get_hash(message)
        if hashed_msg not in self.hash_data:
            self.hash_data[hashed_msg] = message
            self.give_block(packet, message, self.wan_port, is_fin)
        else:
            self.send(tcp_packet.Packet(packet.src, packet.dest, False, is_fin, hashed_msg), self.wan_port)
        # Remove specific buffer pool information
        self.buffers[buffer_key] = ""

    def handle_leftover_packet(self, leftover_packet, leftover_msg):
        # Don't forget to Store hash and send to the other middle box
        buffer_key = (leftover_packet.src, leftover_packet.dest)
        hashed_msg = utils.get_hash(leftover_msg)
        if hashed_msg not in self.hash_data:
            self.hash_data[hashed_msg] = leftover_msg
            self.send(tcp_packet.Packet(leftover_packet.src, leftover_packet.dest, True,
                                        leftover_packet.is_fin, leftover_msg), self.wan_port)
        else:
            # Previous hashed_msg constructed already!
            self.send(tcp_packet.Packet(leftover_packet.src, leftover_packet.dest, False,
                                        leftover_packet.is_fin, hashed_msg), self.wan_port)
        # Remove specific buffer pool information
        self.buffers[buffer_key] = ""

    def give_block(self, packet, message, port, is_fin):
        start_block = 0
        end_block = utils.MAX_PACKET_SIZE
        while end_block < self.BLOCK_SIZE:
            split_msg = message[start_block:end_block]
            self.send(tcp_packet.Packet(packet.src, packet.dest,
                                        True, False, split_msg), port)
            start_block, end_block = end_block, end_block + utils.MAX_PACKET_SIZE
        carry_over_msg = message[start_block:]
        self.send(tcp_packet.Packet(packet.src, packet.dest,
                                    True, is_fin, carry_over_msg), port)
