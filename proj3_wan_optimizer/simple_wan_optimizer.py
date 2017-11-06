import wan_optimizer
import utils


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
        self.buffered_hashes = set()
        self.buffered_bytes = 0
        self.buffered_payload = ""
        self.buffered_packets = []

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

        if packet_size > utils.MAX_PACKET_SIZE:
            # For all communication, the packet size should be less than or equal to utils.MAX_PACKET_SIZE
            return

        if not packet.is_raw_data and packet.payload in self.hash_data:
            # The packet got hashed and is a valid key. Send to the correct clients who are cached.
            packet.payload = self.hash_data[packet.payload]
            packet.is_raw_data = True
            self.send(packet, self.address_to_port[packet.dest])

        elif packet.dest in self.address_to_port and packet.src in self.address_to_port:
            # Expected behavior for when a host sends a packet to a host on the same local network
            self.send(packet, self.address_to_port[packet.dest])

        elif packet.dest in self.address_to_port:
            # The packet is destined to one of the clients connected to this middle box;
            # send the packet there. Since bytes were sent from WAN to client, construct hash mapping here.
            if packet_size == 0 and packet.is_fin:
                self.send(packet, self.address_to_port[packet.dest])
                return
            hashed_msg = utils.get_hash(packet.payload)
            self.hash_data[hashed_msg] = packet.payload
            self.send(packet, self.address_to_port[packet.dest])

        else:
            # The packet must be destined to a host connected to the other middle box
            # so send it across the WAN. Bytes sent from client to WAN.
            total_bytes = packet_size + self.buffered_bytes
            self.buffered_packets.append(packet)
            if total_bytes >= self.BLOCK_SIZE:
                if total_bytes == self.BLOCK_SIZE:
                    self.send_all_wan()
                    return
                # Grab the bytes that made it, heh and don't :(
                squeezed_bytes = self.BLOCK_SIZE - self.buffered_bytes
                # Construct packets
                squeezed_msg = packet.payload[:squeezed_bytes]
                leftover_msg = packet.payload[squeezed_bytes:]
                packet.payload = squeezed_msg
                # Send the first block of 8000 bytes
                self.send_all_wan()
                leftover_packet = packet
                total_bytes = total_bytes - self.BLOCK_SIZE
                while total_bytes >= self.BLOCK_SIZE:
                    # There are more blocks... YIKES! Handle hashing here too :\
                    squeezed_msg = leftover_msg[:self.BLOCK_SIZE]
                    leftover_msg = leftover_msg[self.BLOCK_SIZE:]
                    hashed_msg = utils.get_hash(squeezed_msg)
                    if hashed_msg not in self.buffered_hashes:
                        self.buffered_hashes.add(hashed_msg)
                        leftover_packet.payload = squeezed_msg
                    else:
                        leftover_packet.payload = hashed_msg
                        packet.is_raw_data = False
                    self.send(leftover_packet, self.wan_port)
                    total_bytes = total_bytes - self.BLOCK_SIZE
                if total_bytes == 0:
                    # Handle this case if total_bytes % self.BLOCK_SIZE == 0... no leftover_msg !
                    return
                leftover_packet.payload = leftover_msg
                self.handle_leftover_packet(leftover_packet, leftover_msg)

            else:
                # if total_bytes < self.BLOCK_SIZE:
                if packet.is_fin:
                    if total_bytes == 0:
                        self.buffered_packets.pop()
                        self.send(packet, self.wan_port)
                    else:
                        self.send_all_wan()
                else:
                    self.buffered_bytes = total_bytes

    def send_all_wan(self):
        # Don't forget to Store hash and send to the other middle box
        not_block = True
        cached_hashes = []
        for packet in self.buffered_packets:
            hashed_msg = utils.get_hash(packet.payload)
            if hashed_msg not in self.buffered_hashes:
                not_block = False
                self.buffered_hashes.add(hashed_msg)
            cached_hashes.append(hashed_msg)
        for packet, hashed_msg in zip(self.buffered_packets, cached_hashes):
            if not_block:
                packet.payload = hashed_msg
                packet.is_raw_data = False
            self.send(packet, self.wan_port)

        # Delete buffer pool
        self.buffered_bytes = 0
        self.buffered_packets = []

    def handle_leftover_packet(self, leftover_packet, leftover_msg):
        # Don't forget to Store hash and send to the other middle box
        if leftover_packet.is_fin:
            hashed_msg = utils.get_hash(leftover_msg)
            if hashed_msg not in self.buffered_hashes:
                self.buffered_hashes.add(hashed_msg)
            else:
                # Previous hashed_msg constructed already!
                leftover_packet.payload = hashed_msg
                leftover_packet.is_raw_data = False
            self.send(leftover_packet, self.wan_port)
        else:
            self.buffered_bytes = leftover_msg.__len__()  # the leftover_bytes
            self.buffered_packets.append(leftover_packet)
