import wan_optimizer
import utils


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
        self.hanging_destinations = dict()

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

        if packet.dest not in self.hanging_destinations:
            # initialize hanging_msgs for destinations
            self.hanging_destinations[packet.dest] = ""

        packet_size = self.hanging_destinations[packet.dest].__len__() + packet.size()
        if packet_size > self.hanging_destinations[packet.dest].__len__() + utils.MAX_PACKET_SIZE:
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
            if packet.is_fin and packet_size == 0:
                # final packet with no data
                self.handle_drop(packet)
                return

            # Set up scanning through the packet
            start_block = 0
            start_window = 0
            end_window = self.window_size
            # Include hanging message from before
            copied_payload = self.hanging_destinations[packet.dest] + packet.payload[:]
            while end_window <= packet_size:
                window_msg = copied_payload[start_window:end_window]
                hashed_msg = utils.get_hash(window_msg)
                if self.GLOBAL_MATCH_BITSTRING == utils.get_last_n_bits(hashed_msg, 13):
                    # No more hanging message!
                    self.hanging_destinations[packet.dest] = ""
                    split_start = 0
                    split_end = utils.MAX_PACKET_SIZE
                    block_msg = copied_payload[start_block:end_window]
                    block_msg_size = block_msg.__len__()

                    # Split big block into block sized packets if necessary
                    while split_end < block_msg_size:
                        split_block_msg = block_msg[split_start:split_end]
                        split_block_hashed_msg = utils.get_hash(split_block_msg)
                        if split_block_hashed_msg not in self.buffered_hashes:
                            self.buffered_hashes.add(split_block_hashed_msg)
                            packet.is_raw_data = True
                            packet.payload = split_block_msg
                        else:
                            packet.is_raw_data = False
                            packet.payload = split_block_hashed_msg
                        self.send(packet, self.wan_port)
                        split_start = split_end
                        split_end += utils.MAX_PACKET_SIZE

                    # Handle Leftover Block
                    leftover_block_msg = block_msg[split_start:]
                    if leftover_block_msg != "":
                        leftover_hashed_msg = utils.get_hash(leftover_block_msg)
                        if leftover_hashed_msg not in self.buffered_hashes:
                            self.buffered_hashes.add(leftover_hashed_msg)
                            packet.is_raw_data = True
                            packet.payload = leftover_block_msg
                        else:
                            packet.is_raw_data = False
                            packet.payload = leftover_hashed_msg
                        self.send(packet, self.wan_port)

                    # Restart block / window size
                    start_block, start_window = end_window, end_window
                    end_window += self.window_size
                else:
                    start_window += 1
                    end_window += 1

            # Partake in storing hanging messages...
            start_block = self.hanging_destinations[packet.dest].__len__() if start_block == 0 else start_block
            self.hanging_destinations[packet.dest] += copied_payload[start_block:]
            if packet.is_fin:
                # If the leftover msg is a fin :)
                self.handle_drop(packet)

    def handle_drop(self, packet, is_fin=True):
        # Find hanging message...
        hanging_msg = self.hanging_destinations[packet.dest]
        hanging_msg_size = hanging_msg.__len__()
        if hanging_msg_size > 0:
            start_block = 0
            end_block = utils.MAX_PACKET_SIZE
            packet.is_fin = False
            while end_block < hanging_msg_size:
                block_msg = hanging_msg[start_block:end_block]
                hashed_msg = utils.get_hash(block_msg)
                if hashed_msg not in self.buffered_hashes:
                    self.buffered_hashes.add(hashed_msg)
                    packet.payload = block_msg
                    packet.is_raw_data = True
                else:
                    packet.payload = hashed_msg
                    packet.is_raw_data = False
                self.send(packet, self.wan_port)
                start_block = end_block
                end_block += utils.MAX_PACKET_SIZE
            packet.is_fin = is_fin
            # Handle Leftover Block
            leftover_block_msg = hanging_msg[start_block:]
            if leftover_block_msg != "":
                hashed_msg = utils.get_hash(leftover_block_msg)
                if hashed_msg not in self.buffered_hashes:
                    self.buffered_hashes.add(hashed_msg)
                    packet.payload = leftover_block_msg
                    packet.is_raw_data = True
                else:
                    packet.payload = hashed_msg
                    packet.is_raw_data = False
            else:
                packet.payload = ""
                packet.is_raw_data = True
        self.hanging_destinations[packet.dest] = ""
        self.send(packet, self.wan_port)
