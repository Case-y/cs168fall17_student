import os
import random
import string

import client
import wan


def send_50_random_files(middlebox_module, testing_part_1):
    """ Generates 50 random files that have between 6000-32000 bytes
        of text.
        For each file, between 1 and 6 times (random), chooses a random
        pair of hosts on opposite sides of the WAN, and sends the
        random file between them.
        Makes sure that all files are sent properly.
    """
    random.seed("168isthebesttho")

    NUM_FILES = 50
    total_count = 0
    send_count = 0

    middlebox1 = middlebox_module.WanOptimizer()
    middlebox2 = middlebox_module.WanOptimizer()
    wide_area_network = wan.Wan(middlebox1, middlebox2)
    middleboxes = [middlebox1, middlebox2]

    # Base names for clients on either side of the WAN
    client_address_bases = ["1.2.3.", "9.8.7."]

    # Initialize and connect all clients:
    mb1_clients = []
    mb1_client_addr = []
    mb2_clients = []
    mb2_client_addr = []
    for addr_base, middlebox in zip(client_address_bases, middleboxes):
        for i in range(0, 8):
            client_address = addr_base + str(i)
            if middlebox == middlebox1:
                client_i = client.EndHost(client_address, client_address, middlebox1)
                mb1_clients.append(client_i)
                mb1_client_addr.append(client_address)
            else:
                client_i = client.EndHost(client_address, client_address, middlebox2)
                mb2_clients.append(client_i)
                mb2_client_addr.append(client_address)

    filename = "random.txt"
    for i in range(NUM_FILES):
        generate_random_file(filename)

        with open(filename, "rb") as input_file:
            input_data = input_file.read()
            input_file.close()

        for num_send in range(0, random.randint(1, 6)):
            clientA_index = random.randint(0, 7)
            clientB_index = random.randint(0, 7)

            client_pair = [mb1_clients[clientA_index], mb2_clients[clientB_index]]
            client_addr_pair = [mb1_client_addr[clientA_index], mb2_client_addr[clientB_index]]

            # zipped_pair = list(zip(client_pair, client_addr_pair))
            zipped_pair = [(client_pair[i], client_addr_pair[i]) for i in range(2)]
            random.shuffle(zipped_pair)

            sender = zipped_pair[0][0]
            senderAddr = zipped_pair[0][1]
            receiver = zipped_pair[1][0]
            receiverAddr = zipped_pair[1][1]

            sender.send_file(filename, receiverAddr)

            # Make sure that the files have the same contents.
            output_file_name = "{}-{}".format(receiverAddr, filename)
            with open(output_file_name, "rb") as output_file:
                result_data = output_file.read()
                output_file.close()
            # Remove the output file just created.
            os.remove(output_file_name)

            send_count += 1
            if input_data == result_data:
                total_count += 1

    if total_count != send_count:
        raise Exception(
            "send_mutiple_files failed, because the all files" +
            "received did not match the file sent. Files received correctly:" +
            " {} and files sent are: {}\n".format(
                total_count,
                NUM_FILES))

    ###  IMPLEMENTATION-SPECIFIC   ###
    # You should change the variable names here to match the class variables
    # that cache the hash blocks' keys!
    if middlebox1.buffers != middlebox2.buffers:
        raise Exception("The WAN Optimizers don't have the same state at the end!")


def generate_random_file(name):
    file_len = random.randint(6000, 32000)
    with open(name, "w+") as file:
        random_text = "".join(
            random.SystemRandom().choice(string.ascii_letters + string.digits) for i in range(file_len))
        file.write(random_text)
        file.close()