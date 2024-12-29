import struct
from CovertChannelBase import CovertChannelBase
import time
from scapy.all import IP, UDP, sniff, Raw

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def _init_(self):
        """
        - You can edit _init_.
        """
        pass
    def send(self, log_file_name, parameter1, parameter2):
        """
        - In this function, you expected to create a random message (using function/s in CovertChannelBase), and send it to the receiver container. Entire sending operations should be handled in this function.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        encryption_key = int(parameter1, 16)
        ntp_epoch = parameter2
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        for i in range(8):
            start = 16 * i
            end = start + 16

            word = int(binary_message[start:end], 2)
            encrypted_word = word ^ encryption_key

            ntp_time = time.time() + ntp_epoch
            ntp_seconds = int(ntp_time)
            ntp_fraction = int((ntp_time - ntp_seconds) * (2 ** 32))
            ntp_fraction = ntp_fraction & 0xFFFF0000
            
            ntp_fraction = ntp_fraction | encrypted_word
            #timestamp = (ntp_seconds << 32) | ntp_fraction

            packet = bytearray(48)

            packet[0] = (0 << 6) | (4 << 3) | 3

            packet[1] = 0

            packet[2] = 4

            # precision
            packet[3] = 95

            struct.pack_into('!I',packet, 4, 0x00000000)

            struct.pack_into('!I',packet, 8, 0x00000000)

            struct.pack_into('!I',packet, 12, 0x00000000)

            struct.pack_into('!Q',packet, 16, 0x0000000000000000)

            originate_timestamp = struct.pack('!II', ntp_seconds, ntp_fraction)
            
            packet[24:32] = originate_timestamp

            #receive
            struct.pack_into('!Q', packet, 32, 0x0000000000000000) 

            #transmit
            packet[40:48] = originate_timestamp

            destination_ip = "127.0.0.1"
            destination_port = 123

            packet_to_send = IP(dst = destination_ip) / UDP(dport = destination_port, sport = 20000) / packet

            self.send(packet_to_send, verbose = True)
            self.sleep_random_time_ms(1, 10)

        
    def receive(self, parameter1, parameter2, parameter3, log_file_name):
        """
        - In this function, you are expected to receive and decode the transferred message. Because there are many types of covert channels, the receiver implementation depends on the chosen covert channel type, and you may not need to use the functions in CovertChannelBase.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        capture = sniff(iface = "eth0", count = 8)

        received = []
        message = ""

        for packet in capture:
            payload = bytes(packet[Raw].load)[30:32]
            decoded_payload = payload ^ int(parameter1, 16)
            received.append(decoded_payload)

        for i in received:
            message += chr(received[i][0:8])
            message += chr(received[i][8:16])

        self.log_message(message, log_file_name)