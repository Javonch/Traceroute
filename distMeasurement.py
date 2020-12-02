import struct
import socket
import select
import datetime
import csv
import pandas as pd
import matplotlib.pyplot as plt


class Traceroute(object):
    def __init__(self, dst):
        """
        Constructor for traceroute (not really traceroute)

        Args:
            dst (String): destination to probe
        """
        self.dst = dst
        self.ttl = 1

    def run(self):
        """
        Do the thing (probe the destination)
        :returns
            A tuple containing the total hop count, the rtt, and the amount of data (without the headers) sent in
            the response
        :raises
            IOError
        """
        try:
            dst_ip = socket.gethostbyname(self.dst)
        except socket.error as e:
            raise IOError('Unable to resolve {}: {}', self.dst, e)
        text = 'probing {} (IP: {})'.format(self.dst, dst_ip)

        print(text)
        code = -1
        packet_length = -1
        ttl = -1
        while code != 3:
            receiver = self.create_receiver()
            sender = self.create_sender()
            msg = 'measurement for class project, questions to student jtc131@case.edu or professor mxr136@case.edu'
            payload = bytes(msg + 'a' * (1472 - len(msg)), "ascii")
            code, rtt, packet_length, ttl, port, ret_port, addr = self.trace(receiver, sender, payload, 0)
        print("Type " + type(ret_port[1]))

        return ttl, rtt, (packet_length-56)

    def trace(self, receiver, sender, msg, strikes):
        time_start = datetime.datetime.now()
        sender.sendto(msg, (self.dst, 33434))
        port = sender.getsockname()[1]
        r, w, e = select.select([receiver], [], [], 300)
        if receiver in r:
            try:
                packet, addr = receiver.recvfrom(1500)
                time_end = datetime.datetime.now()
                icmp_header = struct.unpack('bbh', packet[20:24])
                udp_header = struct.unpack('bbHHh', packet[24:32])
                ret_port = struct.unpack('!H', packet[48:50])[0]
                code = icmp_header[0]
                ttl = packet[8]
                rtt = (time_end - time_start) / 1000
                self.ttl = self.ttl + 1

            except socket.error as e:
                raise IOError('Socket error: {}'.format(e))
            finally:
                receiver.close()
                sender.close()
            return code, rtt, len(packet), ttl, port, ret_port, addr
        else:
            if strikes == 3:
                print('Attempt failed. Aborting read')
                return 3, -1, 55, -1
            else:
                strikes += 1
                print('Attempt failed. Trying again : Strike {} of 3'.format(strikes))
                return self.trace(receiver, sender, msg, strikes)

    def create_receiver(self):
        """
        Creates socket to receive ICMP datagram
        :return
            Instance of receiver socket
        :raises
            IOError
        """

        rcvr = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        try:
            rcvr.bind(('', 61354))
        except socket.error as e:
            raise IOError('Unable to bind receiver socket: {}'.format(e))
        return rcvr

    def create_sender(self):
        """
        Crates socket to send custom datagrams
        :return:
            Instance of sender socket
        """
        sndr = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sndr.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)
        sndr.bind(('', 61354))
        return sndr


def create_csv(data):
    fields = ['Hop number', 'Round Trip Time']
    rows = []
    for part in data:
        rows.append(part[0:2])
    with open('Data_Set.csv', 'w') as file:
        writer = csv.writer(file)
        writer.writerow(fields)
        writer.writerows(rows)


def scatter(file):
    df = pd.read_csv(file)
    df.plot()  # plots all columns against index
    df.plot(kind='scatter', x='Hop number', y='Round Trip Time')  # scatter plot
    df.plot(kind='density')


plottable_data = []
sites = open('targets.txt', 'r').readlines()
for site in sites:
    probe = Traceroute('{}'.format(site.strip()))
    result = probe.run()
    if result[0] != -1:
        plottable_data.append(result)
avg = 0
for datagram in plottable_data:
    avg += datagram[2]
avg = avg/len(plottable_data)
print('The average residual data amount was {}'.format(avg))
create_csv(plottable_data)


