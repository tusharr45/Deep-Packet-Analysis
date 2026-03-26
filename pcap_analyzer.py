import pyshark
from dpi_engine import inspect

def analyze(file):

    capture=pyshark.FileCapture(file)

    i=0

    for packet in capture:

        i+=1

        try:

            print(

            i,
            packet.ip.src,
            packet.ip.dst,
            packet.transport_layer,
            packet.length

            )

            inspect(packet)

        except:

            pass