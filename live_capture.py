import pyshark
from dpi_engine import inspect
from stats import show
from flow_tracker import track,show_flows
from logger import log
from colorama import Fore,init

init()

def start(interface):

    # Capture all packets (no filter)
    capture=pyshark.LiveCapture(interface=interface)

    i=0

    print(Fore.GREEN+
    "Capturing packets... Press Ctrl+C to stop\n")

    print(
    Fore.YELLOW+
    "No Time Source Destination Protocol Length"
    )

    try:

        for packet in capture.sniff_continuously():

            i+=1

            try:

                # Safe IP extraction
                if hasattr(packet,'ip'):

                    src=packet.ip.src
                    dst=packet.ip.dst

                    track(src,dst)

                else:

                    src="N/A"
                    dst="N/A"


                # Protocol detection
                if hasattr(packet,'transport_layer'):

                    proto=packet.transport_layer

                else:

                    proto="OTHER"


                length=packet.length


                print(

                Fore.CYAN,
                i,
                packet.sniff_time,
                src,
                dst,
                proto,
                length

                )


                log(

                i,
                packet.sniff_time,
                src,
                dst,
                proto,
                length

                )


                inspect(packet)

            except:

                pass

    except KeyboardInterrupt:

        show()

        show_flows()

        print(Fore.GREEN+
        "\nSaved to packets.csv")

        print("\nCapture stopped")