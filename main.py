from live_capture import start
from pcap_analyzer import analyze
from gui import start_app

def menu():

    print("\n===== DPI Network Traffic Analyzer =====")

    print("1 Live Capture")

    print("2 Analyze PCAP")

    print("3 GUI Mode")

    c=int(input("Choice: "))

    if c==1:

        interface=input(
        "Interface (example en0): "
        )

        start(interface)

    elif c==2:

        file=input("PCAP file: ")

        analyze(file)

    elif c==3:

        start_app()

    else:

        print("Invalid choice")


if __name__=="__main__":

    menu()