stats={

"total":0,
"tcp":0,
"udp":0,
"dns":0,
"http":0,
"https":0,
"icmp":0,
"allowed":0,
"dropped":0

}

def show():

    print("\n------ Statistics ------")

    print("Total:",stats["total"])

    print("TCP:",stats["tcp"])

    print("UDP:",stats["udp"])

    print("DNS:",stats["dns"])

    print("HTTP:",stats["http"])

    print("HTTPS:",stats["https"])

    print("ICMP:",stats["icmp"])

    print("Allowed:",stats["allowed"])

    print("Dropped:",stats["dropped"])


    print("\nTop Protocols:\n")

    for k,v in sorted(

    stats.items(),
    key=lambda x:x[1],
    reverse=True

    ):

        if k!="total":

            print(k,":",v)