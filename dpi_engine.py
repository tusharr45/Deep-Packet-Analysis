from stats import stats
from protocol_map import services
from rule_engine import check
from alerts import alert
from domain_tracker import track_domain
def inspect(packet):

    stats["total"]+=1

    try:

        proto=packet.transport_layer

        if proto=="TCP":

            stats["tcp"]+=1

        elif proto=="UDP":

            stats["udp"]+=1

    except:

        pass


    # DNS inspection
    try:

        if hasattr(packet,'dns'):

            if hasattr(packet.dns,'qry_name'):

                domain=str(packet.dns.qry_name).lower()
                track_domain(domain)

                print("   DNS Query:",domain)

                stats["dns"]+=1


                if check(domain):

                    print("   ACTION: DROP")

                    alert(
                        f"Blocked domain {domain}",
                        packet.ip.src,
                        packet.ip.dst,
                        "CRITICAL"
                    )

                    stats["dropped"]+=1

                else:

                    print("   ACTION: ALLOW")

                    stats["allowed"]+=1

    except:

        pass


    # Port detection
    try:

        if hasattr(packet,'tcp'):

            src_port=int(packet.tcp.srcport)

            dst_port=int(packet.tcp.dstport)

            print("   Ports:",src_port,"→",dst_port)


            if dst_port in services:

                service=services[dst_port]

                print("   Service:",service)


                if service=="HTTPS":

                    stats["https"]+=1

                if service=="HTTP":

                    stats["http"]+=1

    except:

        pass


    # ICMP detection
    try:

        if hasattr(packet,'icmp'):

            print("   ICMP Packet")

            stats["icmp"]+=1

            alert(
                "ICMP traffic detected",
                packet.ip.src,
                packet.ip.dst,
                "INFO"
            )

    except:

        pass

    