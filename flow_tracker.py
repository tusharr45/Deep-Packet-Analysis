flows={}

from alerts import alert

def track(src,dst):

    key=(src,dst)

    if key in flows:

        flows[key]+=1

        if flows[key]==100:

            alert(
                "High traffic flow detected",
                src,
                dst,
                "WARNING"
            )

    else:

        flows[key]=1


def show_flows():

    print("\nTop Connections:\n")

    for k,v in sorted(
        flows.items(),
        key=lambda x:x[1],
        reverse=True
    ):

        print(
            k[0],
            "→",
            k[1],
            ":",
            v,
            "packets"
        )