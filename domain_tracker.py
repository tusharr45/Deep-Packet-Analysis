domains={}

from datetime import datetime

gui_output=None

def set_domain_output(widget):

    global gui_output

    gui_output=widget


def track_domain(domain):

    domain=domain.lower()

    if domain in domains:

        domains[domain]+=1

    else:

        domains[domain]=1

        time=datetime.now().strftime("%H:%M:%S")

        with open("visited_domains.txt","a") as f:

            f.write(f"{time} {domain}\n")

        # GUI show
        if gui_output:

            gui_output.insert(
                "end",
                f"Visited: {domain}\n"
            )

            gui_output.see("end")


def show_domains():

    print("\nTop domains:\n")

    for k,v in sorted(
        domains.items(),
        key=lambda x:x[1],
        reverse=True
    ):

        print(k,v)