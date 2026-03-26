import customtkinter as ctk
from tkinter import filedialog
import pyshark
import threading
import csv
import matplotlib.pyplot as plt
from dpi_engine import inspect
from alerts import set_output
from domain_tracker import set_domain_output

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Counters
tcp=0
udp=0
dns=0
total=0

flows={}
packets=[]
stop=False

# ---------- UI Colors ----------
BG="#0b0f14"
CARD="#121922"
ACCENT="#1f6feb"
GREEN="#2ea043"
RED="#f85149"
TEXT="#c9d1d9"

# ---------- Functions ----------

def animate_label(label,target):
    current=int(label.cget("text").split()[-1])
    if current<target:
        current+=1
        label.configure(text=label.cget("text").split()[0]+" "+str(current))
        app.after(10,lambda:animate_label(label,target))


def analyze():
    file=filedialog.askopenfilename(filetypes=[("PCAP","*.pcap *.pcapng")])
    if not file:
        return

    reset()

    capture=pyshark.FileCapture(file,keep_packets=False)
    process(capture)


def start_live():
    global stop
    stop=False

    iface=interface_entry.get()

    thread=threading.Thread(target=live_thread,args=(iface,))
    thread.daemon=True
    thread.start()


def live_thread(iface):
    try:
        capture=pyshark.LiveCapture(interface=iface)
        process(capture.sniff_continuously())

    except Exception as e:
        output.insert("end",f"Error: {e}\n")


def stop_capture():
    global stop
    stop=True


def process(capture):

    global tcp,udp,dns,total

    for packet in capture:

        if stop:
            break

        try:
            if 'IP' not in packet:
                continue

            src=packet.ip.src
            dst=packet.ip.dst

            proto=packet.transport_layer

            total+=1

            if proto=="TCP":
                tcp+=1

            if proto=="UDP":
                udp+=1

            inspect(packet)

            if 'DNS' in packet:
                dns+=1
                domain=str(packet.dns.qry_name)
                output.insert("end",f"🌐 {domain}\n")

            track_flow(src,dst)

            text=f"{src}  →  {dst}   {proto}"

            output.insert("end",text+"\n")

            packets.append([src,dst,proto])

            output.see("end")

        except:
            pass

    update_stats()


def track_flow(src,dst):

    key=src+" → "+dst

    flows[key]=flows.get(key,0)+1

    update_table()


def update_table():

    table.delete("0.0","end")

    sorted_flows=sorted(flows.items(),key=lambda x:x[1],reverse=True)

    for k,v in sorted_flows[:8]:

        table.insert("end",f"{k}   :   {v}\n")


def update_stats():

    animate_label(tcp_label,tcp)
    animate_label(udp_label,udp)
    animate_label(dns_label,dns)
    animate_label(total_label,total)


def export():

    if len(packets)==0:
        return

    file=filedialog.asksaveasfilename(defaultextension=".csv")

    if not file:
        return

    with open(file,"w") as f:

        writer=csv.writer(f)

        writer.writerow(["Source","Destination","Protocol"])

        for p in packets:

            writer.writerow(p)


def chart():

    udp_non_dns=max(udp-dns,0)

    values=[tcp,udp_non_dns,dns]

    if sum(values)==0:
        return

    plt.figure()

    plt.pie(values,labels=["TCP","UDP","DNS"],autopct="%1.1f%%")

    plt.title(f"Protocol Distribution (Total {total})")

    plt.show()


def reset():

    global tcp,udp,dns,total,flows,packets

    tcp=udp=dns=total=0

    flows={}

    packets=[]

    output.delete("0.0","end")


# ---------- UI ----------

app=ctk.CTk()

app.title("DPI Network Traffic Analyzer")

app.geometry("1200x700")

app.configure(fg_color=BG)

# Top bar

top=ctk.CTkFrame(app,fg_color=CARD,corner_radius=10)

top.pack(fill="x",padx=10,pady=10)

btn_style={
"corner_radius":8,
"fg_color":ACCENT,
"hover_color":"#388bfd"
}

ctk.CTkButton(top,text="Analyze",command=analyze,**btn_style).pack(side="left",padx=5,pady=5)

ctk.CTkButton(top,text="Start Live",command=start_live,**btn_style).pack(side="left",padx=5)

ctk.CTkButton(top,text="Stop",fg_color=RED,hover_color="#ff6a69",command=stop_capture).pack(side="left",padx=5)

ctk.CTkButton(top,text="Export",command=export,**btn_style).pack(side="left",padx=5)

ctk.CTkButton(top,text="Chart",command=chart,**btn_style).pack(side="left",padx=5)

interface_entry=ctk.CTkEntry(top,width=140)

interface_entry.insert(0,"en0")

interface_entry.pack(side="right",padx=10)

# Middle

middle=ctk.CTkFrame(app,fg_color=BG)

middle.pack(fill="both",expand=True,padx=10)

output=ctk.CTkTextbox(middle,fg_color=CARD,text_color=TEXT,corner_radius=10)

output.pack(side="left",fill="both",expand=True,padx=5,pady=5)

set_output(output)
set_domain_output(output)

# Flow table

table=ctk.CTkTextbox(middle,width=320,fg_color=CARD,corner_radius=10)

table.pack(side="right",fill="y",padx=5,pady=5)

# Bottom stats

bottom=ctk.CTkFrame(app,fg_color=CARD)

bottom.pack(fill="x",padx=10,pady=10)

stat_style={"font":("Consolas",16,"bold")}

tcp_label=ctk.CTkLabel(bottom,text="TCP 0",text_color="#58a6ff",**stat_style)

tcp_label.pack(side="left",padx=25)

udp_label=ctk.CTkLabel(bottom,text="UDP 0",text_color="#ffa657",**stat_style)

udp_label.pack(side="left",padx=25)

dns_label=ctk.CTkLabel(bottom,text="DNS 0",text_color="#3fb950",**stat_style)

dns_label.pack(side="left",padx=25)

total_label=ctk.CTkLabel(bottom,text="Total 0",text_color="#c9d1d9",**stat_style)

total_label.pack(side="left",padx=25)


def start_app():

    app.mainloop()