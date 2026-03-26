import csv

file=open("packets.csv","w",newline='')

writer=csv.writer(file)

writer.writerow([
"Packet No",
"Time",
"Source",
"Destination",
"Protocol",
"Length"
])


def log(no,time,src,dst,proto,length):

    writer.writerow([no,time,src,dst,proto,length])