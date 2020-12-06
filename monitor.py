from scapy.layers.inet import IP,ICMP
from scapy.sendrecv import sr
from time import sleep



#f=open("pings_result_p.txt","a+")
f=open("pings_result_c.txt","a+")
count=0
avg=0
total=0
try:
    while 1:
        ans, unans = sr(IP(dst="10.0.2.5")/ICMP(),verbose=0) 
        count+=1
        f.write(f"Ping request number {count}\n")
        f.flush()
        rx = ans[0][1]
        tx = ans[0][0]
        delta = rx.time-tx.sent_time
        total+=delta
        sleep(5)
except KeyboardInterrupt:  
    avg=total/count
    f.write(f"\nAverage ping's RTT is: {avg}\n")
finally:
    f.close()
