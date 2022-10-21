# Network Security - TP 2

## Introduction

![image](https://user-images.githubusercontent.com/91763346/197281209-9f5ed253-1420-4df4-9e2e-9efc6b45293a.png)

# **DNS Spoofing Explained**

Domain Name Server (DNS) spoofing (a.k.a. DNS cache poisoning) is an attack in which altered DNS records are used to redirect online traffic to a fraudulent website that resembles its intended destination.

Once there, users are prompted to login into (what they believe to be) their account, giving the perpetrator the opportunity to steal their access credentials and other types of sensitive information. Furthermore, the malicious website is often used to install worms or viruses on a user’s computer, giving the perpetrator long-term access to it and the data it stores.

* **DNS Spoofing Attacks**

Methods for executing a DNS spoofing attack include:
  
  * **Man in the middle (MITM)** – The interception of communications between users and a DNS server in order to route users to a different/malicious IP address.
  
  * **DNS server compromise** – The direct hijacking of a DNS server, which is configured to return a malicious IP address as explained in the following image.
  
  ![image](https://user-images.githubusercontent.com/91763346/197282217-30ca12bd-57b4-4532-b6f4-28e24b99619e.png)

  
  
# **Debunking DNS Attacks**

The following example illustrates a DNS cache poisoning attack, in which an attacker (IP 192.168.3.300) intercepts a communication channel between a client (IP 192.168.1.100) and a server computer belonging to the website www.videxrealone.com (IP 192.168.2.200).

In this scenario, a tool (e.g., arpspoof, Ettercap) is used to dupe the client into thinking that the server IP is 192.168.3.300. At the same time, the server is made to think that the client’s IP is also 192.168.3.300.
  
   1. The attacker uses arpspoof to issue the command: 
    
   
    arpspoof 192.168.1.100 192.168.2.200 

   This modifies the MAC addresses in the server’s ARP table, causing it to think that the attacker’s computer belongs to the client.

      
   2. The attacker once again uses arpspoof to issue the command: 
    
    
    arpspoof 192.168.2.200 192.168.1.100 
    
    
   Which tells the client that the perpetrator’s computer is the server.
    
   3. The attacker issues the Linux command: 
    
     
    echo 1> /proc/sys/net/ipv4/ip_forward 
    
    
   As a result, IP packets sent between the client and server are forwarded to the perpetrator’s computer.
    
   4. The host file, 192.168.3.300 videxrealone.com is created on the attacker’s local computer, which maps the website www.videxrealone.com to their local IP.
    
   5. The perpetrator sets up a web server on the local computer’s IP and creates a **fake** website made to resemble www.videxrealone.com.
    
   6. Finally, a tool (e.g., dnsspoof) is used to direct **all DNS requests** to the perpetrator’s local host file. The **fake** website is displayed to users as a result and, only by interacting with the site, **malware** is installed on their computers, thus gaining an interpreter that can exploit to gain **persistance**, **escalate privilages** and gain a **root** shell thus PWNING the victim's machine.

# **Mitigating DNS Attacks**

DNS is an unencrypted protocol, making it easy to intercept traffic with spoofing. What’s more, DNS servers do not validate the IP addresses to which they are redirecting traffic.

DNSSEC is a protocol designed to secure your DNS by adding additional methods of verification. The protocol creates a unique cryptographic signature stored alongside your other DNS records, e.g., A record and CNAME. This signature is then used by your DNS resolver to authenticate a DNS response, ensuring that the record wasn’t tampered with.

Although **DNSSEC** might seem the perfect solution, but it still has many downsides, including:

   1.**Lack of data confidentialityg**:
DNSSEC authenticates, but doesn’t encode DNS responses. As a result, perpetrators are still able to listen in on traffic and use the data for more sophisticated attacks.

    
   2 **Complex deployment**: 
DNSSEC is often misconfigured, which can cause servers to lose the security benefits or even deny access to a website altogether.
    
   3 **Zone enumeration**: 
DNSSEC uses additional resource records to enable signature validation. One such record, NSEC, is able to verify the non-existence of a DNS zone. It can also be used to walk through a DNS zone to gather all existing DNS records—a vulnerability called zone enumeration. Newer versions of NSEC, called NSEC3 and NSEC5, publish hashed records of hostnames, thereby encrypting them and preventing zone enumeration.
      
# **DNS Spoofing PoC**

Let's start by using Ettercap.

![image](https://user-images.githubusercontent.com/91763346/197285708-33807b0a-1659-45b5-ad23-a1fc1bf31c70.png)

We can see that we're promted with an Ettercap window.

![image](https://user-images.githubusercontent.com/91763346/197286010-bb3b3cfb-3ab1-4800-b8fc-17af49917c06.png)

Let's set our primary interface, in my case it's eth0.
To verify which one we get to use we can use **ip** command.

 ``` 
$ ip link show
 
 ```
The result would look something like this:
 
 ``` 
1: lo:  mtu 16436 qdisc noqueue state UNKNOWN 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth1:  mtu 1500 qdisc mq state UP qlen 1000
    link/ether b8:ac:6f:65:31:e5 brd ff:ff:ff:ff:ff:ff
3: wlan0:  mtu 1500 qdisc mq state DOWN qlen 1000
    link/ether 00:21:6a:ca:9b:10 brd ff:ff:ff:ff:ff:ff
4: vboxnet0:  mtu 1500 qdisc noop state DOWN qlen 1000
    link/ether 0a:00:27:00:00:00 brd ff:ff:ff:ff:ff:ff
5: pan0:  mtu 1500 qdisc noop state DOWN 
    link/ether c2:10:fa:55:8e:32 brd ff:ff:ff:ff:ff:ff
6: vmnet1:  mtu 1500 qdisc pfifo_fast state UNKNOWN qlen 1000
    link/ether 00:50:56:c0:00:01 brd ff:ff:ff:ff:ff:ff
7: vmnet8:  mtu 1500 qdisc pfifo_fast state UNKNOWN qlen 1000
    link/ether 00:50:56:c0:00:08 brd ff:ff:ff:ff:ff:ff
11: ppp0:  mtu 1496 qdisc pfifo_fast state UNKNOWN qlen 3
    link/ppp 
 
 ```
We can also use the following command:

 ``` 
$ netstat -i
 
 ```
 ``` 
Kernel Interface table
Iface   MTU Met   RX-OK RX-ERR RX-DRP RX-OVR    TX-OK TX-ERR TX-DRP TX-OVR Flg
eth0       1500 0   2697347      0      0 0       2630262      0      0      0 BMRU
lo        16436 0      2840      0      0 0          2840      0      0      0 LRU
ppp0       1496 0    102800      0      0 0         63437      0      0      0 MOPRU
vmnet1     1500 0         0      0      0 0            49      0      0      0 BMRU
vmnet8     1500 0         0      0      0 0            49      0      0      0 BMRU
 
 ```
 After knowing which interface we'll be using, we can now scan start our MiTM attack.

The next thing to do is to scan for hosts.

![image](https://user-images.githubusercontent.com/91763346/197299854-61e738b8-ad23-4bb7-b2c9-97a51e630219.png)

Now what we want to do is to add our victim machine to **target 1**, and our **network gateway** to **target 2** but we need to find their IP addresses.

To figure that out, we can use **nmap** and launch a scan to gather some info about the IP address and know for sure our target's IP.

As for the **gateway** IP, we can simply use the following command:

 ``` 
$ ifconfig
 
 ```
 
Now we can look for **Bcast**, it will have our gateway IP address. We can proceed by adding the victim's IP to **Target 1** and our gateway IP to **Target 2**.

Now we need to launch the MiTM ARP Spoofing attack.

![image](https://user-images.githubusercontent.com/91763346/197300362-2b980d17-5617-497e-8060-4c66ca723c3d.png)

![image](https://user-images.githubusercontent.com/91763346/197301020-5cfa1c33-7856-4138-ac8a-f82f412ff9f1.png)


To be able to execute the DNS Spoofing attack, we need to load the **dns_spoof** plugin by double clicking it. 

![image](https://user-images.githubusercontent.com/91763346/197301331-29a54dc7-1f62-43ee-b4dc-9274491bcf64.png)


Now to redirect specific DNS requests, we need to use the ***etter.dns*** file and specify the website and the IP that's going to be redirected to.

![image](https://user-images.githubusercontent.com/91763346/197298507-d06edcc6-37ca-4c06-83d6-235faf89ba45.png)

In our case, the website is **cck.rnu.tn** and as for the IP it's gonna be our **KALI** machine's IP.

![image](https://user-images.githubusercontent.com/91763346/197298565-70cffeb1-4182-41f9-ad0e-ea2c3b9319a0.png)



To make things simpler, we're just going to use a very simple webpage to test the attack, but from here on, the attack can be scalable to RCE, File UPLOAD, malware injection, scripting etc...
  
I will be using Apache to accept incoming traffic.

 ``` 
$ service apache2 start
 
 ```
  
The default html webpage,**index.html** , is located at **/var/www/html/**
We can try to edit it and make it look the same as the actual website to fool the target without getting him to suspect that the webpage he's using is a clone.

![image](https://user-images.githubusercontent.com/91763346/197298741-f15fd33a-be65-4599-b9e9-2245f4c4e318.png)

Let's try to connect to **cck.rnu.tn**

![image](https://user-images.githubusercontent.com/91763346/197298840-a1553209-90aa-48bd-881a-be1249e351fd.png)

We can see that it's not the content we expected, thus we **successfully** did a DNS attack.

The idea here is to be able to clone the website so, once the target tries to connect to that server, it's actually gonna be our **clone** that will give us access to his credentials.

The Process is not that hard, you can also find many tools that can automate most of the work for you.

# **Detecting an ARP Attack**
  
There exists many ways to check for ARP attacks, but perhaps the easiest method is by using the following command.

 ``` 
$ arp -a
 
 ```
The idea here is to check if there are two IP addresses that have the same MAC.

Here's an example of that scenario.

 ``` 
Internet Address    Physical Address

192.168.5.1        00-14-22-01-23-45  <-----.
192.168.5.201      40-d4-48-cr-55-b8        |
192.168.5.202      00-14-22-01-23-45  <-----.

 ```

We can see that we have 2 IPs with the same MAC, taking into consideration that 192.168.5.1 is the **ROUTER**'s IP.




