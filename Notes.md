## 01 - DDOS-ATTACKS

### Introduction to Large Scale Attacks
We begin our discussion of network security with an attack that all of us are familiar with.
Large scale attacks.
Specifically, distributed denial of service attacks, and malware based attacks.
We will discuss the methods used and the security weaknesses that are exploited in these attacks.
### Denial of Service Taxonomy Quiz One
Let's do a quick review of the denial of service.
Match the denial of service attack classification with its description.
### Denial of Service Taxonomy Quiz One Solution
For random scanning, it means that each compromised computer probes random addresses.
For permutation scanning, all compromised computers share a common pseudo-random permutation of the IP address space.
Signpost scanning uses the communication patterns of the compromised computer to find new target.
In hitlist scanning, a portion of a list of targets is supplied to a compromised computer.
### Denial of Service Taxonomy Quiz Two
Now let's do another quiz.
Again, match the denial of service attack classification with its description.
### Denial of Service Taxonomy Quiz Two Solution
Subnet spoofing means that the spoof address is within a given address space.
Random spoofing means that the spoof address is a randomly generated 32-bit address.
Fixed spoofing means that the spoof address is the address of a target.
### Denial of Service Taxonomy Quiz Three
Here's another quiz.
Again, let's match the denial of service attack classification with this description.
### Denial of Service Taxonomy Quiz Three Solution
If the denial-of-service attack targets server application, it means that the target is a specific application on a target server.
If the target is Network Access, that means the attack is used to overload or crash the communication mechanism of a network, so that Network Access now is unavailable.
If the target is Infrastructure, that means the attack is aimed at the crucial services of the global
Internet, for example, the core routers.
### Network DoS
Now let's discuss network denial of service attack in some more details.
The goal of network denial of service attack is to take out a large site such as a web server with as little computing power as possible.
So how is network denial of service accomplished?
One of the main approaches is amplification.
This means that the attacker only needs to send a small number of packets and can achieve a big effect such as rendering the targeted site unavailable.
There are two types of amplification attacks.
The first type is to exploit a bug or vulnerability on the server.
For example, if there's a design flaw or implementation error on the server code, then the attacker machine can send a few packets that contain input that would trigger the bug and then crash the server.
And of course, when the server program is crashed, then the server become unavailable.
Another type of denial of service attack is to send a flood of packets.
For example, an attacker can use a large botnet to send a lot of requests to the server.
Network denial of service attack can happen at any network layer.
As a quick review, there are multiple layers in a network stack.
For example, denial of service attack can happen at the link layer.
This means that the attacker simply sends a lot of traffic to saturate the link.
Denial of service attack can happen at a TCP/UDP layer or the transport layer.
For example, the server needs to use memory to hold the state of TCP connections, so the attacker can send a lot of TCP packets to exhaust the server's memory.
Denial of service attack can also happen at the application layer.
For example, the attacker can request the server application to fetch a large amount of data.
And if there are many such requests, the server's resources will be exhausted.
The sad truth is that the current Internet design cannot handle distributed denial of service attacks.
### Amplification Quiz
Now let's go over an application example and then do a quiz.
One example of attacks is to use the NTP, Network Time Protocol.
This protocol is used to synchronize machines to the clocks.
For example on a Mac, the day and time are set by an NTP server run by Apple.
When a computer request the time from the NTP server, the server responds with the correct time and date.
In NTP, the data volume of the request from a machine is much smaller than the response from the server.
Now you can imagine how NTP can be used for the now service attack.
So with that background, let's do a quiz.
Which of these are reasons why the UDP-based NTP protocol is particularly vulnerable to amplification attacks?
### Amplification Quiz Solution
As we already discussed, the volume of request from a computer is smaller than the response from the server.
That means a small command can generate a large response.
And the attack works because the attacker can send the request to a server by spoofing the IP address of the target.
So that the servers response is sent through target and that's how the attack works.
And it is difficult to ensure that the computers only communicate with legitimate NTP servers.
This means that it is not easy to figure out responses from NTP servers.
### Amplification Example
Let's take a closer look at amplification attacks.
Typically, the attacker uses a machine, and then these attacker machine controls a number of bots, or compromised computers.
And each of these bots will send many requests to a server, and the response from the server is much larger than the request.
So the amplification is accomplished by two factors.
One is the number of bots involved.
And second, the server response is much larger than the requests.
Here's a specific example of amplification attack.
This involves DNS, the domain name system.
Here's the amplification factor involving the server, the DNS server.
So here we have the machine sending a DnS request to the server.
And of course, the address, the source of the DnS query is spoofed and the server thinks that the request is from the target.
The server response is much larger than the request.
In this case, it is 50 times.
Here, EDNS means extension mechanism for
DNS.
It allows for actual flags and response data.
Therefore, the response is much larger.
In a DNS-based amplification attack, each of the bots controlled by the attacker will send many requests to any of the DNS resolvers.
And there are many of them.
And for each request, the response will be sent to the target because in each request, the source IP address is spoofed.
The attacker can choose any subset of the DNS servers to use because there are so many open DNS resolvers on Internet.
This attack can generate a huge amount of traffic in a very short period of time.
For example, the attacker can easily generate tens or even hundreds of gigabits per second traffic targeted at a victim.
### TCP
Now let's take a look at the network protocols to understand why the internet is vulnerable to DoS service attacks.
So the internet protocol or
IP is connectionless.
This means that it is not reliable, meaning that each packet will find it's way to destination and there is no mechanism to ensure that all packets will arrive properly and in sequence at least not at IP layer essentially it is the best effort delivery.
So here is the format of the IP header for the purpose of our discussion let's focus on a source IP address and a destination IP address.
>From the security point of view the main weakness of IP is that there is no authentication of the source IP address.
Which means that the attacker can spoof an IP source address.
Now let's take a look at TCP.
TCP is session based which means the destination is going to make sure that all packets belonging to a same connection will arrive and properly sequence.
And in order to achieve this there's congestion control and in order delivery mechanisms.
These mechanisms ensure that the data loss or packet loss is minimized and the need to retransmit packets is also minimized.
And here's the format of the TCP header.
Notice that we use a sequence number for each packet.
Acknowledgement number to acknowledge a packet as received.
And number flags to actually keep the state of the session.
Now let's take a look at TCP handshake or the steps to establish a TCP connection.
Suppose our client wants to connect to a server.
It first sends a SYN packet, this packet has a SYN flag set and also a sequence number.
The acknowledgement number is 0 because this is the first packet.
The server responds with a SYN/ACK packet, which means that both the SYN flap and the ACK flags are set.
The sequence number is a server sequence number and acknowledgment number is the sequence number plus one.
This means that this SYN/ACK packet is an acknowledgement of the initial SYN packet from the client.
And then the client sends a final
ACK packet to the server.
In this ACK packet, it incremented its Its own sequence number and acknowledge the sequence number from the server.
This tells the server that the client has received this SYN/ACK packet.
At this point, the TCP connection is established.
### TCP SYN Flood I
With that background, let's discuss how TCP SYN flood or denial of service attack can work.
Notice that, in TCP handshake, after the server receives a SYN packet from the client, it sends a SYN/ACK packet back to the client, and then waits for the ACK packet from the client.
When it received the ACK packet, it knows that the connection is established.
Therefore, the server needs to keep in memory the state of the connection, meaning that it's waiting for the ACK packet that matched the SYN/ACK packet, which matched the initial
SYN packet from client.
So SYN flood exploits the fact that server needs to keep in memory such state information.
In particular, the attacker can send a lot of SYN packets to the server, and the source IP address is spoofed to some random target source IP address.
The result is that the SYN/ACK packet will be sent to the spoofed or the target address.
Since the source IP address of these
SYN packets are randomly generated and spoofed, the SYN/ACK packets may get lost, meaning that the ACK packet may never arrive at a server.
The result is that the server's memory gets filled up, because the server needs to keep track of the SYN/ACK packets and wait for the ACK packet from the clients.
And since many of these
ACK packets do not arrive, the server is holding in memory this state information.
And as a result, its buffer gets filled up.
And when that happens, no further connections can be serviced.
In other words, the denial of service is accomplished.
Here's a real example of SYN flood.
The Blaster worm in 2003 infected many machines.
And these infected machines were insructed to launch a denial of service attack at noon on August 16th.
That is, these machines were instructed to launch SYN flood on port 80 on the target server windowsupdate.com.
In particular,
50 SYN requests were sent every second.
And each packet is 40 bytes.
And the source IP address of these request packets were randomly generated.
As a result, the server windowsupdate.com was rendered unavailable.
As a response, Microsoft moved the
Windows update service to a new domain, windowsupdate.microsoft.com.
So how do we defend against SYN flood attacks?
How about increase the memory size or decrease the timeout value so that when a server does not receive an ACK packet, it just clears out the memory.
These are not good solutions, because an attacker can just send more packets or at a faster pace.
A better solution is to remove the need for a server to keep state.
And this, of course, comes with a cost.
### SYN Cookies Quiz
Now let's do a quiz on SYN cookies.
Select all true statements.
### SYN Cookies Quiz Solution
SYN cookies does not require modified version of TCP, so this is false.
SYN cookies are only applied when there's a SYN flood attack.
That is, during normal operations, or when a server does not experience a overload, it does not require SYN cookies.
Therefore, SYN cookies should not lead to overall slower performance, that is the second statement is false.
The third statement is true because during an attack, the server uses SYN cookies and does not keep stay information in memory.
### SYN Flood II
SYN flood attacks can be launched at a massive scale.
Typically, for distributed denial of service attack, a large botnet can be used to generate a huge amount of traffic.
And the result is that the website, or even its uplink network routers, can be saturated.
It is very hard to filter these SYN packets, because they all look legitimate.
So how do we defend against such massive flooding attack?
One idea is to use a very powerful server, or a group of servers, to protect a website.
The idea is that these intermediate servers will only forward established TCP connections to the real website.
Suppose many machines or bots send a lot of requests to the website, but they're intercepted by the proxy.
The proxy is very powerful because it can use many servers.
And they can be distributed across the Internet.
The proxy sends the SYN/ACK packets in response to the initial SYN packets.
When a proxy receives the ACK packets from the client, it will then forward to the real website.
The idea here is that the attacking machine or the bot will not send actual
ACK packets to the proxy.
Only the legitimate clients will send the ACK packets to the proxy, and only those will be forwarded to the website to be serviced.
In other words, the proxy here stops the flooding attack.
However, the idea of using a proxy to protect a website is not bulletproof.
Here's an example of a stronger attack.
An attacker can use an army of bots to actually completely finish the TCP handshake.
In other words, use complete TCP connections to website.
Then it can send requests to the website and keep repeating all these requests to the server.
That is, all of these requests are legitimate from a protocol point of view, but they were designed to overload the server with a lot of work.
And the result is that if the attacker can command a huge army of bots, the attacker can still bring down a website.
This is similar to the situation when there are huge number of legitimate users visiting a website at the same time.
Of course, such attack can actually render the proxy protection useless, but on the other hand, because the TCP connection is fully established, that means the attacker cannot use any random source IP address.
The attacker must use the real
IP address of the bots, which means that the bots' IP addresses are now revealed.
And then a proxy can actually block or rate limit traffic from these bots.
In other words, after the initial attack, there's a chance that the proxy can actually use the information to rate-limit and then reduce the effect of the flooding attack.
Here's a real-world example of such an attack, it's fairly recent.
So here, a honest end user visits a popular website, but this website is compromised and the response will include a miniature
JavaScript injected into the response.
And the user has no idea that this JavaScript is embedded into the response HTML page.
For example, this JavaScript can be embedded in an invisible iframe.
Once the response HTML page runs on the user's browser, the malicious JavaScript will run, and it will do a denial of service attack on a server, say, Github.com.
Here's how the JavaScript can launch an attack on Github.com.
It basically asks the victim website, say, GitHub.com, to fetch a random resource on a server.
And it sends such a request every ten milliseconds.
Therefore, with many users unknowingly running this malicious JavaScript, the victim website, say Github.com, can be rendered unavailable.
### Attack Quiz
Now let's do a quiz on flooding attack.
With regards to a UDP base flooding attack, which of the following statements are true?
### Attack Quiz Solution
Attackers can obviously spoof the IP address.
The attack cannot be mitigated using firewalls because the idea is that the packets involved in the attack, they all look legitimate.
In addition, even if the firewall is attempting to do filtering, it itself is susceptible to flooding.
The reason is that the firewall now needs to examine many, many packets.
### DoS and Route Hijacking
The Internet routing protocol can also be exploited to launch in our service attacks.
In particular, there have been several incidents of route hijacking that resulted in denial of service.
Here's one example involving
Pakistan and YouTube.
The Internet is divided into a large number of so-called autonomous systems.
Each autonomous system or
AS is responsible for logging packets in and out a subset of the Internet defined by the prefix.
For example, the YouTube service address is within this prefix.
It is actually 208.65.103.238.
In February 2008, Pakistan Telecom advertise that, is actually responsible for subset of Internet defined by this particular prefix.
And this prefix is more specific than a segment that includes the YouTube server.
And since the routing positions for a specific IP address, such as the YouTube server use the more specific prefix.
Then the whole Internet thought that
Pakistan Telecom is responsible for routing traffic to YouTube.
The result of this route hijacking is that all traffic to YouTube was instantly routed to Pakistan.
As you can see, the traffic volume at the YouTube server jumped to zero until the route hijacking mistake was corrected.
In a more recent example,
China Telecom published
BGP routes that caused .mail and
.gov to route through China Telecom.
### Higher Level DoS
So far, we have discussed denial service attacks that exploit weaknesses in network protocols.
Denial service attack can also happen at a higher level.
For example, let's look at a typical handshake protocol.
Here's a protocol that use publicly based authentication.
So the client sends a hello message to the server, and a server sends its public key to the client.
And then, the client will use that public key to perform key exchange.
For example, the client can generate a secret share key between a client and a server, and encrypt that using the server's public key.
And when a server receives this encrypted key, it will use its private key to decrypt, to extract this secret share key.
The point is the client encrypts the secret share key using the server's public key, and then the server decrypts that using its private key.
It's all good from a crypto point of view.
However, RSA Decrypt is ten times more costly than RSA Encrypt, since the server has to do so much more work.
The attacker can send many such handshake requests to the server to bring it down.
Similarly, at the application level a client can send a simple HTTP request to your server asking for a very large PDF file.
And obviously, the server needs to spend far more resources than the client.
Therefore, an attacker can send many such HTTP requests to your server, causing the server to fetch a large number of very large PDF files, and this will actually bring down the web server.
### DoS Mitigation Client Puzzles
So how do we mitigate such denial of service attacks.
One solution is to use client puzzles.
The main idea is to slow down the attacker.
For example, we can ask the client to solve a problem.
For example, the server can challenge C to the client and ask the client to find or compute X such that the n needs significant bits of the SHA-1 hash are all 0s.
The assumption here is that it would take the client 2 to the n time to solve this challenge.
For n=16, it would take 0.3 seconds on a 1 gigahertz machine.
And of course, the client needs to present X back to the servers, and it is very easy for server to check that the solution is correct.
This is because the server needs to only compute hash
1 whereas the client is to compute to the n times.
During a denial of service attack everyone, that is including legitimate clients or possible attackers, everyone must submit puzzle solution to the server.
And of course, when there's no attack, no one needs to solve the puzzle.
Here are some examples of how client puzzles can be deployed.
For TCP connection flooding, the challenge C can be the TCP's server sequence number, and the first data packet from the client must contain the puzzle solution.
Otherwise the server will terminate the TCP connection.
For SSL handshake denial of service attack, the challenge C can be based on a TLS session ID.
And the server will check the puzzle solution before even attempting to do
RSA decrypt, because RSA decrypt is very expensive.
And similar ideas can be applied to application layer denial of service attacks.
One advantage of the client puzzle is that the hardness of the challenge, or in particular, n, can be decided based on the DoS attack volume.
For example, if the volume is high, you can set n to be higher so that it takes more time for the client to find a solution.
In other words, this will reduce the volume of traffic to the server.
The limitation is that this requires changes to both the client code and the server code.
It also hurts legitimate clients, in particular, clients that use low power computing devices such as cellphones.
Another variant of client puzzle is to use memory-bound functions.
This is because CPU-bound functions such as the one we just discussed, cannot be scaled to very hard puzzles for low end machines such as cell phones.
Whereas memory-bound functions can be easily scaled, even for low-end machines.
There are several proposals to use memory-bound functions as puzzles.
You are encouraged to study these papers.
### Puzzle Quiz
Now let's do a quiz on puzzle.
Which of the following statements are true?
### Puzzle Quiz Solution
Client puzzles should not be hard for a server to construct, so this is false.
Client puzzles should be stateless, this will keep a client from being able to guess the puzzle and find a solution before even being asked.
Puzzle complexity should increase as the attack volume increases.
### DoS Mitigation   CAPTCHAs
Let's discuss another mitigation technique.
You may be already familiar with this.
It is called CAPTCHA, which stands for
Completely Automated Public Turing test to tell Computers and Humans Apart.
The idea is that the server should verify that the connection is from a human instead of, for example, from a bot or a malware.
So I'm sure many of you are familiar with this.
The idea is that only human can interpret this figure and then type in the actual words.
During a denial of service attack, the server can generate CAPTCHAs and process request only if the client presents the actual valid solution to the CAPTCHA challenge.
Because that will prove that there's actual human behind the request.
### DoS Mitigation Source Identification
Another important mitigation is source identification.
The goal is to identify the source of attack packets so that ultimately we can block the attack at each source.
You may think that this problem should be easy because, for example, we discussed that many of the packets involved a denial of service attacks, they have spoof or random source IP addresses.
So the question is, why don't we just ask the ISPs to filter out source IP addresses that are not legitimate or valid for the ISP?
For example, if the router expects that all traffic is from this particular prefix, then it can drop all packets with a source
IP address other than from this prefix.
That way smooth packets can be dropped.
The biggest problem for this proposal is that it requires all ISPs to do this.
Because, as we will show, if only 10% of ISPs do not implement, then there's actually no defense against denial of service for the whole Internet.
Then the problem becomes that every ISP is waiting for everyone else to implement this first.
As we have shown in the previous example, if only 3 ISPs do not implement ingress filtering, the attackers can already launch a big denial of service attack.
As of 2014, a quarter of the autonomous systems are mostly ISPs or big enterprises.
They do not implement ingress filtering.
In total, that means 13% of the IP addresses can be spoofed.
### DoS Mitigation Traceback
Now let's discuss another source identification technique called Traceback.
The goal is that given a set of attack packets, we want to determine the paths of these packets and use a path to determine the source of these packets.
And the way to do this is to change the Internet routers to record some path information into the packet.
There are a few assumptions here.
First, most the routers remain uncompromised, meaning that these routers can record information faithfully.
Second, the attackers send many packets, and the route from the attackers source to the victim remains relatively stable.
Here's a naive strawman method.
We can have each router at its own IP address in the packet.
So, at the end, the victim can read a path from the packet because each router has written its own IP address.
The problem with this is that it requires space in packet and this can be a problem when a path is long.
There's no extra fields in the current
IP format to record this whole path information.
If we expect the packet format to be changed to include this path information it would take years, if ever, to get this implemented.
So here's a better idea.
We observe that the non-service attack involve many, many packets on a same path, so we can have each router to take a probability to store its own address in a packet.
This required only a fixed amount of space regardless of the path length.
### Traceback Quiz
Let's do a quiz on Traceback.
Which of the following are assumptions that can be made about Traceback?
### Traceback Quiz Solution
Attackers can generate unlimited types of packets, so this is false.
Attackers can indeed work alone or in groups.
And the Traceback will work regardless whether the attacker are aware of the tracing mechanisms or not.
So this is false.
### DoS Mitigation Edge Sampling
So now, let's go into the detail of the traceback mechanism.
The main component is the edge sampling algorithm.
An edge includes the start and end IP addresses.
It also includes distance, which is the number of hops since the last edge stored.
Here's the procedure for a router to decide how to record the edge information.
When a packet arrives, it throws a coin.
If it's heads, then it will write its address into the start address and then write 0 into the distance field.
If it's tail, then if distance is 0, then it writes its IP address into the end address field.
And regardless, it will increment the distance field.
So here's an example.
Again, a packet would include edge information, which includes the start address, end address, and distance.
Suppose the packet travels through three routers, R1, R2, and R3.
R1 tosses a coin and it's head.
So R1 writes its address to the start field and 0 in distance.
Now R2, it tosses a coin and it's tail.
The distance was 0.
So according to the process, it should write itself to the end and then increment distance to 1.
Now for R3, it tosses the coin and it's tail again.
But the distance was not 0.
So it does not write itself to the end.
It simply increment the distance.
Now it's 2.
Now, for R3, it tosses a coin, it's tail again, and the distance is greater than 0, so it does not write itself to the end.
It simply increment the distance from 1 to 2.
Now, as you can see, the edge information includes the starting of the edge, which is R1, the end, which is R2, the distance is 2.
That means from R3's perspective, the distance is 2 since the beginning of the edge.
With the edge information, now we can talk about how do we reconstruct the path.
The package arrive at the victim contains edge information.
And this information can be extracted to reconstruct the path that started from the victim all the way to the source of the attack packets.
Again, the edge information contains the starting router and the end router of the edge and the distance from the starting router.
And the number of packets needed to reconstruct the path is given by this formula.
This is the expected number of packets.
And p is the probability of head versus tail, and d is the length of the path.
### Edge Sampling Quiz
Let's do a quiz on edge sampling.
Select all the statements that are true for edge sampling.
### Edge Sampling Quiz Solution
With edge sampling, multiple sources can be identified.
Therefore, multiple attackers can be identified.
As we can see, it's relatively easy for a victim to reconstruct a path given the edge information.
So this second statement is false.
The edge information is stored in the IP packet header, so therefore, the third statement is true.
### Reflector Attack
Let's discuss a more recent type of denial-of-service attack called reflector attack.
So here, the attacker spoofed the victim's source IP address and sends DNS query to many DNS servers.
And all DNS servers will respond to this query and send their response to the victim machine.
And, of course, the result is that the victim is flooded.
In addition to DNS example, there are other examples that use web servers and Gnutella servers.
A reflector attack is typically launched by a bot master.
Commanding many bots, each of them will send a lot of requests to many reflectors, such as DNS servers, web servers and the Gnutella servers.
And these requests will spoof the victim IP address and as a result, the reflectors will send the response to the victim.
Since the actual flooding traffic is from the reflectors to the victim, a traceback scheme will trace the attack packets back to the reflectors.
And the reflectors may not do any marking or keep any state, so there's no traceback from the reflector back to the bots or bot master.
### Reflector Attack Quiz
Now, let's do a quiz on reflector attack.
Self defense against reflector attacks should incorporate which of the following?
### Reflector Attack Quiz Solution
Filtering should take place as far from the victim as possible, so the first statement is false.
Server redundancy is always helpful and rate limiting is always helpful.
### Capability Based Defense
Now let's discuss some novel idea to defend against denial of service attacks.
There are a number of examples for capability-based defenses.
You're welcome to study these papers.
Here's a brief overview of these defenses.
The basic idea is that the receivers, such as a server, can specify what packets they want, and this is called the capability.
When the sender sends a request to the receiver, he must include capability in his SYN packet, meaning that he needs to tell the server that, hey, I am the packet that you want.
When a client wants to connect to a server, it needs to first request capability.
And such a request should be very limited.
And the server can respond with a capability that the sender can later include in his packets.
Furthermore, all the routers will only forward packets with valid capability.
If a source is attacking, then its capability can be revoked, and as a result, the routers will drop or block such packets.
And this can take place as close to the source as possible.
### DoS Reality
So in summary, denial of service attack is a real and present danger on the Internet and to mitigate such attacks, security must be considered at Internet design time.
Therefore, the sad truth is that the current Internet is ill-equipped to handle denial of service attacks.
There are some commercial solutions.
There are many good proposals for internet core redesign such as based blogging.

---
&nbsp; \pagebreak
## 02 - Cybercrimes

### Introduction to Cybercrimes
In this lesson, we will examine cyber crime, its economy, and some of the motivations of the players.
When you finish this lesson, you should have a much better understanding of where legitimate Internet commerce ends and Internet crime begins.
### Actors in the Underground
Now let's talk about underground economy.
To understand the underground economy of server crimes we have to first understand who are the actors in the underground.
The first are the ones who write exploits.
They discover bugs that can be exploited to cause security to be compromised and they sell them for a profit.
Then there are the botnet masters, or bad guys that create and operate a malicious network composed of compromised computers.
Essentially, they buy exploits and turn them into malware and they put in the botnet command and control components.
So when they release the malware, they have a botnet under their control.
Then they rent out the botnet to other bad actors for malicious and fraudulent activities.
One of the utilities of a botnet is to send spam.
And so the bot master of a botnet can simply rent out his botnet to a spammer, and the spammer in turn sends out a spam contents on behalf of other bad actors.
One type of bad actors that can use to help of spammers are the phishers.
They set up scam sites to steal information and they ask the spammers to send the URL's to victim users to the scam sites.
Similarly, counterfeiters use spams to sell their counterfeit goods and obviously, they need to be able to collect money from the victim users.
For example, from their credit cards.
A bad actor in a cyberspace needs to consider the possibility that his operation, in particular his websites, may be detected and shut down by the law enforcement.
And so he needs to find a so-called bulletproof hosting providers.
These providers typically operate in lawless places and they are expensive.
A majority of the bad actors are in it for the money.
And on the Internet, what they can steal are the bank accounts and credit cards.
And so they need to turn them into cash.
They allow carders, cashiers, and mules to do just that.
The crowdturfers leverage human powered crowd sourcing platforms to create and manage fake accounts that are not tired to real users.
And they can use crowd sourcing to solve captures.
### Structure of the Underground
As we have discussed, there are quite a few types of bad actors in a cyber space and they form an interconnected ecosystem.
For example, a botnet is created when computers are compromised, a malware is installed and a botnet is used to launch a number of malicious and fraudulent activities.
For example these are activities that can be launched by botnet, in particular spam.
Spam can be used to facilitate a number of other activities such as phishing, selling counterfeit goods or malware installation.
Again, the point here is that the bad actors form an interconnected ecosystem because their activities or even structures support each other.
### Underground Forums
Underground forums are one the entry points of the bad guy's communication systems, especially for those new to the underground.
There are many underground forums on the Internet.
And they're just one search and one click away.
And there are a large number of illicit activities being advertised on these forums.
Obviously law enforcements are watching and can shut down these sites.
However, new forums can always pop up and fill the void.
These forums also provide valuable data sources to researchers.
For example, researchers can study the data to learn about new trends and detect unfolding attacks.
The forums are full of buyers, sellers, and the rippers.
There are honest deal makings but there are also rip-offs of the buyers.
Basically, these forums are as regulated as what administrators can handle.
Most messages on the forums are just advertisements.
For example, one can advertise that he has stolen bank accounts or access to computers or email lists.
One can ask for stolen credit card numbers in exchange for access to a hacked LINIX machine.
Many of these advertisements include evidence of the advertisers capabilities.
For example, to demonstrate that the stolen accounts are valid or show a sample of the stolen information.
Again, the forum is typically useful just advertisement.
The actual due-making is typically done via private messaging.
### Exploits as a Service
Now let's discuss a few underground activities.
The first is Exploits-as-a-Service.
In the past, compromising computer systems and use them for profit are typically done by the same criminal or criminals gangs.
For example, the same criminal gangs will develop their own exploits, launch them, and then use the hacked machines to make money.
Nowadays the bad guys are specialized and do different functions.
For example, there are developers who develop exploit kits and packets, and sell them to other bad guys.
And the other bad guys are responsible for using these exploit kits to compromise computers.
For example, they can send out spam with malware attachment.
Or they can put the malware in a compromised web servers, so that when a victim's computer visit those servers, they will be compromised.
These compromised computers are then sold on the black market so that other bad guys can use them to launch malicious and fraudulent activities.
And the bad actors here are being paid using the pay-per-install model.
Let's discuss exploits-as-a-service, and in particular, the pay-per-install model in more details.
One way to distribute malware, or causing computers to be compromised by the malware, is through so called drive-by-download.
Basically a website is compromised to have malware embedded in their scripts.
And then when a client computer visits the website, the malware will be installed on their computer.
The number of exploit kits that package the malware, and install the malware on the client computers.
There are two components in this malware distribution model.
The first is that the bad guy needs the exploit kit because the exploit kit will be responsible for installing the malware on the victim computers.
The bad guys can buy an exploit kit and deploy it themselves.
Or, they can simply rent access to exploit server that hosts the exploit kit.
In the first option, the bad guy needs to figure out how to distribute the malware themself, and typically that means at least he has to set up a server with exploit kits.
A more convenient option is for the bad guy to rent access to a server that already hosts an exploit kit.
The second component of this malware distribution model is that the bad guy needs to have the kind computers visit the exploit server so that malware will be installed on these computers.
The most common way to accomplish this is to use spam or phishing to attract traffic to this exploit server.
Traffic paper install simplifies this malware dispersion process.
It essentially combine the two elements into a single service.
And pay-per-install is now the most popular way of distributing malware.
### Dark Web Quiz
The fact that there are so many underground forums and malware sites on the internet, it is just one example that the web actually has multiple facets.
So let's do a quiz, match the term with its definition.
### Dark Web Quiz Solution
A deep web is one that's not indexed by the standard search engines such as Google.
A dark web refers to also invisible web or hidden web where the web content typically only exists on so-called darknets.
And so what is a darknet?
It is an overlayed network that can only be assessed with specific software, configurations or authorization, often using non-standard communication protocols and ports.
Two example darknet are the friend to friend peer to peer networks and the privacy network such as tor,
T-O-R, tor.
And a surface web is one that we are probably most familiar with.
It contains web contents that are public, searchable and indexed by standard search engines.
When we think of the Internet we're usually referring to the surface web.
As you can see in this visual, the surface web is actually a very small part of the Internet.
### Traffic PPI Example
Let's look at a traffic paper install example.
There are three causes of actors in traffic paper install.
There are the victims, the exploit developers, and the clients, or bad guys that use the exploits to dispute malware.
If you look at the traffic flow, we notice that the payment flows from the clients or the bad guys who buy or rent the exploits to exploit developers.
The malware flows from these attackers to the victim.
The payment amount depends on the volume of malware installation.
### PPI Quiz
Now let's do a quiz on pay per install.
Match the term with its definition.
### PPI Quiz Solution
A doorway page is a web page that lists many keywords in hopes of increasing search engine ranking.
And then, scripts on that page will redirect the visit to attackers website.
A crypter is a program that hides malicious code from anti-virus software.
A Blackhat Search Engine Optimizer, or Blackhat SEO, is one that tries to increase traffic to the attacker's website by manipulating search engines.
A Trojan Download Manager is a piece of software that allows an attacker to update or install malware on a victim's computer.
### From Malware to Botnets
So we have just discussed how malware can be distributed and installed on victim's computers.
These infected computers are valuable resources.
For example, they have a unique
IP addresses and bandwidth, and they're typically distributed across the internet.
And they have spare CPU cycles that can perform a wide range of activities.
From attackers point of view he wants to control and utilize these infected machines and the way to do this is to turn the compromised computers into a Botnet.
The bad guy or the botmonster will need a command control infrastructure to control the bots.
For example he can then ask the bot to update its malware or can send commands to the bots to launch synchronised activities and the botnet can rent it out to other bad guys to launch their activities, such as sending spams.
Once in place, the botnet now becomes a platform to launch any number of malicious and fraudulent activities.
### Command and Control
The key to a botnet success is efficient and robust command and control.
And this is not always easy.
The simplest, most efficient way to perform command control is through centralized control.
For example through IRC command or command, he can instruct the bots to send spam.
However this kind of command control is not robust.
Even though it's very efficient, because it has a single point of failure.
There's only one command channel from the attacker.
For example the IRC channel can be taken down.
Or the twitter account can be shut down.
A more robust command control structure is to use peer to peer network.
Here, the botmaster can connect to a number of bots in this peer to peer network.
And upload his commands, and update to the malware.
And make advertisements, so that other bots can get the command and updates from the peers.
The drawback is that the botmaster does not have direct synchronized communication with autobot.
In fact, the Botmaster does not know how many bots get it's commands and when.
Nowadays, the most popular approach for command control is for all the bots to connect to a command control website.
Obviously, this is very efficient.
And the Botmaster can make this set up more robust.
For example, the Botmaster can map this website to different IP addresses.
The website is not always fixed on one physical server.
It can be moved to different servers.
In fact, in Fast Flux, the Botmaster can change the DNS IP mapping for the website every ten seconds.
This can defeat detection or blocking, based on IP addresses.
But since the domain name is not changed, this domain can still be detected as using for botnet command control.
And the ISPs can't block access to this domain.
Instead of using fixed domains that can be detected and blocked.
Botmaster's now used random domain generation.
On each day, a bot will generate a large number of random looking domain names and lock them up.
The Botmaster will knows exactly the same set of random domain each day.
Because each domains are generated using the same algorithm.
And same random seeker seed straight between the botmaster and the bot malware.
In the botmaster, only register a few of these random domains.
Although each bot generates many random domain names, and look up each of them.
Only few of them will actually connect to the websites.
These are the sites that are registered to the botmaster.
And of course, these sites can use fast flux to move around on the internet.
By mapping to different IP addresses every ten seconds.
This command and control approach is very robust, because it is hard for detection.
This is because each of these command control domains are randomly looking.
And they're new.
And they are only used for a very short period of time.
Say, one day.
### SPAM Quiz
Let's do a quiz on spam.
What are the two defining characteristics of internet spam?
### SPAM Quiz Solution
They are typically inappropriate or irrelevant to the user and typically it's being sent to a large number of recipients.
### SPAM
It is estimated that more than 90% of our email are actually spam.
That will translate into hundreds of billions of spam messages every day.
Spammers play a very key role in the underground economy and cybercrime.
They have contacts of many many people and many organizations.
They send messages on behalf of other bad actors.
They can be used to push malware or phish to steal information.
Spammers typically use botnets to send spam.
They need a large number of IP addresses because otherwise, sending a large number of emails from a few IP addresses will easily trigger detection and blocking by spam filters.
Let's start via few examples of how spam works in the underground economy.
Many spammers are affiliates of various kinds of scam campaigns.
Scammers typically set up websites to sell counterfeit goods.
The scammers try to act legitimately by delivering goods and collecting payments.
They can even have customer services.
But how do the scam websites attract traffic?
They need the spammers to advertise for them.
And in return, the spammers collect commissions.
For example, the commission can be as high as 30 to 50% of the final sales price.
Now the key to the success of both the scammers and the spammers is the spam conversion rate.
The spam conversion rate is the percentage of spam messages that result in a final sale.
We know that there are spam filters around.
And we have the feeling that a lot of them are very effective.
So why do spammers continue to send spam?
And how many messages get past spam filters?
We heard numbers such as more than
99% of the spams are filtered.
Any spam leads to a successful transaction.
How much money can be made?
The only way to precisely answer these questions is to infiltrate and instrument the spam generation and monetization process.
Because by doing so we can find out exactly what's going on.
### 12_SPAM Filter Effectiveness
Let's discuss a case study on Storm botnet.
This botnet was used to send spams.
And this research was performed by the
University of California in San Diego, where the researchers penetrated into the Storm botnet.
The researchers were able to measure the percentage of spam that got through the spam filters.
Here are different campaigns carried out by the spams.
Pharmacy is a spam advertising an online pharmacy.
The postcard and April Fool campaigns are for installing malware.
As we can see here from data that's available, there are spam filters that can actually filter out more than 99% of the spam messages.
On average, only 0.014% of the spam messages that can get through the filters, which translates into 1 in more than 7,000.
Looking at the whole lifecycle of a spam message, some get not delivered, some get blocked by spam filters, some are ignored by the users, and users may just leave the sites.
Of course, some of them will actually commit a transaction.
But some of these traffics are due to crawlers, meaning that they're not actual users.
This table shows that for each campaign, what's the percentage of spams that can be delivered, filtered, result in user visiting the website, and user conversion.
Obviously, user conversion is the most interesting number that we should look at.
For pharmacy, it's 1 in 1,737.
For postcard, it's 1 in 37.
For April Fool, it's 1 in 25.
This conversion rate is computed for the spams that got into the user's inbox.
How many of them result in user transactions?
The pharmacy campaign advertise a fake online pharmacy.
The researchers observed that there were 28 purchases in 26 days.
The average price per purchase is $100.
But the researchers only controlled
1.5% of the bots sending the spams.
If we extrapolate this amount to the whole botnet population, then we get close to $9500 a day, or $3.5 million a year.
Of course, the scammer and spammer will divvy up this money.
So the Storm operators or the spammers will get $1.7 million a year.
### SPAM Revenue Quiz
Now, let's do a quiz on spam revenue.
Name the top three countries where spam directed visitors added items to their shopping cart.
These are the visitors that can make transactions.
### SPAM Revenue Quiz Solution
This may be a surprise to you, but a top country is the United States, followed by Canada, followed by Philippines.
There's an interesting paper called
Show Me the Money: Characterizing
Spam-advertised Revenue, and
I encourage you to study this paper.
### Scamming Ain't Easy
With the example storm botnets, you may think that making money is easy in the underground.
Actually, it is not easy.
In fact, scamming is supported by a whole ecosystem that includes network infrastructure and payment system.
For example, we're going to start the pharmaceutical scams.
Suppose you want to set up a website called canadianpharma.com.
The question is that how do you do this?
What sort of infrastructure do you need?
Because obviously you should worry about law enforcement agencies shutting down your website.
Even before that, you should worry about that legitimate registers may not even let you register your domain name.
So you go to the shady registrars, but they would charge you more.
After you obtain your domain, you want a DNS server that map the domain name into an IP address.
Some DNS providers will shut down your domain if they hear complaints.
So you go to the so-called bulletproof DNS providers, that operates in lawless land, but they are expensive.
Now to set up your website, you need to stand up a web server.
For example, a machine in ISP.
But, the ISP or law enforcement can shut down your website.
So, you want to go to the bulletproof network providers.
Again, they're expensive.
There are indeed service providers that offer very low priced, resilient hosting services, but obviously they are very expensive after you set up the network infrastructure, now you need to consider how do you receive payments.
Basically you need to handle credit card payments and get money out of these accounts.
The trouble is that most banks and credit card processors won't do business with scammers.
Again your solution is to go to a few banks in some lawless countries to handle your payment.
To be successful in scamming, you almost have to learn it like a legitimate business.
For example, you should ship products to customers, why?
Because if the customers are not happy, they will complain and the processors and banks will shut down your accounts.
### Example  Pharmacy Express
Now let's study an example of scam.
First, the Botnet sends scam messages to the victim users.
The user clicks on the link and the link will eventually lead him to website to purchase fake drugs.
And payment will then be withdrawn from his bank account and he will receive shipment of the fake drug.
Using data collected from spam feeds,
Botnet infiltration and various types of honeypot data.
The researchers were able to find some interesting data regarding this Pharmacy Express scam.
In particular, they find that these two accounts for around 35% of all affiliate scams.
And we will look more into these scammers in more details shortly.
### Pharmaleaks
In 2012, some of these scammers got breached and their data were dumped and made publicly available.
The data contained complete logs of sales, customers, and affiliate relationships.
So researchers study this data and publish their findings in this paper.
Here's a look at the transaction volumes per week for these scammers.
We can see that these scammers were around for a long time.
We can see here that the repeat customers or the repeat orders are an important part of the business.
This data presents a counter-point to the conventional wisdom that online pharmacies are pure scams.
They don't simply take credit card and either never providing goods, or providing goods of no quality.
Because if that is true, then we would not see repeat customers.
Here's a breakdown of the different types of drugs being purchased by customers.
Here we see that pharma scams bring in a lot of revenue, but there are also a lot of costs.
The actual net revenue, or profit is not huge.
These costs include payment to the affiliates.
Cost of the network infrastructure, and payment to spammers and botnet operators.

---
&nbsp; \pagebreak
## 03 - Penetration-Testing

### Introduction to Penatration Testing
In this lesson, we will discuss the first line of network defense.
The basic tools and techniques of penetration testing and security assessments.
We will also discuss one of the most powerful tools of the network hacker, you.
Yes, you and I.
In fact, everyone has a potential to be a hacker's best friend.
Social engineering is a fast, low risk method to gain access to data.
Pay close attention to the methods used and think about how they can be deployed to make a network more secure.
### Overview
Let's have an overview of what penetration testing is all about.
Penetration testing is used to evaluate the security of a network.
More specifically, penetration testing is used to evaluate all security controls.
These include the security procedures, the operations, and the technologies.
With penetration testing, you can find out how secure your network really is.
In particular, you can discover security vulnerabilities.
And by actually exploiting the vulnerabilities, you can also demonstrate how likely the threats can take place and what are the likely damages associated with these threats.
The scope of penetration testing include not just technical or cyber operations, it can also include social engineering, and also gaining physical access to your organization.
The scale of the testing includes the entire network.
For example, the testing may include your mobile devices, or BYOD.
### Methodology
Now let's discuss the methodology of penetration testing.
Penetration testing includes several steps.
The first step is footprinting.
This is about finding the general information of your network.
Next step is scanning.
This is about finding more detailed information about your network, such as the services available on your network.
The third step is enumeration.
It finds more target information such as user account.
The fourth step is gaining access.
It finds vulnerabilities associated with the network services, and then exploit these vulnerabilities to gain access to the network.
The fifth step is escalating privilege.
The goal here is to gain route of super user access.
The sixth step is pilfering.
The goal here is to try to steal information from the network.
This is one of the standard activities that an attacker would do to a network.
The seventh step is covering the tracks.
The goal here is to hide an evidence of a break in so that security amends cannot easily find out that the network has been breached.
The last step here is creating back doors.
The goal is to create easy access for future malicious activities on the network.
The last few steps can be iterated for example to move from one part of the network to another part.
### Footprinting
Now, let's discuss these steps in more details.
The first step is footprinting.
In this step, the attacker, or tester, conducts reconnaissance and information gathering.
The important network information includes network IP addresses, the namespace, and topology.
Even a phone number range can be used for modem access or social engineering.
Such information is critical for planning the next steps of testing or attacks.
Example, you will need the IP addresses to decide how to scan the network.
Here we'll list the different techniques and the corresponding tools for footprinting.
For example, you can use Google to find out the company information, and use Whois to find out the domain name information of the name servers and
IP ranges.
### Scanning
Once you have the general information such as the IP ranges of a network, now you gain more detailed information of the network using scanning.
You can find out which machine is up, and which ports are open.
Similarly on the servers what services are running.
You can even find out the versions and configurations of these services.
Then you can look up the corresponding vulnerability information on the web.
For example for a particular version of the Apache web server, you can look it up on the web to see one of the known vulnerabilities, such as what input can cause a buffer overflow.
Most promising avenues are typically associated with services that are always up, such as the web services, so you want to focus on analyzing these services.
On the other hand, you want to avoid detection so you want to reduce the frequency and volume of your scanning and analysis.
Here are the different techniques and tools for scanning.
As you can see, Nmap is one of the most popular tools It can find out which
IP's up, which port is open and even perform OS finger prints.
### Enumeration
You can also perform more targeted attack or testing by figuring out which user accounts are poorly protected.
And obviously, this is more targeted and intrusive than scanning.
And here are the techniques and tools for enumeration.
For example, you can use these tools to list user accounts and use these other tools to find out file sharing information.
### Gaining Access
Once you have obtained the relevant information of network services and user accounts, now you can exploit and gain access to the network.
Typically, there are all the existing tools and scripts associated with known vulnerabilities.
But of course, you can customize them to suit your needs.
On the other hand, if the vulnerability is new or there does not exist a tool or script, then you have to develop the exploit yourself.
In general, this is a manual process and can be quite difficult.
Here are some examples of techniques and tools for gaining access.
For example, you can use tools to capture and crack password.
And there are tools that will exploit vulnerabilities in widely used services.
### Escalating Privilege
The next step is escalating privilege.
And the goal is to gain super user access so that you can gain complete control of the system.
Here's some examples and tools.
Again, you can capture and crack the super user passwords.
There are tools that will exploit vulnerabilities of privileged services in order to help you gain good access.
### Pilfering
After you've gained access to the system.
Now you can steal valuable information.
Such information can allow you further access to the system.
For example, you can discover the trust relationship among the machines on a network, and you can obtain user credentials such as passwords.
### Covering Tracks
It is important to cover the tracks, so that the attack cannot be detected and stopped easily.
For example, you can use these tools to edit or even clear the system logs, and you can use rootkit to hide your malware.
### Creating Back Doors
The first time gaining access to a network through an exploit is always hard.
And you want subsequent access to be easy and look normal, so you will create trap doors or back doors.
There are many techniques and tools.
For example, you can create fake user accounts, or you can plant remote access services.
You can also schedule your activities at certain time.
### Penetration Testing Quiz
Now let's do a quiz on penetration testing.
Which events should trigger a penetration testing?
### Penetration Testing Quiz Solution
All of these events should trigger a penetration testing.
I should also add that penetration testing should also be done on a regular basis as well as on these triggering events.
### Persistence and Stealth
To simulate the modern attacks, such as the so called advanced persistent threats.
Penetration testing can try to be persistent and stealth.
For example, the tester can install a backdoor through a malware so that there's a permanent foothold in the network.
The malware can be placed in a strategic place such as a proxy.
And the result can be that now the malware can listen and record all traffic within the network.
And by analyzing internal traffic, the malware can capture user credentials and find out valuable information.
These steps can be iterated and moved from one port of the network to the next while hiding the tracks.
### Social Engineering
As we discussed earlier, penetration testing can include social engineering.
So now let's discuss social engineering.
We all know that users are the weakest link in security, so the goal here is to use social engineering techniques to evaluate how vulnerable your user population really is.
In particular, you will want to find out which user groups are particularly vulnerable.
You will likely discover policy gaps, so you will want to fix these policies and develop new mechanisms including educating and training the users.
Social engineering is effective when the users are manipulated into undermining the security of their own systems.
This can be accomplished by abusing the trust relationships among the users.
Social engineering can be very easy and cheap for the attacker because the attacker does not need any specialized tools or technical skills.
### RSA Breach Quiz
Now let's do a quiz.
In 2011, the security company,
RSA, was compromised.
And it began with social engineering.
Once gaining access, the attackers then installed backdoor using Adobe Flash vulnerability.
In this quiz, list the steps the attackers used to access RSAs Adobe Flash software.
### RSA Breach Quiz Solution
The first step is to identify employees that are vulnerable.
The second step was crafting an email with an enticing subject line.
In particular, the subject line was a provocative 2011 recruitment plan.
And one employee was intrigued enough to open it.
The first step is to hide an executable file in the e-mail, so that it will install on the victim's computer when the e-mail is opened.
In this case, the attachment is an Excel spreadsheet, that contains a zero day exploit that leads to a back door through Adobe Flash.
This one e-mail resulted in a loss of $66 million for RSA.
### Common Social Engineering Techniques
Now let's discuss the common social engineering techniques.
The first category is impersonation.
For example, you can impersonate help desks, third-party authorization, technical support.
Or you can roam the halls or tailgate or you can impersonate a trusted authority.
And you can even send snail mail.
The other category of social engineering techniques involve the use of computers.
This include pop-up windows, instant messages and IRC, email attachments, email scams, chain letters, efficient websites.
### Impersonation
Let's discuss the impersonation techniques first.
For example, an attacker can pretend to be an employee and call the help desk, and claim that he has forgotten his password.
A common weakness is that, the help desk does not require adequate authentication.
For example, the help desk may just ask for the mother's maiden name.
And the attacker may only know this, because he has read the Facebook information of the employee.
Another impersonation technique is to fake a third party authorization.
For example, the attacker can claim that a third party has authorized him to access the network.
And if the attacker can provide the fishing information to convince people that he really knows the third party.
Then, he will have easy time gaining the trust and the access to the network.
In particular, if the third party is not present.
Another very effective impersonation technique is to pretend to be a tech support person.
For example, the attacker can claim that the company needs to reconfigure its systems, and ask for user credentials.
If the users have not been properly trained to guard their credentials, then this attack can easily succeed.
Another old fashioned way of impersonation is to just walk around and see what information is valuable.
For example, passwords or sticky notes, or other kind of important documents, or even overhearing important conversations.
An attacker can dress up like a repairman, because a repairman is typically allowed access to the facility.
The attacker can then plant listening devices to capture useful information.
This exploit works because users typically do not question people in uniform.
Similarly, an attacker can pretend to be someone in charge of a department or company.
For example, the attacker can pretend to be a medial personnel, a home inspector, or school superintendent.
In each of these examples, the attacker can actually gain useful information from a user.
The attacker can gain information such as address, mother's maiden name, and so on of an employee.
And this information can then be used to impersonate employee through the call to a help desk.
Again, this exploit works because users tend to trust authority.
Impersonation can also take place in snail mail.
For example, an attacker can send mail to a user pretending to be an authority and ask for personal information.
This exploit works because users tend to trust the printed materials more than webpages and emails.
These are examples that I'm sure you're familiar with.
### Impersonation Quiz
Now let's do a quiz on impersonation.
Match each tool with its description.
### Computer Attacks
Now let's discuss social engineering attacks that involves computers.
The first kind is popup windows.
For example, a popup window can pretend to be a login window.
This exploit will work if the users have not been properly trained to tell the difference between the fake and the legitimate login windows.
The attacker can also use IM or
IRC to fake a technical support desk.
And the users would be redirected to a malicious site and malware can then be downloaded.
An attacker can also check the user to open an email and download email attachment which includes malicious software.
There are many ways to hide malicious programs in email attachments that may appear to be legitimate.
For example, PDF files can include executable macros and a .exe file can be camouflaged into a .doc file.
And of course, we are familiar with various kinds of email scams. the attackers can amplify the effects of email scams using chain emails.
For example, an email can be sent to everybody on your address book.
An attacker can create a website that claims to offer prizes but require the user to create login and passwords.
The goal of the attacker is to harvest user credentials since many users uses same username and password on many websites.
The attacker can then use the credentials obtained from his website on other websites.
### Computer Attacks Quiz
Now let's do a quiz.
On this pie chart, what are the top three industries that were targets of cyber attacks in 2016?
### Computer Attacks Quiz Solution
Defense contractors, restaurants, and software companies.
The other 56% consists of industries.
They are targeted about 5.6% each.
### Counter Social Engineering Attacks
Here's how we should educate users to counter social engineering attacks.
Never disclose passwords to anybody.
Only the IT staff should discussed details of the network and system configurations and IT staff should not answers survey calls.
This also check with the call from the vendor is legitimate.
Also, we should limit information in all auto-reply emails.
Keep information in all auto-reply emails to a bare minimum.
We should always escort our guests.
This protects against attacks such as attackers dressing up like repairmen or trusted authority figure.
We should always question people that we don't know.
We should educate all employees about security, both physical and IT security.
We should have a central reporting and management of all suspicious behavior.
### Motivator Quiz
Let's do a quiz on human behaviors.
Match the motivation with its description.
### Motivator Quiz Solution
Liking is a desire to fit in.
Scarcity is a desire to pursue a limited or exclusive item or service.
Commitment is a desire to act in a consistent manner.
Social proof is looking to others for clues on how to behave.

---
&nbsp; \pagebreak
## 04b - DNS-Security

### Introduction to Domain Name Servers
In this lesson, we will discuss domain name systems or DNS.
We will explore there weaknesses and the security measures that have been implemented to protect the internet.
### DNS
DNS or the domain name system is a hierarchical database.
There are root servers, top level domains, second level domains, third level domains, and so on.
Just for your information there are 13 DNS root name servers.
### DNS Lookup Example
A DNS Lookup is an iterative or recursive process carrying the hierarchy code database.
For example, suppose your browser is looking up www.cc.gatech.edu.
The local DNS service is handling this request of looking up the IP address of this domain name.
The query will start on the root or top level domain servers.
That is, the local DNS server asks the root and top level domain servers what is the IP address of www.cc.gatech.edu.
And these servers say, I don't know, but
I know the main server of gatech.edu.
So the local DNS server then asks gatech.edu DNS server what is the IP address of www.cc.gatech.edu.
And the gatech.edu DNS server says,
I don't know but
I know the name server cc.gatech.edu.
So finally, the name server cc.gatech.edu says,
I know the IP address of www.cc.gatech.edu and here it is.
So that's an example of looking up a domain name in most iterative or recursive queries to DNS servers.
There are several types of DNS records in the response to DNS query.
One is the NS record.
This points to a name server.
That is, this record contains the IP address of a name server such as gatech.edu.
And then there's A record.
This contains the address of the domain name in the original query.
For example, www.cc.gatech.edu.
And then there's MX record.
This contains the address of the mail server for the domain.
For example, mail.gatech.edu.
And finally, there's a TXT record.
It contains all the useful information about a domain.
For example, it can be used to distribute public keys.
### DNS Caching Quiz
Now let's do a quiz.
### DNS Caching Quiz Solution
As illustrated in the previous example, querying the IP address of a domain name can involve a number of steps.
To save time, the records are cached on a local server for reuse later.
For example, when the IP address of www.cc.gatech.edu has been obtained, the mapping of this IP address and the domain is cached so that the next time the browser is looking up www.cc.gatech.edu, the DNS server does not have to go out to look it up again because the mapping is already stored in the cache.
Obviously, this saves time.
On the other hand, each record, meaning the mapping of IP address and domain that's being stored in the DNS cache, has a TTL, or time-to-live.
And, when this TTL expires, the cache entry is invalid.
Which means, if the browser looks up www.cc.gatech.edu, after the TTL of the cache entry has expired, the DNS server, then has to go out and look it up again.
TTL is useful because a server, say www.cc.gatech.edu maybe moved to a new IP address.
So, you want the TTL to expire, so that the DNS servers can look up for the new mapping.
### Caching
As we have discussed, the DNS responses and in particular, the mapping between the IP address and a domain are cached so that we can save time on repeated queries.
The NS records of the domains are also cached.
Therefore, if the browser looks up www.ece.gatech.edu, the local DNS server only needs to start with gatech.edu instead of the root.
DNS servers can also cache the negative results such as a domain does not exist.
For example, if somebody misspelled gatech.edu to say gatech.ed, the DNS query response will be this domain does not exist.
And this result is cached.
So that, next time if somebody mistype again the same way, gatech.ed, the DNS cache can always say, hey this domain does not exist, without having to query it.
And all cache data, whether it's positive or negative response has a TTL.
### Basic DNS Vulnerabilities
Now let's discuss the main vulnerabilities of DNS.
First of all, we must be able to trust the domain name and address mapping provided by DNS.
In fact, many security policies depend on this.
For example, the same origin policy in browsers, or URL-based filtering.
Obviously if the host address mapping provided by DNS can be forged, then the traffic intended for the original legitimate host is now destined to the wrong or malicious host.
This means that the wrong or forged host can now intercept the legitimate traffic.
What if the host address mapping provided by DNS can be forged?
For example, instead of getting the IP address of gmail.com, the browser instead gets the IP address of evil.com.
The result is that, traffic will be routed to evil.com instead.
Which means evil.com can intercept traffic to gmail.com.
There are several ways to forge the host as just mapping.
For example, the attackers can compromise the DNS servers, including cache poisoning, which we're going to discuss shortly.
Or the attackers can control the access point or gateway and intercept DNS queries and forge a response.
A solution is to authenticate each request and response using cryptography.
And DNSsec is such a solution.
Now let's discuss attacks on the inner server, in particular cache poisoning.
The basic idea is that the attacker would provide to the local DNA server some false records and get the records cached.
For example, if the local DNS server queries the domain gmail.com and the attacker is able to inject a response with the IP address of evil.com and have that IP address of evil.com cached by the local DNS server and then subsequent traffic to gmail.com will be routed to evil.com.
The existing defense in DNS is the users 16-bit request ID to link a respond with a query.
That is, the attackers response must have the ID that matches the ID of the original query and we will discuss how an attacker can overcome this defense.
A DNS cache can be easily poisoned if the DNS server does not use the IDs properly, or the IDS are predictable
### DNS Quiz
Now let's do a quiz.
Select the true statements about DNS.
### DNS Quiz Solution
The first statement,
DNS stores IP address.
For security reasons, the domain name is stored somewhere else.
This is false.
DNS stores both the IP address and the domain name.
That's the whole point of providing the mapping between domain name and
IP address.
The second statement.
All domain names and IP addresses are stored at the Central Registry.
This is true.
When a new domain name is registered at a local DNS, it will also be copied to the Central Registry.
The third statement, it can take several days for information to propagate to all DNS servers.
This is true.
It takes anywhere from 12 to 36 hours to propagate information to all DNS servers worldwide.
### DNS Packet
Now let's take a closer look at the internals of DNS query and response.
Let's start with the format of a DNS packet.
There is the usual IP header.
There's a UDP header because DNS uses UDP, and the UDP payload is the actual DNS data.
One of the most important fields in DNS data is the query ID, which is a 16 bit random value.
A DNS query contains a query ID.
And a response also carries the ID.
Therefore, even though a DNS server may send out many, many queries at the same time, it can use the ID to link a response to a query.
That is, the response to a query will have the same ID of the query ID of the original query.
Now, let's look through an example.
Suppose a local DNS server is looking up for the domain www.unixvis.net on behalf of a browser.
So, this is the local DNS server.
It's going to send the query to one of the root service.
It sent a flag to say recursion desired.
That means it's asking the destination
DNS server to perform recursive queries on its behalf.
Here is the response from the root server.
The root server does not know the IP address of www.unixwiz.net.
So it provides the IP addresses of the next NS service.
And these are called glue records.
Let's look at this in more detail.
The response comes from the root server, back to the local DNS server.
It says that it's a response, the root server does not know the IP address of www.unixwiz.net, but it knows where to ask.
It responds with a series of
NS records that should know how to handle the original query.
Notice that both the domain names and
IP addresses of these named servers are provided.
Because this response is not the final answer to the original query, it sets this flag to zero to indicate that this is not authoritative.
And also because the root server is busy, it's not going to perform because of queries on behalf of the local DNS server.
That's why it sets this flag to indicate that it's not going to perform because of queries.
That is, the local DNS server should contact these named servers instead.
The final, or authoritative, response comes from the named server, linux.unixwiz.net.
And notice that now the authoritative flag is set to 1.
Notice that this final response contains the IP address of the domain www.unixwiz.net, which is the domain name contained in the original query.
And the TTL is one hour, which means this record will be cached and be valid for one hour.
And since these NS records are in the same second level domain, unixwiz.net, of the original queried domain, they are also cached.
### Poisoning Attacks
Now let's discuss DNC cache poisoning attacks in more detail.
Let's start with traditional poisoning attack.
Suppose the attacker wants to poison the cache of the DNS server at gartech.edu.
In particular, the attacker wants to forge the IP address of www.google.com.
The attacker first sends a query to the local DNS server.
This can be done, for example, through a compromised machine within gartech,edu.
The local DNS server is now going to perform a recursive query with the query ID 12345.
And at some point the main server, ns1.google.com, is going to provide an authoritative answer given the IP address of www.google.com with a matching query ID.
Now the attacker knows that this recursive query is taking place.
Because he has an inside hub that initiated the original lookup.
So the attacker is going to forge a response claiming it is from ns1.google.com.
And in that response it's going to use the IP address of evil.com instead of the real
IP address of www.google.com.
But the attacker does not know the real query ID, so all he can do is send a flood of responses, each with a guest query ID.
So this is a matter of the attacker being able to guess the correct query ID and reach the local
DNS server faster than the legitimate response from the real DNS server of Google.
If the attack succeeds, then the incorrect answer will be cached resulting in cache poisoning.
But if the attacker's attempt fails, the legitimate IP will be cached and the attacker has to wait for
TTL to expire before launching the whole attack again.
As you can see, the traditional poisoning attack is hard to successfully implement.
But then Kaminsky found an approach that's drastically more effective than the traditional attack.
The general approach is the same as the traditional attack.
But the key difference is the nature of the forged payload.
The intention of cache poisoning is to poison the final answer that is the A record with the IP address.
But what then Kaminsky discovered is that we can go up one level and hijack the authority records instead.
As in the previous example, let's assume that the attacker wants to poison the cache of the DNS server caltech.edu.
And he wants to forge the IP address of www.google.com.
But this time the inside help is going to send a query of a random domain within www.google.com.
For example, 12345678.www.google.com.
And as before the DNS Server is going to perform a recursive query.
Now the legitimate response, you say that this random domain does not exist.
But you will provide the IP address of www.google.com.
The attacker is attempting to do the same thing.
The goal is to have the DNS server cache this raw IP address.
And you may ask, what's new here?
Isn't the attacker facing the same challenge of guessing correctly the query ID before the response from
Google In the traditional attack.
When the first attempt fails, the attacker has a way for TTL to expire.
What's new here in the Kaminsky's Poisoning Attack is that when a first attempt fails, the attacker can start immediately again.
That is, it doesn't have two wait for
TTL to expire and the reason is he can simply use a different random domain and that will immediately result in another query.
So that he can flood the DNS server again.
That is, the attacker can repeatedly and continuously force the local DNS server to query a random domain.
And keep flooding the local DNS server until the poisoning attack succeeds.
Yet when you put it that, such Kaminsky's Poisoning Attack can succeed in mere ten seconds.
### DNS Defenses
So what are the defenses against cache poisoning attack?
The first few here simply make the attackers do a lot more work in order to succeed.
For example we can increase the query ID size, we can randomize the source port or we can query twice.
More fundamentally, we can use cryptography to provide authenticity of DNS records, and that's the idea behind DNSSEC.
### DNS SEC
So let's discuss the DNSSEC.
The goals of DNSSEC is to provide guarantees of the authenticity of the DNS servers as well as the integrity of their responses.
These guarantees are accomplished by having the DNS servers sign responses every step of the way.
It is also assumed that the DNS servers themselves can be secured.
### DNS Signing
Here's an example of the DNS signing process.
Suppose a local DNS server looks up wikipedia.org.
They first query the root server.
The root server provides the IP address of .org and signs it.
The signature is based on private key of the root server.
The DNS server performs recursive query, in this case sending the request to .org.
And the response contains the IP address of wikipedia.org signed with the public key of .org.
The local DNS server can modify all these signatures and be confident that the IP address that it receives is correct.
### DNS Rebinding Attack
Even DNS-SEC cannot prevent all DNS attacks.
The DNS Rebinding Attack is one such example.
To among a DNS rebinding attack, the attacker needs only register a domain name, such as evil.com.
And attract web traffic, for example, by running an advertisement in a frame.
In this attack, when evil.com is looked up, the attacker answers with the IP address of his own server and use a very short TTL value.
The attacker's server, evil.com, also serves the browser a malicious JavaScript.
To circumvent the firewall, when the malicious JavaScript issues a query to evil.com, the TTL has expired.
The attacker then rebinds the host name, evil.com, to an IP address of an internal server.
That is, now the firewall thinks that evil.com is internal.
The browser now believes that these two servers belong to the same origin, because they share the same host name, www.evil.com.
So it will allows script to read back the response.
Therefore, the malicious script can easily extra trade information from the server to evil.com.
That is now the attacker is able to read arbitrary documents from the internal server.
To mitigate such attack, the browser should use DNS Pinning.
Meaning that, you should refuse the switching to new IP address for domain.
On the other hand, this means that it may break proxies,
VPNs, dynamic DNS and so on.
Therefore, it is not consistently implemented in all browsers.
For the internal servers, they should check Host headers for unrecognized domains such as evil.com.
It should also provide stronger authentication of users.
For the firewall is to implement a policy such that external domain names cannot resolve to internal IP address.
It should provide stronger protection of browsers within the network.
### DNS Rebinding Quiz
Now, let's do a quiz.
Select all true statements about rebinding attacks.
### DNS Rebinding Quiz Solution
The first statement, the attacker needs to register a domain and delegate it to a server under his control, this is true.
The second statement, the attacker's server responds with a short TTL record, this is true.
The third statement, a short TTL means that the page will be quickly cached, this is false.
The fourth statement, the attacker exploits the same origin policy, this is true.

---
&nbsp; \pagebreak
## 05b - Advanced Web Security-Session-Management

### Session Management
Now, let's discuss session management on the web.
What is a session?
A session is a sequence of requests and responses from a browser to a server.
A server can be long.
Without session management, a user can be asked to reauthenticate himself again and again.
So, the goal of session management is to authenticate user only once.
So that all subsequent requests are tied to the authenticated user.
So, the general idea behind session management is to use session tokens.
So, for example, there's the initial handshake that's in the browser and the web server.
And then, as the user wants to access some more secure content, he may be asked to authenticate himself.
And once the user has been authenticated, the server can elevate the token from anonymous browsing token to a authenticated token.
And when the user logs out or checks out, this login session token should be cleared.
There are many ways to restore the session tokens.
Obviously, we can use browser cookie.
For example, we can create a session token cookie or session cookie.
The problem with browser cookie is that a browser can send a cookie with every request, even when it's not, and this gives rise to the cross-site request forgery attack.
A session token can be embedded in a URL, which means that every request will have the session token.
This means that if the application is not returned securely, there can be token leaks via http referer header, or if the user posts URL in a public forum.
Another option is to store that session token in a hidden field in a forum.
The downside to this method is that every user action must result in a submission of a form, or you lose the session token.
So, none of these methods are perfect.
The best solution is, depending on the application, is you choose a combination of these three options.
Now, let's discuss the HTTP referer header.
When a browser sends a URL request to a server, if the request contains a HTTP referer header, it tells the server the page that you are coming from, meaning your referer.
Here's an example.
It shows that the user were here.
Again, by checking the referer, the web server can see where the request originated.
In the most common situation, this means that when the user clicks a hyperlink in the web browser, the browser sends the request to the server.
The request includes the referer field, which indicates the last page the user was on that is.
The one where they click the link.
The problem with referer is that it can leak the session token to the previous server.
The solution is that he can suppress the referer, means that don't send referer when you refer to a site.
### Session Logout
For example, after the user logs out, he should be allowed to log in with a different account.
And a website should prevent a user from accessing content left behind by a previous user.
So what should happen during a log out?
First, the session token on a browser should be deleted.
Second, on a server side, the session token should be marked as expired.
The problem is that many web sites do 1, but not 2, this is especially dangerous for sites that use HTTPS for login, but then fall back to the clear text HTTP after login.
This is because an active network attacker can intercept the clear text HTTP traffic and steal a copy of the session token.
Then even after the user logs out, because the server does not expire the session token, the attacker can continue to use that session token.
### Session Token Quiz
Now let's do a quiz on session token.
Check all the statements that are true.
First, the token must be stored somewhere.
Second, tokens expire, but there should be mechanisms to revoke them if necessary.
Third, token size, like cookie size, is not a concern.
### Session Token Quiz Solution
The first two statements are obviously true.
The third statement is false, because depending on how much information you store in it, tokens can become quite large.
Cookies, on the other hand, are quite small.
### Session Hijacking
A major threat in web session management, is session hijacking.
Here, the attacker waits for user to log in, and then the attacker can steal the user session token and hijacks the session.
And session hijacking is not limited to active network attacker that intercept traffic.
For example, if counter is used a session token, then when a user logs in a website it can get a counter value, then he can view sessions of other users because he would know other counter values.
Similarly, even if the token is protected using cryptography, if the cryptographic algorithm or the key is weak then a user can still break the protection, get the counter value, and then view sessions of other users.
So the point here is that we should use tokens that are not predictable, and there are APIs that allow us to generate random session IDs.
Again, to make session tokens unpredictable to attacker, we can use the underlying framework.
For example, rails.
For example, by combining the current time stamp and random nouns and compute this values over MD5, that should give you a very unpredictable token.
Even when a session token is random, there's still a security threat of session token theft.
For example, if a web site uses HTTPS for log in, but subsequently use
HTTP for the rest of the session, then an active network attacker, for example, can sit at a wireless cafe and use a tool, for example, Firesheep to intercept the clear text HTTP traffic and steal the session token.
Another way for the attacker to steal the session token is to play man in the middle at the beginning of the SSL connection.
Another approach to steel session token is to use Cross Site Scripting attacks, and if the server does not invalidate a session token after the user has logged out, then the stolen token can still be used by the attacker even after the user has logged out.
One idea to mitigate session hijacking is to bind a session token to the user's computer.
For example, we can embed some machine specific data in the session ID.
So what machine specific data of a user can be used?
We begin by binding the session token to the user's computer.
Now we must decide specifically what information we should use as the session token.
We want it to be unguessable and unique to the machine, but still quick to generate.
So is using the IP address a good idea?
Probably not and the reason is that the user's computer changes its IP address.
For example, due to DHCP, then the user will be locked out of his own session.
What if we used the browser user information instead of the IP address as a session token?
The problem with this approach is that such information is easily stolen or guessable by the attacker.
So the conclusion is that, while it is appealing to use kind site information a session token, there's not a good solution when we consider both security and convenience.
Therefore, the best approach is still an unpredictable session token generated by the sever.
### Session Fixation
In addition to stealing tokens, an attacker can also fake session tokens.
For example, the attacker can trick the user into clicking a URL that sets a session token, or it can use cross-scripting attacks to set token values.
Here's an example of how an attacker can use session fixation attack to elevate his anonymous token to a user logged-in token.
First the attacker gets anonymous browsing session token from site.com.
He then sends a URL to the user with the attacker's session token.
The user clicks on the URL and logs in www.site.com.
Now the attacker can use the elevated token to hijack user's session.
To mitigate such attacks when elevating a user from anonymous to logged in, a website should always issue a new session token.
So with this, after the user logs in, the token will change to a different value unknown to the attacker.
That is, the anonymous token that the attacker had originally obtained is not elevated.
### Session Hijacking Quiz
Now let's do a quiz on session hijacking.
Check all the statements that are true.
First, active session hijacking involves disconnecting the user from the server once that user is logged on.
Social engineering is required to perform this type of hijacking.
Second, in passive session hijacking, the attacker silently captures the credentials of a user.
Social engineering is required to perform this type of hijacking.
### Session Hijacking Quiz Solution
The first statement is true.
The second is false.
Of these two methods, passive hijacking is less likely to raise suspicions.
### Session Management Summary
To summarize what we've learned about the security of session management, we should always assume cookie data retrieved from client is adversarial, or not trusted.
There are multiple ways to store session tokens.
Cookies, by themselves, are not secure.
For example, they can be overwritten.
Session tokens should be unpredictable.
And finally, when a user logs out, the server should invalidate the session token.

---
&nbsp; \pagebreak
## 05c - Adanced Web Security - HTTPS

### Goals
Let's discuss HTTPS and how it is integrated into the web browser.
And we are going to discuss a number of security problems with HTTPS.
### HTTPS
HTTPS is essentially HTTP over SSL, the secure socket layer, which is now called TLS, transport layer security.
With HTTPS, all traffic between a web browser and a web site is encrypted, whereas HTTP is a clear text protocol, meaning that the traffic is not encrypted.
For example, using HTTP, a user sends a password and a web server receives it.
Since the traffic data is in clear text, a network attacker with access to the link can intercept the traffic data and learn the user's password.
Now with HTTPS, the user still sends the password, but the password is encrypted in transmission.
Therefore, even when attacker can access a link, he cannot learn your clear text password.
In summary, HTTPS allows for secure communication over untrusted or public network.
It encrypts traffic and uses public key to authenticate the web server and. if possible. even the browser.
Even if only the web service public key is known, many in the man-in-the-middle-attack can still be prevented.
With all these benefits,
HTTPS is not used for all web traffic.
The reason is that crypto operations can slow down the web service, in particular, if it is not implemented right.
And some ad networks, do not support HTTPS.
For example, the ad publishers cannot learn the web contents as being viewed by the users.
On the other hand,
Google is now trying to encourage websites from adopting HTTPS.
### HTTPS Quiz
Now let's do a quiz on HTTPS.
Select all items that can be encrypted by HTTPS.
### HTTPS Quiz Solution
The first four can be encrypted by HTTPS.
Host address and port numbers are used to route traffic and so they're not encrypted.
The amount of transferred data and length of session can be inferred by observing the traffic.
So the attacker can learn this.
### Network Attacker
Recall that a network attacker can control network infrastructures such as routers and DNS servers.
It can eavesdrop to learn traffic contents, inject data, block traffic, or even modify the contents.
For example, such a network attacker can sit at an internet cafe or hotel lobby to compromise the network.
HTTPS was designed to thwart such network attackers.
### SSL TLS Overview
Since HTTPS is HTTP over SSL, let's briefly review SSL/TLS.
It uses public key for authentication and key exchange.
As a quick review, in public key cryptography, each user, say Bob, has a pair of public key and private key.
And Alice, after obtaining Bob's public key, can use Bob's public key to encrypt message into cypher text, and a cypher text can only be encrypted by Bob, using the corresponding private key.
### Certificates
An essential problem in public key cryptography is how Alice can obtain the public key of Bob.
The standard is to use certificate issued by a certificate authority, we call it the CA.
First, every entity has installed the public key of CA.
Then Bob can ask the CA to generate a certificate for his public key.
The certificate authority keeps the signing private key to itself.
And again, the corresponding public key has been installed in all entities.
The CA signs Bob's public key using it's signing private key and the signature is put into the certificate.
So Bob can now present the certificate to Alice.
And because Alice has the certificate authority's public key, she can verify that the signature was constructed properly.
Which means that Bob's public key has been certified by the certificate authority.
Here's an example of public key certificate.
Let's go over some important information.
First, there's a unique serial number.
Second, there's a valid time period.
And there's a public key and a signature produced by the CA.
Here's an example of certificate information that a user sees on his computer.
It identifies that the certificate is for the public key of mail.google.com.
A certificate is for an entity or subject that is identified by the common name.
So what is a common name?
A common name can be an explicit name, for example cc.gatech.edu.
Or it can be a wildcard, for example, *.gatech.edu.
If a wildcard is used it can only be the leftmost component, and it does not match dot.
For example: *.a.com matches x.a.com but not y.x.a.com.
There are large numbers of CAs out there, and a browser typically accepts certificates from 60 top level CAs and
1200 intermediate CAs.
### SSL and TLS
Let's briefly review SSL/TLS.
The goal of this handshake is to authenticate the server and optimally the browser and more importantly, at the end, both will have a shared secret key that can be used to encrypt HTTP traffic.
The client sends a hello message to a server and the severs response includes a proper key certificate.
The browser verifies the certificate, meaning that now the browser knows the server's valid public key.
And with that, the browser can now perform key exchange.
For example, it can use Elliptic curve Diffie-Hellman key exchange.
With a server's public key, the browser and the server can perform secure key exchange and prevent man-in-the-middle attack.
And the result is that they now establish a shared secret key and they can use this shared secret key to encrypt HTTP data.
### HTTPS in the Browser
HTTPS is integrated into a browser, or it is indicated in the browser GUI.
The goal is to let the user know where a page came from.
And it tells the users that the page contents are protected, meaning that they're encrypted so that a network attacker cannot see them or modify them.
In reality, there are several security problems.
When the lock icon is displayed on the browser, it means that all the elements on the page are fetched using HTTPS.
But for the browser to even accept this HTTPS connection, it means that the browser has trusted the certificate and verified that the certificate is valid.
And also, the domain URL matches the CommonName or
SubjectAlternativeName in the certificate.
For example, the certificate of google.com can simply supply a list of alternative names.
### HTTPS Disadvantages Quiz
Now lets take another quiz on HTTPS.
Which of the following are real disadvantages of using HTTPS?
### HTTPS Disadvantages Quiz Solution
You need to buy an SSL certificate.
Mixed modes issues, loading insecure content on a secure site.
This will continue to be the problem until many, many sites are all using HTTPS.
Proxy caching problems, public caching cannot occur.
This is because all traffic is encrypted, so there's no public caching possible.
### HTTPS Problems
Let's discuss several security problems with HTTPS and the lock icon.
This include upgrade from HTTP to HTTPS.
Forged certificates.
First, let's discuss upgrade from HTTP to HTTPS.
There's an attack method called SSL stripped.
It prevents the browser from upgrading.
With SSL stripping, the browser won't display any SSL certificate errors, and the user has no clue that such an attack is happening.
This attack is also known as HTTP downgrading attack.
The connection established between the victim user's browser and the web server is downgraded from HTTPS to HTTP.
For example, when a user wants to transfer money to his account using an online banking service, he enters the following URL in the address bar of his browser, www.foobank.com/onlinebanking.
Of course, this URL is intended for the web server of the bank.
In the background, the user's computer happen to be connected to the attacker's machine.
The attacker waits for a response from the bank server.
The attacker forwards the request to the bank and waits for the response.
The connection between the attacker and the bank is secure.
That means the traffic is transferred using an SSL tunnel.
Therefore, the login page from the bank's web server will be https://www.foobank.com/onlinebanking.
The attacker has access to the login page and can modify the response from the server from HTTPS to HTTP and then forward the login page in HTTP to the client.
The user's browser now is connected to http://www.foobank.com/onlinebanking.
The user's browser is now connected to the bank's website with an insecure connection.
>From this point on, all the user's requests go out in plaintext, and the attacker can access the data and collect the credentials.
While the server thinks that it's been using a secure connection, that connection is really just between the web server of the bank and the attacker.
On the other hand, the user's browser is using the insecure HTTP connection, thinking that that's what the bank's web server wants it to use.
The solution to SSL strip attack is to use HSTS, which stands for
Strict Transport Security.
This policy can be set for a maximum of one year.
It basically tells the web browser to always use HTTPS, even for its subdomains.
When a web browser visits a website for the first time, the website can tell the browser to always use HTTPS.
That is, for any subsequent visit, all connection must be over HTTPS, and HTTP connections will be rejected.
A web browser can also have a preloaded list of HSTS websites.
Even before web browser visits a site on this list, it knows that it must use HTTPS.
The HSTS flag set by a website can be cleared when the user selects clear private data.
Another serious security problem is forged certificates.
For example, if a CA is hacked, the attacker can issue rogue certificates.
For example, for Gmail.
And once a rogue certificate is issued, now the attacker can set up a fake website and calling itself Gmail.
In this website, we have the rogue certificate for Gmail.
And several countries have been caught issuing unauthorized certificates, for example, for Google so the ISPs in these countries can play man in the middle between a user and the real Google server.
This is further illustrated in this example.
Suppose a user wants to connect to a bank.
There's a bad guy in the middle, and this attacker has a rogue certificate, therefore it can pretend to be the bank.
The user may think that he is connected to the bank because the certificate says so, but however, the certificate is rogue, meaning that the user is actually connected to the bad guy.
This illustrates that with a rogue certificate, an attacker can play man in the middle, even in HTTPS connection.
The attacker plays the bank server to the user and the user to the bank server.
And both sides of connections are in HTTPS.
### HTTPS Attack Prevention
One approach to deal with rogue certificate is to use dynamic public-key pinning.
This means that a website will declare the CAs that sign its certificate.
When a browser first visits a website, the website tells the browser the list of authorized CAs.
Then on subsequent visits, the browser will reject any certificate issued by other CAs.
Very similarly there's a public-key pinning extension for HTTP or HPKP.
This feature tells a web browser the list of proper keys to be associated with the website.
And it can prevent man-in-the-middle attacks with forged certificates.
When the browser visits a website for the first time, the browser sends a list of public-key hashes.
And on subsequent visits, the browser expects the server to use one or more of these public keys in its certificates.
Another problem to deal with forged certificate is for the CAs to be transparent.
That is, the CAs must publish in a public log of all the certificates that they have issued and a browser will only accept a certificate if it is published on a public log.
And companies like Google can constantly scan the public logs to look for invalid or forged certificates.

---
&nbsp; \pagebreak
## 06 - Advanced-Malware-Analysis

### Introduction to Advance Malware Analysis
So far, we have discussed how to find the enemy, how to identify the enemy, and even how to catch the enemy.
But now we come to a crucial question, what do we do once they're caught?
It has been said, "Observe your enemies, for the first find faults."
In this lesson, we are going to discuss the analysis of malware.
We're going to find our weaknesses through the efforts of our enemies, and then about the continued battle between malware analysis and malware obfuscation.
### Introduction to Advance Malware Analysis
But now we come to a crucial question, what do we do once they're caught?
It has been said, "Observe your enemies, for the first find faults."
In this lesson, we are going to discuss the analysis of malware.
We're going to find our weaknesses through the efforts of our enemies, and then about the continued battle between malware analysis and malware obfuscation.
### Malware Prevalence
Let's review why malware is such a big security problem.
It is very easy for malware to get on a user's computer.
Say a user browses the web, for example, reading the news at USAToday.com.
And this may result in a compromise to his computer.
The reason is that USAToday.com's ad network can be compromised, so when they use their browsers usatoday.com, his browser will be served with malicious JavaScript.
And of course, this script is bundled with ad and this malicious JavaScript will automatically direct the user's browser to a rogue AV website.
Rogue AV stands for rogue antivirus software.
The end result is that the user's tricked to download a rogue AV, which is actually a malware.
Here's a case study on how many sites may have been compromised and serve malicious contents.
The researchers analyzed the Alexa top ranked domains.
They allowed 252 million domains worldwide in 2016 at this time.
A research system was created to examine
Alexa top 25,000 domains each day.
Essentially the browser within a virtual machine is forced to visit each domain.
A research system was created to examine
Alexa's Top 25,500 domains each day.
Essentially, the browser within the virtual machine is forced to visit domain.
The network traffic that follows a visit to these websites are analyzed to determine whether drive by download had occurred.
The result show that 39 domains resulted in drive by download.
And among these, 87% of these sites involved exploits of JavaScripts.
And 46% of these sites served the exploits through ad networks.
>From Alexa statistics, about 7.5 million users visited these 39 sites.
And about 1.2 million user computers are likely compromised because these computers don't have adequate defenses.
For example, they have out of date antimalware software.
Collectively the attackers always develop new malware and new ways to spread malware widely.
For example, an exploit was developed on mobility in Acrobat Reader's Flash interpreter.
As defenders we may discover that one of our user's computers was compromised by this exploit.
For example, we may be able to observe the phone home traffic from the compromised computer.
That is we may observe the command control traffic.
>From the compromised computer.
And the chances are our user is not alone because we may soon discover that many websites are hosting the same kind of exploits.
This is indeed the real case.
And of course, users remain the weakest link and often they are subject to social engineering attacks.
For example, a very compelling email may make a user click on an active content.
For example a video or flash content.
That result in a compromise such as this real case.
### Malware Evolution
You may wonder, don't we already have defenses against malware?
Yes we do, but malware keeps evolving very fast and some of the traditional mechanisms are not adequate.
We should deploy defense in depth, and for network protection we have firewalls as the prevention mechanism and IDS as the detection mechanism.
But for firewall, command control traffic can look just like normal traffic, such as visiting a webpage.
For IDS that analyzes the payload of traffic, the encrypted or specially encoded malicious contents can evade such analysis.
On the host, if you ask the user's consent, most often since the users often do not understand the security implications, they will simply say yes.
In terms of antivirus software, the traditional signature matching approaches are not effective where malware uses obfuscation techniques.
And so, we have to continue to develop more complex behavior-based analysis approaches.
### Malware Obfuscation Quiz
Now let's do a quiz.
Based on this definition of packing, which is a typical obfuscation technique?
Which of these statements are true?
### Malware Obfuscation Quiz Solution
Since the malware contents are encrypted, and look random, a signature-based approach would not work.
Therefore, the first statement is true.
And, since the malware contents are encrypted, and look different, there's no single signature that matches all the instances.
So, the second statement is false.
Of course, we need to include code that decrypts the malware in runtime so that the malware can execute.
Therefore, the first statement is true.
Know that we can simply use the code that the compressed or the encrypted malware as a signature because legitimate programs can contain such instructions, for example for digital rights management.
### Malware Obfuscation
Now let's take a closer look at one of the most widely used obfuscation techniques, packing.
Given the original malware program, the packing tool would transform it, so that the transformed code looks random.
Because it is encrypted, we randomly generate a key.
And this happens each time the packing program is run on a malware program.
That is even for the same malware program, each packed instance will look different.
And therefore, a signature based approach is not effective in detecting the malware.
Furthermore, the transformed machine code looks like data.
Therefore, a network IDS that looks for executables and email attachment will miss it.
If the anti virus company obtains the zero day malware, even though it is obfuscated.
Eventually, the researchers can de-obfuscate the malware and discover its behaviors.
But such analysis takes time and the attacker can make such analysis fruitless.
Even anti virus company analyzes a zero day malware even though it is obfuscated.
Eventually, the researchers can de-obfuscate the malware and discover its behaviors.
But such analysis takes time.
And the attacker can make such analysis fruitless.
In particular, the attacker's server can continuously send an updated or new malware.
That is obfuscated of course, to the compromised computers.
Then in effect, the defenders or researchers have to deal with zero day on new malware constantly.
That is by the time they have successfully analyzed a malware, it has become obsolete.
A real example of this server polymorphism is Waledac.
This particular version of the malware postcard.exe was released on December 30,
2008 and by February 25, 2009, the majority of the antivirus software can detect it.
But a new version of the malware disc.exe was detected by only a very small percentage of the antivirus software on the date it was released.
Here's an example showing the challenges the anti-virus industry is facing.
The researchers surveyed McAfee anti-virus software using
20,000 malware samples collected over six months.
53% of the malware samples were detected on the day of release.
32% of the malware samples were detected with a delay.
And the delay was on average 54 days.
And 15% of the malware samples were not detected even six months later.
### MALWARE QUIZ
Now let's do a quiz.
Obfuscation techniques are commonly used for one of three purposes, to hide from the users, to hide from security mechanisms, or to hide from researchers.
Given these techniques, which one is hiding from the users or hiding from the security mechanisms or hiding from the researchers?
### MALWARE QUIZ Solution
Rookits is used to hide the malware from the users.
Mapping the security sites and honey pots are used to avoid security mechanisms, such as detection mechanisms.
Use nonce-based encryption schemes would make cryptanalysis more difficult, and this is to hide from the security researchers.
### Malware Analysis
Now let's discuss malware analysis.
What are the benefits of malware analysis?
If we understand malware's network behaviors, we can create rules to detect and block malware traffic.
If we understand malware's on-host behaviors, we can repair the compromised hosts.
If we have knowledge of the malware's support infrastructure on the internet and it's evolution history, we can also analyze it's trend and threat scope.
Such as, how widespread the malware is and the likely next target, etc.
Of course, the attackers try to defeat malware analysis, and are using the most sophisticated techniques available.
Another challenge in malware analysis is the volume of malware is really huge.
Available and automated tools made a job of creating malware obfuscated of course very easy.
And in fact there are hundreds of thousands of new samples every day.
Since the malware creation process is already automated it is imperative that malware analysis has to be automated as well In addition to automation, malware analysis also needs to be transparent so that the malware does not know it is being analyzed.
Otherwise the malware may refuse to run, or purposely alter to its behaviors to fool the analysis.
This is the so-called malware uncertainty principle, but this is very challenging.
In physics, the Heisenberg principle says that an observer will inevitably affect the observed environment.
In malware analysis, our tools may be so invasive that the malware can detect them if we're not careful.
In malware analysis, our tools and techniques are often invasive.
And if we are not careful, the malware can detect a presence of the analyzer and refuse to run.
In fact, malware authors already tried to actively detect malware analysis tools.
In the malware creation tool kits, there are standard point and click options to add logics to detect various malware analysis methods, such as these examples.
So we need malware analysis to be transparent to malware.
That is, malware should not be able to detect that it is being analyzed.
But how do we fulfill such transparency requirements?
A malware analyzer should be at a higher privilege level than a malware, so that the malware can not directly access, or know about, the analyzer.
In addition, the malware may use operations to try to find the presence of the analyzer.
For example, it may try to find a side effect of analysis.
These operations should be privileged, so that the malware cannot directly get the answers back.
And, since the analyzer is at a higher privilege level, it can actually lie the answers back to the malware.
That is, the malware gets the wrong answer and doesn't know about the side effects.
And obviously, the malware should get the same correct result of instruction execution as if the analyzer is not present.
Likewise, the malware should see identical signals and instruction handlings, as well as time durations.
In terms of fulfilling the transparency requirements most interesting tools fall short.
For example, even analyzer is in guest this means that the analyzer runs on a same machine and has the same privilege as the malware then the analyzer does not have high privilege.
Some of the analysis study facts can be discovered but a malware without privilege operations.
And the exceptions trapped by the analyzer may be discovered by the malware.
If the analyzer runs in a virtual machine that's based on software virtualization such as VMWare then there could be side effects that can be discovered.
But a malware without privileged operations.
If the analyzer runs in emulation environment such as QEMU the execution semantics of instructions maybe different from real hardware.
Emulation based malware analysis tools are the most widely used.
But they have major shortcomings.
The main issue here is that this emulation emirames do not fully emulate the hardware.
There is that a corner cases where a set of instructions give different results on emulation emirames versus hardware.
And there have been attacks based on these corner cases to detect emulation emirames.
But the bigger problem is that there is no way to eliminate all these corner cases.
In fact, in theory there's no way to guarantee the absence of such attacks.
And the reason is the so-called
EQTM is not decidable.
Which means that when you view an emulator, you cannot determine that it behaves exactly the same as the real machine.
In other words, you cannot rule out the possibility that there are situations that your emulator and the real machine behave differently.
Here's a simple example of the discrepancies between emulator and real hardware.
That is, the real hardware will give an illegal instruction exception, but an emulator will happily execute the instruction.
### Identical Notion of Time
The most challenging transparency requirement is the identical notion of time.
In particular, if malware uses network timing measurements to infer the presence of analyzer.
For example, the analyzer causes delay, or the website that the malware connects to is not a real one.
There are many direct or indirect measurements that a malware can perform and it is impossible to identify all direct or indirect measurement techniques.
In fact, the problem of identifying all network-based timing measurements is equivalent to the problem of detecting and removing all covert channels.
This problem has been proved to be undecidable.
### Analysis Difficulty Quiz
Now let's do a quiz.
There are four basic types of malware analysis that can be performed.
Please rank these techniques from the easiest to the hardest.
### Analysis Difficulty Quiz Solution
Fully automatic tools should be first performed, they are typically the easiest.
Static analysis should be tried next.
Interactive analysis requires more skills and time to set up.
The most difficult one is manual reverse engineering.
It requires a lot of skills and time.
### Analysis Technique Results Quiz
Let's do another related quiz.
Rank these analysis techniques by how much information each technique can reveal.
### Analysis Technique Results Quiz Solution
It is not surprising that the harder an analyst's technique is, the more information it can yield.
### Robust and Efficient Malware Analysis
Now let's discuss how to build a robust and efficient malware analysis system.
By robust, we mean it is transparent and is not easily detected and evaded by malware.
By efficient, we mean it is automated and fast.
We focus on host-based analysis.
That is, learning malware on a machine and analyze its behaviors.
As a recap, the malware will tried to detect the presence or the side effect of the analyzer.
And our goal is to achieve the same result of malware execution, regardless of the presence of the analyzer.
So let's analyze the transparency requirements again and see how they can be fulfilled.
For higher privilege, let's put analyzer in hardware or a virtual machine.
For the requirement of no non-privileged side-effects, we need to make sure that no side effects can be detected by non-privileged instructions.
That is those are the malware can execute and get results.
Of course the analyzer will inevitable introduce side-effects.
But if the malware has to use privileged instructions to learn about these side-effects, these instructions have to be executed at a higher privilege level than the malware, and then the answers are provided back to the malware.
The analyzer, since it is at a high privilege level, can lie the answers back to the malware.
For the requirement of identical basic instruction execution semantics, we need to use the real hardware.
Likewise, we need to make sure that exception handling will be the same as if on real hardware.
For timing, we need to know the timing of each instruction I/O, and exception handling on the real hardware.
And make sure that the malware can only use privileged instructions to get timing measurements on the host so that the analyzer can lie the answers back.
Just to recap, in order to achieve transparency, a malware analyzer needs to be on a higher privilege, has no non-privileged side effects, has identical basic instruction execution semantics, has the same transparent exception handling, and identical measurement of time.
### Ether Malware Analyzer
Here's an example of a transparent malware analyzer that they built at
Georgia Tech called Ether.
By the way, it is open source.
Let's briefly describe how Ether fulfills the transparency requirements.
Ether is built using Intel VT for hardware virtualization.
The Hypervisor has higher privilege over the OS kernel.
Therefore, Ether has higher privilege than malware.
Some of these hardware supported traps further guarantee this higher privilege.
Ether runs outside of the virtual machine where the malware runs.
Therefore, there's minimal side-effects that malware can directly observe.
Ether uses hardware based authorization and therefore, the instruction execution semantics are the same as on hardware.
For exception handling, again, hardware-based virtualization allows the same semantics as on hardware.
For on-host time measurement, the operations comes down to the use of read time-stamp counter instruction.
This is a privileged instruction and therefore, the Hypervisor and ether can control the return results to the malware when the malware tries to get a measurement of time.
Here's the architecture of Ether.
Ether has a component within Xen, the Hypervisor.
And the rest of Ether is in Dom0.
A separate, privileged virtual machine.
The malware runs on a separate user level virtual machine called DomU.
Ether provides a fine grained insertion by insertion examination of malware and also a coarse grained system call by system call examination.
We created two tools to evaluate Ether.
The fist is EtherUnpack.
It extracts hidden code from obfuscated malware.
The second one is EtherTrace, it records system calls executed by obfuscated malware.
We then compare both of these tools to the current academic and industry approaches.
For EtherUnpack, we compared how well current tools extract hidden code by obfuscating a test binary and looking for a known string in the extracted code.
For EtherTrace, we obfuscated a test binary which executes a set of known operations and then observe if they were logged by the tool.
For EtherTrace again, the results show that Ether has much better transparency than other tools.
Now Ether has limitations and it is only one of the tools in the continued battle between defenders or malware analysis and the attackers or obfuscations.
Let's take a look at this model.
Here, for each major categories of analysis approaches, the attackers come up with obfuscation techniques to defeat such analysis.
For example, for static analysis, including scanning the binaries looking for fixed strings, the attacker can obfuscate the malware.
For example, as a result of packing, the binary contents will look different from one instance to the next.
We also use dynamic analysis, meaning running the malware.
The corresponding obfuscation technique is trigger-based behavior.
For example, the malware will not run until the time is right.
Or it detects the fact that it's been analyzed in an emulation environment and then stopped.
And since simple dynamic analysis now becomes inadequate, researchers have come up with various ways to force execution of this malware.
And of course, this battle between analysis and obfuscation will continue.
### Malware Emulators
A recent trend is that malware authors are starting to use emulation-based obfuscation techniques.
And this is an insertion level approach.
And there are several commercial tools out there and they can be used for instrument purposes such as digital rights management.
So how does emulator-based obfuscation work?
Suppose we have the original malware and it is for x86 instruction set architecture.
For example, your Intel based machines.
The malware is then transformed into Bytecode Program of an arbitrary language L.
And then, this emulator, based on L, will emulate this microprogram on x86.
That is the obfuscated malware
Include both the Bytecode Program and its emulator.
And when the obfuscated malware runs on x86, the emulator will emulate this Bytecode
Program and execute the malware logic.
So what are the impact of emulation based obfuscation on malware analysis?
First of all, the malware program now is a Bytecode of arbitrary language L which is not known.
In fact, the language L can be randomly generated and since we don't know the language
L we can not perform pure static analysis on malware
Bytecode program written in L.
We can perform analysis on the Emulator.
The Emulator actually is not specific to the malware Bytecode program.
It is only specific to the language L.
In face, the malware Bytecode program is only one of the possible inputs to the Emulator.
We can perform dynamic analysis including some of the low code analysis.
We call this greybox methods.
But such analysis is actually performed on the Emulator, not the malware code directly.
The reason is that the executable is the Emulator.
The malware Bytecode is the input.
Therefore, the analysis results that we get are from the Emulator, not directly from the malware Bytecode.
Manual reverse-engineering cannot scale, because each instance can have a different language L, and a different Emulator.
Since the process of creating such confiscated malware is automated.
We also needed an automated approach to reverse engineer these Emulators.
By this, we mean that we should not require knowledge of the language L.
And our approach should be general enough that will work on a large class of Emulators.
But is an automated approach possible?
In theory, it is not.
On the other hand, most of the Emulators have a fetch-decode-execute behavior that can be identified at runtime and then can be the starting point of our reverse engineering.
### Approaches of Emulation
Now let's understand how emulation works in a bit more detail.
In fetch, decode, and execute, the emulator fetch the next bytecode, decode to get it's opcode.
And look up the execution routine for this opcode and then execute it.
Notice that the execute routine execute real x86 machine code.
The Virtual Program Counter,
VPC, is a maintained point to the next bytecode to fetch from.
Now let's discuss briefly how we can reverse engineer emulator-based obfuscation.
There are quite a few challenges.
First of all, we don't even know where the bytecode program resides in memory.
The emulator code responsible for fetch, decode, and execute, is also not known.
The malware author can certainly make reverse engineering more difficult by changing how the emulation works.
We develop a tool to automatically reverse engineer emulator-based malware, and here's a very high level overview.
The first step is to identify abstract variables, in particular pointers.
And of course, one of the most important pointers we need to identify is VPC.
A VPC points to the next bytecode to fetch, decode, and execute.
Therefore, once we identify the VPCs, we can identify the fetch, decode, and execute behavior in the emulator.
>From the fetch, decode, and execute operations in the emulator, we can obtain the opcode and operands, as well as the execution routine of the malware bytecode.
We can then construct a control flow graph of the original malware.
And this will tell us the behaviors of the malware.
Here are some results of our experiments.
We created a synthetic program.
We then apply two emulation-based obfuscation techniques.
One is called VMProtect, the other one is called Code Virtualizer.
We then applied our tool to the obfuscated program.
We then compared a control flow graphs of the original program and the control flow graphs from our reverse engineering.
Here is the control flow graph of the original program, and a graph from reverse engineering
Code Virtualizer, and a graph from reverse engineering VMProtect.
As you can see, our tool is succesful in terms of extracting the main properties of the original control flow graph.
Here are the results from the experiments on a real program,
NOTEPAD.EXE.
Again, here's a CFG of the original program.
And here's the result from reversing VMProtect.
Again, our tool is able to obtain the main information and properties of the original CFG.

---
&nbsp; \pagebreak
## 07 - Botnet-Detection

### Introduction
With regards to malware, the laws of engagements are changing.
In the past, the enemy was easy to distinguish, we just needed to look.
The rise of sophisticated malware, such as botnets and APTs have changed this dynamic.
We're now in the age where distinguishing friend from foe is more difficult.
In this lesson, we're going to examine methods to detect botnets.
We will discuss the subtle signs of botnet activities in our networks, which will lead to, hopefully, ways to mitigate the damage of botnets.
### Network Monitoring
The goal of network monitoring is to detect and prevent attack traffic.
Attack traffic used to be obvious.
For example, the payload of a packet may contain exploit to a known vulnerability and therefore a signature can be used to detect such attack.
Or a network monitor can detect, deny a service attack or spam activity by analyzing the volume and rate of network traffic.
The typical network monitoring systems are the firewalls and the network intrusion detection systems.
Increasingly, the traditional firewalls and network IDS are becoming less effective.
First of all, mobile devices are now widely used.
A mobile device can be compromised when an employee is on travel.
And then when the employee brings the mobile device into the company's network, it effectively has bypassed the perimeter defense.
In addition, attack traffic now is very subtle and they often look like normal traffic.
For example, botnet HTTP-based command and control traffic would look like normal legitimate web traffic.
Therefore, we need more advanced network monitoring systems to detect this new generation of attacks.
In this lesson, we're going to discuss botnet detection systems.
### BOT Quiz
Here's a quiz on the definition of a BOT.
### BOT Quiz Solution
A bot is often called a zombie because it is a compromised computer controlled by malware without the consent and knowledge of the user.
### BOTNET Quiz
Here's a quiz on Botnet.
### BOTNET Quiz Solution
A Botnet is a network of bots controlled by a Bot Master or an attacker.
More preciously Botnet is a coordinated group of malware instances that are controlled via command control channels.
Command architectures include centralized architecture or disputed architecture.
Botnet is a key platform for fraud and other for-profit exports.
### BOTNET Tasks Quiz
Here's a quiz on botnet activities.
Select all the activities that botnet commonly perform.
### BOTNET Tasks Quiz Solution
All of these tasks are commonly performed by botnets.
Other than span and DDoS, these other attacks can look a lot like normal traffic.
### Traditional Security Fail
Let's analyze why the traditional security measures cannot detect Botnets effectively.
First of all, traditional signature-based anti-virus systems are not effective, because bot codes are typically packed and they can use rootkit to hide.
And they also use frequent updates to defeat anti-virus tools.
The traditional IDS/IPS are not effective, because they typically look at the specific aspect of an attack For example, let's be specific exploit.
Whereas Botnet typically perform multiple kinds of activities, because they are for long-term use.
That is, although we can detect that a host has been compromised by an exploit, we do not know that it belongs to Botnet.
Because we need to analyze its command control traffic and daily malicious activities.
Honeypots and
Honeynets are also not effective.
First of all, since they only passively waiting for incoming connections they are to be lucky to capture botnet activities.
In addition, sophisticated bot malware can detect a honeypot because the lack of realistic user activities.
And since a Honeypot is a single host it cannot detect a network of bots.
### Botnet Detection
What are the challenges in botnet detection?
First of all bots try to hide themselves.
Second of all, bots are also involved in multiple activities over a period of time.
Bot malware can also get updates frequently.
Botnets can have many different command control methods.
In fact, a bot malware can be programmed to select one of several C&C methods at run time.
So how do we go about detecting botnets?
We need to first focus on the characteristics that botnets are different from normal traffic.
First of all, a bot is not a human.
That is, the activities by bots may look different from the activities by human.
Second of all, the fact that botnet is a network means that the bots are connected, and their activities are somehow coordinated.
We can also distinguish botnets from other traditional attacks.
Botnets are for profits, and they most likely are going to use the compromised computers as resources.
Botnets are for long-term use.
And therefore there will be frequent updates to the bot malware.
And again there must be coordination among the bots to form a botnet.
Let's first discuss how do we detect botnets in the enterprise network.
We can deploy a botnet detection system at a gateway or router.
This is how we deploy firewall in IDS.
There are several detection approaches in a so called vertical correlation.
We are looking for correlated events across a time horizon, even if a bot has multiple activities in its life cycle.
In horizontal correlation we are looking for similar or coordinated behaviors across multiple bots.
In cause and effect correlation, we inject traffic to pay with the bot to conform that the traffic is generated by bot versus human.
In this lesson, we going to discuss two systems, one is BotHunter, the other one is BotMiner.
### Bot Hunter
BotHunter is a system that performs vertical correlation.
We also call it dialog correlation.
That is,
BotHunter correlates multiple events that belong to the life cycle of a bot.
Let's use an example to illustrate the multiple steps or types of activities in a bot's life cycle.
First, the attacker scan the network and identify vulnerable host.
It then sends the exploit to compromise the victim host and opens a back door.
The compromised computer then downloads the real bot malware, it then connects to a command control server.
And from there, it can perform a number of activities.
For example image scan, for other number of hosts.
>From the phatbot example, we can extract the life cycle of a botnet.
You can include inbound scan and inbound infection, and then outbound traffic to download the egg or the bot malware and command control traffic, as well as other activities.
Such as outbound scan.
So the main idea behind BotHunter is to analyze network traffic to detect patterns that suggest any of these activities belonging to the BotNet lifecycle.
These observations don't have to follow this strict order, but they do have to appear within the same period of time.
BotHunter uses a table to keep track of the evidence that it collects for each host.
And here's an example for each internal host, BotHunter keeps track of the specific activities that belong to each steps of the botnet life cycle.
There are timers associated with these observations.
That is they are valid as long as a timer has not expired.
The integration is that within a period of time that is before the timer expired, if you see multiple evidence belonging to the botnet life cycle then we can determine that this host is a bot.
And we give more weight to evidence that suggests that an internal machine has been compromised and it is participating in botnet activities such as egg downloading, outbound scanning and outbound spamming.
### BotHunter Architecture
Here's the architecture of BotHunter.
He has a number of detection engines.
Each of these engines are disposable for detecting certain activities of the botnet lifecycle.
And the correlator correlates evidence of these activities and makes detection that an internal machine has been compromised and has become a bot and produces a bot infection profile.
Let's discuss the BotHunter detection engines.
The first is SCADE.
SCADE is for scan detection, recur in the bounded lifecycle inbound scan is a first event.
SCADE used different ways for different inbound scan connections, in particular, it gives us higher weight to vulnerable ports.
SCADE also detects outbound scan.
It looks at the rate of outbound connections, how likely such connection fails and the distribution of the destination of these outbound connections.
Collectively this can suggest outbound scan.
Another BotHunter detection engine is SLADE.
SLADE can detect anomalies in network payloads.
The main idea is that we can establish the normal profile of a network service by looking at the n-gram byte distribution of the traffic payload of this network service.
That is, an attack such as an exploit or egg download will cause deviation from this normal profile because the n-gram byte distribution of the attack traffic will be different from the normal traffic.
SLADE has a very efficient implementation of payload anomaly detection.
BotHunter also includes a signature engine.
This signature engine can detect known exploits and know patterns of command control.
The signature rules come form multiple open sources.
Here's an example of infection profile produced by BotHunter.
It list the initial host that infects the internal machine, the internal machine that has become a bot and the command and control server.
It also lists evidence of the lifecycle steps.
### Botminer
Now let's discuss another
Botnet Detection System, Botminer.
The first question is, why do we need another Botnet detection system.
Notice that Bot hunter is based on some specific Botnet infection life cycles.
But Botnet can have different infection life cycles and they can change the protocols and structures of the command control.
For example, Botnet can use a centralized command-control system or fully distributed peer-to-peer control system.
Our goal is to have a Botnet detection system that is independent of the command-control protocol and structure.
In order to achieve this goal, we need to focus on the intrinsic properties of Botnet.
In particular, Bots are for long-term use, and bot with the Botnet have similar or coordinated communication and activities.
Therefore, we need to perform both vertical and horizontal correlation, here's the architecture of BotMiner.
We arrive at this architecture based on the definition of a Botnet.
We coded a botnet is a coordinated group of malware instances, they're controlled via
Command Controlled Channels.
The C-Plane monitor here, is for monitoring Command Controlled Traffic and A-Plane here, is for monitoring malicious activities because these are malware instances.
On both planes, we perform clustering to detect groups they are in correlated or similar ways.
Then we use cross-plane correlation to detect a group of machines that perform similarly in both command control activities and malicious activities.
And these are parts of the same Botnet, here's a workflow of C-plane clustering.
First of all, a flow record for connection between a local host and a remote service is defined by the protocol, source and destination IP Destination port, time, and number of bytes.
All flow records go through a number of steps that include filtering, aggregation, feature extraction, and clustering.
Here are some example of our features, look at bytes per second, flows per hour, bytes per packet, and packets per flow and we perform clustering in two steps.
In step one, we group C-flow records into course-grained clusters.
In step two, within each of these course-grained clusters, we further position them into finer grain groups.
The main idea here is that we can use a small set of features to perform course-grain clustering.
Because the number of features that we use is small, this step is very efficient.
There within each course-grained cluster, you can afford to use the full feature space to perform fine-grained clustering.
In A-plane clustering, we first cluster based on activity type, for example, this is scan, spam, binary downloading or exploit.
Within each activity,refer to use the features that tend traffic to perform clustering.
For example for scan, we can use the destination sump nets and the ports and for spam we can use a spam template.
Again the main idea of A-plane clustering is to capture similar activity patterns among the hosts.
In cross-plane correlation we are looking for the intersection between a-plane and c-plane clusters.
Intuitively, hosts, there in the sections, have similar malicious activities and similar C&C patterns.
In particular, if two machines appear in the same activity clusters and in at least in one common C-cluster.
That means they should be clustered together because they're in the same Botnet.
### Botnet Detection Quiz
Now, let's do a quiz on botnet detection.
Which of these behaviors are indicative of botnets?
### Botnet Detection Quiz Solution
Generating DNS requests by itself is not indicative of Botnet activities.
However, if multiple machines looking up the same domains at the same time and the domain is not on a Y list, that is quite suspicious.
### Botminer Limitations Quiz
Now, let's consider the limitations of BotMiner.
What can botnets do to evade the C-plane clustering?
And, what can a botnet do to evade A-plane clustering?
### Botminer Limitations Quiz Solution
Botnets can vary the CNC communication patterns and they can introduce random noise in their communication traffic.
For A-plane clustering, the botnets can also vary their activities to evade our detection heuristics.
### Botnet Detection
So far, we have discussed botnet detection in the Enterprise network.
Now, let's discuss how we detect botnets on the internet.
We observed that a botnet must use internet protocols and services in order to maintain a network infrastructure.
For example, in order to maintain its network structure must use some sort of look-up services to find command-and-control servers or the peers.
And you know that to support is various kinds of malicious activities, a botnet must use hosting services, for example to store and distribute attack data and for malware download.
A botnet can also use transport services to route or hide its attack traffic.
Therefore by identifying the abnormal use of internet services, we can detect botnet activities on the internet.
In this lesson, let's focus on DNS.
And the reason is that most bots use
DNS to locate command control and hosting service.
### Botnet and Dynamic DNS 1
Many botnets use DNS for command control.
A key advantage is that DNS is used whenever a machine on the internet needs to talk to another, because DNS stores the mapping between domain name and IP address.
That is DNS is always allowed in a network and using DNS for command control won't standout easily.
Suppose a malware infects many machines, that is many machines now have become bots.
The question is how can this bot organize into a botnet?
The bot malware has instructions to connect to this command control server.
But in order to connect to the command control server, it will perform a DNS lookup first.
And with the IP address, the bot can connect to the command control server and that's how the bot becomes part of a botnet.
The DNS service providers preferred by botnets are Dynamic DNS providers, because they allow the frequent changes of the mapping between DNS domain name and IP address.
That is the botmaster can change to use another machine on the internet for command control and all he needs to do is log into his
Dynamic DNS provider, and make changes.
If we can detect that, a domain is used for botnet command control, then we can detect which machine connects to this domain and this machine is a bot, but how do we know this domain is used for botnet command control?
It terms out that way the bots look at the domain is different from how machines look at instrument domain such as a news website, because of normal use activities.
For example, a botnet CNC is looked up by hundreds of thousands of machines across the internet.
And yet, it is so-called unknown according to Google search and that's an anomaly.
We can use anomaly detection at the
Dynamic DNS service provider by examine queries in DNS domains to identify botnet CNC domains.
And once we identify a domain is used for botnet CNC, then a number of responses are available.
One is for the service provider to disable a domain, but it's one thing to occur when none such domain reply.
Another option is for the provider to set a mapping of a domain to a single address.
So that instead of connecting to the botnet command control server, the bots are now connected to a sinkhole.
The sinkhole in addition to disabling the botnet security researchers can also learn where the bots are by looking at the origins of the connections to the sinkhole.
### Botnet and Dynamic DNS 2
Now let's focus on how do we detect that a domain is used for upon as C&C.
There are a number of heuristics based on observations.
First, member masses purchase a domain, they must use credit card, and that leaves traceable financial information.
And the other limit such traceable information as little as possible.
Therefore, they may do the so-called package deal, where for one second level domain, they're going to use it for multiple three level domains for botnets, for example here for the same package deal for the second level domain evilhacker.org, there are multiple botnets using different three level domains, the point is that with a single financial transaction, they can support multiple botnets, therefore we can cluster the three level domains under the same second level domain that's looks similar in their names or they resolved to similar subnets of IPs.
Because they're likely to be botnets they're related.
And we sum up the look-ups to all of these domains within a cluster.
By doing so we will compare the look-up patterns of legitimate domains. which is the Botnet domains they look different.
That is the Botnet domains tend to have larger lookup volumes.
And remember these domains are in dynamic DNS providers and the domains tend to be small and medium sized businesses, therefore legitimate domains will not have a very large lookup volumes.
Another observation is that bots tend to look up their their Command and
Control service as soon as their host machines are connected to the internet.
The intrusion is that bots must maintain communication with the command control server and since they have no control over when the host machines connect to the internet, they must take their first opportunity.
The result is that there is an exponential arrival of DNS request from the bots, whereas legitimate DNS lookups by normal user activities is a lot smoother.
For example, Human uses don't all immediately check the same side.
Therefore, if you sought the lookout volume per hour by 24 hour windows, we can see the exponential arrival rate of the bot's queries, whereas human queries are a lot smoother.
There are other detection heuristics.
For example, the look up's are from all over the internet.
And a C&C server is resolved to many different IP's across the internet.
And the resolved IP address change frequently and so on.
Any of these observations alone cannot effectively detect a Botnet command control domain.
And therefore, we combine them in a detection system.
### Botnet and Dynamic DNS 3
Now let's discuss how we detect botnets in large networks such an ISP.
Here, we can focus on the DNS queries that can be observed by the recursive
DNS server and the ISP.
That is, we can analyze the Internet traffic from the internal host to the DNS server.
In particular, we can detect any abnormal growth of the popularity of a domain name.
It can suggest that this domain name is used for botnet command-control.
Intuitively, the reason that a botnet will grow is that more machines become infected, and become bots.
Therefore, the growth pattern of a botnet corresponds to the propagation pattern of an infection.
According to studies, exploit-based infection grows exponentially.
Email-based infection grows exponentially or linearly.
And dry-by downloads growth likely sublinear.
In a large ISP, there are many domain names being looked up every day.
But we don't have to analyze all domain names.
In fact, we can focus on a few anomalous domain names.
These are domain names that look suspicious.
In particular, many regularly spelled, easily sounding domain names have been taken up by businesses and individuals already.
Therefore botnets are forced to use very random looking domain names.
In other words, these random looking domain names are suspicious.
And then we need to analyze the growth pattern of these suspicious domain names.
In particular, we look for the exponential or linear growth of their popularities.
Here's a sketch of our ideas.
We assume a baseline of N days, and we assume that, within this N days, all domains are legitimate.
Therefore, we record these domains In a Bloom filter.
A Bloom filter is a very efficient representation of set.
That is, we use the Bloom filter to record a set of domains observed within these N days.
We also use a Markov model to model how these domain names are spelled.
After this baseline, whenever we observe a new domain, that is, a domain that is not in our Bloom filter on a set of recorded domains.
And if this domain does not fit our Markov model, that means it is spelled in a different way and looks suspicious.
Then we know that we have a new and suspicious domain.
Then we analyze the lookup sequence to this new and suspicious domain.
And if the growth is linear or exponential, then we know that this domain is used for botnets.
So far we have discussed botnet detection.
The latest threats are more targeted and more advanced.
For example, the use custom built malware on zero-day exploits, their activities are low-and-slow and they move within network and covering their tracks.
Even the existing botnet detection systems are not effective against these targeted advanced threats.
In order to counteract these targeted and advanced threats, we need multifaceted monitoring and analysis.
That is we need malware analysis, host-based monitoring, forensics, and recovery, network monitoring,
Internet monitoring, threat analysis, and attribution.
### APT Quiz
Now let's do a quiz on APT.
Which of the following information should we consider in order to identify the source of an APT attack?
### APT Quiz Solution
We need all of them.

---
&nbsp; \pagebreak
## 08a - Internet-Scale-Threat-Analysis

### Introduction
The Internet is a large ecosystem of networks.
It is also a large ecosystem of vulnerabilities.
To defend the network, we need to know it.
In other words, we need to map the entire Internet.
In this lesson, we'll learn how to map the internet efficiently and thoroughly, and survey vulnerabilities.
### Attacker Intelligence Quiz
Let's start with a quiz on how attackers can gather intelligence.
Match each phrase with its description.
### Attacker Intelligence Quiz Solution
In Footprinting, the attacker gathers information about target.
The kind of information gathered is: DNS, email servers, and the IP address range.
In Scanning, the attacker uses the internet to obtain information on specific IP addresses.
The kind of information gathered is: Operating System, services, and architecture of the target system.
In Enumeration, the attacker gathers information on network user and group names, routing tables and simple network management protocol.
### Internet Wide Security Scanning
There are a lot of benefits from Internet Wide Security Scanning.
For example, we can discover new vulnerabilities, we can understand how a defensive mechanism has been adopted.
On the other hand, Internet Wide Security Scanning means that we have to probe the entire address space and with existing tools, this is very difficult and slow task.
On the other hand, some of the Security Studies does require the scanning of the entire address space.
For example, if we can obtain the cryptographic keys in the entire address space, then we can understand the ecosystem of public key infrastructure and its vulnerabilities.
### Internet Wide Network Studies
In fact there have been quite a few inferential Internet-Wide Network Studies.
For example, in 2012 researchers at the University of Michigan released a paper describing the weak keys used in network devices.
In particular, they found vulnerabilities in more than five percent of HTTPS hosts and
10 percent of SSH hosts but a study required a lot of computing powers and time.
Similarly there's a study from the Electronic Frontier Foundation on public key certificates.
Again the study requires a lot of effort and a comprehensive scan of the whole internet also requires months of efforts.
All these projects require heroic effort just to perform initial data collection.
As you can see these scans require massive polarization and typically they also require an extended period of time.
Given the benefits of Internet-Wide Network Security Studies we want to see just a few more of them.
### ZMap
But in order to do that,
Internet surveys should not require heroic efforts.
For example, it would be nice if we can scan the whole HTTPS ecosystem every day.
Given that existing tools are so slow, researchers at the University of Michigan wrote ZMap, a new Internet scanner, from scratch.
ZMap is a fully-functional open-source network scanner that can scan a single port on the IPv4 address space.
On a gigabit network, it can cover 98 percent of the IPv4 address space from a single machine in under 45 minutes.
With ZMap, performing a scan on the Internet no longer requires hundreds of hours of coding or months to execute.
Now, performing an Internet scan is a single command which could be finished within an hour.
### ZMap Architecture
While there are many excellent multi-purpose network scanners, these scanners were never intended or optimized for scanning the entire Internet.
ZMap, on the other hand, was designed from the ground up for the specific purpose of completely scanning the whole Internet.
Let's compare existing network scanners with ZMap.
Existing network scanners need quite immense amount of resources to keep track of state of the entire Internet.
ZMap, on the other hand, eliminate local per-connection state.
Existing scanners also spend a lot of resources keeping track of which host is being scanned and which host have responded.
On the other hand, ZMap uses
Shotgun Scanning Approach and keeps minimum state information.
Previous scanners have been attempting to be more polite by slowing the scans.
ZMap, on the other hand, distributes the scan across the Internet.
This allow ZMap to scan at more aggressive rate without impacting the destination networks.
Finally, ZMap also bypasses the inefficient network stack in the operating system and generate outgoing packets directly.
### Addressing Probes
If we simply poll network actresses in numerical order, we will risk overloading the destination networks.
However, we also don't want to have to track what host we have scanned or need to scan.
In order to scan according to a random permutation, we select addresses according to a cyclic group.
Specifically, we iterate over a multiplicative group of integers modulo a prime number slightly larger than 2^32.
Here's an example of how do we randomly iterate through all the numbers in a group.
Here, the generator is 5, and we start with number 2.
The process is we multiply the current number by 5 mod 7, and the result is the next number, and all numbers will be enumerated or iterated.
For example, we start with 2.
2 multiply by 5 mod 7 is 3.
So we move 3.
3 times 5 mod 7 is 1, and so on.
As you can see we can iterate through all the numbers in a group.
Following that simple example, here's how we can iterate through the addresses in address space.
Each scan is essentially a random permutation of the address space.
Again, we treat the address space as a multiplicative group.
So we first decide on the generator and then we choose a random starting address.
With this approach, we can guarantee that all addresses in the address space can be iterated.
More importantly, there's very little state information we need to keep track of.
Essentially, for each scan, we need to keep track of the primitive root or the generator and the current address because when the first address is visited again we know that we have iterated all the addresses in the address space.
As you can see, this is very little information to keep track of for each scan.
### TCP IP Quiz
Now, let's do a quiz.
### TCP IP Quiz Solution
Which protocol is used to break data into packets?
It is TCP. Which protocol is used to move packets from router to router?
It's IP, the internet protocol.
Which protocol reassembles the data packets?
Again, it's TCP.
And here's an illustration of the concepts in the quiz.
On the sender's side, the TCP protocol breaks data into packets.
When a packet comes out of the sender, the routers are responsible for sending a packet to the recipient.
And the recipient, the TCP protocol, again resembles the packets back into the original data.
### Validating Responses
We have discussed how we can scan [inaudible] state information, but how do we validate the responses?
The idea here is that we can encode secrets into the fields of the probe packets.
This is similar to the SYN cookies.
Here are the formats of the Ethernet,
IP and TCP packets, and some of the fields here can be used to encode the secrets.
In order to validate packets, we receive.
We encode a scan invocation and host-specific secret into mutable fields that will have a recognizable effect on the probe responses.
Specifically, for each scan host ZMap computes a hash of the destination address keyed by the scan's specific secret.
This MAC value or Message Authentication Code is then spread across any appropriate and available fields.
In the case of using a TCP SYN packet for scanning, we encode the secret into the source port and sequence number.
We know that the destination host will have to include the port and sequence number to send a response.
For example, a sequence number will be encoded into the acknowledgement number field.
More precisely, in response packet the receiver port was the sender port in the scanning packet and the acknowledgement number is the sequence number of the scanning packet.
### Packet Transmission and Receipt
Here are the high level workflows of ZMap.
To send scanning packets,
ZMap will be configured, for example, of a random permutation of the address space.
And then the probing packets will be sent to these addresses according to the random permutation.
Since the majority of fields in a probe packet never change,
ZMap performs all network operations at the ethernet layer using a raw socket in order to cache values.
This eliminates time lost to kernel operations such as route lookups.
This allows ZMap to send probing packets at a very high speed and validate the responses.
For example, checking the MAC value and the probing results can then be analyzed.
This configuration allows ZMap to send probes at approximately
1.4 million packets per second on a gigabit network.
ZMap is an extensible framework to allow any type of single packet scan such as a TCP sync scan,
ICMP echo requests or application-specific UDP scan.
The ZMap framework abstracts out details such as configuration, timing, addressing and validation.
### Scan Rate
The first major question is whether ZMap or our network can handle scanning at gigabit speed.
In order to answer this question researchers at the University of Michigan perform 10 trials scanning one percent of the IPB for address space at different rates ranging from 1,000 packets per second to the maximum 1.4 million packets per second.
This maximum is determined by the NIC configuration.
NIC stands for network interface card.
As we can see there is no correlation between a scanning rate and the number of hosts that respond.
One way to interpret this result is that even slower scanning rates does not produce additional response.
### Coverage
Another interesting question is,
"Is one probe packet sufficient or is sending multiple packets beneficial?"
This is difficult to answer directly because there is no ground truth for the number of live hosts on the Internet.
In order to estimate ZMap coverage, multiples in packets were sent to one percent samples of the IPv4 address space.
If you look at the number of responses we clearly see a plateau after a SYN packets.
In fact, we should expect to see an eventual plateau in a number of responsive hosts regardless of additional SYN packets sent.
Analyzing these results we can estimate that with a single packet the coverage is about
97.9 percent and with three packets the coverage is 99.4 percent.
### ZMap vs NMap
Many previous projects have used the popular Nmap network scanner to perform scans.
Therefore, we should compare ZMap with Nmap.
The researchers performed several experiments focusing on the total time spent for scanned and scan coverage.
In these experiments, one million addresses were scanned.
In these experiments, Nmap used the most aggressive scan template called insane and with a minimal scan rate of 10,000 packets per second.
As we can see from these results,
ZMap is capable of scanning the IPv4 address space more than 1,300 times faster than Nmap.
ZMap also has higher coverage than Nmap even when Nmap sends multiple probes.
To be fair, Nmap is an excellent multi-purpose network scanner and it is optimized for completely different use cases than ZMap.
So why does ZMap have higher coverage than Nmap?
We analyzed the response time of the scan responses.
ZMap does not timeout hosts, but Nmap does.
In fact, if Nmap sent one packet, it times out after 250 milliseconds.
If it uses two packets, it times out after 500 milliseconds.
As you can see, some responses arrive after Nmap has timed out.
Ultimately, since ZMap uses stateless scanning and does not keep state, it has both increased performance and increased coverage.
Ultimately, since ZMap uses stateless scanning, it has both increased performance and increased coverage.
### Entropy Quiz
Now let's do a quiz on entropy.
Fill in the blanks with the correct answers.
### Entropy Quiz Solution
With regards to computing. What is entropy?
Entropy is randomness for use in cryptography or other applications that require random data.
What are the two sources of entropy?
Hardware sources or randomness generators.
A lack of entropy will have a negative impact on performance and security.
### Cryptographic Keys
Now, let's discuss a few interesting internet-wide security studies using ZMap.
In one study, the researchers scanned the HTTPS servers and the SSH servers and collected their public keys.
As you can see, a large number of machines share their public keys.
Although there are lot legitimate reasons why machines would share their keys, we need to understand whether the keys happen to be the same without the intention of sharing because that is bad for security.
In particular, researchers find that some of these machines share their key in a vulnerable manner.
For example, they simply use the default keys without creating their own keys and there's a apparent entropy problem that caused them to have the same keys.
Let's look at the effect of not having sufficient entropy.
As a quick review, in RSA, the public key n is the product of p and q, where p and q are large random prime numbers.
The security of RSA is based on the fact that factoring n back to p and q is very, very inefficient.
That is, it's very hard for the attacker.
On the other hand, if two private keys N_1 and N_2 share the same prime number, say p, then it's trivial to compute p because p is the greatest common denominator of N_1 and N_2.
The reason that two different public keys may have the same prime number can be that there's not sufficient entropy and therefore two machines may happen to generate the same large prime number p. There is also a very efficient algorithm due to D.J.
Bernstein to compute the GCD of every pair of N_1 and N_2.
With this efficient approach, the researchers were able to crack many keys on TLS and SSH machines.
The majority of these machines are network devices.
### Embedded Systems
Now, let's look at why these embedded systems or network devices generate broken keys.
These embedded systems all run Linux and they all use urandom to generate cryptographic keys.
Linux maintains several entropy pools.
As entropy is gathered, it is stored in the input pool and is eventually mixed into the non-blocking pool which feeds urandom.
However, many of these sources are not present on an embedded system.
For example, the system may not have keyboard and many of them don't have spindle-based disks.
In fact, most of these embedded systems don't even support real-time clocks.
Therefore, with all of these random sources removed, we end up with a deterministic source of randomness.
Furthermore, entropy is a mix from the input pool to the non-blocking pool until there are more than,
192 bits of entropy have been collected.
Therefore, even if a small amount of entropy has been collected on a device, none of it is available until the pool reaches this threshold.
This graph shows the build-up of entropy on the first boot of a typical Ubuntu desktop server.
No randomness is added from the input pool to urandom until 192 bits of entropy is available.
From the graph, we can tell that this did not happen until fairly late in the boot process.
This is the so-called Boot-Time Entropy Hole problem, which means that urandom may be predictable for a period after boot.
Unfortunately, cryptographic keys may be based on this predictable urandom.
### Certificate Authoriazation
Another interesting study is on the certificates issued by certificate authorities.
This is an important topic because HTTPS underlines all secure Web communications and HTTPS is depending on the security of certificate authorities.
The problem is that there are many certificate authorities and every one of them can sign for any website.
In fact, we don't even know all the certificate authorities, until we see them.
### Certificate Chains
Let's have a quick review of how certificates is used in Web browsing.
Browsers such as Firefox decide who they trust.
These certificates are stored as part of the browser or the operating system.
Browsers typically support a couple of hundred root certificates, such as this.
These root certificate authorities then agree to sign other certificates for example,
Equifax is a root certificate authority and agrees to sign Google with authority.
And this can go on in moving multiple intermediates and we end up having a certificate chains.
That is, if you look at Google.com, it's signed by a chain of certificates and a top certificate is just a self-signed certificate.
This entire chain is presented by
Web browser to the client and the client can verify the signatures by traversing the certificate chain up to the browser trusted certificate, which is self-signed.
The researchers at the University of Michigan perform regular scans to try the use of certificates.
They observe 3,700 browser trusted certificates in one year.
They also discovered two cases of misused certificates.
In one case, a signing certificate was accidentally issued to a Turkish transit provider.
In another case, 1,300 certificates were issued by the Korean government.
### Identifying CA
The researchers found 1,800 signed certificates belonging to
683 organizations and these include various kinds of institutions.
The most worrisome finding is that all major browser roots are selling intermediates to third parties without any constraints.
By analyzing the certificate chains, we see that 90 percent of the certificates are signed by five organizations.
They are sent from four roots and signed by
40 intermediates and there are only a few big players.
Another interesting fact is that 26 percent of the trusted sites are signed by only a single intermediate certificate.
### CA Risks
At a high level, there are several worrisome observations.
First, the certificate authorities are ignoring defense in depth, a least privilege.
They are offering services that put the whole ecosystem at risk and they're using some weak keys and deploying HTTPS remains difficult.
Let's go on with these observations next.
For defense in depth, there are several technical practices already in place for limiting the scope of a signing certificate including setting, name or path length constrains and distributing leave certificates among a large number of intermediate certificates.
There are clear cases for using these restrictions but the vast majority of the time, the CA's do not utilize these options.
As another example, local domain names are not fully qualified and intended resource is ambiguous and there is no identifiable owner.
As such, these local domain names frequently appear on more than one certificate.
In one example, there are about 1,218 browser trusted certificates for a domain male, owned by organizations ranging from the U.S. Department of Defense to small companies.
In terms of the keys used, the researchers also find that 90 percent of the certificates use a 2048 bit or 4096 bit RSA keys.
But 50 percent of the certificates are rooted in the 1024 bit key.
More importantly, more than 70 percent of these will expire after 2016 and many still use signs using MD5.
### HTTPS Adoption
The researchers also find that within a year, the number of HTTPS servers only increased by 10% and there's a 23% increase in the number of Alexa top 1 million sites using the HTTPS.
And there's 11% increase in a raw number of browser trusted certificates.
So here's an example of how do we use
Internet-Wide Scan to check adoption of a technology.
### ZMap Open Source
The researchers at the University of Michigan have released ZMap as an open source project.
You can download ZMap and use it for your own Internet wide security study.
Of course, please remember to be a good citizen on the Internet.
There's also a repository of data from previous scans.

---
&nbsp; \pagebreak
## 08b - Domain-and-Network-Reputation

### Introduction
In this lesson, we will discuss domain and network reputation.
We will learn who to trust and, more importantly, who not to trust.
Hopefully, we can figure out who is disreputable as soon as they are on the Internet.
In other words, we're going to do all those things that we're told not to do: prejudge, profile and stereotype in order to stop hackers and protect the Internet.
### DNSBL Quiz
Before we discuss domain name reputations, let's do a quiz on DNBSL.
DNSBL stands for DNS black list.
Match the DNSBL level with its description.
### DNSBL Quiz Solution
White means that this IP address is completely trusted.
Black means that there's no trust in this IP address.
Gray means that this IP address is not directly involved in spamming but is associated with spam-like behaviors.
In other words, it's in the gray area.
Yellow means that this IP address is known to produce spam and non-spam e-mail.
NoBL means that this IP address does not send spam and should not be blacklisted, but it is not fully trustworthy.
### Motivation for Reputation
Traditionally, when an IP address is discovered to have been used to send spam, it is added to a blacklist.
This is called a static blacklist.
If an IP address is in a blacklist, then emails coming from this IP address can be blocked.
This is a great idea except that attackers also know about the blacklist.
So spammers can circumvent the blacklist by using new IP addresses, and by the time an IP address is discovered to have been used to send spam and edit to blacklist, the spammers can then move on to use a new IP address.
We need to change this model to be in line with our philosophy about network security, and that is an IP address should not be trusted by default.
### New Blocklist Model Criteria
Now, let's discuss a new blocklist model.
We know that static blocklist are increasingly ineffective.
What we need is a dynamic reputation system that outputs the reputation score or the trustworthiness of a domain.
The intuition of this new model is that legitimate use of domains and sites are different for malicious use.
The question is, how do we observe such differences?
Our intuition is that such differences can be observed in DNS traffic.
For example, we can look at the patterns of requests and the reputation of the requester, the resolved IPs, and the network providers for these domains.
Therefore, our approach is to analyze DNS traffic, extract temporal and statistical features and then apply machine learning algorithms to learn models that can provide the dynamic score of a domain.
### DNS Quiz
Now, let's do a quiz on how malicious applications use DNS domains.
Match the malicious application with its DNS characteristics.
### DNS Quiz Solution
A botnet typically have a set of domains at his disposal.
So, each domain is only used for short period of time.
A spyware is used to steal information, and it needs to upload information to a site.
This site is typically registered anonymously.
Adaware uses domains.
They are not associated with legitimate businesses.
Therefore, these domains are disposable.
### Notos
Now, let's discuss two DNS repetition systems.
The first one is NOTOS.
NOTOS is a system that dynamically assigns repetition score to a domain name.
It uses features that capture the characteristics of resource provisioning, usages, and management of DNS domains.
Given examples of legitimate and malicious domains,
NOTOS uses machine learning algorithm to compute a scoring function based on these features.
This scoring function can output a repetition score for new domain.
In our study, we are shown that NOTOS has very high accuracy.
That is, it has a very low false positive rate and very high true positive rate.
That is, NOTOS can detect a fraudulent or malicious domain weeks or days before it is widely used.
NOTOS can be applied to a large network, for example, a particular ISP.
Whereas another system called Kopis has
Internet-wide visibility because it performs monitoring at the upper levels of the DNS hierarchy.
That is, Kopis uses DNS traffics at authoritative DNS or top-level domain DNS service.
Similar to NOTOS, Kopis also extract a set of statistical and temporal features from the traffic and then uses machine learning algorithm to chain a scoring function.
Similar to NOTOS, Kopis also has very high accuracy rate.
Similar to NOTOS, Kopis can also detect malicious domains weeks before they were listed in any blacklist.
Since Kopis has the Internet-wide visibility, it can detect that a domain is being used by malware within one country months or weeks before the malware begin to spread to other countries.
For example, in our study,
Kopis was able to detect a DDoS botnet rising in networks within
China almost one month before it propagated to other countries.
### Global Kopis
To summarize what we have discussed so far,
Notos can be deployed at Large Local Network, such as an ISP.
In other words, Notos use traffic to do recursive DNS servers whereas Kopis is deployed at the upper level of the DNS hierarchy.
In particular, the authoritative name servers or the top-level domain servers.
In other words, Notos has local views and Kopis can have a global Internet view.
### Malicious Domain Names Quiz
One of the methods used to detect malicious domain names involves name analysis.
Domain names are analyzed to determine the likelihood that a name is used or created for not legitimate purposes.
Lists of types of characters a malicious domain name detection program should look for in a domain name.
### Malicious Domain Names Quiz Solution
We can look for the number of characters.
Malicious domain names tend to be long.
We can also look for the number of hyphens.
Again, malicious domain names tend to have a lot more hyphens.
We can look the number of digits.
Again, malicious domain names tend to have a lot more digits.
Similarly, with numbers.
### Notation and Terminology
Before we discuss the details of notice and coppice, let's go over some of the notations and terminologies.
We use RR to represent resource record.
It's a tuple of domain name and its reserved IP address.
For domain, www.example.com.
2LD is example.com, and 3LD is www.example.com.
The related historic IPs of a domain are all the routable IPs historically mapped with this domain name, and any other domain name, within the same 2LD and 3LD.
Related historic domains of an IP address are all the fully qualified domain names that historically had been linked with this IP, and also, all the IPs with this address box, and the autonomous systems.
The authoritative domain name tuple is the requester for example, that because of DNS, the domain name and RDATA, which includes all information about this domain.
Notos uses passive DNS data collected at a recursive DNS server.
For example, this can be your ISP.
In our study, we use data from multiple ISPs and data repositories.
For coppice, we use data from two large authoritative DNS servers, and the Canadian top-level domain server.
### Local Notos
Now, let's discuss the temporal and statistical features of Notos.
Given a resource record, and that is a tuple of domain name and its resolve IP,
Notos uses the passive DNS data to extract network based features.
These features are based on the related historic IPs.
It also extracts the zone features.
These features are based on the related historic domains.
Notos also constructs the so-called evidence features by analyzing the blacklist and honeypot data, and look for evidence associated with these IPs and domains.
These features are then combined and forwarded to the reputation engine which computes a reputation score for this domain.
### DNS Database Quiz
Now, let's do a quiz.
We have just discussed that the information extracted from the passive DNS database can be grouped into three categories of features.
Match the category to its definition.
### DNS Database Quiz Solution
Network-based features. These include, the total number of IPs historically associated with a domain, or the number of distinct autonomous systems.
Zone-based features. These include, the average length of domain names, the occurrence frequency of different characters, etcetera.
Evidence-based features.
These include, the number of distinct malware samples.
### Notos Statistical Features
Here's a summary of Notos statistical and temporal features.
The network-based features are extracted from the set of related historic IPs.
The features include, the total number of IPs historically associated with a domain, the diversity of their geographical locations, the number of distinct autonomous systems, and so on.
The zone-based features are extracted from the set of related historic domains.
The features include, the average length of domain names, the number of distinct top-level domains, the occurrence frequency of different characters, and so on.
The evidence-based features include, the number of distinct malware samples that contacted the domain, and the same for any of its resolved IPs.
Here we show the result of clustering 250,000 domains using the Noto features.
As we can see, the clusters don't overlap.
This tells us that the Notos features are very good at separating domains of different types into different clusters.
### Notos Reputation Function
Now, let's discuss how Notos computes reputation of a domain.
First, Notos needs to chain a repetition function, given a set of domains known to be legitimate or malicious.
Notos extract features for each of these domains and give label 1 to malicious domains, and label 0 to legitimate domains.
Then, given this training data set,
Notos can use a machine learning algorithm to learn a function that, given the Notos feature vector of a domain, it will output a label, meaning 0 or 1, and the reputation score of this domain is simply the confidence of this label.
That is, the probability that this domain is malicious.
As we can see here, this function is very accurate.
That is, it has a very high true positive array and very low false positive rate.
Here, we show that Notos can detect many malicious domains days or weeks before they show up in any blacklist.
Sometimes that's even months before they show up in any blacklist.
This is true for all the malicious domains and also for different types of malicious domains
### Dynamic Detection Quiz
Let's do a quiz. Check all true statements, that pertain to a dynamic, malware-related domain detection system.
### Dynamic Detection Quiz Solution
A dynamic malware-related domain detection system should: have global visibility into DNS request and response messages, it should not require data from other networks, should be able to detect malware-related domains even if there's no repetition data.
Such a system should also be able to detect malware domains before the infection which is a local network.
Therefore, the second statement is false.
### Kopis Statistical Features
Now, let's take a look at Kopis.
Recall that Kopis is similar to Notos except that
Kopis is deployed at the upper level of the DNS hierarchy.
Therefore, the main difference between Kopis and Notos is in their features.
In particular, Kopis analyzes requester diversity.
This requester diversity features characterize if the machines that query a given domain name are localized or are globally distributed.
The requester profile features distinguish request from a small network versus a large network because a larger network would have a larger number of infected machines.
The resolved IP reputation futures look at whether the IP address space pointed to by a given domain name has been historically linked with known malicious activities.
### Kopis Detection Performance
Similar to Notos, given examples of malicious and legitimate domains,
Kopis can use machine learning algorithm to learn a scoring function based on the features.
Here, we show the detection performance of the scoring function.
As we can see here, if we use more data, meaning using a longer time window, the accuracy is higher.
In particular, with a five-day time window, we can achieve very high detection rate and very low false positive rate.
### Predictability
Here, we show that Kopis can detect many malicious domains days, weeks or even months, before they show up in any blacklist.
### Mobile
Now, let's discuss a study of mobile malware prevalence using domain amputation.
The motivation of our study is that most research has been focusing on analyzing malicious mobile apps, but the question remains, how prevalence are the infections on mobile devices?
Our intuition is that mobile web is actually part of the regular web and therefore mobile malware will use similar command control infrastructure and therefore our approach is to analyze DNS traffic obtained from cellular network providers and identify domains looked up by mobile apps.
Then for the internet machines that host these domains, we analyze their reputation.
### Key Data and Findings
In our study, we used data from a major US cellular provider and a major non-cellular ISP.
We find that, at least in the US, the number of machines that are infected with no malware remains to be very small, and iOS and Android devices are equally likely to look up these suspicious domains.
### Methodology
In our study, we first identified the mobile devices, and then we attribute each DNS query to a device.
We then analyze the repetition of the resource records associated with the DNS query.
We use the Notos features to analyze the hosting infrastructures of mobile domains and compute repetition scores.
The difference is that we use different features.
In particular, for mobile domain, we first find the IP address of the machine that hosts this domain.
Then for each of these IP addresses, we extract the following features: the historic non-cellular domains, the related historic mobile domains, any evidence of malware association with these domains, as well as URLs for phishing and drive-by download associated with these domains, and evidence that these domains have been blacklisted before.
With these features and examples of malicious and legitimate mobile domains,
Notos can then use machine learning algorithm to learn a scoring function.
This scoring function can tell us how likely a mobile domain is malicious.
Here are some results from our study.
This column is the breakdown of total number of DNS requests for mobile devices.
As you can see, there are lot more Android devices than iOS devices.
When a machine on Internet has filed a petition, we call it as machine tainted.
Some mobile domains are hosted on these tainted machines.
This column shows the percentage of requests to this tainted hosts.
As we can see, the iOS and Android devices are equally likely to connect to these tainted hosts.
We also measure the number of devices, their lookup domains that are associated with known malware families.
As you can see, the number of devices we've known, malware infection is small.
### Botnet Takedown Quiz
Now, let's discuss botnet takedown using DNS reputation.
But, before we discuss the details, let's do a quiz.
With regards to botnets, select all the true statements.
### Botnet Takedown Quiz Solution
The first statement, one of the most successful methods to taking down a botnet requires investigators to find and target each bot in the net.
This is false because typically, it is not possible to enumerate all paths in the net.
The second statement, a proven method to stop botnets require isolating the C&C domain from the bot net. This is true.
If you take down the command control infrastructure, the bot net will cease to function.
The third statement, with regards to take downs,
P2P-based networks are much easier than centralized C&C networks.
This is false because P2P-based networks use distributed C&C and that's much harder to take down than centralized C&C.
### Botnet Takedowns
To motivate our study, we observed that currently Botnet Takedowns are ad hoc, and performed without oversight and sometimes are not successful.
Our goal is to develop a system and framework to reason about Takedowns and recommend the best Takedown strategies.
The goal of our study is to develop a system to reason about Takedowns, evaluate previous takedown attempts, and recommend future directions.
The high-level idea is that we need to have as complete knowledge of the Botnet infrastructure as possible.
We use both passive DNS analysis and malware analysis to expand our knowledge of the Botnet infrastructure.
Here's an overview of our system called RZA.
We start with a set of seed domains.
These domains are known to be associated with Botnet infrastructure.
They may use passive DNS data to analyze domains related to these seed domains including the reputation and malware samples associated with these domains.
For the malware samples, we perform malware analysis to find out more domains, and that is how our system now has a much more complete knowledge of the Botnet infrastructure.
Based on this knowledge, we can perform analysis of previous takedowns, and also recommend takedown strategies of a current Botnet.
To summarize, we start with a set of seed domains they are known to be associated with Botnet infrastructure, then we enumerate all related domains.
Some of these domains have low reputation, and some are associated with malware.
For the malware samples, we further interrogate to find out more domains.
Here's a high level idea of how we interrogate a malware.
Suppose this is domain that are malware would use by default.
So, the malware is going to perform a lookup of this domain, and then connect with CNC server.
To force the malware to tell us more domains that you may use, we can intercept the DNS query and respond with no such domain.
Then, if there's a backup domain, the malware is going to look it up.
Therefore, by analyzing the malware DNS traffic we can find out more domains that a malware might use.
### RZA Malware Interrogation
Here is our infrastructure to interrogate malware.
You run the malware image machine and have a gateway between the malware and Internet.
Therefore, we can control how the malware can connect to its infrastructure.
For example, we can play with DNS, no such domain, or TCP reset to force the malware to exhibit backup behaviors.
Such a backup behaviors can include using additional domains or switching to a Peer-2-Peer.
We observe that a malware typically would use hard-coded domains or when these domains are becoming not available, it may we try again and then it may try the next set of domains and IPs as a backup.
When those are not available, they may switch to Peer-2-Peer, or the so-called, domain generation algorithm, to use randomly generated domains.
The intuition behind our approach is that malware will use an increasing number of domains and IPs when the infrastructure becomes now available.
The easiest manipulation is by DNS and TCP.
Of course, we can easily add more protocols.
### RZA Takedown
Now, let's discuss an ideal takedown procedure.
Again, we start with a set of seed domains.
These domains are known to be associated with partner infrastructure.
We enumerate the infrastructure using passive DNS.
We get the malware associated with the domains and interrogate a malware.
If the malware tells us additional domains, we look back.
On the other hand, if there is no addition no domains, then we take the set of domains that we know so far and revoke all of them.
That's how we take down the botnet.
If you find that the malware is using dynamically-generated domains, then we need to first reverse engineer the algorithm, then we need to tell the TLD operators and
DNS registrars to stop hosting or adjusting these new domains.
We will also revoke the set of non CNC domains.
If the malware exhibits behavior of using peer-to-peer network, then we need to take down the peer-to-peer protocol.
For example, by penetrating into the peers.
We also need to revoke the set of non CNC domains.
### RZA Studies
Now, let's discuss some case studies.
We perform analysis of previous takedowns.
We also analyze how we can take down some of the active botnets.
Here we showed a log scale of lookup volumes to different set of domains.
This is the date of takedown.
As we can see, lookups to the seed domains, the intogrey domains, and malware domains stop immediately at takedown or soon after.
This means that, this takedown is very effective.
In the case of Zeus, although there are multiple groups including Microsoft and several research groups taking place in takedowns, their efforts were not coordinated.
More importantly, none of them had complete knowledge of the botnet infrastructure.
Therefore, even after the takedown effort, the botnet continue to connect to its infrastructure.
This takedown was accomplished by transferring the entire 3322.org name server authority to Microsoft and domains the malicious result to a set of long single IP addresses.
That is, domains were sunk on a day of takedown and were limited to the 3322.org domain names.
Unfortunately, this only accounted for a fraction of domains associated with malware.
Therefore, lookups to this malware associated domains remain frequent.
In other words, this is not an effective takedown.
### RZA Takedown Study
Of the 45 active Botnet, we find that too had TGA based backup mechanisms, and one had a peer-to-peer based backup mechanism.
On the other hand, 42 of them are subject to DNS only Takedown.
To summarize the drawbacks of current Takedown efforts, there ad hoc meaning that they don't have complete knowledge of the Botnet infrastructure.
There's a valid oversight, meaning that different groups may step on each other, and the success rate is not high.
Therefore, we believe that a central authority to coordinate Takedown efforts is necessary.
Icons policies can provide an example framework.
For example, there is policy for domain name dispute resolution.
There's also system for rapid suspension.
Therefore, we should study policy criteria for Takedowns, and have the community to review such criterias.
We can test the policy with the newly created top-level domains.

---
&nbsp; \pagebreak
## 09a - Basics-of-Bitcoin-and-Blockchain

### Acknowledgements
First, I would like to acknowledge that the slides that I'm going to present are from Joseph Bonneau,
Ed Felten, Arvind Narayanan, and Andrew Miller.
### Where Does Joe Go Quiz
First, let's do a quiz on hash table.
Suppose we want to store pointers to student records in a hash table, the hash function is the length of the name mod 5.
Therefore, for Alice, since the length is 5, her record is going to be stored in slot 0,
John will be in slot 4, and Sue will be in slot 3, so where will Joe go?
### Where Does Joe Go Quiz Solution
Since the length is three, you should go to slot three, but Sue is already in slot three.
Therefore, there is a collision, in fact, that's the weakness of this hash function.
### Hash Function Quiz
Now, let's do a quiz on cryptographic hash functions.
Which statements are true?
### Hash Function Quiz Solution
Cryptographic hash functions do not have a key.
Second, a major drawback of cryptographic functions is that it is easy to find two messages that have the same hash value.
That is false. Third, cryptographic hash functions are primarily used for message integrity. That is true.
### Review of Hash Functions
Now, let's have a quick review of hash functions.
There are several important properties of cryptographic hash functions.
First, it is easy to compute.
You can compute the hash of a message of any size.
For a given hash function, it produces fixed length output.
Hash function is a one-way function, that is, given the hash of the message, it is not easy to find the original message.
Hash functions are also designed to be collision resistant.
That is, given a particular message, m_1, it is computationally infeasible to find a different message, m_2, such that m_2 and m_1 have the same hash value and that is the weak collision-resistant property.
A strong collision resistant property states that, computationally, it is infeasible to find two different messages such that they've the same hash value.
### Pointers and Structures
Now, let's introduce a new data structure called hash pointer.
We know that a typical data pointer is the address to where the data is stored.
A hash pointer contains a pointer to where the data is stored but also the hash of that data.
That is, we expand the data pointer to include the hash of the data.
We're going to use this notation to represent hash pointers.
If we have a hash pointer, obviously, we can use the data pointer to get the data back.
But since we have the hash, we can also verify that the data has not been changed.
We can use hash pointers to build very useful data structures.
In particular, we can build blockchain, which is a linked list of hash pointers.
Suppose we have a hash pointer pointing to a block.
This block contains not only data value but also the hash pointer of the previous block, and likewise, the previous block contains not only the data values but also a hash pointer to the previous block.
And this is called a blockchain.
To construct a blockchain, we append a block at the end, include a hash pointer in a block, and then compute a hash and store the hash pointer.
This hash pointer is a root of this blockchain.
A use case for blockchain is a tamper-evident log.
That is, we want to be a log data structure that stores a bunch of data and allows us to append data onto the end of the log.
But if somebody changes the data in the log, it is easy for us to detect that.
We can see that if an attacker changes data in this block, the hash will not match the hash pointer store in the next data block.
Of course, the attacker can then change the hash value stored in this hash pointer.
But the result is that the hash value of this block will not match the hash value stored in the hash pointer of the next block.
The attacker can again change this hash value.
But then, it will not match the hash value stored in the root.
Therefore, tampering a data item will cause the difference of the computed hash of the whole chain to be different than the hash value stored in the hash pointer to the whole chain.
That is, by just remembering this single hash pointer, we can easily detect data tampering.
### Digital Signatures
Now, let's have a quick review of digital signatures.
What we want from signatures is that only the owner of the private key can sign, but anyone can modify because they can retrieve the owners public key.
Further, a signature is tied to a particular document.
Let's review how digital signatures are created and verified.
We have a private signing key and a public verification key.
The key pair can be created by specifying the key size.
Then, for particular message, we can create a signature by essentially encrypting the message using the private signing key.
Given the message and the signature, any person who has obtained the public key can verify the signature.
The verification is performed by using the public key to decrypt the signature and matching the result with the message.
What are the requirements for signatures?
Obviously, a valid signatures can be verified, and no one can forge a signature.
Public key cryptography guarantees that although anyone can know the public key, but without the private key, which is only known to the owner, no one can forge a signature.
### Public Keys as Identities
Public key can be used as an identity.
For example, if you can verify a signature using a person's public key, you can think of it as a person who owns the public key has stated the message.
Of course, you can create a valid signature only because you have the private key.
Therefore, by creating a valid signature or speak of a message, it means that you can prove to anybody that you're already the owner of the public key.
Here's how we can use public key to create a new identity.
First, we'll create a new random pair of public key and private key.
The public key or the hash of the public key becomes your name or your ID.
But the private key is really what you can use to prove your identity.
The advantage of this approach is that since only you who have the private key, nobody can forge your identity; and if the public key looks very random, nobody really knows who you are.
Another advantage is the decentralized identity management.
That is, anybody can create a new identity at anytime.
In fact, you can make as many identities as you want.
There's no central point of control or coordination.
These public key-based identities are called addresses in Bitcoin
### Cryptocurrency Quiz
Before we discuss cryptocurrency, let's have a quiz.
Select or choose statements with regards to cryptocurrency.
### Cryptocurrency Quiz Solution
First, the security of cryptocurrency ledgers depends on the honesty of its miners.
This is true, and we will discuss some of the details later.
Second, most cryptocurrencies are designed to maintain production to keep inflation in check.
This is false. Most cryptocurrencies are designed to reduce production mimicking the markets of precious metals.
Third, since cryptocurrencies are pseudo-anonymous, it is okay that they are more susceptible to law enforcement seizure.
This is false. Cryptocurrencies are pseudo-anonymous and they are less susceptible to law enforcement seizure.
### Simple Cryptocurrencies
Now let's start with very simple cryptocurrencies.
GoofyCoin is about the simplest cryptocurrency we can imagine.
There are just two rules of GoofyCoin.
The first rule is that Goofy can create new coins anytime he wants and the second rule is that the newly created coins belong to Goofy.
To create a coin, Goofy generates a uniqueCoinID, that is, ID that he's never used before.
Then he construct a string, CreateCoin[uniqueCoinID].
He then computes the digital signature of the string using his private signing key.
He then computes the signature on this string using his private signing key.
The string, together with his signature is a coin.
Anyone can verify that the coin contains
Goofy's valid signature of a CreateCoin statement and is therefore a valid coin.
Another rule of GoofyCoin is that whoever owns a coin can transfer the coin to someone else.
Transferring a coin is not simply a matter of sending a coin data structure to the recipient, it is done using cryptographic operations.
Let's say Goofy wants to transfer a coin that he equated to Alice.
To do this, he creates a new statement that says "Pay this to Alice" where this is a hash pointer that references the coin that he created and that he wants to transfer to Alice.
As we discussed earlier, identities are just public keys and therefore
Alice here is really the public key of Alice.
Goofy also signs the statement because he owns the coin and therefore he has to sign any transaction that spends the coin.
Let's say Goofy wants to transfer a coin that he created to Alice.
To do this, he creates a new statement that says,
"Pay this to Alice" where this is hash a pointer that references the coin that he created and then he wants to transfer to Alice.
As we have discussed earlier, identities are just public keys and therefore
Alice here is represented by the public key of Alice.
Goofy also signs the string that represents this transfer statement.
That is, since Goofy is the original owner of the coin, he has a sign any transaction that spends the coin.
Once this data structure in particular with Goofy signature is created,
Alice now owns the coin.
She can prove to anyone that she owns the coin because she can present the data structure with Goofy's valid signature.
In particular, this data structure contains not only the statement signed by Goofy, it also points to a very coin that was owned by Goofy.
Therefore, anyone can verify that this transfer is valid and that Alice is now the new owner of the coin.
Once Alice owns the coin, she can spend it in turn.
To do this, she creates a statement that says,
"Pay this to Bob's public key" where this is a hash pointer to the coin that was owned by her and of course, she signs the statement.
Now Bob owns the coin and anyone can verify that Bob is really the new owner.
That is, anyone can follow the chain of hash pointers to the coin's creation and verify that at each step, the rightful owner signed a statement that says,
"Pay this coin to a new owner".
### Double Spending Attack
Let's say Alice pass a coin to Bob by sending her a sign statement to Bob, but didn't tell anyone else.
She could create another sign statement that pays the very same coin to Chuck.
To Chuck, this would appear to be a perfectly valid transaction, and now he thinks he's the owner of the coin.
Bob and Chuck would both have valid-looking claims to be the owner of this coin.
This is called a double spending attack.
That is, Alice is spending the same coin twice.
Intuitively, we know coins are not supposed to work this way.
In fact, double spending attacks are one of the key problems to any cryptocurrency has to solve.
GoofyCoin does not solve the double spending attack, and therefore, it is not secure.
GoofyCoin is simple, and its mechanism for transferring coins is very similar to Bitcoin.
But because it is insecure, it is not a cryptocurrency.
### Wallet Quiz
Now let's do a quiz on digital wallets.
Match the characteristics of each wallet, with a name.
### Wallet Quiz Solution
First, a wallet connected to the internet.
This is called a hot wallet.
Second, the wallet is offline.
This is called the cold wallet.
Third, used on laptops and personal computers.
These are the desktop wallets.
Fourth, QR code capable with instant payments.
These are the mobile wallets.
Fifth, wallets provided on the cloud.
These are the online wallets.
Developers make use of top grade cryptography.
These are the hardware wallets.
### Scrooge Coin
To solve the double spending problem, we will design another cryptocurrency, which we will call Scrooge Coin.
Scrooge Coin is build of Goofy Coin, but it is more complicated in terms of data structures.
The first key idea is that a designated entity called Scrooge, publishes an append-only ledger that contains, the history of all the transactions that have happened.
The append-only property ensures that any data written to this ledger will remain forever.
If the ledger is truly append-only, we can use it to defend against double-spending by requiring that all transactions to be written to the larger before they accepted.
That way, it will be visible to anyone if coins were previously sent to a different owner.
To implement this append-only feature,
Scrooge can be a blockchain that he will sign.
This blockchain is a series of data blocks.
Each with one transaction or multiple transactions, each block contains the IDs of the transactions, the contents of the transactions, and a hash pointer to the previous block.
Scrooge signs a final hash pointer, which binds all the data in the entire blockchain and then publishes the signature along with the blockchain.
In Scrooge Coin, a transaction is only valid if it is in the blockchain signed by Scrooge.
Anybody can verify that a transaction was endorsed by Scrooge, by checking Scrooge's signature on the block that it appears in.
Scrooge makes sure that it doesn't endorse a transaction that harm suitable span on already spent coin.
Why do we need a blockchain with hash pointers in addition to having Scrooge sign each block?
This ensure the append-only property.
If Scrooge tries to add or remove a transaction to the history or change an existing transaction, it will affect all of the following blocks because of the hash pointers.
That is, as soon as someone is monitoring the latest hash pointer published by Scrooge, the change will be obvious and easy to catch.
In a system where Scrooge sign blocks individually, you will have to keep track of every single signature Scrooge ever issued.
A broad chain makes it easy for any two individuals to verify that they have observed the exactly same history of transactions signed by Scrooge.
### Scrooge Transactions
In Scrooge coin, there are two kinds of transactions: the first kind is CreateCoins.
In this example, a CreateCoins transaction creates multiple coins.
Each coin has a serial number within a transaction number.
Each transaction has an ID, and each coin has a serial number within a transaction.
Each coin has a value, meaning it's worth a certain number of Scrooge coins and also recipient, which is the recipient's public key.
In this example, a CreateCoins transaction creates multiple coins.
A transaction has a transaction ID.
Each coin has a serial number within a transaction.
Each coin has a value, that is, it's worth a certain number of Scrooge coins, and each coin has a recipient, which is the public key of the recipient.
A Scrooge coin transaction is always valid by definition if it is signed by Scrooge.
The second kind of transaction is called PayCoins.
It consumes some coins, that is, destroy them and creates new coins of the same total value.
The new coins might belong to different people, that is, different public keys.
This transaction has to be signed by everyone who's paying in a coin, that is, if you're the owner of one of the coins, there's going to be consumed in this transaction, then you have to sign this transaction to say that you're really okay with spending this coin.
The rules of Scrooge coin say that a PayCoins transaction is valid if four things are true.
First, the consumed coins are valid.
They really were created in previous transactions.
Second, the consumed coins were not already consumed in some previous transaction, that is, this is not a double-spending.
Third, the total value of the coins that come out of this transaction is equal to the total value of the coins that went in, that is, only Scrooge can create new value.
Forth, the transaction is correctly signed by owners of all the consumed coins.
If all of these conditions are met, then this PayCoins transaction is valid and Scrooge will accept it.
He'll write it into the history by appending it to the blockchain, after which everyone can see that this transaction has happened.
It is only at this point that the participants can accept that this transaction has actually occurred.
### Centralization Problem
Now we come to the core problem with ScroogeCoin.
ScroogeCoin will work in a sense that people can see which coins are valid.
It prevents double spending because everyone can look into the blockchain and see that all the transactions are valid and that every coin is consumed only once.
But the problem is that Scrooge has too much influence.
He cannot create fake transactions because he cannot afford other people's signatures.
But Scrooge could stop endorsing transactions for some users denying their service and making their coins unspendable, or Scrooge can be greedy and he could refuse to publish transactions unless he gets a fee.
Scrooge can of course create as many new coins for himself as he wants.
The problem here is centralization.
Although Scrooge is happy with the system, the users might not be.
Cryptocurrencies with a central authority have largely failed to take off and the main reason is that it is difficult for people to accept a cryptocurrency with a centralized authority.
Therefore, a key technical challenge is that can we create a cryptocurrency without a central authority.
To do this, we must figure out how we can agree upon a single published blockchain with history of all the transactions.
The users must all agree which transactions are valid and which transactions have actually occurred.
They also need to be able to assign IDs to things in a decentralized way.
Finally, the mining of new coins needs to be controlled in a decentralized way.
If we can solve all of these problems, then we can build a currency that will be like
ScroogeCoin but without a centralized authority.
In fact, this will be a system very much like Bitcoin.
### Top Cryptocurrency Failures Quiz
Now, let's do a quiz on cryptocurrency failures, match the description to its name.
### Top Cryptocurrency Failures Quiz Solution
First, provide a globally accessible blockchain through the use of nanosatellites.
This is Spacebit.
Second, a social networking platform that uses cryptocurrency to members that view ads in the app.
Popular in Uzbekistan.
This is GetGems.
Third, a decentralized peer-to-peer digital currency.
The community is friendly and vibrant, and known for charitable acts such as sending the 2014 Jamaican bobsled team to the Olympics.
This is Dogecoin.
Fourth, according to a published white paper, it used new variations on the blockchain that would result in new breed of cryptocurrency. That's Paycoin.
Fifth, the largest crowdfund in history.
An attacker exploited a vulnerability in its smart contract with losses totaling $50 million. This is DAO.
This quiz highlights some important points about cryptocurrency.
There is a strong market for it, but it is also a volatile field, and it is not an easy problem to solve.
To further muddy the water, at the end of 2016, there was talk of cryptocurrencies disappearing altogether.
### Bitcoins and Decentralization
The key technical problems we need to solve in bitcoins are, who maintains the ledger or the block chain, who can decide which transactions are valid, who creates new bitcoins, who determines how the rules of the system can change, and how do bitcoins acquire exchange values?
In addition, we need infrastructure support for bitcoins.
That includes exchange, wallet software, and service providers, and so on.
### Distributed Consensus
Since there's no centralized authority in Bitcoin, it is very important for us to understand how we can achieve distributed consensus.
In Bitcoin, there's no centralized authority and therefore we need to understand how we can achieve distributed consensus.
There are two basic requirements for distributed consensus.
First, the consensus protocol terminates when all correct nodes decide on a same value, and the value must have been proposed by some correct node.
There has been a lot of research on distributed consensus.
Now let's look at a unique setting of Bitcoin.
First, Bitcoin is a peer-to-peer system.
When Alice wants to pay Bob, she simply broadcasts a transaction to all Bitcoin nodes.
In fact, Alice doesn't know where Bob's computer really is and the computer may not be online.
Achieving consensus in a peer-to-peer system is very hard because some nodes may crash, some nodes may be malicious, the network is not perfect because not all pairs of nodes are connected and there are network faults and latency.
Now let's discuss how we can achieve consensus in Bitcoin.
The trick is to use incentive and this is possible only because Bitcoin is a currency and we embrace randomness or the imperfect nature of the peer to peer network by doing away with the exact termination point of the consensus protocol.
The protocol is that achieves consensus over a long timescale, for example, in about an hour.
The key idea here is implicit consensus.
At each round a random node is picked, this node then proposes the next block in the block chain.
Other nodes implicitly accept or reject this block.
If they accept they will extend the block chain from this block.
If they reject they will ignore this block and instead extend the block chain from an earlier block.
Every block here contains not only the transactions, but also a hash pointer to the block that it extends.
Here is a high level discussion of the consensus algorithm.
First, new transactions are broadcast to all nodes, each node collects new transactions into a block, at each round a random node gets a chance to broadcast its block.
Other nodes would accept this block if all of the transactions in it are valid, that is the signatures are valid and it is not double spend.
If the nodes accept this block, they will include a hash pointer to this block in the next block that they create.
### Bitcoin Safeguards
Now let's discuss the security of bitcoins.
First, can Alice steal bitcoins that belonged to another user?
This is not possible because there's no way
Alice can create a valid signature that spends that coin.
That is, as long as the underlying cryptography is solid,
Alice cannot steal bitcoins.
But can Alice launch a double spending attack?
Suppose Alice creates two transactions.
Here we use C subscript A to represent a coin owned by Alice.
Suppose in the first transaction she sends Bob a bitcoin.
In the second transaction,
Alice double spends by sending the same bitcoin to another node that she controls.
Of course, only one of these transactions can be included in the blockchain.
If the blockchain get extended from the second transaction, then Bob will be denied this bitcoin.
Suppose Bob is the merchant.
In order to protect himself from this attack,
Bob should wait until the transaction has multiple confirmations.
That is, there are multiple blogs extended from this block in the blockchain.
The most common heuristics is to wait until you hear six confirmations.
Let's summarize the safeguards in bitcoin.
The protection against invalid transactions is done through cryptography, but also enforced by consensus.
Protection against double-spending is purely by consensus.
There's no 100% guarantee that a transaction is in the consensus branch.
That is, the guarantee is probabilistic.
Again, the more confirmation you see, the higher probability that a transaction is valid.
### Proof of Work Quiz
Now, let's do a quiz on proof of work.
With regards to bitcoin, which of the following statements are true?
### Proof of Work Quiz Solution
First, proof of work is costly and time consuming to produce, this is true.
Second, proof of work is costly and time consuming to verify, this is false.
Third, to earn a coin, miners of bitcoins must complete some of the work in the block, this is false because minor must complete all the work in a block.
Fourth, changing a block requires degenerating all the successors and re-doing the work that they contain, this is true.
In fact, this is a temporary system property.
### Incentives and Proof of Work
Recall in a double spending example.
This is a valid transaction, and we want more confirmation of this block.
The question is, can we reward nodes that extend from this transaction block?
We cannot simply rely on honesty.
In fact, we should use incentive to promote honesty.
Since we are dealing with bitcoin which has value, we should be able to provide incentive to nodes that behave honestly.
### Bitcoin Incentive #1
The first incentive is that, for node to create a block, the node can create a special transaction and can choose the recipient of this transaction.
Typically, that's itself.
In particular, this coin creation transaction, the value is fixed as, for example, 25 bitcoins.
On the other hand, the block creator can collect this reward only if the block is accepted by the nodes.
That means, this block ends up in the long-term consensus branch.
Again, block reward is how bitcoins are created, but there are a finite supply of bitcoins.
Unless we change the rules, bitcoins can run out in the year 2040.
### Bitcoin Incentive #2
Another incentive that Bitcoin can provide is the so-called transaction fees.
Suppose we have a lot of new Bitcoins, then we'll now create a new block.
How do we reward this node?
Remember, a block contains transaction and therefore this block creator can collect transaction fees.
That is, the creator of transactions can choose to make output value less than input value.
The difference is the fee paid to the block creator.
Currently, this is like a tip.
But in the future, when Bitcoins run out, this may become monetary.
### Sybil Attack Quiz
Before we discuss the remaining problems with Bitcoin, let's do a quick review of Sybil attack.
Which statements are true?
### Sybil Attack Quiz Solution
First, the attacker creates a lot of fake identities and use them to change voting outcomes and control the network. This is true.
Second, a Sybil attack is designed to attack reputation system in a peer-to-peer network.
This is also true. Third, Sybil attack can be stopped if users are willing to give up anonymity. This is also true.
### Bitcoin Remaining Problems
There are several remaining problems with Bitcoin.
The first one is, how do we pick a random node?
Second, the system can become unstable if everybody wants to run a Bitcoin code in order to capture some of these rewards.
Third, how can we prevent an adversary from creating a large number of Sybil nodes to try to subvert the consensus protocol?
### Proof of Work
To select a random node, we can select nodes in proportion to resource that no one can monopolize.
In particular, we can use proof of work to select a node that is in proportion to computing power.
Alternatively, we can select nodes in proportion to ownership.
### Hash Puzzles
In Bitcoin, we use proof-of-work.
To create a block, a no finds a nonce such that the hash of the nonce with a hash pointer to the previous block and all the transactions in this block is very small.
Specifically, this hash value has to be smaller than a target value.
With this proof-of-work, if Alice has 100 times more computing power than Bob, it doesn't mean that she always wins the race of finding this nonce.
It means that she has about a 99 percent chance of winning.
In the long run, Bob can still create one percent of the blocks.
### PoW Properties
Because the target hash value is very small, it is very hard to find a correct nonce.
In fact, only the nodes with a lot of computing power these are kind of miners would do this proof of work.
Another nice property is that we can adjust the cost of proof of work.
For example, if the goal is to be able to create one block every 10 minutes, then the nodes can automatically recalculate the target hash value every two weeks.
It is obvious that probability that Alice will win the next block depends on the fraction of global computing hash power she can choose.
Therefore, the key security assumption is that attacks are infeasible if the majority of the miners weighted by hash power follow the protocol.
In other words, the majority of the miners weighted by hash power are honest.
It is obvious that proof of work is very easy to verify.
In particular, the nonce value has to be published as part of the bulk.
Therefore, other miners can simply verify that the hash value is smaller than target hash value.
Obviously, proof of work can be used as incentive when the mining reward is greater than the mining cost.
### Bitcoin Summation
To summarize this lesson, let's think about what a 51 percent attacker can do, that is, an attacker that controls 51 percent of the computing power.
Can the attacker steal Bitcoins?
No, because digital signatures can prevent this.
Can the attacker suppress some transactions from the blockchain?
Yes, because this attacker can refuse to extend from that block.
Can the attacker suppress transactions from Peer-2-Peer network?
No, because the transitions are broadcasted to Peer-2- Peer network.
Can they change the block reward?
No. That is determined by the whole system.
Can the attacker destroy confidence in Bitcoin?
Yes. For example, by refusing to extend from the valid block, then Bitcoin may become useless for valid transactions.

---
&nbsp; \pagebreak
## 10a - ML-For-Security

### Introduction
In this lesson, we will review machine learning, then use it to determine if a network flow is benign anomaly or adversarial.
The goal of applying machine learning to intrusion and detection is to be able to automatically and quickly identify new attacks.
The earlier we can detect bad behavior, the faster we can stop it.
### Data Analysis Quiz
Let's start with a quiz on data analysis.
Match the type of analytics to its characteristic.
The types are anomaly detection, hybrid, or misuse detection.
### Data Analysis Quiz Solution
The first one, model normal network and system behavior and identify deviations from the norm.
This is anomaly detection.
Second, combination of misuse and anomaly detection, this is hybrid detection.
The third one, detect known attacks using signatures of those attacks, this is misused detection.
The forth one, can detect known types of attacks without generating a lot of false positives, this is misuse detection.
The last one, have the ability to detect zero-day attacks, this is anomaly detection.
### Machine Learning Review
Let's have a quick overview of machine learning.
The task of machine learning is that, given training examples, we would learn a function that can predict the output.
Then, once we learn this function, we can apply it to testing examples and this function can then produce the output.
For example, the input can be fruits and the output can be the names of the fruits.
For example, is it an apple or orange?
A partition function will be able to analyze the features of these fruits and determine whether it is apple versus orange.
The first step in machine learning is training.
Here, the Xs are the examples and the Ys are the labels of these examples.
Then, the machine learning algorithm is going to produce the best possible function by minimizing the prediction error on this training data set.
We're going to discuss a few example machine learning algorithms.
In a testing phase, we apply the learned function to a set of test data which was not used in training, and the function should be able to produce predicted value of Y given X.
Ideally, data used in machine learning should reflect the real world.
Therefore, we use a process to draw data from the real-world application.
Then, that data is randomly split into a training data set and test data set.
We can then apply a machine learning algorithm to a training data to learn the particular function that can be applied to test dataset.
### Machine Learning Example
Here is an example of machine learning.
Suppose you want to learn the name or predict the name of an object, for machine learning purpose, these objects are represented as feature vectors of their images.
For example, apple, tomato, and cow, they're all represented as feature vectors, and then our function based on these feature vectors can predict the type of the object.
So, let's go over the steps in this machine learning example.
We start with the images of these objects, we then make exact features from these images so that each of these objects now is represented as a feature vector.
Of course, we put the correct label to each object.
For example, all these are apples, all these are pears, and so on.
Then, once we have the objects represented as feature vectors with their labels, then we can apply machine learning algorithm to chain a predictive function.
This predictive function is the learned model.
In testing, again, we start with the image of an object, we extract the same set of image features as in chaining.
That is, now the object is represented as a feature vector.
We then apply the learned model into this feature vector.
The learned model which is a predictive function is going to tell us the prediction or the type of this object.
### Machine Learning Features
The features using machine learning are very much application-dependent.
For images, these are useful features: the raw pixels, the histogram, and GIST, which is a representation of the scene, and so on.
We are going to discuss features useful for network monitoring later.
### Generalization
A good machine learning model should be able to generalize from the data that it was trained on to new test data set.
That is, we don't want to just learn the data from the training data set.
That is, given the objects in a training data set, for example, the different apples here, we want the machine learning algorithm to be able to learn the general characteristics of the apples so that given an image of apple that was not previously seen in the training data set, the learned model is able to correctly predict that it is indeed an apple.
In short, generalization is the most important property of machine learning.
### ML Types Quiz
Let's do a quiz on different types of machine learning.
Match the machine learning type to its characteristic.
Supervised, Semi-supervised, or Unsupervised.
### ML Types Quiz Solution
The first one, the main task is to find patterns, structures or knowledge in unlabeled data that is unsupervised because the data is not labeled.
That is the machine learning algorithm is not told which label belongs to which data.
Second, the task is to find the function or model that explains the data.
This is supervised because the data is labeled and machine-learning is going to produce a function that model the relationship between the data and its label.
Third, some of the data is labeled during acquisition.
This is semi-supervised.
### Performance Measures
Now, let's discuss some of the key performance metrics of machine learning.
The error rate is the fraction of false predictions.
Accuracy is the fraction of correct predictions.
Precision is a fraction of correct predictions among all examples predicted to be positive.
Recall is the fraction of correct predictions among all real positive examples.
Precision and recall are not limited to two class or positive versus negative problems.
That is, they can be generalized into multi-class applications.
### Classification Problem
Many machine learning applications or classification problems, that is the training data set contains records with attributes or features and class labels.
Then, the machine learning algorithm is to produce a model that would output the class label based on a set of attributes or features.
Once we have this model, we can then use it to classify future data.
### Decision Tree Learning
Now, let's discuss a few examples of classification models.
The first one is decision tree, here the training data is repeatedly petitioned until all examples in each petition belong to one class.
The decision tree can also be thought of as a set of rules that describe the decision logic.
Let's go over a simple example, the application here is to learn the decision tree to decide whether we should play tennis or not.
So the class label here is yes to no to play tennis, and the features or attributes include the weather conditions, and here is the decision tree produced by a machine learning algorithm.
Again, a decision tree can be represented as a set of rules.
For example, if you see outlook equal to sunny and humidity equal to normal, then yes we play tennis.
If the outlook is overcast then also yes to play tennis, or if the outlook is rain and wind is weak, then we also say yes to play tennis.
Here's a high level overview of the process of building a decision tree.
We first find the best attributes that can serve as the root.
Then we break-up the training dataset into subsets based on the values of this root attribute, that is, we grow from the root into branches.
Therefore each subset we test the remaining attributes to see which is best at petitioning this subset, that is, for each branch, we test attributes to determine how to best grow into branches.
We continue this process until all examples in a subset belong to one class, or there's no more attributes left to further permission to subset.
In this case, the default cast label is the majority.
Now the question is, how do we determine which attribute is best at partitioning a set into subsets?
We use entropy and information gain to determine this.
The entropy of a set is the minimal number of bits needed to represent examples in this set according to their class labels.
Therefore, roughly speaking, the entropy of a set represents how pure the examples are in this set.
That is, if the examples of this set are evenly distributed into different classes, then the entropy is the maximum and if the examples are all in a single class, then the entropy is the minimum.
In order to determine which attribute is best at partitioning a set, we compute its information gain.
As you can see from this formula, a high information gain value for attribute A, means that A is better as separating samples in a set S according to their classification, that is, using A S a petition into purer subsets.
Therefore, we should select the attribute that has the highest information gain and use it to partition a set.
### Decision Tree Quiz
Now, let's do a quiz on Decision Tree.
Select the true statements with regards to decision tree based detection models.
That is if we use a decision tree based models for intrusion detection, which statements are true?
### Decision Tree Quiz Solution
First, can it supplement honeypot analysis?
Yes. Can it supplement penetration testing?
Yes. Can it highlight or detect malicious traffic?
Yes, and therefore the third statement is false.
Fourth, can it characterize known scanning activity?
Yes, and therefore the fourth statement is false.
The last one, can it detect previously unknown network anomalies? The answer is yes.
### Clustering
Clustering can also be used for classification.
In clustering, we assigned training examples into different clusters based on some distance measure.
That is examples in the same cluster are more similar to each other than examples from different clusters.
Typically, we defined some distance function to measure similarity.
Here's an overview of the clustering process.
Typically, we predetermine the number of clusters.
We also start with seed clusters, each with one element.
That is, each seed is a representative example of a cluster.
They may assign a samples to these C clusters based on distance measures, then we adjust or find a new centroids.
A centroid is the center of the cluster according to distance measure.
Then based on the new centroids, we are just cluster membership, so the examples are assigned to the best fit clusters.
The example here belong to this cluster because it is closer to the centroid than to the centroid and that centroid.
In other words, cluster membership is based on distance to the centroid of the cluster.
We continue this process of finding new centroids and adjusting cluster membership, until the customers converge.
That is, there's no more changes in the cluster membership.
Once the clusters are finalized, then each cluster can be represented by its centroid.
Given a test data, it is assigned to a cluster if its distance to the centroid is the shortest.
### Define the ML Problem Quiz
Now, let's do a quiz.
The context is applying machine learning to the problem of detecting bonded command control.
Supposed we decide to use supervised learning, that means data should be labeled, and we want a high percentage of network flows to be correctly classified.
The question is which type of data do we need for C&C Protocol Detection?
### Define the ML Problem Quiz Solution
We need label data.
That is, we need known C&C communication examples.
### Classifiers
As a way to summarize, classifiers are very useful to many applications, including security applications, such as intrusion detection.
However, we should be reminded that, machine learning algorithms are just tools.
Therefore, we need to use them carefully.
We should always try simple classifiers first.
Most specifically, it is more important to have small features than complicated or smart classifiers.
The reason is that, smart features, capture the domain knowledge.
This is the key to producing effective classifiers.
On the other hand, if we have a lot of data or wide variety of data, we can use more powerful classifiers.
The problem of intrusion detection, can be considered as, a classification problem.
Suppose, we are monitoring network traffic.
The traffic can contain normal traffic and various types of attack traffic.
The process of intrusion detection, is to determine, among this set of all traffic, which ones are normal, which ones belong to different types of attacks.
In other words, intrusion detection, is about classifying each number flow into normal or different attack types.
Therefore, it is natural to think that, we can apply machine learning algorithm, to learn a classifier, to detect intrusions.
That is, given a traffic data which has higher entropy, because it is mixed with intrusions and normal traffic.
Our goal is to partition the data into subsets that each has a pure class.
Either normal or one of the attack types.
As we have discussed in decision tree, we need to use features that has high information gain, in this process of partitioning the original data set into subsets of pure classes.
So, that's the high level intuition, of applying machine learning, to the problem of intrusion detection.
Now let's discuss some details.
### Audit Data Preprocessing
We start with raw data captured from the network tab, for example, your pickup data.
From the pickup data, we can summarize the data into connection records.
Each record has a set of attributes, for example, time stamp, duration, source IP, destination IP, number of bytes, the service, and the flag, and so on.
For example, SF means the connection has gone through both SYN and FIN, and REJ means that the connection request has been rejected.
As we have discussed earlier, having small features is the key to building effective classification models.
This is known as the feature construction problem.
In the context of intrusion detection, the attributes or features of the connection records are not very useful.
For example, if you look at SYN flag, that means, we only see the initial SYN packet.
Of course, with SYN flag, we'll see a lot of connection attempts with SYN flag.
Of course, normal data can also have this S0 flag, for example, because the connection request or response is lost.
That is, by looking at the feature flag, it is not sufficient to detect intrusion.
On the other hand, if you look at the percentage of
S0 flag connections to particular host, then we can see that this feature can distinguish intrusion from normal.
In other words, this feature has high information gain.
The problem is that this feature is not in the original feature set, which means we need to construct features that have high information gains.
So, the question is how do we construct features that have high information gains?
That is, features that are useful to distinguish normal versus intrusions.
Our approach is to use temporal and statistical patterns associated with intrusions, for example, a lot of S0 connections to the same service and host, within a short period of time.
This pattern is associated with SYN flag.
Once we have these patterns, we can then construct features accordingly that can be used to detect these intrusions.
### Building ID Models
Here's a high level overview of this process.
We start with raw audit data.
For example, packets.
We summarize data into connection records.
Then we find frequent patterns, and then we compare the patterns to determine the unique patterns associated with intuitions.
We then construct features according to these patterns.
With these features, we can learn classification models.
This process is iterative.
In fact, each step can iterate it over and over to improve performance.
### Mining Patterns
Now, let's discuss how do we find patterns.
We use data mining algorithms to find patterns.
We first find the associations among the features.
For example, this association tells us that there are a lot of S0 HTTP connections.
We then find the patterns that describe how the associations tend to appear in a sequence.
For example, this pattern says that, if you see the first two, there's 80 percent chance that you will see the third one, and all these are within a two second terminal.
### Basic Algorithms
The basic algorithms are the association rules and frequent episodes.
These algorithms can produce many useless patterns.
For example, these algorithms can produce associations and frequent sequences involving source bytes and destination bytes.
These patterns are not useful for intrusion detection.
The reason is that, these patterns don't even involve more important attributes such as a service and the flag.
Therefore, we modify the basic algorithms, so that they only produce relevant or useful patterns.
The intuition is that, development patterns must describe these essential features.
More specifically, we use some of these essential features as a so-called axis attributes, or reference attributes, to constrain how the patterns can be computed.
### Axis Algorithms
An axis attribute is typically the most important attribute, for example, the service.
An association must contain an axis attribute.
Therefore, we can eliminate patterns that describe associations among non-essential attributes.
Once we compute associations involving axis attributes, then we can compute sequential patterns involving these associations, and that's how we compute sequential patterns.
Here's an example. We use service as the axis attribute, then we can compute a number of associations.
For example, there's frequent association of S zero and http.
We then use reference attribute to compute a sequence of related associations.
These associations in a sequence all refer to the same reference subject because they are essentially a sequence of related actions.
For example, in this sequential pattern, all associations are referring to the same destination host.
Again, the reference attribute can be used as a constraint to filter out patterns, that are not useful for intrusion detection.
### Patterns
After we compute the frequent patterns from the normal data and from the intrusion data, we can then compare and identify the unique patterns that are from the intrusion data.
We can then use these patterns to construct futures to build classifiers.
We call the axis and reference attributes the anatomy of an attack and the emergence attributes are those that are independent of the axis and reference attributes.
Since our patterns are frequent and sequential in nature, we apply these operators to add the corresponding, temporal and statistical features.
To summarize, we mind patterns from both the intrusion and a normal datasets and compare the patterns.
We identify the patterns associated with only the intrusion dataset.
We construct futures according to these patterns and add these features into the training dataset.
We can then apply a machine learning algorithm to learn a classifier that can detect intrusions.
### Dataset Collection Quiz
Now let's do a quiz. Suppose we want to select data set to train a classifier to detect intrusions, what are the considerations?
### Dataset Collection Quiz Solution
First, we should recognize that, there's no perfect way of labeling data and therefore there's really no perfect IDS dataset.
What we can do, is select a baseline dataset for network.
Then, also use a dataset, that has a range of intuition examples.
### Construction Example
Let's consider an example of feature construction.
Suppose here's the set of connection records associated with syn flood.
Using service as the access attribute and destination host as a reference attribute, we can compute a frequent pattern.
Based on this pattern, we can construct these following features, count the connections to the same destination host in the past two seconds, and among these connections, the percentage with the same service, and the percentage that has the S0 flag.
### DARPA Evaluation
Now, let's discuss an evaluation of our approach.
We use the darpa evolution dataset.
There are 38 attack types in the data and these attack types are in four categories, denial service, probing, remote to local, and user to root.
In particular, remote to local means that gaining local axis and user to root means that gaining superuser privilege.
In this evaluation, training dataset is provided but 40 percent of the attack types are only in test data.
That is these attack types are new to the intrusion detection systems.
Here are the features that we defined and constructed for each connection record.
The intrinsic features such as protocol, duration and flag, these are the ones that are inherent to any connection.
In other words, they can be used for many applications not just intrusion detection.
We construct a feature for the purpose of intrusion detection.
The content features are based on analysis of the payload.
For example, we can tell how many failed login attempts.
Whether the login was successful or not, number of root shells, whether a su root has been attempted, number of access to security control files and so on.
We compute a frequent patterns from the connection record and then we construct temporal and statistical features accordingly.
These include number of connections to the same destination host as the current connection in the past two seconds and among these connections, number of rejected connections, number of connections with syn errors, number of different services, percentage of connections they have the same service, percentage of different or unique services, and number of connections they have the same service as the current connection and among these connections, number of rejected conditions, number of connections with syn errors, number of different destination hosts, percentage of connections they have the same destination host, percentage of different or unique designation hosts.
Here we showed examples of the values of content features interconnection record.
We also label each connection as normal or one of the attacks.
Here is some example rules produced by machine learning.
For example, a buffer overflow attack can be detected because there are a number of indicators of compromise.
A root shell has to be attained and su root has not be attempted.
Here we show examples of the values of traffic features.
Again, each connection record is labeled as normal or one of the attacks, and here are some example rules produced by machine learning.
For example, in a smurf attack
ICMP echo request has been sent to the same service on the same host.
Satan is a probing attack and therefore there are many different ports or services being probed and since many of them are closed, many connection attempts are rejected.
### TCP Dump Overall
This shows that our data mining and machine learning-based approach performed quite well.
Other approaches are all based on rules hand-coded by experts.

---
&nbsp; \pagebreak
## 11a - Cloud-Computing-VM-Monitoring

### Introduction to Network Security
Welcome to Network Security.
When we think about network security, we need to think about ways we can protect our most valuable network assets, data, and access to the data.
We need to protect it from misuse, authorized modification, and destruction.
We need to make sure assets is restricted only to those who are granted access.
Sun Tzu said in the Art of War,
Know thy self, know thy enemy.
A thousand battles and a thousand victories.
Now that may seem a little extreme but it is not.
We are at war.
Our enemies are hackers, scammers, and script kitties off the internet.
The battlefield is our networks and the price is our data.
Network security requires us to use all hardware and software means at our disposal to protect our assets and to effectively deploy them.
In this course, we're going to learn about our enemies, their motivations, methods, and attacks.
We also going to investigate how defensive weapons and counter attacks.
Once you have completed this course, you will have a clear understanding of who, how, and hopefully even why our networks are under attack.
And what you must do to prevent or at least minimize the damage.
### Introduction to Large Scale Attacks
We begin our discussion of network security with an attack that all of us are familiar with.
Large scale attacks.
Specifically, distributed denial of service attacks, and malware based attacks.
We will discuss the methods used and the security weaknesses that are exploited in these attacks.
### Denial of Service Taxonomy Quiz One
Let's do a quick review of the denial of service.
Match the denial of service attack classification with its description.
### Denial of Service Taxonomy Quiz One Solution
For random scanning, it means that each compromised computer probes random addresses.
For permutation scanning, all compromised computers share a common pseudo-random permutation of the IP address space.
Signpost scanning uses the communication patterns of the compromised computer to find new target.
In hitlist scanning, a portion of a list of targets is supplied to a compromised computer.
### Denial of Service Taxonomy Quiz Two
Now let's do another quiz.
Again, match the denial of service attack classification with its description.
### Denial of Service Taxonomy Quiz Two Solution
Subnet spoofing means that the spoof address is within a given address space.
Random spoofing means that the spoof address is a randomly generated 32-bit address.
Fixed spoofing means that the spoof address is the address of a target.
### Denial of Service Taxonomy Quiz Three
Here's another quiz.
Again, let's match the denial of service attack classification with this description.
### Denial of Service Taxonomy Quiz Three Solution
If the denial-of-service attack targets server application, it means that the target is a specific application on a target server.
If the target is Network Access, that means the attack is used to overload or crash the communication mechanism of a network, so that Network Access now is unavailable.
If the target is Infrastructure, that means the attack is aimed at the crucial services of the global
Internet, for example, the core routers.
### Network DoS
Now let's discuss network denial of service attack in some more details.
The goal of network denial of service attack is to take out a large site such as a web server with as little computing power as possible.
So how is network denial of service accomplished?
One of the main approaches is amplification.
This means that the attacker only needs to send a small number of packets and can achieve a big effect such as rendering the targeted site unavailable.
There are two types of amplification attacks.
The first type is to exploit a bug or vulnerability on the server.
For example, if there's a design flaw or implementation error on the server code, then the attacker machine can send a few packets that contain input that would trigger the bug and then crash the server.
And of course, when the server program is crashed, then the server become unavailable.
Another type of denial of service attack is to send a flood of packets.
For example, an attacker can use a large botnet to send a lot of requests to the server.
Network denial of service attack can happen at any network layer.
As a quick review, there are multiple layers in a network stack.
For example, denial of service attack can happen at the link layer.
This means that the attacker simply sends a lot of traffic to saturate the link.
Denial of service attack can happen at a TCP/UDP layer or the transport layer.
For example, the server needs to use memory to hold the state of TCP connections, so the attacker can send a lot of TCP packets to exhaust the server's memory.
Denial of service attack can also happen at the application layer.
For example, the attacker can request the server application to fetch a large amount of data.
And if there are many such requests, the server's resources will be exhausted.
The sad truth is that the current Internet design cannot handle distributed denial of service attacks.
### Amplification Quiz
Now let's go over an application example and then do a quiz.
One example of attacks is to use the NTP, Network Time Protocol.
This protocol is used to synchronize machines to the clocks.
For example on a Mac, the day and time are set by an NTP server run by Apple.
When a computer request the time from the NTP server, the server responds with the correct time and date.
In NTP, the data volume of the request from a machine is much smaller than the response from the server.
Now you can imagine how NTP can be used for the now service attack.
So with that background, let's do a quiz.
Which of these are reasons why the UDP-based NTP protocol is particularly vulnerable to amplification attacks?
### Random Initial Sequence Numbers
We call that in TCP handshake, the first packet from the client and the first packet from the server have the sequence numbers randomly generated.
This is very important.
Suppose, these initial sequence numbers are predictable.
Then the attacker can forge a source ID address and still be able to finish the TCP handshake and establish a TCP session.
And this will break IP-based authentication such as SPF, which is Sender Policy Framework that is used to authenticate email.
We can use an example to illustrate the importance of having random initial sequence numbers.
Suppose there's an attacker and he wants to forge the source IP address of the victim to create a TCP session.
So the attacker sends the initial
SYN packet to the server and forge the source IP address to be from the victim.
Now the server is going to send a SYN/ACK packet to the victim with its own sequence number.
Of course, the attacker did not receive the SYN/ACK packet because the SYN/ACK packet is sent to the victim.
Now if this sequence number is predictable, then the attacker can still send ACK packet to ACK this SYN packet as if that the attacker had received the SYN/ACK packet.
And when a server receives this
ACK packet on its SYN/ACK packet, then the server knows that the connection should be established.
From this point on, the attacker can send command through the server and the server will think that the command is from its victim.
Because the victim and the server hasn't established TCP connection.
Here's an example of attacks on predictable sequence numbers, suppose the attacker can correctly guess the sequence number.
He can then send a reset packet.
This will terminate a connection and result in the null service attack.
### Protocols Quiz
Before we begin our discussion on routing security, let's do a quiz to refresh our knowledge of routing protocols.
Match the protocol with its description.
### Protocols Quiz Solution
Address Resolution Protocol or ARP is a protocol designed to map IP network addresses to the hardware addresses used by the data link protocol.
Open Shortest Path First or
OSPF is a protocol that uses a link state routing algorithm for interior routing.
Border Gateway Protocol or
BGP is a protocol designed to exchange routing and reachability information among autonomous systems or AS.
Here's an example of how op works.
Supposed a router received data with a destination IP address of a host within each local area network.
It needs to know the MAC address or the destination IP address in order to send the data to the host.
This is because machines on the same local area network identify each other via MAC addresses.
Here, the router sends an OP request asking for the MAC address of the specified IP address.
This request will reach all computers on a network because the destination MAC address is one there's accepted by all computers.
The ARP reply essentially says, hey,
I'm the host with the IP address and here's my MAC address.
On OSPF looks for the lowest cost path within nodes.
In this instance, let's assume that all the lengths are of the same cost.
What would be the shortest path between the node R3 and R5?
Obviously, the shortest path is to go from R3 to R4 and then, to R5.
In BPG, the autonomous systems exchange information through peer exchanges.
In this example, each AS talks to a peer to learn the address prefix of the computers within their peer network.
This helps the ASs to work together to determine how to route traffic from one network to the other.
### Routing Security
Again, from the perspective of routing, the Internet is a collection of domains or autonomous systems.
An autonomous system is a connected group of computers where their
IP addresses share some common prefixes, and they're using a single or common routing policy.
The routing between these domains is determined by BGP.
And the routing within each domain is determined by protocols such as OSPF.
Now let's discuss the security of routing protocols.
Recall that the ARP protocol maps IP address to MAC address.
Now, suppose there's an ARP request asking for the MAC address for node B's IP address.
This ARP request is broadcasted to the whole network.
Now if node A is malicious, it can send ARP reply to the gateway with its own Mac address.
If this reply arrives at the gateway before the reply of node B does, then the gateway will think that node A is node B.
Which means that node A now is right in the middle, and you can read or inject packets into node B sessions.
The Border Gateway Protocol, or BGP, decides the routing policy between autonomous systems.
However, in BGP routing information, and in particular route updates, are not authenticated.
Therefore, through a false advertisement, an attacker can cause traffic to a victim host to instead route to the attacker's own address.
There are plenty of examples illustrating the danger of false route advertisement.
Essentially, anyone can hijack route to victim
### BGP
Let's illustrate how BGP works.
Here, the nodes are the autonomous systems.
And the edges represent peering relations.
Here, nod 2 provides transit to node 7, and this information is propagated, so all autonomous systems know how to reach node 7.
The main security issues of BGP are due to the fact that BGP path information is not authenticated which means that anyone can inject false advertisements and such advertisements will be propagated everywhere.
As a result, attackers can shape and route traffic to launch denial of service attacks, send spams and perform eavesdroppings.
Here's an example of BGP path hijacking.
Here's a normal or legitimate path.
And then, there was path hijacking event in February 2013.
In this attack, only the path of this direction is changed.
The other direction is not changed.
Therefore, if you are in DC, because this direction is not changed, you cannot tell by doing traceroute.
### BGP Attacks Quiz
Now, let's do a quiz on BGP attacks.
Match the attack to its characteristics.
### BGP Attacks Quiz Solution
Denial of service attack.
The attacker hacks the routing table and either adds a false route or kills a legitimate one.
Sniffing.
An attacker needs to control a device along the communication route.
To do this, the attacker can BGP to detour traffic through a malicious site.
Routing to endpoints in malicious networks.
This requires that the attacker redirect traffic away from a legitimate host to an attacker-controlled site.
Creating route instabilities.
This has not been exploited by attackers yet.
These instabilities are too unpredictable and can cause attacker to be affected by their own attack.
However, there is a possibility that script kiddies could begin to exploit them.
Revelation of network topologies.
This begins with attacker gaining access to the routing table and can, with patience, discover the peer relations among the ASs.
Now let's discuss some solutions to the BGP security issues.
One solution is around PKI, or Public Key Infrastructure.
Here, each AS obtains a certificate to certify each route origination authority from the regional Internet register, and then attach the ROA to path advertisement.
Essentially, each AS that advertise a path is a route origination authority.
Another solution is to use SBGP.
The main idea here is to sign every hop of a path advertisement.
### S BGP
Let's discuss S-BGP in more detail.
The users IPsec to protect the point-to-point router communication.
It also assumes PKI.
The reason is that it uses public key cotography to provide attestations.
In particular address attestation proves the authorization to advertise certain address blocks.
And route attestations proves the validation of the route update information.
And of course S-BGP requires repositories and tools to manage certificates.
The certificate's revocation lists and the address attestations.
Here's an example of address blocks advertised by autonomous system nodes seven.
That is as the routing information is being publicated. all the nodes need to know that nodes seven is responsible for these addresses.
Now let's discuss attestation in more detail.
In address attestation, the issuer is the organization that owns the address prefixes contained in the attestation and the subject is one or more ASS that are authorized to advertise these prefixes.
For example, this ASS are the organization's internet service providers.
In other words, an AS such as an ASP has to be authorized by the owner of the address blocks to advertise the route to these address blocks.
An address at the station includes the following information.
Essentially it certifies that the owner owns the address blocks and the owner authorizes the AS to advertise for this address blocks.
The owner uses his private key to sign the address blocks.
Address attestation is used to protect BGP from incorrect updates.
The second type of attestation is route attestation.
Here the issuer or the speaker is an AS and the subject or the listener is a transit AS.
Basically, route attestation allows
BGP speaker that receives a route advertisement to verify that each AS along the route has been authorized by the preceding AS along the path to advertise that route.
And that the originating AS has been authorized by the owner of each IP address prefix contained in the update to advertise these prefixes.
Route Attestation includes the following information.
The speakers certificate, the address block and the list of AS's, the neighbor, and the expiration date.
The signature guarantees that the organization owning the IP address space advertised in the update was allocated that address space through a chain of delegation originating at the eye can.
And this can protect BGP from incorrect updates.
In order to validate a route, an AS needs to perform address attestation for each organization owning the address block.
And also, route attestation for each AS along the path.
And of course, all the certificates must be available, and they must be valid.
### Introduction to Domain Name Servers
In this lesson, we will discuss domain name systems or DNS.
We will explore there weaknesses and the security measures that have been implemented to protect the internet.
### DNS
DNS or the domain name system is a hierarchical database.
There are root servers, top level domains, second level domains, third level domains, and so on.
Just for your information there are 13 DNS root name servers.
### Amplification Quiz Solution
As we already discussed, the volume of request from a computer is smaller than the response from the server.
That means a small command can generate a large response.
And the attack works because the attacker can send the request to a server by spoofing the IP address of the target.
So that the servers response is sent through target and that's how the attack works.
And it is difficult to ensure that the computers only communicate with legitimate NTP servers.
This means that it is not easy to figure out responses from NTP servers.
### DNS Lookup Example
A DNS Lookup is an iterative or recursive process carrying the hierarchy code database.
For example, suppose your browser is looking up www.cc.gatech.edu.
The local DNS service is handling this request of looking up the IP address of this domain name.
The query will start on the root or top level domain servers.
That is, the local DNS server asks the root and top level domain servers what is the IP address of www.cc.gatech.edu.
And these servers say, I don't know, but
I know the main server of gatech.edu.
So the local DNS server then asks gatech.edu DNS server what is the IP address of www.cc.gatech.edu.
And the gatech.edu DNS server says,
I don't know but
I know the name server cc.gatech.edu.
So finally, the name server cc.gatech.edu says,
I know the IP address of www.cc.gatech.edu and here it is.
So that's an example of looking up a domain name in most iterative or recursive queries to DNS servers.
There are several types of DNS records in the response to DNS query.
One is the NS record.
This points to a name server.
That is, this record contains the IP address of a name server such as gatech.edu.
And then there's A record.
This contains the address of the domain name in the original query.
For example, www.cc.gatech.edu.
And then there's MX record.
This contains the address of the mail server for the domain.
For example, mail.gatech.edu.
And finally, there's a TXT record.
It contains all the useful information about a domain.
For example, it can be used to distribute public keys.
### DNS Caching Quiz
Now let's do a quiz.
### DNS Caching Quiz Solution
As illustrated in the previous example, querying the IP address of a domain name can involve a number of steps.
To save time, the records are cached on a local server for reuse later.
For example, when the IP address of www.cc.gatech.edu has been obtained, the mapping of this IP address and the domain is cached so that the next time the browser is looking up www.cc.gatech.edu, the DNS server does not have to go out to look it up again because the mapping is already stored in the cache.
Obviously, this saves time.
On the other hand, each record, meaning the mapping of IP address and domain that's being stored in the DNS cache, has a TTL, or time-to-live.
And, when this TTL expires, the cache entry is invalid.
Which means, if the browser looks up www.cc.gatech.edu, after the TTL of the cache entry has expired, the DNS server, then has to go out and look it up again.
TTL is useful because a server, say www.cc.gatech.edu maybe moved to a new IP address.
So, you want the TTL to expire, so that the DNS servers can look up for the new mapping.
### Caching
As we have discussed, the DNS responses and in particular, the mapping between the IP address and a domain are cached so that we can save time on repeated queries.
The NS records of the domains are also cached.
Therefore, if the browser looks up www.ece.gatech.edu, the local DNS server only needs to start with gatech.edu instead of the root.
DNS servers can also cache the negative results such as a domain does not exist.
For example, if somebody misspelled gatech.edu to say gatech.ed, the DNS query response will be this domain does not exist.
And this result is cached.
So that, next time if somebody mistype again the same way, gatech.ed, the DNS cache can always say, hey this domain does not exist, without having to query it.
And all cache data, whether it's positive or negative response has a TTL.
### Basic DNS Vulnerabilities
Now let's discuss the main vulnerabilities of DNS.
First of all, we must be able to trust the domain name and address mapping provided by DNS.
In fact, many security policies depend on this.
For example, the same origin policy in browsers, or URL-based filtering.
Obviously if the host address mapping provided by DNS can be forged, then the traffic intended for the original legitimate host is now destined to the wrong or malicious host.
This means that the wrong or forged host can now intercept the legitimate traffic.
What if the host address mapping provided by DNS can be forged?
For example, instead of getting the IP address of gmail.com, the browser instead gets the IP address of evil.com.
The result is that, traffic will be routed to evil.com instead.
Which means evil.com can intercept traffic to gmail.com.
There are several ways to forge the host as just mapping.
For example, the attackers can compromise the DNS servers, including cache poisoning, which we're going to discuss shortly.
Or the attackers can control the access point or gateway and intercept DNS queries and forge a response.
A solution is to authenticate each request and response using cryptography.
And DNSsec is such a solution.
Now let's discuss attacks on the inner server, in particular cache poisoning.
The basic idea is that the attacker would provide to the local DNA server some false records and get the records cached.
For example, if the local DNS server queries the domain gmail.com and the attacker is able to inject a response with the IP address of evil.com and have that IP address of evil.com cached by the local DNS server and then subsequent traffic to gmail.com will be routed to evil.com.
The existing defense in DNS is the users 16-bit request ID to link a respond with a query.
That is, the attackers response must have the ID that matches the ID of the original query and we will discuss how an attacker can overcome this defense.
A DNS cache can be easily poisoned if the DNS server does not use the IDs properly, or the IDS are predictable
### DNS Quiz
Now let's do a quiz.
Select the true statements about DNS.
### DNS Quiz Solution
The first statement,
DNS stores IP address.
For security reasons, the domain name is stored somewhere else.
This is false.
DNS stores both the IP address and the domain name.
That's the whole point of providing the mapping between domain name and
IP address.
The second statement.
All domain names and IP addresses are stored at the Central Registry.
This is true.
When a new domain name is registered at a local DNS, it will also be copied to the Central Registry.
The third statement, it can take several days for information to propagate to all DNS servers.
This is true.
It takes anywhere from 12 to 36 hours to propagate information to all DNS servers worldwide.
### DNS Packet
Now let's take a closer look at the internals of DNS query and response.
Let's start with the format of a DNS packet.
There is the usual IP header.
There's a UDP header because DNS uses UDP, and the UDP payload is the actual DNS data.
One of the most important fields in DNS data is the query ID, which is a 16 bit random value.
A DNS query contains a query ID.
And a response also carries the ID.
Therefore, even though a DNS server may send out many, many queries at the same time, it can use the ID to link a response to a query.
That is, the response to a query will have the same ID of the query ID of the original query.
Now, let's look through an example.
Suppose a local DNS server is looking up for the domain www.unixvis.net on behalf of a browser.
So, this is the local DNS server.
It's going to send the query to one of the root service.
It sent a flag to say recursion desired.
That means it's asking the destination
DNS server to perform recursive queries on its behalf.
Here is the response from the root server.
The root server does not know the IP address of www.unixwiz.net.
So it provides the IP addresses of the next NS service.
And these are called glue records.
Let's look at this in more detail.
The response comes from the root server, back to the local DNS server.
It says that it's a response, the root server does not know the IP address of www.unixwiz.net, but it knows where to ask.
It responds with a series of
NS records that should know how to handle the original query.
Notice that both the domain names and
IP addresses of these named servers are provided.
Because this response is not the final answer to the original query, it sets this flag to zero to indicate that this is not authoritative.
And also because the root server is busy, it's not going to perform because of queries on behalf of the local DNS server.
That's why it sets this flag to indicate that it's not going to perform because of queries.
That is, the local DNS server should contact these named servers instead.
The final, or authoritative, response comes from the named server, linux.unixwiz.net.
And notice that now the authoritative flag is set to 1.
Notice that this final response contains the IP address of the domain www.unixwiz.net, which is the domain name contained in the original query.
And the TTL is one hour, which means this record will be cached and be valid for one hour.
And since these NS records are in the same second level domain, unixwiz.net, of the original queried domain, they are also cached.
### Poisoning Attacks
Now let's discuss DNC cache poisoning attacks in more detail.
Let's start with traditional poisoning attack.
Suppose the attacker wants to poison the cache of the DNS server at gartech.edu.
In particular, the attacker wants to forge the IP address of www.google.com.
The attacker first sends a query to the local DNS server.
This can be done, for example, through a compromised machine within gartech,edu.
The local DNS server is now going to perform a recursive query with the query ID 12345.
And at some point the main server, ns1.google.com, is going to provide an authoritative answer given the IP address of www.google.com with a matching query ID.
Now the attacker knows that this recursive query is taking place.
Because he has an inside hub that initiated the original lookup.
So the attacker is going to forge a response claiming it is from ns1.google.com.
And in that response it's going to use the IP address of evil.com instead of the real
IP address of www.google.com.
But the attacker does not know the real query ID, so all he can do is send a flood of responses, each with a guest query ID.
So this is a matter of the attacker being able to guess the correct query ID and reach the local
DNS server faster than the legitimate response from the real DNS server of Google.
If the attack succeeds, then the incorrect answer will be cached resulting in cache poisoning.
But if the attacker's attempt fails, the legitimate IP will be cached and the attacker has to wait for
TTL to expire before launching the whole attack again.
As you can see, the traditional poisoning attack is hard to successfully implement.
But then Kaminsky found an approach that's drastically more effective than the traditional attack.
The general approach is the same as the traditional attack.
But the key difference is the nature of the forged payload.
The intention of cache poisoning is to poison the final answer that is the A record with the IP address.
But what then Kaminsky discovered is that we can go up one level and hijack the authority records instead.
As in the previous example, let's assume that the attacker wants to poison the cache of the DNS server caltech.edu.
And he wants to forge the IP address of www.google.com.
But this time the inside help is going to send a query of a random domain within www.google.com.
For example, 12345678.www.google.com.
And as before the DNS Server is going to perform a recursive query.
Now the legitimate response, you say that this random domain does not exist.
But you will provide the IP address of www.google.com.
The attacker is attempting to do the same thing.
The goal is to have the DNS server cache this raw IP address.
And you may ask, what's new here?
Isn't the attacker facing the same challenge of guessing correctly the query ID before the response from
Google In the traditional attack.
When the first attempt fails, the attacker has a way for TTL to expire.
What's new here in the Kaminsky's Poisoning Attack is that when a first attempt fails, the attacker can start immediately again.
That is, it doesn't have two wait for
TTL to expire and the reason is he can simply use a different random domain and that will immediately result in another query.
So that he can flood the DNS server again.
That is, the attacker can repeatedly and continuously force the local DNS server to query a random domain.
And keep flooding the local DNS server until the poisoning attack succeeds.
Yet when you put it that, such Kaminsky's Poisoning Attack can succeed in mere ten seconds.
### DNS Defenses
So what are the defenses against cache poisoning attack?
The first few here simply make the attackers do a lot more work in order to succeed.
For example we can increase the query ID size, we can randomize the source port or we can query twice.
More fundamentally, we can use cryptography to provide authenticity of DNS records, and that's the idea behind DNSSEC.
### Amplification Example
Let's take a closer look at amplification attacks.
Typically, the attacker uses a machine, and then these attacker machine controls a number of bots, or compromised computers.
And each of these bots will send many requests to a server, and the response from the server is much larger than the request.
So the amplification is accomplished by two factors.
One is the number of bots involved.
And second, the server response is much larger than the requests.
Here's a specific example of amplification attack.
This involves DNS, the domain name system.
Here's the amplification factor involving the server, the DNS server.
So here we have the machine sending a DnS request to the server.
And of course, the address, the source of the DnS query is spoofed and the server thinks that the request is from the target.
The server response is much larger than the request.
In this case, it is 50 times.
Here, EDNS means extension mechanism for
DNS.
It allows for actual flags and response data.
Therefore, the response is much larger.
In a DNS-based amplification attack, each of the bots controlled by the attacker will send many requests to any of the DNS resolvers.
And there are many of them.
And for each request, the response will be sent to the target because in each request, the source IP address is spoofed.
The attacker can choose any subset of the DNS servers to use because there are so many open DNS resolvers on Internet.
This attack can generate a huge amount of traffic in a very short period of time.
For example, the attacker can easily generate tens or even hundreds of gigabits per second traffic targeted at a victim.
### DNS SEC
So let's discuss the DNSSEC.
The goals of DNSSEC is to provide guarantees of the authenticity of the DNS servers as well as the integrity of their responses.
These guarantees are accomplished by having the DNS servers sign responses every step of the way.
It is also assumed that the DNS servers themselves can be secured.
### DNS Signing
Here's an example of the DNS signing process.
Suppose a local DNS server looks up wikipedia.org.
They first query the root server.
The root server provides the IP address of .org and signs it.
The signature is based on private key of the root server.
The DNS server performs recursive query, in this case sending the request to .org.
And the response contains the IP address of wikipedia.org signed with the public key of .org.
The local DNS server can modify all these signatures and be confident that the IP address that it receives is correct.
### DNS Rebinding Attack
Even DNS-SEC cannot prevent all DNS attacks.
The DNS Rebinding Attack is one such example.
To among a DNS rebinding attack, the attacker needs only register a domain name, such as evil.com.
And attract web traffic, for example, by running an advertisement in a frame.
In this attack, when evil.com is looked up, the attacker answers with the IP address of his own server and use a very short TTL value.
The attacker's server, evil.com, also serves the browser a malicious JavaScript.
To circumvent the firewall, when the malicious JavaScript issues a query to evil.com, the TTL has expired.
The attacker then rebinds the host name, evil.com, to an IP address of an internal server.
That is, now the firewall thinks that evil.com is internal.
The browser now believes that these two servers belong to the same origin, because they share the same host name, www.evil.com.
So it will allows script to read back the response.
Therefore, the malicious script can easily extra trade information from the server to evil.com.
That is now the attacker is able to read arbitrary documents from the internal server.
To mitigate such attack, the browser should use DNS Pinning.
Meaning that, you should refuse the switching to new IP address for domain.
On the other hand, this means that it may break proxies,
VPNs, dynamic DNS and so on.
Therefore, it is not consistently implemented in all browsers.
For the internal servers, they should check Host headers for unrecognized domains such as evil.com.
It should also provide stronger authentication of users.
For the firewall is to implement a policy such that external domain names cannot resolve to internal IP address.
It should provide stronger protection of browsers within the network.
### DNS Rebinding Quiz
Now, let's do a quiz.
Select all true statements about rebinding attacks.
### DNS Rebinding Quiz Solution
The first statement, the attacker needs to register a domain and delegate it to a server under his control, this is true.
The second statement, the attacker's server responds with a short TTL record, this is true.
The third statement, a short TTL means that the page will be quickly cached, this is false.
The fourth statement, the attacker exploits the same origin policy, this is true.
### Introduction to Advanced Web Security
This is a large lesson because the topic,
Advanced Web Security, is an expansive subject.
By the end of this lesson, you should be familiar with the web security model, defenses against attacks on web applications, HTTPS, its goals and pitfalls and content security policies and web workers.
### Common Application Attacks Quiz
Before we discuss web security, let's remind ourselves as to why we need web security.
In this quiz, match the attacks to their descriptions.
So the attacks are, using components with known vulnerabilities, missing function level access control, sensitive data exposure, security misconfiguration, insecure direct object references, cross site scripting, broken authentication and session, injection.
And the descriptions are, modifies back-end statement through user input, inserts Javaccripts into trusted sites, program flaws allow bypass of authentication methods, attackers modify file names, abuses the lack of data encryption, exploits misconfigured servers, privilege functionality is hidden rather than enforced through access controls, uses unpatched third party components.
### Common Application Attacks Quiz Solution
And the answers are the first attack using components with known vulnerabilities.
The description is uses unpatched third party components because unpatched third party components have known vulnerabilities.
Second, missing function level access control.
For this attack, the description is privilege functionality is hidden rather than enforced through access controls.
Because the attacks here says it's missing function level access control.
The third attack sensitive data exposure.
For that to work, the description is this one.
Abuses the lack of data encryption.
The next attack security misconfiguration.
The description is exploits misconfigured servers.
The next attack insecure direct object references.
The description is that the attacker can modify file names because file names are direct object references.
The next attack, cross site scripting.
The description is, inserts Javascript into trusted sites.
The next one, broken authentication and session.
The description is, program flaws allow bypass of authentication methods.
Because the attack here exploits broken authentication and session.
The last one, injection, the description is modifies back-end statement through user input.
In other words the attack action is injected through user input.
### Goals of Web Security
Now, let's discuss the goals of web security.
Obviously, we need to be able to browse the web safely.
This means that, when browsing a website, sensitive data on the user's computer can not be stolen and uploaded to the web.
And that if the web browser has multiple open sessions with multiple sites.
For example, one session to a bank website, and another session is to a social network site.
The sessions don't interfere with each other.
Intuitively, if the social network site is compromised, it should not affect the user session with the bank site.
In addition, we need to ensure that the web applications can have the same security protection, as applications that run on the operating system on our computers.
### Threat Models
Now let's discuss the Web Security Threat Model.
We use threat model to understand what the web attackers are likely to do.
And we're going to compare the Web Security Threat Model and the Network Security Threat Model.
On the web, attacker can typically setup a malicious website and the attacker waits for users to visit the malicious website so that the attack can be launched through the malicious websites to compromise the user's computers.
A web attacker typically does not control the network.
Now let's look at the Network Security Threat Model.
A network attacker can be much more active.
Typically, we would assume that a network attacker can intercept and control the network.
For example, the attacker can intercept and drop the traffic.
Or he can intercept and perform traffic analysis to crack open the encryption key to read the data that's being transmitted.
Or he can inject malicious traffic into the network.
### TCP
Now let's take a look at the network protocols to understand why the internet is vulnerable to DoS service attacks.
So the internet protocol or
IP is connectionless.
This means that it is not reliable, meaning that each packet will find it's way to destination and there is no mechanism to ensure that all packets will arrive properly and in sequence at least not at IP layer essentially it is the best effort delivery.
So here is the format of the IP header for the purpose of our discussion let's focus on a source IP address and a destination IP address.
From the security point of view the main weakness of IP is that there is no authentication of the source IP address.
Which means that the attacker can spoof an IP source address.
Now let's take a look at TCP.
TCP is session based which means the destination is going to make sure that all packets belonging to a same connection will arrive and properly sequence.
And in order to achieve this there's congestion control and in order delivery mechanisms.
These mechanisms ensure that the data loss or packet loss is minimized and the need to retransmit packets is also minimized.
And here's the format of the TCP header.
Notice that we use a sequence number for each packet.
Acknowledgement number to acknowledge a packet as received.
And number flags to actually keep the state of the session.
Now let's take a look at TCP handshake or the steps to establish a TCP connection.
Suppose our client wants to connect to a server.
It first sends a SYN packet, this packet has a SYN flag set and also a sequence number.
The acknowledgement number is 0 because this is the first packet.
The server responds with a SYN/ACK packet, which means that both the SYN flap and the ACK flags are set.
The sequence number is a server sequence number and acknowledgment number is the sequence number plus one.
This means that this SYN/ACK packet is an acknowledgement of the initial SYN packet from the client.
And then the client sends a final
ACK packet to the server.
In this ACK packet, it incremented its Its own sequence number and acknowledge the sequence number from the server.
This tells the server that the client has received this SYN/ACK packet.
At this point, the TCP connection is established.
### Attack Top 10 Quiz
Now let's do a quiz relates to web attacks.
According to the OWASP in 2013, the following are the top
10 attacks on web security.
I would like you to rank them in order,
1 for the most common and 10 for the least common.
These attacks are, security misconfiguration, insecure direct object references, missing function level access control, sensitive data exposure, using components with known vulnerabilities, cross site scripting, unvalidated redirects and forwards, broken authentication and session, injection, cross site request forgery.
### Attack Top 10 Quiz Solution
According to OWASP 2013, injection is the most common.
Unvalidated redirects and forwards is the least common.
And the order of the rest is here.
### Threat Models
Let's go over the various types of attackers in more details.
For the web attacker, the attacker could typically control a suspicious site, say, attacker.com.
He can even obtain certificate for his website so that the website can interact with users' browsers through HTTPS.
And then the attacker can wait for the user to visit attacker.com.
For example, this can be done through phishing and other kinds of redirect.
Or, the attacker can set up some sort of malicious, or fake, web app and wait for the user to download these apps and run these apps.
The point here is that, typically, a web attacker is somewhat passive.
He sets up some attack infrastructure and waits for the users to actually either visit those sites or use those malicious apps.
A network attacker is more powerful.
He can perform both passive and active attacks.
For example, a passive attack means that the attacker simply intercepts and analyze traffic to learn about the communication.
For example, the attacker can perform wireless eavesdropping to crack the encryption key for you're Wi-Fi network.
Examples of active attacks include inserting a malicious router in the network so that traffic can route through the router and be subject to the attackers attack.
That includes both passive like eavesdropping, or active attacks such as traffic injection.
Another example is DNS poisoning, where the attacker changed the DNS entry so that a legitimate site such as cnn.com, now has an IP address of a server that's controlled by the attacker.
That is, legitimate traffic such as to cnn.com will not be redirected, so that legitimate traffic such as those to cnn.com will now be redirected to the attacker's machine.
The most general and powerful attack is through malware.
By injecting a piece of malware on the user's computer, the attacker essentially escapes, the browser's isolation mechanism.
And now, has a program that runs directly under the control of the operating system.
That is, the malware runs as any other applications on your computer.
You may ask, why is that possible?
Isn't the browser supposed to isolate the rest of the computer from the web?
The problem is that browser is a very complex piece of software, and as such, browsers may contain exploitable bugs, and these bugs often enable remote execution of malicious code.
For example, when a browser visits a site that's controlled by the attacker, the attacker can send a webpage that contains malicious input.
And the result is that a bug is being exploited and a piece of malicious software, or malware, is now installed on a computer.
Now, even if the browsers are bug free, there are still lots of vulnerabilities on the web, in particular on the web-server side.
That would enable cross-site scripting,
SQL injection, and cross-site request forgery.
For example, SQL injection would allow the attacker to bypass the control of the web server, and directly inject attackers' code into the back end of the SQL database.
The point is that malware attackers can actually bypass the basic control of web, including browser, to actually attack the users' computers or the web service.
So we will discuss three main types of attackers.
The malware attacker, the network attacker, and the web attacker.
It is obvious that a web attacker is the least lethal because he's mostly passive.
A network attacker is more powerful because he can perform both passive and active attacks.
And a malware attacker is the most lethal and powerful because it can inject code into a user's computer or a server to perform any actions desired by the attacker.
### Modern Websites
Before we go into the details of web security, let's understand how the modern web works.
For typical website, it contains both static and active contents.
The active contents, or the code, can be from many sources and they can be combined in many ways.
Then the security challenges are we have many different types of data and codes for many different sources.
And they run and interact with each other.
For example, on a typical web page we have code or data related to the page itself, the third-party API's, for example to tutor, third-party libraries to how you navigate and scripts that run advertising contents.
And the data and codes on a website can be from many different sources, by many different developers.
For example, a website can have many parties contributing to its data and code.
These include page developers, library developers, service providers, data providers, ad providers, and other users, and extension developers, such as the web app developers and the CDN's, the content distribution networks.
Obviously these parties can be from different vendors and companies.
So the basic security questions are with data and codes from so many different sources, how do we ensure data And integrity when we browse the web?
For example, we need to figure out how to protect page from ads and services because they are from different sources.
On the other hand, maybe there's a legitimate reason to share data when they are from different sources.
That is, how do we share data with cross-origin page and how do we protect one user from another user's content?
How do we protect the page from a third-party library?
How do we protect a page from the content distribution network?
And how do we protect browser extensions from page?
### Website Quiz
Lets take a moment to understand the enormity of the web security problem.
Take your best shot at answering these questions.
First, in 2015 how many active websites were on the internet?
Second, how many websites does
Google quarantine each day?
Third, how many malicious websites are identified every day?
### Website Quiz Solution
The answers are, in 2015, there are 1 billion active websites.
And each day,
Google quarantine 10,000 websites.
And 30,000 malicious websites are identified every day.
As you can see, web security is not a small issue.
Understanding and stopping malicious actions is paramount to network security.
### Browsers
Now, let's discuss browser security model.
Let's take a step back and compare operating system with web browser.
An operating system supports multiple applications to run on a computer at the same time and allows them to share the resources on a computer.
Similarly, a web browser can render multiple webpages to different sites.
And each page can contain data and code from multiple sources.
So it is instructive to compare the operating system and web browser security models.
For Operating System, the primitives are system calls, processes, and disk storage.
For Web Browser, the primitives are Document Object Model or
DOM, frames, cookies and local storage.
The principles on the operating system are users, and associated with users is the discretionary access control policy.
For web browser, the principles are origins and mandatory access control is used.
Vulnerabilities in operating system can lead to buffer overflow, root exploit and so on.
Whereas on web browser, such vulnerabilities can lead to cross-scripting, cross-site request forgery, cache history attacks, and so on.
Now let's take a look at the execution model of web browsers.
Given a webpage, the browser goes through these steps.
First, load the contents.
Second, renders the contents.
That is, the browser processes the HTML pages and runs each JavaScripts to display the contents of the page.
The page may include images and frames and so on.
And then the browser response to events.
What are the events handled by a web browser?
The main events are user actions, such as clicking, moving the mouse.
Rendering, like loading a page.
Timing such as Timeout.
The contents being rendered can be from many sources.
For example, you could have scripts, frames loading HTML pages,
Flash objects, etc.
By specifying allowscriptaccess, the Flash object can communicate with external data, such as external scripts and navigate external frames and opening windows, etc.
The point is that there are many contents from many sources, and they can interact with each other.
Obviously, this makes it challenging for enforcing security policies.
The basic idea of browser security is to Sandbox web contents.
More specifically, we want to safely execute JavaScript code.
Because it can be from a remote website, this means that a JavaScript code cannot access the file system directly.
It can only have limited access to the operating system, the network and browser data, as well as content from other websites.
The main policy is the so-called
Same Origin Policy.
That means active code, such as JavaScript, can only read properties of documents and windows from the same origin defined as the same protocol, domain and port.
Now exceptions to this policy can be allowed.
That means scripts that are assigned by legitimate developers that a user can trust, such as scripts signed by Microsoft, Google, Apple, etc.
For example, the user can grant these privileges such as
UniversalBrowserRead/Write,
UniversalFileRead, and so on.
### Sandbox Quiz 1
Sandboxes and virtual machines are often confused with one another.
Let's use this quiz to try and set the record straight about the two.
Next to each characteristic, put an S for Sandbox, V for virtual machine, and B for both.
First, anything changed or created is not visible beyond its boundaries.
Second, if data is not saved, it is lost when the application closes.
Third, it is a machine within a machine.
Fourth, lightweight and easy to setup.
Fifth, disk space must be allocated to the application.
### Sandbox Quiz 1 Solution
First, anything changed or created is not visible beyond its boundaries.
This can apply to both sandboxes and virtual machines.
Sandboxes will isolate applications so that other applications cannot see it.
To see changes in virtual machines you must be in the virtual machine.
Second, if data is not saved, it is lost when the application closes.
This is an advantage of sandbox.
And you can call it a security strength of the sandbox because any malware downloaded will not be saved.
Third, virtual machines have their own copies of complete operating systems.
There can be multiple operating systems on a single hardware platform.
Four, sandbox is lightweight and easy to set up.
Fifth, for virtual machines, disc space must be allocated to the application.
### Browser SOP
Origin is defined by protocol, domain, and port.
So the same origin means the same protocol, domain, and port.
For document objects or DOM in a browser, the same origin policy says that origin A can access origin B's DOM if A and B have the same origin.
Meaning that they have the same protocol, domain, and port.
For cookies we say two cookies have the same origin if they have the same domain and path.
The protocol is optional.
We're going to discuss in more detail the same origin policy for cookies later.
### TCP SYN Flood I
With that background, let's discuss how TCP SYN flood or denial of service attack can work.
Notice that, in TCP handshake, after the server receives a SYN packet from the client, it sends a SYN/ACK packet back to the client, and then waits for the ACK packet from the client.
When it received the ACK packet, it knows that the connection is established.
Therefore, the server needs to keep in memory the state of the connection, meaning that it's waiting for the ACK packet that matched the SYN/ACK packet, which matched the initial
SYN packet from client.
So SYN flood exploits the fact that server needs to keep in memory such state information.
In particular, the attacker can send a lot of SYN packets to the server, and the source IP address is spoofed to some random target source IP address.
The result is that the SYN/ACK packet will be sent to the spoofed or the target address.
Since the source IP address of these
SYN packets are randomly generated and spoofed, the SYN/ACK packets may get lost, meaning that the ACK packet may never arrive at a server.
The result is that the server's memory gets filled up, because the server needs to keep track of the SYN/ACK packets and wait for the ACK packet from the clients.
And since many of these
ACK packets do not arrive, the server is holding in memory this state information.
And as a result, its buffer gets filled up.
And when that happens, no further connections can be serviced.
In other words, the denial of service is accomplished.
Here's a real example of SYN flood.
The Blaster worm in 2003 infected many machines.
And these infected machines were insructed to launch a denial of service attack at noon on August 16th.
That is, these machines were instructed to launch SYN flood on port 80 on the target server windowsupdate.com.
In particular,
50 SYN requests were sent every second.
And each packet is 40 bytes.
And the source IP address of these request packets were randomly generated.
As a result, the server windowsupdate.com was rendered unavailable.
As a response, Microsoft moved the
Windows update service to a new domain, windowsupdate.microsoft.com.
So how do we defend against SYN flood attacks?
How about increase the memory size or decrease the timeout value so that when a server does not receive an ACK packet, it just clears out the memory.
These are not good solutions, because an attacker can just send more packets or at a faster pace.
A better solution is to remove the need for a server to keep state.
And this, of course, comes with a cost.
### Frame Security
Frame and iFrame are like many browser windows.
A frame is typically rigid or fixed on a page, whereas iFrame can be floating.
Here's an example of iFrame.
It essentially says that here is the width and height of the frame window and it will display this page.
So why do we discuss frames in a context of web security?
Or in more general, why do we even use frames?
As the previous simple example shows, we can display a webpage within a frame, or a minute browser window.
So, from this example, it is obvious that frames provide a natural isolation of separation of different web contents.
For example, we can delegate screen area to content from another source.
And a browser provides isolation based on frames.
And, even if a frame is broken, the parent window can still work.
Again, to display web contents from two different sides, A and B, we can have two different browser windows, such as what we see here, A and B.
On the other hand, we can achieve the same result by having just one browser window, let's say B here on the right-hand side.
And within it, we have a frame that display contents from A.
The point is that we should be able to achieve the same kind of isolation whether we use two different browser windows or use a frame within a window.
Again, we apply the same origin policy to achieve frame security.
Specifically, each frame of a page has an origin, that's defined as protocol, host, and port.
A frame can access only the data from its own origin.
That is, a frame cannot access data associated with a different origin.
Therefore, for example, even though we have a frame within a browser window and they display contents from different sites, for example, A and B.
The same-origin policy guarantees that these two sessions, the frame and the browser window, they don't interfere with each other.
So there was the default same origin policy.
In addition, frame-to-frame access control policy can also be specified.
For example, we can say canScript(A,B).
That means Frame A can execute a script that manipulates
DOM elements of Frame B.
We can use canNavigate to specify that
Frame A can change the origin of content for Frame B.
Likewise, we can specify policy for frame to access principle.
For example, we can use readCookie, writeCookie, to specify that can Frame A read/write cookies from a site.
You can read more about the web browser security mottos by following these links.
### Browsing Context
So far we have described the classic web browser security models.
To understand the more modern mechanisms, let's define browsing context.
A browsing context may be a frame with its DOM, that is a frame with web contents.
Or web worker, which does not have a DOM.
A web worker as defined by the World Wide Web Consortium or W3C and the Web Hypertext Application Technology
Working Group is a Javascript executed from HTML page that runs in the background independently of other user interface scripts that may also have been executed from the same HTML page.
In short, a web worker is a Javascript that runs in the background and it is independent of the user interface elements.
Now, every browsing context has an origin.
Again, an origin is determined by protocol, host, and port.
And as such, our browsing context is isolated from another context by the same-origin policy.
Different browsing contexts may communicate using postMessage.
And they can make network requests through XHR or tags.
XHR stands for XML HTTP Request.
It is an API available to Javascript.
Typically, XHR is used to send HTTP or
HTTPS requests to a web server.
And lo, the server responds data back into the script.
That is, a Javascript use XHR to request contents from a web server.
There are similarities between browsing context and process context.
An opening system uses separation and isolation to allow multiple execution context and provide local storage and communication services.
Similarly while a web browser provides common local storage it uses isolation and separation to provide security protection to the browsing contexts.
The modern browser mechanisms that can be used for security protection include
HTML5 iframe Sandbox.
Content security policy.
Cross Origin resource sharing.
And HTML Web Workers.
Sub Resource Integrity.
And we're going to discuss these mechanisms now.
As in operating systems, sandbox is very useful for browser security.
The idea is to restrict frame actions.
When we used a directive Sandbox for frame essentially we are insuring that the iframe has unique origin, cannot submit forms, and
APIs are disabled, and it can prevent contents from plugins.
On the other hand when we create iframe if we use Sandbox allow-scripts directive, then we only ensure that iframe has unique origin.
But we can allow the rest of the actions.
For example, here's a Twitter button in iframe.
In this example, there's no Sandbox related directive.
So this you can call it the classic iframe.
Now we can use a Sandbox directive here.
We specified the Sandbox directive.
But then we also specified that we will allow Javascripts and allow form submissions and so on.
This simple example shows that we can use the Sandbox directive associated with the iframe in order to specify the security policy that's appropriate.
Here are the list of Sandbox permissions that you can specify for iframe.
### Content Security Policy
Now let's discuss, content security policy, or CSP.
The goal of content security policy to prevent or at least limit the damage of Course side scripting.
Recall that we discussed course side scripting attacks in CS
6035: Introduction to
Information Security.
Essentially a course side scripting attack bypasses the same origin policy by tricking a site into delivering some malicious code along with the intended content.
For example, a website is setup to echo the user input as a web page back to a browser.
Such as echoing the user's name.
But if the user input contains malicious code, then the website will be sending malicious code to a web browser.
With CSP, the main idea is that a browser can be instructed to load resources only from a white-list.
CSP prohibits inline scripts embedded in script tags, inline event handlers,
JavaScript, and URLs, etc, and also disables JavaScript eval, new function and so on.
That means all the resources that a browser will load can be statically checked.
And again the resources are loaded only from a white list.
Since there are many different types of web contents, with CSP we can specify the white list for each type of web contents.
The sources of web contents can be specified and matched.
For example, they can be specified by scheme such as HTTPS or
HTTP, host name, then we match any origin on that host.
Or fully qualified URI such as https://example.com:443.
You can also specify how to match the sources listed on a white list, such as, wildcards accepted, none, or self, and so on.
You can even create exceptions or allow inline JavaScripts or allow eval functions.
### CSP Quiz
Now let's do a quiz on CSP.
Which of the following statements are true?
First, if you have third party forum software that has inline script,
CSP cannot be used.
Second, CSP will allow third party widgets, such as Google +1 button, to be embedded on your site.
Third, for a really secure site, start with allowing everything, then restrict once you know which sources will be used on your site.
### CSP Quiz Solution
The second statement is true because you can certainly list
Google + as a trusted source and list it in the white list.
For the first statement, if you use third party software that has inline script, you can still embed it on your site.
You can use script source and style source to allow inline script.
For the third statement, for really secure site, it is best to restrict everything.
Then once you know which sources will be used, add them to the whitelist.
### Web Worker
Now let's discuss Web Worker.
Web Workers were ultimately not intended for security, but they help improve security because they allow
JavaScript to run in isolated threads.
Here's an example of how do you create a Web Worker.
Again, it is loaded from JavaScript.
A Web Worker has the same origin as the frame that creates it, but the Web Worker has no DOM.
It can communicate using postMessage.
So here's a simple example.
The main thread, meaning the main iframe thread, creates a worker.
It then starts the worker thread by sending a message using postMessage.
And here the worker actually performs the work.
### Subresource Integrity
Now let's discuss SubResource Integrity.
Integrity is a very important security goal.
In the context of web browsing, many pages load scripts and styles from a wide variety of service and content delivery networks.
Given that contents can be from many different sources and content delivery networks, how do we ensure the integrity of the contents that we're loading?
For example, how do we protect against loading contents from a malicious server?
For example, the browser gets to the malicious server because of DNS poisoning and how do we ensure that contents that we load from a Content Delivery Network has not been modified, for example, on purpose by the CDN?
The main ideas that the author of the content specifies and makes available the hash of the contents.
And so when the browser loads the contents, it use the hash value to check integrity.
For example, the author of this stylesheet will specify the hash of the file.
Similarly, for JavaScript, the author can also specify its hash.
So basically, to use SubResource
Integrity, our website author who wishes to include a resource from a third party can specify a cryptographic hash of that resource in addition to the location of the resource.
Then when a browser fetches the resource, it can compare the hash provided by the website author with the has computed from the resource.
If the hashes don't match, the resource is discarded.
So, what happens when the integrity check fails?
By default, the browser can report the violation and simply does not render, or execute the resource.
Or if the directive simply says, report that means the browser will report the violation, but can still render or execute the resource.
### Cross Origin Resource Sharing
Now, let's discuss cross origin resource sharing.
We've been discussing the same origin policy, which means that cross origin reading and writing is typically not allowed.
Now, what happens when a website has multiple domains?
For example, Amazon, the company has both the amazon.com and aws.co websites.
These two domains belong to the same company, so we expect that they should be able to share some resources.
Now of course, we want the same origin policy, so that another analytic website cannot easily access resource from Amazon.
Cross Origin Resource Sharing is a technique that we can use to relax the same-origin policy, so that JavaScript on a web page such as on amazon.com now can consume content from different origin.
Let say, aws.com.
It basically uses wireless.
For example, amazon.com can list the domains that it allowed.
Here's how
Cross Origin Resource Sharing works.
The browser sends the options request to the origin HTTP header.
The value of this header is the domain that served the parent page.
For example, when a page from amazon.com attempts to access a users data in aws.com, the following request header will be sent to aws.com.
That is it specifies origin https://amazon.com.
The server can inspect the Origin header and respond whether the access is allowed or not.
For example, the server can send back an error page, if the server does not allowed the cross origin request or it can specify which origin is allowed to access.
For example, in this case, the origin https://amazon.com is allowed or it can use a roll call to say that all domains are allowed.
### CORS Quiz
Now, let's do a quiz.
Select all statements that are true.
First, cross-origin resource sharing allows cross-domain communication from the browser.
Second, it requires coordination between the server and client.
Third, it is not widely supported by browsers.
Fourth, the header can be used to secure resources on a website.
### CORS Quiz Solution
The first two are true.
The first statement is false because it is not widely supported by many browsers.
The fourth is also false because the cross-origin resource sharing header cannot be used as a substitute for sound security.
### SYN Cookies Quiz
Now let's do a quiz on SYN cookies.
Select all true statements.
### SOP Quiz
As a quick review let's do a quiz.
Recall that a same-origin policy requires that requests to access data must be from the same origin.
But what is the definition of an origin?
### SOP Quiz Solution
An origin is the combination of a URI which stands for
UniformResource Identifier scheme, such as HTTP or
HTTPS, and hostname, and port number.
Here are some examples of URI references.
### SOP Review
Let's continue with a review of Same Origin Policy.
We have discussed the Same Origin Policy for
DOM, which stand for
Document Object Model.
The Same Origin Policy for
DOM says that origin A can access origin
B's DOM if A and B have the same protocol, domain and port.
In this lesson, we are going to discuss the Same Origin Policy for cookies.
Here, origin is determined by the combination of scheme, domain, and path, and scheme can be optional
### SOP and Cookies
We call that when a browser connects to a site, the server sets the cookie for the web browsing session.
There are a number of attributes that a server can set for a cookie.
For example SameSite means that do not send cookie on a cross-site post request.
Strict, means that never send cookie on cross-site request.
Therefore, they provide some sort of cross-site request forgery defense.
With HttpOnly, it tells the browser that this particular cookie should only be assessed by the server.
Any attempt to assess the cookie from script is strictly forbidden.
This can provide defense against cross-site scripting attacks.
And the scope of the cookie is determined by the combination of domain and path.
### Setting and Deleting Cookies
In a domain is any domain-suffix of a URL-hostname, except the top level domain.
For example, the web server login.site.com can set cookies for all of site.com.
Because site.com is a suffix, but not another site or the TLD, which is .com.
Using this rule the cookies is set by login.site.com have these allowed domains, login.site.com and site.com.
And these domains are not allowed because they are other domains or the TLD, .com.
And path can be set to anything within that domain.
How are domains identified?
They are identified by name, domain, and path.
Here we have two cookies.
Both cookies store in browser's cookie jar.
And both are in scope of login.site.com, but they're distinct.
What are the policies for a server to read cookies?
In other words, the reading same origin policy.
The browser sends all cookies in URL scope, which is determined by domain and path.
And the goal is that server should only see cookies in its own scope.
Here's an example.
We have two cookies, both set by login.site.com.
The different servers see different cookies depending on their scopes.
For example the server http://checkout.site.com only sees Cookie2 because it's within the scope of site.com.
Another example, http://login.site.com, again, only sees Cookie2.
And the reason is Cookie1 requires secure which means that the connection has to be HTTPS.
The third example here, https://login.site.com, it can use both Cookie1 and Cookie2.
What are the rules for client-side read/write of cookies?
A JavaScript can set cookie values.
It can also read out the attributes of a cookie.
It can even delete a cookie.
The exception is that if the cookie is set as HTTP only, that means it cannot be accessed by client-side scripts.
Which means client-side scripts cannot read or write this HttpOnly cookie.
### SOP Security Quiz
Now let's do a quiz on the same origin policy.
Given this website, for the requests that are submitted from the following
URLs, which of these URLs will result in a successful request, and which will be rejected as not being from the same origin?
Determine the outcome, success or failure, for each URL.
### SOP Security Quiz Solution
The first three are allowed because they have the same protocol, host and port.
The fourth has a different port, port 81, so it's not in the same origin.
The fifth has a different host and the sixth has a different protocol.
### Cookie Quiz
For the following cookies, determine whether they are session cookie, persistent cookie, secure cookie,
HttpOnly cookie, SameSite cookie,
Third-party cookie,
Super cookie, or Zombie cookie.
### Cookie Quiz Solution
In particular, a cookie that can only be sent in requests originating from the same origin as the target domain is a SameSite cookie.
Again, this can be used to defend against cross-site request forgery.
And a cookie that cannot be accessed by client-side APIs is the HTTPOnly cookie.
It can be used to defend against cross-site scripting attacks.
### Cookie Protocol Problem
Now let's discuss some security problems with cookies.
First of all, the server is blind and what do we do mean by that?
It does not see all the cookie attributes.
For example, whether the cookie attributes include secure, which means Https only, or has the attribute HttpOnly.
When a server receives a cookie, it does not see which domain sent the cookie.
Actually, all the server sees is some selected attributes sent by the browser.
This problem can be exploited by attackers.
For example, say Alice wants to submit her homework.
She logs in login.site.com and login.site.com sets the session-id cookie for site.com.
And then, Alice decides to take a break and unknowingly visits a malicious site.
For example, because of a phishing attack.
And evil.site.com can override the .site.com session-id cookie with a session-id of user Badguy.
Then Alice returns to the homework site ready to turn in her homework.
Of course.site.com thinks that it is talking to the badguy because the session-id has been overwritten.
The problem is that course.site.com expects session-id cookie that was set by login.site.com.
It cannot tell that the session-id cookie was overwritten.
Here's another example of cookie security problems.
Suppose Alice logs in https://accounts.google.com, meaning that she logs in into her Google account.
And accounts.google.com will set the cookie.
In particular, it also says that this cookie is Secure, meaning that it should be used for
HTTPS.
Now suppose that due to some phishing attack, Alice visits the create text site, http://www.google.com and because this is a clear text protocol, a network attacker can intercept the traffic and override the cookie attributes.
And the result is that this overwritten cookie can be used for a HTTPS session.
As we can see, a network attacker can intercept and rewrite HTTPS cookies, which means that even a HTTPS cookie, its values cannot be trusted.
We have not talked about the path of a cookie.
The path separation is done only for efficiency, not for security.
For example, x.com/A would tell that if a server only needs to access this path, that only this cookie's needed.
Recall that the scope of a cookie is determined by domain and path.
Which means that x.com/A does not see cookies of x.com/B because they are different paths.
That is, they're in different scopes.
However, this is not a strong security measure.
Because x.com/A still has access to the
DOM, meaning the document object model of x.com/B, because they are the same origin as far as DOM is concerned.
For example, x.com/A can use the following to print out or read the cookie of x.com/B.
Another security problem of cookies is that cookies have no integrity.
For example, a user can change or even delete cookie values.
For example, there are tools that a user can use to change or delete cookie values.
For example, a user can change the shopping cart cookie and change the total dollar amount from $150 to $15.
Similarly, if the website had used a hidden field in the webpage to record the value, a user can still edit the source of the page and change the value.
### SYN Cookies Quiz Solution
SYN cookies does not require modified version of TCP, so this is false.
SYN cookies are only applied when there's a SYN flood attack.
That is, during normal operations, or when a server does not experience a overload, it does not require SYN cookies.
Therefore, SYN cookies should not lead to overall slower performance, that is the second statement is false.
The third statement is true because during an attack, the server uses SYN cookies and does not keep stay information in memory.
### Cryptographic Checksums
Obviously, we can use cryptography to provide data integrity protection.
The main idea is that when a server sets a cookie attribute, it will attach a integrity check value for the attribute, and it can later on check whether that attribute has been modified.
So to do this, the server uses a secret key that is unknown to the browser, and for each attribute value that is set, it computes a integrity check.
The courier tag T, that essentially is a message authentication code, using the secret key k, and compute over the session ID the name and value of the attribute.
And when it sets the cookie, we attach the message authentication code to each attribute value.
When a browser, later on, presents the cookie to a server, the server can then check the integrity of that cookie attribute value.
The server essentially uses the secret key and compute over the session ID, name and value of the cookie attribute, and then verify that the result is the same as T.
Again, because T is computed using the secret key, the browser cannot compute it.
So that is, only the server can compute T, and the server can use T to verify that the attribute value of the cookie is not changed.
Here's a example of how this can be done in the real world.
So a server key can be generated and the integrity of a cookie can be protected using this key.
Similarly, integrity can be tracked.
Here, are the example
APIs that you can use to provide cookie integrity protection.
### Checksum Quiz
Now let's do a quick review quiz on cryptographic checksum.
Check all the statements that are true.
First, cryptographic hash functions that are not one-way are vulnerable to preimage attacks.
Second, a difficult hash function is one that takes a long time to calculate.
Third, a good cryptographic hash function should employ an avalanching effect.
### Checksum Quiz Solution
The first and third statements are true.
The second statement is false.
A difficult hash function should be very hard for the attackers to analyze.
But we want all the hash function to be efficient to calculate
### Session Management
Now, let's discuss session management on the web.
What is a session?
A session is a sequence of requests and responses from a browser to a server.
A server can be long.
Without session management, a user can be asked to reauthenticate himself again and again.
So, the goal of session management is to authenticate user only once.
So that all subsequent requests are tied to the authenticated user.
So, the general idea behind session management is to use session tokens.
So, for example, there's the initial handshake that's in the browser and the web server.
And then, as the user wants to access some more secure content, he may be asked to authenticate himself.
And once the user has been authenticated, the server can elevate the token from anonymous browsing token to a authenticated token.
And when the user logs out or checks out, this login session token should be cleared.
There are many ways to restore the session tokens.
Obviously, we can use browser cookie.
For example, we can create a session token cookie or session cookie.
The problem with browser cookie is that a browser can send a cookie with every request, even when it's not, and this gives rise to the cross-site request forgery attack.
A session token can be embedded in a URL, which means that every request will have the session token.
This means that if the application is not returned securely, there can be token leaks via http referer header, or if the user posts URL in a public forum.
Another option is to store that session token in a hidden field in a forum.
The downside to this method is that every user action must result in a submission of a form, or you lose the session token.
So, none of these methods are perfect.
The best solution is, depending on the application, is you choose a combination of these three options.
Now, let's discuss the HTTP referer header.
When a browser sends a URL request to a server, if the request contains a HTTP referer header, it tells the server the page that you are coming from, meaning your referer.
Here's an example.
It shows that the user were here.
Again, by checking the referer, the web server can see where the request originated.
In the most common situation, this means that when the user clicks a hyperlink in the web browser, the browser sends the request to the server.
The request includes the referer field, which indicates the last page the user was on that is.
The one where they click the link.
The problem with referer is that it can leak the session token to the previous server.
The solution is that he can suppress the referer, means that don't send referer when you refer to a site.
### Session Logout
For example, after the user logs out, he should be allowed to log in with a different account.
And a website should prevent a user from accessing content left behind by a previous user.
So what should happen during a log out?
First, the session token on a browser should be deleted.
Second, on a server side, the session token should be marked as expired.
The problem is that many web sites do 1, but not 2, this is especially dangerous for sites that use HTTPS for login, but then fall back to the clear text HTTP after login.
This is because an active network attacker can intercept the clear text HTTP traffic and steal a copy of the session token.
Then even after the user logs out, because the server does not expire the session token, the attacker can continue to use that session token.
### Session Token Quiz
Now let's do a quiz on session token.
Check all the statements that are true.
First, the token must be stored somewhere.
Second, tokens expire, but there should be mechanisms to revoke them if necessary.
Third, token size, like cookie size, is not a concern.
### Session Token Quiz Solution
The first two statements are obviously true.
The third statement is false, because depending on how much information you store in it, tokens can become quite large.
Cookies, on the other hand, are quite small.
### Session Hijacking
A major threat in web session management, is session hijacking.
Here, the attacker waits for user to log in, and then the attacker can steal the user session token and hijacks the session.
And session hijacking is not limited to active network attacker that intercept traffic.
For example, if counter is used a session token, then when a user logs in a website it can get a counter value, then he can view sessions of other users because he would know other counter values.
Similarly, even if the token is protected using cryptography, if the cryptographic algorithm or the key is weak then a user can still break the protection, get the counter value, and then view sessions of other users.
So the point here is that we should use tokens that are not predictable, and there are APIs that allow us to generate random session IDs.
Again, to make session tokens unpredictable to attacker, we can use the underlying framework.
For example, rails.
For example, by combining the current time stamp and random nouns and compute this values over MD5, that should give you a very unpredictable token.
Even when a session token is random, there's still a security threat of session token theft.
For example, if a web site uses HTTPS for log in, but subsequently use
HTTP for the rest of the session, then an active network attacker, for example, can sit at a wireless cafe and use a tool, for example, Firesheep to intercept the clear text HTTP traffic and steal the session token.
Another way for the attacker to steal the session token is to play man in the middle at the beginning of the SSL connection.
Another approach to steel session token is to use Cross Site Scripting attacks, and if the server does not invalidate a session token after the user has logged out, then the stolen token can still be used by the attacker even after the user has logged out.
One idea to mitigate session hijacking is to bind a session token to the user's computer.
For example, we can embed some machine specific data in the session ID.
So what machine specific data of a user can be used?
We begin by binding the session token to the user's computer.
Now we must decide specifically what information we should use as the session token.
We want it to be unguessable and unique to the machine, but still quick to generate.
So is using the IP address a good idea?
Probably not and the reason is that the user's computer changes its IP address.
For example, due to DHCP, then the user will be locked out of his own session.
What if we used the browser user information instead of the IP address as a session token?
The problem with this approach is that such information is easily stolen or guessable by the attacker.
So the conclusion is that, while it is appealing to use kind site information a session token, there's not a good solution when we consider both security and convenience.
Therefore, the best approach is still an unpredictable session token generated by the sever.
### Session Fixation
In addition to stealing tokens, an attacker can also fake session tokens.
For example, the attacker can trick the user into clicking a URL that sets a session token, or it can use cross-scripting attacks to set token values.
Here's an example of how an attacker can use session fixation attack to elevate his anonymous token to a user logged-in token.
First the attacker gets anonymous browsing session token from site.com.
He then sends a URL to the user with the attacker's session token.
The user clicks on the URL and logs in www.site.com.
Now the attacker can use the elevated token to hijack user's session.
To mitigate such attacks when elevating a user from anonymous to logged in, a website should always issue a new session token.
So with this, after the user logs in, the token will change to a different value unknown to the attacker.
That is, the anonymous token that the attacker had originally obtained is not elevated.
### Session Hijacking Quiz
Now let's do a quiz on session hijacking.
Check all the statements that are true.
First, active session hijacking involves disconnecting the user from the server once that user is logged on.
Social engineering is required to perform this type of hijacking.
Second, in passive session hijacking, the attacker silently captures the credentials of a user.
Social engineering is required to perform this type of hijacking.
### SYN Flood II
SYN flood attacks can be launched at a massive scale.
Typically, for distributed denial of service attack, a large botnet can be used to generate a huge amount of traffic.
And the result is that the website, or even its uplink network routers, can be saturated.
It is very hard to filter these SYN packets, because they all look legitimate.
So how do we defend against such massive flooding attack?
One idea is to use a very powerful server, or a group of servers, to protect a website.
The idea is that these intermediate servers will only forward established TCP connections to the real website.
Suppose many machines or bots send a lot of requests to the website, but they're intercepted by the proxy.
The proxy is very powerful because it can use many servers.
And they can be distributed across the Internet.
The proxy sends the SYN/ACK packets in response to the initial SYN packets.
When a proxy receives the ACK packets from the client, it will then forward to the real website.
The idea here is that the attacking machine or the bot will not send actual
ACK packets to the proxy.
Only the legitimate clients will send the ACK packets to the proxy, and only those will be forwarded to the website to be serviced.
In other words, the proxy here stops the flooding attack.
However, the idea of using a proxy to protect a website is not bulletproof.
Here's an example of a stronger attack.
An attacker can use an army of bots to actually completely finish the TCP handshake.
In other words, use complete TCP connections to website.
Then it can send requests to the website and keep repeating all these requests to the server.
That is, all of these requests are legitimate from a protocol point of view, but they were designed to overload the server with a lot of work.
And the result is that if the attacker can command a huge army of bots, the attacker can still bring down a website.
This is similar to the situation when there are huge number of legitimate users visiting a website at the same time.
Of course, such attack can actually render the proxy protection useless, but on the other hand, because the TCP connection is fully established, that means the attacker cannot use any random source IP address.
The attacker must use the real
IP address of the bots, which means that the bots' IP addresses are now revealed.
And then a proxy can actually block or rate limit traffic from these bots.
In other words, after the initial attack, there's a chance that the proxy can actually use the information to rate-limit and then reduce the effect of the flooding attack.
Here's a real-world example of such an attack, it's fairly recent.
So here, a honest end user visits a popular website, but this website is compromised and the response will include a miniature
JavaScript injected into the response.
And the user has no idea that this JavaScript is embedded into the response HTML page.
For example, this JavaScript can be embedded in an invisible iframe.
Once the response HTML page runs on the user's browser, the malicious JavaScript will run, and it will do a denial of service attack on a server, say, Github.com.
Here's how the JavaScript can launch an attack on Github.com.
It basically asks the victim website, say, GitHub.com, to fetch a random resource on a server.
And it sends such a request every ten milliseconds.
Therefore, with many users unknowingly running this malicious JavaScript, the victim website, say Github.com, can be rendered unavailable.
### Session Hijacking Quiz Solution
The first statement is true.
The second is false.
Of these two methods, passive hijacking is less likely to raise suspicions.
### Session Management Summary
To summarize what we've learned about the security of session management, we should always assume cookie data retrieved from client is adversarial, or not trusted.
There are multiple ways to store session tokens.
Cookies, by themselves, are not secure.
For example, they can be overwritten.
Session tokens should be unpredictable.
And finally, when a user logs out, the server should invalidate the session token.
### Goals
Let's discuss HTTPS and how it is integrated into the web browser.
And we are going to discuss a number of security problems with HTTPS.
### HTTPS
HTTPS is essentially HTTP over SSL, the secure socket layer, which is now called TLS, transport layer security.
With HTTPS, all traffic between a web browser and a web site is encrypted, whereas HTTP is a clear text protocol, meaning that the traffic is not encrypted.
For example, using HTTP, a user sends a password and a web server receives it.
Since the traffic data is in clear text, a network attacker with access to the link can intercept the traffic data and learn the user's password.
Now with HTTPS, the user still sends the password, but the password is encrypted in transmission.
Therefore, even when attacker can access a link, he cannot learn your clear text password.
In summary, HTTPS allows for secure communication over untrusted or public network.
It encrypts traffic and uses public key to authenticate the web server and. if possible. even the browser.
Even if only the web service public key is known, many in the man-in-the-middle-attack can still be prevented.
With all these benefits,
HTTPS is not used for all web traffic.
The reason is that crypto operations can slow down the web service, in particular, if it is not implemented right.
And some ad networks, do not support HTTPS.
For example, the ad publishers cannot learn the web contents as being viewed by the users.
On the other hand,
Google is now trying to encourage websites from adopting HTTPS.
### HTTPS Quiz
Now let's do a quiz on HTTPS.
Select all items that can be encrypted by HTTPS.
### HTTPS Quiz Solution
The first four can be encrypted by HTTPS.
Host address and port numbers are used to route traffic and so they're not encrypted.
The amount of transferred data and length of session can be inferred by observing the traffic.
So the attacker can learn this.
### Network Attacker
Recall that a network attacker can control network infrastructures such as routers and DNS servers.
It can eavesdrop to learn traffic contents, inject data, block traffic, or even modify the contents.
For example, such a network attacker can sit at an internet cafe or hotel lobby to compromise the network.
HTTPS was designed to thwart such network attackers.
### SSL TLS Overview
Since HTTPS is HTTP over SSL, let's briefly review SSL/TLS.
It uses public key for authentication and key exchange.
As a quick review, in public key cryptography, each user, say Bob, has a pair of public key and private key.
And Alice, after obtaining Bob's public key, can use Bob's public key to encrypt message into cypher text, and a cypher text can only be encrypted by Bob, using the corresponding private key.
### Certificates
An essential problem in public key cryptography is how Alice can obtain the public key of Bob.
The standard is to use certificate issued by a certificate authority, we call it the CA.
First, every entity has installed the public key of CA.
Then Bob can ask the CA to generate a certificate for his public key.
The certificate authority keeps the signing private key to itself.
And again, the corresponding public key has been installed in all entities.
The CA signs Bob's public key using it's signing private key and the signature is put into the certificate.
So Bob can now present the certificate to Alice.
And because Alice has the certificate authority's public key, she can verify that the signature was constructed properly.
Which means that Bob's public key has been certified by the certificate authority.
Here's an example of public key certificate.
Let's go over some important information.
First, there's a unique serial number.
Second, there's a valid time period.
And there's a public key and a signature produced by the CA.
Here's an example of certificate information that a user sees on his computer.
It identifies that the certificate is for the public key of mail.google.com.
A certificate is for an entity or subject that is identified by the common name.
So what is a common name?
A common name can be an explicit name, for example cc.gatech.edu.
Or it can be a wildcard, for example, *.gatech.edu.
If a wildcard is used it can only be the leftmost component, and it does not match dot.
For example: *.a.com matches x.a.com but not y.x.a.com.
There are large numbers of CAs out there, and a browser typically accepts certificates from 60 top level CAs and
1200 intermediate CAs.
### SSL and TLS
Let's briefly review SSL/TLS.
The goal of this handshake is to authenticate the server and optimally the browser and more importantly, at the end, both will have a shared secret key that can be used to encrypt HTTP traffic.
The client sends a hello message to a server and the severs response includes a proper key certificate.
The browser verifies the certificate, meaning that now the browser knows the server's valid public key.
And with that, the browser can now perform key exchange.
For example, it can use Elliptic curve Diffie-Hellman key exchange.
With a server's public key, the browser and the server can perform secure key exchange and prevent man-in-the-middle attack.
And the result is that they now establish a shared secret key and they can use this shared secret key to encrypt HTTP data.
### Attack Quiz
Now let's do a quiz on flooding attack.
With regards to a UDP base flooding attack, which of the following statements are true?
### HTTPS in the Browser
HTTPS is integrated into a browser, or it is indicated in the browser GUI.
The goal is to let the user know where a page came from.
And it tells the users that the page contents are protected, meaning that they're encrypted so that a network attacker cannot see them or modify them.
In reality, there are several security problems.
When the lock icon is displayed on the browser, it means that all the elements on the page are fetched using HTTPS.
But for the browser to even accept this HTTPS connection, it means that the browser has trusted the certificate and verified that the certificate is valid.
And also, the domain URL matches the CommonName or
SubjectAlternativeName in the certificate.
For example, the certificate of google.com can simply supply a list of alternative names.
### HTTPS Disadvantages Quiz
Now lets take another quiz on HTTPS.
Which of the following are real disadvantages of using HTTPS?
### HTTPS Disadvantages Quiz Solution
You need to buy an SSL certificate.
Mixed modes issues, loading insecure content on a secure site.
This will continue to be the problem until many, many sites are all using HTTPS.
Proxy caching problems, public caching cannot occur.
This is because all traffic is encrypted, so there's no public caching possible.
### HTTPS Problems
Let's discuss several security problems with HTTPS and the lock icon.
This include upgrade from HTTP to HTTPS.
Forged certificates.
First, let's discuss upgrade from HTTP to HTTPS.
There's an attack method called SSL stripped.
It prevents the browser from upgrading.
With SSL stripping, the browser won't display any SSL certificate errors, and the user has no clue that such an attack is happening.
This attack is also known as HTTP downgrading attack.
The connection established between the victim user's browser and the web server is downgraded from HTTPS to HTTP.
For example, when a user wants to transfer money to his account using an online banking service, he enters the following URL in the address bar of his browser, www.foobank.com/onlinebanking.
Of course, this URL is intended for the web server of the bank.
In the background, the user's computer happen to be connected to the attacker's machine.
The attacker waits for a response from the bank server.
The attacker forwards the request to the bank and waits for the response.
The connection between the attacker and the bank is secure.
That means the traffic is transferred using an SSL tunnel.
Therefore, the login page from the bank's web server will be https://www.foobank.com/onlinebanking.
The attacker has access to the login page and can modify the response from the server from HTTPS to HTTP and then forward the login page in HTTP to the client.
The user's browser now is connected to http://www.foobank.com/onlinebanking.
The user's browser is now connected to the bank's website with an insecure connection.
From this point on, all the user's requests go out in plaintext, and the attacker can access the data and collect the credentials.
While the server thinks that it's been using a secure connection, that connection is really just between the web server of the bank and the attacker.
On the other hand, the user's browser is using the insecure HTTP connection, thinking that that's what the bank's web server wants it to use.
The solution to SSL strip attack is to use HSTS, which stands for
Strict Transport Security.
This policy can be set for a maximum of one year.
It basically tells the web browser to always use HTTPS, even for its subdomains.
When a web browser visits a website for the first time, the website can tell the browser to always use HTTPS.
That is, for any subsequent visit, all connection must be over HTTPS, and HTTP connections will be rejected.
A web browser can also have a preloaded list of HSTS websites.
Even before web browser visits a site on this list, it knows that it must use HTTPS.
The HSTS flag set by a website can be cleared when the user selects clear private data.
Another serious security problem is forged certificates.
For example, if a CA is hacked, the attacker can issue rogue certificates.
For example, for Gmail.
And once a rogue certificate is issued, now the attacker can set up a fake website and calling itself Gmail.
In this website, we have the rogue certificate for Gmail.
And several countries have been caught issuing unauthorized certificates, for example, for Google so the ISPs in these countries can play man in the middle between a user and the real Google server.
This is further illustrated in this example.
Suppose a user wants to connect to a bank.
There's a bad guy in the middle, and this attacker has a rogue certificate, therefore it can pretend to be the bank.
The user may think that he is connected to the bank because the certificate says so, but however, the certificate is rogue, meaning that the user is actually connected to the bad guy.
This illustrates that with a rogue certificate, an attacker can play man in the middle, even in HTTPS connection.
The attacker plays the bank server to the user and the user to the bank server.
And both sides of connections are in HTTPS.
### HTTPS Attack Prevention
One approach to deal with rogue certificate is to use dynamic public-key pinning.
This means that a website will declare the CAs that sign its certificate.
When a browser first visits a website, the website tells the browser the list of authorized CAs.
Then on subsequent visits, the browser will reject any certificate issued by other CAs.
Very similarly there's a public-key pinning extension for HTTP or HPKP.
This feature tells a web browser the list of proper keys to be associated with the website.
And it can prevent man-in-the-middle attacks with forged certificates.
When the browser visits a website for the first time, the browser sends a list of public-key hashes.
And on subsequent visits, the browser expects the server to use one or more of these public keys in its certificates.
Another problem to deal with forged certificate is for the CAs to be transparent.
That is, the CAs must publish in a public log of all the certificates that they have issued and a browser will only accept a certificate if it is published on a public log.
And companies like Google can constantly scan the public logs to look for invalid or forged certificates.
### Malware Prevalence
Let's review why malware is such a big security problem.
It is very easy for malware to get on a user's computer.
Say a user browses the web, for example, reading the news at USAToday.com.
And this may result in a compromise to his computer.
The reason is that USAToday.com's ad network can be compromised, so when they use their browsers usatoday.com, his browser will be served with malicious JavaScript.
And of course, this script is bundled with ad and this malicious JavaScript will automatically direct the user's browser to a rogue AV website.
Rogue AV stands for rogue antivirus software.
The end result is that the user's tricked to download a rogue AV, which is actually a malware.
Here's a case study on how many sites may have been compromised and serve malicious contents.
The researchers analyzed the Alexa top ranked domains.
They allowed 252 million domains worldwide in 2016 at this time.
A research system was created to examine
Alexa top 25,000 domains each day.
Essentially the browser within a virtual machine is forced to visit each domain.
A research system was created to examine
Alexa's Top 25,500 domains each day.
Essentially, the browser within the virtual machine is forced to visit domain.
The network traffic that follows a visit to these websites are analyzed to determine whether drive by download had occurred.
The result show that 39 domains resulted in drive by download.
And among these, 87% of these sites involved exploits of JavaScripts.
And 46% of these sites served the exploits through ad networks.
From Alexa statistics, about 7.5 million users visited these 39 sites.
And about 1.2 million user computers are likely compromised because these computers don't have adequate defenses.
For example, they have out of date antimalware software.
Collectively the attackers always develop new malware and new ways to spread malware widely.
For example, an exploit was developed on mobility in Acrobat Reader's Flash interpreter.
As defenders we may discover that one of our user's computers was compromised by this exploit.
For example, we may be able to observe the phone home traffic from the compromised computer.
That is we may observe the command control traffic.
From the compromised computer.
And the chances are our user is not alone because we may soon discover that many websites are hosting the same kind of exploits.
This is indeed the real case.
And of course, users remain the weakest link and often they are subject to social engineering attacks.
For example, a very compelling email may make a user click on an active content.
For example a video or flash content.
That result in a compromise such as this real case.
### Malware Evolution
You may wonder, don't we already have defenses against malware?
Yes we do, but malware keeps evolving very fast and some of the traditional mechanisms are not adequate.
We should deploy defense in depth, and for network protection we have firewalls as the prevention mechanism and IDS as the detection mechanism.
But for firewall, command control traffic can look just like normal traffic, such as visiting a webpage.
For IDS that analyzes the payload of traffic, the encrypted or specially encoded malicious contents can evade such analysis.
On the host, if you ask the user's consent, most often since the users often do not understand the security implications, they will simply say yes.
In terms of antivirus software, the traditional signature matching approaches are not effective where malware uses obfuscation techniques.
And so, we have to continue to develop more complex behavior-based analysis approaches.
### Malware Obfuscation Quiz
Now let's do a quiz.
Based on this definition of packing, which is a typical obfuscation technique?
Which of these statements are true?
### Malware Obfuscation Quiz Solution
Since the malware contents are encrypted, and look random, a signature-based approach would not work.
Therefore, the first statement is true.
And, since the malware contents are encrypted, and look different, there's no single signature that matches all the instances.
So, the second statement is false.
Of course, we need to include code that decrypts the malware in runtime so that the malware can execute.
Therefore, the first statement is true.
Know that we can simply use the code that the compressed or the encrypted malware as a signature because legitimate programs can contain such instructions, for example for digital rights management.
### Malware Obfuscation
Now let's take a closer look at one of the most widely used obfuscation techniques, packing.
Given the original malware program, the packing tool would transform it, so that the transformed code looks random.
Because it is encrypted, we randomly generate a key.
And this happens each time the packing program is run on a malware program.
That is even for the same malware program, each packed instance will look different.
And therefore, a signature based approach is not effective in detecting the malware.
Furthermore, the transformed machine code looks like data.
Therefore, a network IDS that looks for executables and email attachment will miss it.
If the anti virus company obtains the zero day malware, even though it is obfuscated.
Eventually, the researchers can de-obfuscate the malware and discover its behaviors.
But such analysis takes time and the attacker can make such analysis fruitless.
Even anti virus company analyzes a zero day malware even though it is obfuscated.
Eventually, the researchers can de-obfuscate the malware and discover its behaviors.
But such analysis takes time.
And the attacker can make such analysis fruitless.
In particular, the attacker's server can continuously send an updated or new malware.
That is obfuscated of course, to the compromised computers.
Then in effect, the defenders or researchers have to deal with zero day on new malware constantly.
That is by the time they have successfully analyzed a malware, it has become obsolete.
A real example of this server polymorphism is Waledac.
This particular version of the malware postcard.exe was released on December 30,
2008 and by February 25, 2009, the majority of the antivirus software can detect it.
But a new version of the malware disc.exe was detected by only a very small percentage of the antivirus software on the date it was released.
Here's an example showing the challenges the anti-virus industry is facing.
The researchers surveyed McAfee anti-virus software using
20,000 malware samples collected over six months.
53% of the malware samples were detected on the day of release.
32% of the malware samples were detected with a delay.
And the delay was on average 54 days.
And 15% of the malware samples were not detected even six months later.
### Attack Quiz Solution
Attackers can obviously spoof the IP address.
The attack cannot be mitigated using firewalls because the idea is that the packets involved in the attack, they all look legitimate.
In addition, even if the firewall is attempting to do filtering, it itself is susceptible to flooding.
The reason is that the firewall now needs to examine many, many packets.
### MALWARE QUIZ
Now let's do a quiz.
Obfuscation techniques are commonly used for one of three purposes, to hide from the users, to hide from security mechanisms, or to hide from researchers.
Given these techniques, which one is hiding from the users or hiding from the security mechanisms or hiding from the researchers?
### MALWARE QUIZ Solution
Rookits is used to hide the malware from the users.
Mapping the security sites and honey pots are used to avoid security mechanisms, such as detection mechanisms.
Use nonce-based encryption schemes would make cryptanalysis more difficult, and this is to hide from the security researchers.
### Malware Analysis
Now let's discuss malware analysis.
What are the benefits of malware analysis?
If we understand malware's network behaviors, we can create rules to detect and block malware traffic.
If we understand malware's on-host behaviors, we can repair the compromised hosts.
If we have knowledge of the malware's support infrastructure on the internet and it's evolution history, we can also analyze it's trend and threat scope.
Such as, how widespread the malware is and the likely next target, etc.
Of course, the attackers try to defeat malware analysis, and are using the most sophisticated techniques available.
Another challenge in malware analysis is the volume of malware is really huge.
Available and automated tools made a job of creating malware obfuscated of course very easy.
And in fact there are hundreds of thousands of new samples every day.
Since the malware creation process is already automated it is imperative that malware analysis has to be automated as well In addition to automation, malware analysis also needs to be transparent so that the malware does not know it is being analyzed.
Otherwise the malware may refuse to run, or purposely alter to its behaviors to fool the analysis.
This is the so-called malware uncertainty principle, but this is very challenging.
In physics, the Heisenberg principle says that an observer will inevitably affect the observed environment.
In malware analysis, our tools may be so invasive that the malware can detect them if we're not careful.
In malware analysis, our tools and techniques are often invasive.
And if we are not careful, the malware can detect a presence of the analyzer and refuse to run.
In fact, malware authors already tried to actively detect malware analysis tools.
In the malware creation tool kits, there are standard point and click options to add logics to detect various malware analysis methods, such as these examples.
So we need malware analysis to be transparent to malware.
That is, malware should not be able to detect that it is being analyzed.
But how do we fulfill such transparency requirements?
A malware analyzer should be at a higher privilege level than a malware, so that the malware can not directly access, or know about, the analyzer.
In addition, the malware may use operations to try to find the presence of the analyzer.
For example, it may try to find a side effect of analysis.
These operations should be privileged, so that the malware cannot directly get the answers back.
And, since the analyzer is at a higher privilege level, it can actually lie the answers back to the malware.
That is, the malware gets the wrong answer and doesn't know about the side effects.
And obviously, the malware should get the same correct result of instruction execution as if the analyzer is not present.
Likewise, the malware should see identical signals and instruction handlings, as well as time durations.
In terms of fulfilling the transparency requirements most interesting tools fall short.
For example, even analyzer is in guest this means that the analyzer runs on a same machine and has the same privilege as the malware then the analyzer does not have high privilege.
Some of the analysis study facts can be discovered but a malware without privilege operations.
And the exceptions trapped by the analyzer may be discovered by the malware.
If the analyzer runs in a virtual machine that's based on software virtualization such as VMWare then there could be side effects that can be discovered.
But a malware without privileged operations.
If the analyzer runs in emulation environment such as QEMU the execution semantics of instructions maybe different from real hardware.
Emulation based malware analysis tools are the most widely used.
But they have major shortcomings.
The main issue here is that this emulation emirames do not fully emulate the hardware.
There is that a corner cases where a set of instructions give different results on emulation emirames versus hardware.
And there have been attacks based on these corner cases to detect emulation emirames.
But the bigger problem is that there is no way to eliminate all these corner cases.
In fact, in theory there's no way to guarantee the absence of such attacks.
And the reason is the so-called
EQTM is not decidable.
Which means that when you view an emulator, you cannot determine that it behaves exactly the same as the real machine.
In other words, you cannot rule out the possibility that there are situations that your emulator and the real machine behave differently.
Here's a simple example of the discrepancies between emulator and real hardware.
That is, the real hardware will give an illegal instruction exception, but an emulator will happily execute the instruction.
### Identical Notion of Time
The most challenging transparency requirement is the identical notion of time.
In particular, if malware uses network timing measurements to infer the presence of analyzer.
For example, the analyzer causes delay, or the website that the malware connects to is not a real one.
There are many direct or indirect measurements that a malware can perform and it is impossible to identify all direct or indirect measurement techniques.
In fact, the problem of identifying all network-based timing measurements is equivalent to the problem of detecting and removing all covert channels.
This problem has been proved to be undecidable.
### Analysis Difficulty Quiz
Now let's do a quiz.
There are four basic types of malware analysis that can be performed.
Please rank these techniques from the easiest to the hardest.
### Analysis Difficulty Quiz Solution
Fully automatic tools should be first performed, they are typically the easiest.
Static analysis should be tried next.
Interactive analysis requires more skills and time to set up.
The most difficult one is manual reverse engineering.
It requires a lot of skills and time.
### Analysis Technique Results Quiz
Let's do another related quiz.
Rank these analysis techniques by how much information each technique can reveal.
### Analysis Technique Results Quiz Solution
It is not surprising that the harder an analyst's technique is, the more information it can yield.
### Robust and Efficient Malware Analysis
Now let's discuss how to build a robust and efficient malware analysis system.
By robust, we mean it is transparent and is not easily detected and evaded by malware.
By efficient, we mean it is automated and fast.
We focus on host-based analysis.
That is, learning malware on a machine and analyze its behaviors.
As a recap, the malware will tried to detect the presence or the side effect of the analyzer.
And our goal is to achieve the same result of malware execution, regardless of the presence of the analyzer.
So let's analyze the transparency requirements again and see how they can be fulfilled.
For higher privilege, let's put analyzer in hardware or a virtual machine.
For the requirement of no non-privileged side-effects, we need to make sure that no side effects can be detected by non-privileged instructions.
That is those are the malware can execute and get results.
Of course the analyzer will inevitable introduce side-effects.
But if the malware has to use privileged instructions to learn about these side-effects, these instructions have to be executed at a higher privilege level than the malware, and then the answers are provided back to the malware.
The analyzer, since it is at a high privilege level, can lie the answers back to the malware.
For the requirement of identical basic instruction execution semantics, we need to use the real hardware.
Likewise, we need to make sure that exception handling will be the same as if on real hardware.
For timing, we need to know the timing of each instruction I/O, and exception handling on the real hardware.
And make sure that the malware can only use privileged instructions to get timing measurements on the host so that the analyzer can lie the answers back.
Just to recap, in order to achieve transparency, a malware analyzer needs to be on a higher privilege, has no non-privileged side effects, has identical basic instruction execution semantics, has the same transparent exception handling, and identical measurement of time.
### Ether Malware Analyzer
Here's an example of a transparent malware analyzer that they built at
Georgia Tech called Ether.
By the way, it is open source.
Let's briefly describe how Ether fulfills the transparency requirements.
Ether is built using Intel VT for hardware virtualization.
The Hypervisor has higher privilege over the OS kernel.
Therefore, Ether has higher privilege than malware.
Some of these hardware supported traps further guarantee this higher privilege.
Ether runs outside of the virtual machine where the malware runs.
Therefore, there's minimal side-effects that malware can directly observe.
Ether uses hardware based authorization and therefore, the instruction execution semantics are the same as on hardware.
For exception handling, again, hardware-based virtualization allows the same semantics as on hardware.
For on-host time measurement, the operations comes down to the use of read time-stamp counter instruction.
This is a privileged instruction and therefore, the Hypervisor and ether can control the return results to the malware when the malware tries to get a measurement of time.
Here's the architecture of Ether.
Ether has a component within Xen, the Hypervisor.
And the rest of Ether is in Dom0.
A separate, privileged virtual machine.
The malware runs on a separate user level virtual machine called DomU.
Ether provides a fine grained insertion by insertion examination of malware and also a coarse grained system call by system call examination.
We created two tools to evaluate Ether.
The fist is EtherUnpack.
It extracts hidden code from obfuscated malware.
The second one is EtherTrace, it records system calls executed by obfuscated malware.
We then compare both of these tools to the current academic and industry approaches.
For EtherUnpack, we compared how well current tools extract hidden code by obfuscating a test binary and looking for a known string in the extracted code.
For EtherTrace, we obfuscated a test binary which executes a set of known operations and then observe if they were logged by the tool.
For EtherTrace again, the results show that Ether has much better transparency than other tools.
Now Ether has limitations and it is only one of the tools in the continued battle between defenders or malware analysis and the attackers or obfuscations.
Let's take a look at this model.
Here, for each major categories of analysis approaches, the attackers come up with obfuscation techniques to defeat such analysis.
For example, for static analysis, including scanning the binaries looking for fixed strings, the attacker can obfuscate the malware.
For example, as a result of packing, the binary contents will look different from one instance to the next.
We also use dynamic analysis, meaning running the malware.
The corresponding obfuscation technique is trigger-based behavior.
For example, the malware will not run until the time is right.
Or it detects the fact that it's been analyzed in an emulation environment and then stopped.
And since simple dynamic analysis now becomes inadequate, researchers have come up with various ways to force execution of this malware.
And of course, this battle between analysis and obfuscation will continue.
### DoS and Route Hijacking
The Internet routing protocol can also be exploited to launch in our service attacks.
In particular, there have been several incidents of route hijacking that resulted in denial of service.
Here's one example involving
Pakistan and YouTube.
The Internet is divided into a large number of so-called autonomous systems.
Each autonomous system or
AS is responsible for logging packets in and out a subset of the Internet defined by the prefix.
For example, the YouTube service address is within this prefix.
It is actually 208.65.103.238.
In February 2008, Pakistan Telecom advertise that, is actually responsible for subset of Internet defined by this particular prefix.
And this prefix is more specific than a segment that includes the YouTube server.
And since the routing positions for a specific IP address, such as the YouTube server use the more specific prefix.
Then the whole Internet thought that
Pakistan Telecom is responsible for routing traffic to YouTube.
The result of this route hijacking is that all traffic to YouTube was instantly routed to Pakistan.
As you can see, the traffic volume at the YouTube server jumped to zero until the route hijacking mistake was corrected.
In a more recent example,
China Telecom published
BGP routes that caused .mail and
.gov to route through China Telecom.
### Malware Emulators
A recent trend is that malware authors are starting to use emulation-based obfuscation techniques.
And this is an insertion level approach.
And there are several commercial tools out there and they can be used for instrument purposes such as digital rights management.
So how does emulator-based obfuscation work?
Suppose we have the original malware and it is for x86 instruction set architecture.
For example, your Intel based machines.
The malware is then transformed into Bytecode Program of an arbitrary language L.
And then, this emulator, based on L, will emulate this microprogram on x86.
That is the obfuscated malware
Include both the Bytecode Program and its emulator.
And when the obfuscated malware runs on x86, the emulator will emulate this Bytecode
Program and execute the malware logic.
So what are the impact of emulation based obfuscation on malware analysis?
First of all, the malware program now is a Bytecode of arbitrary language L which is not known.
In fact, the language L can be randomly generated and since we don't know the language
L we can not perform pure static analysis on malware
Bytecode program written in L.
We can perform analysis on the Emulator.
The Emulator actually is not specific to the malware Bytecode program.
It is only specific to the language L.
In face, the malware Bytecode program is only one of the possible inputs to the Emulator.
We can perform dynamic analysis including some of the low code analysis.
We call this greybox methods.
But such analysis is actually performed on the Emulator, not the malware code directly.
The reason is that the executable is the Emulator.
The malware Bytecode is the input.
Therefore, the analysis results that we get are from the Emulator, not directly from the malware Bytecode.
Manual reverse-engineering cannot scale, because each instance can have a different language L, and a different Emulator.
Since the process of creating such confiscated malware is automated.
We also needed an automated approach to reverse engineer these Emulators.
By this, we mean that we should not require knowledge of the language L.
And our approach should be general enough that will work on a large class of Emulators.
But is an automated approach possible?
In theory, it is not.
On the other hand, most of the Emulators have a fetch-decode-execute behavior that can be identified at runtime and then can be the starting point of our reverse engineering.
### Approaches of Emulation
Now let's understand how emulation works in a bit more detail.
In fetch, decode, and execute, the emulator fetch the next bytecode, decode to get it's opcode.
And look up the execution routine for this opcode and then execute it.
Notice that the execute routine execute real x86 machine code.
The Virtual Program Counter,
VPC, is a maintained point to the next bytecode to fetch from.
Now let's discuss briefly how we can reverse engineer emulator-based obfuscation.
There are quite a few challenges.
First of all, we don't even know where the bytecode program resides in memory.
The emulator code responsible for fetch, decode, and execute, is also not known.
The malware author can certainly make reverse engineering more difficult by changing how the emulation works.
We develop a tool to automatically reverse engineer emulator-based malware, and here's a very high level overview.
The first step is to identify abstract variables, in particular pointers.
And of course, one of the most important pointers we need to identify is VPC.
A VPC points to the next bytecode to fetch, decode, and execute.
Therefore, once we identify the VPCs, we can identify the fetch, decode, and execute behavior in the emulator.
From the fetch, decode, and execute operations in the emulator, we can obtain the opcode and operands, as well as the execution routine of the malware bytecode.
We can then construct a control flow graph of the original malware.
And this will tell us the behaviors of the malware.
Here are some results of our experiments.
We created a synthetic program.
We then apply two emulation-based obfuscation techniques.
One is called VMProtect, the other one is called Code Virtualizer.
We then applied our tool to the obfuscated program.
We then compared a control flow graphs of the original program and the control flow graphs from our reverse engineering.
Here is the control flow graph of the original program, and a graph from reverse engineering
Code Virtualizer, and a graph from reverse engineering VMProtect.
As you can see, our tool is succesful in terms of extracting the main properties of the original control flow graph.
Here are the results from the experiments on a real program,
NOTEPAD.EXE.
Again, here's a CFG of the original program.
And here's the result from reversing VMProtect.
Again, our tool is able to obtain the main information and properties of the original CFG.
### Mobile Device Quiz
We are going to spend this lesson discussing mobile malware or malware on mobile devices.
So let's take a moment to make sure that we all agree as to what we mean when we say mobile device.
According to Wikipedia, which of these devices is a mobile device?
### Mobile Device Quiz Solution
Wikipedia says that a mobile device must be mobile.
Therefore, a smartphone by itself is not mobile.
However, a smarthone held by a person can be mobile because it is a non mobile device with a mobile host.
These are examples of true mobile devices because either myself can be mobile.
We are not going to use the strict definition of mobile device.
Instead, we're going to use this common definition.
That is a smartphone is a mobile device.
### Forensics Quiz
Before we discuss mobile malware, we should understand the difference between mobile devices and the traditional stationary computers.
Which of the following characteristics are associated with mobile devices versus stationary computers?
### Forensics Quiz Solution
Mobile devices tend to use specialized hardware.
Whereas stationary computers tend to use standardized hardware.
Mobile devices tend to use many different versions of operating systems.
For example, there are many different versions of Android.
Whereas stationary computers tend to run Windows, MAC OS or Linux.
They also have large storage capacity.
On the other hand, mobile devices tend to have a large number of accessories such as cameras and GPS.
### Malware Trends
Since mobile devices are increasingly used for critical functions in our daily lives, and they have become powerful computers with good connectivity, they have become security targets.
This part shows the major categories of mobile malware.
### iOS Malware
Some apps may appear to be providing useful functions but they secretly still uses confidential information.
These apps are considered malware.
Here's an example of such malicious apps and it was taken off the app store.
But malicious apps may still get on victims devices even after it is taken off the app store.
One technique is to exploit the design floor in Apple's DRM scheme.
Apple allows users to purchase and download iOS apps from their app store through the iTunes client running on their computers.
They can then use their computers to install the apps onto their iOS devices.
The iOS devices will request an authorization code for each app installed to prove the app was actually purchased.
In a FairPlay man in the middle attack, attackers purchase an app from the app store, then intercept and save the authorization code.
They then develop a program that simulates the iTunes software, and installs the software on a victim's computer.
And this fake iTunes software can check the victim's iOS devices to believe the app was purchased by the victim.
Therefor the user can install apps they never actually paid for, and the attacker can install malicious apps without the user's knowledge.
This attack continues to work even after the malicious app is removed from the app store.
### Android Malware
There is a large increase of the number of Android malware and the majority is still SMS Trojans.
You can read more about current
Android malware at the link in the instructor's notes.
We discuss a few here.
AccuTrack turns an Android smartphone into a GPS tracker.
Ackposts steals contact information.
Acknetdoor opens a backdoor.
Steek does fraudulent advertising and also steals private information.
Tapsnake posts the phone's current location to a web service.
ZertSecurity steals the user's bank account information.
Similarly, Zitmo also steals the user's bank account information.
And there are many other more.
Again, you can read more about the current Android malware at the link in the instructor's notes.
This plot summarizes the major categories of Android malware and their trends.
There are quite a few free Android antivirus apps, here are a few examples.
The security companies own statements provide some insights of the state of anti malware on mobile phones.
First of all, the risk is relatively low.
In general, mobile devices are still less powerful than desktops and laptops and there are plenty of those that can be targeted by hackers.
Furthermore, the [INAUDIBLE] process and the sandbox space execution model also means that the mobile devices are in general more secure.
Nevertheless, there is still the need to protect mobile devices.
In particular, in addition to protection against malware, a bigger problem is the loss of devices and the loss or the theft of data.
And therefore secure companies also try to protect and manage mobile data.
Mobile malware are becoming more sophisticated and are showing the same advanced features of malware and laptops and desktops.
Here's an example of Android malware that uses social engineering to spread.
It targets a group of activists.
On March 24, 2013, the email account of a high-profile
Tibetan activist was hacked and it was used to send spear phishing emails to people on his contact lists.
This is what the spear phishing email looked like.
The recipient of this email is tricked that he should install this APK file on his Android device which is the malware.
After installation, an application named
Conference appears on the desktop.
After the installation, if the user launches this Conference app, he will be seeing the information about the upcoming event.
While the victim reads this fake message, the malware secretly reports the infection to a command control server.
After that, it begins to harvest information stored on a device.
The stolen data includes contacts, call logs, SMS messages, your location and phone data, which includes phone number,
OS version, phone model, etc.
Know that the stolen data won't be uploaded to the command control center automatically.
The malware waits for incoming SMS messages from the command control center.
And based on the message, the malware knows what data to upload.
### Lifetime of iOS Malware
Now let's review iOS Malware, in particular the lifetime or stages of an iOS malware and how the functions of each stage can be realized.
These stages include produce, distribute, do evil and make profit.
And there are multiple approaches to go about at each stage.
### Higher Level DoS
So far, we have discussed denial service attacks that exploit weaknesses in network protocols.
Denial service attack can also happen at a higher level.
For example, let's look at a typical handshake protocol.
Here's a protocol that use publicly based authentication.
So the client sends a hello message to the server, and a server sends its public key to the client.
And then, the client will use that public key to perform key exchange.
For example, the client can generate a secret share key between a client and a server, and encrypt that using the server's public key.
And when a server receives this encrypted key, it will use its private key to decrypt, to extract this secret share key.
The point is the client encrypts the secret share key using the server's public key, and then the server decrypts that using its private key.
It's all good from a crypto point of view.
However, RSA Decrypt is ten times more costly than RSA Encrypt, since the server has to do so much more work.
The attacker can send many such handshake requests to the server to bring it down.
Similarly, at the application level a client can send a simple HTTP request to your server asking for a very large PDF file.
And obviously, the server needs to spend far more resources than the client.
Therefore, an attacker can send many such HTTP requests to your server, causing the server to fetch a large number of very large PDF files, and this will actually bring down the web server.
### Toolchain Attacks
Toolchain attack is one approach to produce malware.
Here's a real example, an official distribution of Xcode was compromised with malware.
If a developer used this infected
Xcode library to develop an app, the app will be infected.
The infected app will then collect information on devices and upload the data to a C&amp;C server.
This attack is very potent, because any app that is compiled using this Xcode library now becomes a malicious app.
This XcodeGhost was able to infect many apps, including 39 apps published in the official iOS App Store.
Attacking the App Store review process is one approach to distribute malware.
Here's an example.
We created the Jekyll app in 2013, we planted vulnerability in this app, this vulnerabilities can be exploited at run time with a particular input.
Once the vulnerabilities is exploited the Jekyll app can activate new addition execution path through
Return-Oriented Programming.
And then the app can send SMS, email, tweet, and so on.
On the other hand the App Store review process cannot find these malicious paths, because they cannot review without a correct input and runtime.
To illustrate, the App Store review process finds that the control flow of the app to be safe, that is all the exclusion paths are acceptable.
On the other hand a run time minimal ability planted in the code is exploited, because of the specific input that a new control flows that were not observable in the app view process.
These new control flows allow the Jekyll app to do evil and make profit.
For example, it can do a number of activities.
These can be achieved by calling private
APIs that are not directly accessible to legitimate apps.
But a Jekyll app knows the memory layout and hence the addresses of these APIs and can directly jump to them.
### Toolchain Attacks Quiz
You can read more about the XCodeGhost attack with the link in the instructor's note.
Then you can answer the question, what kind of information can an infected app obtain from the device?
### Toolchain Attacks Quiz Solution
There is quite a bit of information that can be gathered by the infected app.
Information can then be used to craft further attacks, or it can be used to steal passwords and user names.
### Hardening the ToolChain Quiz
We now know that toolchain have occurred and will continue.
So, the question is, can you hold on the toolchain?
In this quiz, list the four areas of the C based toolchain where hardening can occur.
### Hardening the ToolChain Quiz Solution
Essentially, all the main steps of the toolchain can be hardened.
### Mobile Malware Protection
Let's discuss a few approaches to mobile malware detection.
Please check the instructors notes for links to these papers.
Kirin is a very simple system that looks for suspicious combination of permissions.
RiskRanker use heuristics such as cryptos that relates to unpacking code.
Similarly, DroidRanger use heuristics such as loading native code from suspicious websites.
DREBEN uses a machine learning algorithm called SVM, or Support Vector Machine.
And the data attributes used for modeling include permissions,
API calls, and so on.
Many malicious apps are actually repackaged version of legitimate apps.
This is actually the most effective way to distribute malware, because a popular or cool app already has a large number of users.
There are research systems on clone detection.
Here are a few examples.
For example, DroidMOSS use fuzzy hashing of Java methods to match and detect clone code.
DNADroid performs similarity analysis on PDGs.
PDGs are program dependency graphs between methods.
There are a few sandboxes for mobile malware analysis.
And these sandboxes enable dynamic analysis.
Here are a few example sandboxes.
Many dynamic analysis and detection tools use system call information.
Here are a few examples.
For example, PREC stands for particle root explore containment.
It can dynamically identify system calls from high risk components, for example, third party native libraries.
And execute those system calls within isolated threads.
Therefore, PREC can detect and stop root exploits with high accuracy, while imposing very low interference to benign applications.
### Information Leakage Protection
Information leakage is a big concern, and apps that leak sensitive information can often be considered malware even though many think that they are in a gray area.
There are several approaches to detect leakage, for example,
PiOS performs static analysis to detect information leakage.
TaintDroid uses taint tracking to perform information flow analysis.
That is, it analyzes how data from a source, such as address book, flows to the sync, such as the internet.
Another approach is to check if an app does what it promises to do, for example, WhyPer compares the app's permissions against its description.
And the analysis is based on natural language processing techniques.
### STAMP Admission System
Now let's discuss a research system designed to analyze mobile apps and decide if the mobile apps meet security and privacy requirements.
The system is intended to be used in an App Store to decide if an app should be admitted.
The system uses both static and dynamic analysis approaches because they have pros and cons of their own.
### Data Flow Analysis
One of the most important analysis is data flow analysis.
Here's an example of data flow, the source is location data and the sink is SMS or website on the internet.
Data flow analysis can be useful malware or greyware analysis to find out what information is being stolen.
And based on the discoveries, we can improve enterprise specific policies.
Data flow analysis can be used to check the external app to make sure that there's no API abuse or data theft.
Data flows gathered from an app can be used to inform users about potential privacy implications.
Data flow analysis can also be used to discover abilities in applications.
For example, accepting data from untrusted sources.
However, analyzing data flows is a very challenging task.
For example, Android has more than three million lines of very complex code.
Performing data analysis on whole system would take a long time, and it's not practical.
And of course to be useful, data flow analysis has to be accurate.
As we have just discussed, analyzing a app in a context of full Android is very expensive because there is too much code involved.
The STAMP approach is to abstract the Android stack into models.
And these models include the following information.
We are going to focus on data flows.
### Data Flows
There are more than 30 types of sources.
Here are some examples.
There are more than ten types of sinks, and here are some examples.
Each pair of source and sink is a flow type, and there are close to 400 flow types.
Here's an example of data flow analysis on the Facebook app.
The description of the app says that it allows the user to synchronize contacts.
And it says that Facebook does not allow the export of phone numbers or emails.
And the users can plug one or all apps but there's no privacy policy.
Here are the possible flows.
On the left, we have the sources.
On the right, we have the sinks.
That is potentially all resources can go to all the sinks.
From the Facebook description, we expect to see the state of flow for sinking contacts.
However, the data flows observed from the Facebook app include additional flows that lead to leakage.
### DoS Mitigation Client Puzzles
So how do we mitigate such denial of service attacks.
One solution is to use client puzzles.
The main idea is to slow down the attacker.
For example, we can ask the client to solve a problem.
For example, the server can challenge C to the client and ask the client to find or compute X such that the n needs significant bits of the SHA-1 hash are all 0s.
The assumption here is that it would take the client 2 to the n time to solve this challenge.
For n=16, it would take 0.3 seconds on a 1 gigahertz machine.
And of course, the client needs to present X back to the servers, and it is very easy for server to check that the solution is correct.
This is because the server needs to only compute hash
1 whereas the client is to compute to the n times.
During a denial of service attack everyone, that is including legitimate clients or possible attackers, everyone must submit puzzle solution to the server.
And of course, when there's no attack, no one needs to solve the puzzle.
Here are some examples of how client puzzles can be deployed.
For TCP connection flooding, the challenge C can be the TCP's server sequence number, and the first data packet from the client must contain the puzzle solution.
Otherwise the server will terminate the TCP connection.
For SSL handshake denial of service attack, the challenge C can be based on a TLS session ID.
And the server will check the puzzle solution before even attempting to do
RSA decrypt, because RSA decrypt is very expensive.
And similar ideas can be applied to application layer denial of service attacks.
One advantage of the client puzzle is that the hardness of the challenge, or in particular, n, can be decided based on the DoS attack volume.
For example, if the volume is high, you can set n to be higher so that it takes more time for the client to find a solution.
In other words, this will reduce the volume of traffic to the server.
The limitation is that this requires changes to both the client code and the server code.
It also hurts legitimate clients, in particular, clients that use low power computing devices such as cellphones.
Another variant of client puzzle is to use memory-bound functions.
This is because CPU-bound functions such as the one we just discussed, cannot be scaled to very hard puzzles for low end machines such as cell phones.
Whereas memory-bound functions can be easily scaled, even for low-end machines.
There are several proposals to use memory-bound functions as puzzles.
You are encouraged to study these papers.
### Network Monitoring
The goal of network monitoring is to detect and prevent attack traffic.
Attack traffic used to be obvious.
For example, the payload of a packet may contain exploit to a known vulnerability and therefore a signature can be used to detect such attack.
Or a network monitor can detect, deny a service attack or spam activity by analyzing the volume and rate of network traffic.
The typical network monitoring systems are the firewalls and the network intrusion detection systems.
Increasingly, the traditional firewalls and network IDS are becoming less effective.
First of all, mobile devices are now widely used.
A mobile device can be compromised when an employee is on travel.
And then when the employee brings the mobile device into the company's network, it effectively has bypassed the perimeter defense.
In addition, attack traffic now is very subtle and they often look like normal traffic.
For example, botnet HTTP-based command and control traffic would look like normal legitimate web traffic.
Therefore, we need more advanced network monitoring systems to detect this new generation of attacks.
In this lesson, we're going to discuss botnet detection systems.
### BOT Quiz
Here's a quiz on the definition of a BOT.
### BOT Quiz Solution
A bot is often called a zombie because it is a compromised computer controlled by malware without the consent and knowledge of the user.
### BOTNET Quiz
Here's a quiz on Botnet.
### BOTNET Quiz Solution
A Botnet is a network of bots controlled by a Bot Master or an attacker.
More preciously Botnet is a coordinated group of malware instances that are controlled via command control channels.
Command architectures include centralized architecture or disputed architecture.
Botnet is a key platform for fraud and other for-profit exports.
### BOTNET Tasks Quiz
Here's a quiz on botnet activities.
Select all the activities that botnet commonly perform.
### BOTNET Tasks Quiz Solution
All of these tasks are commonly performed by botnets.
Other than span and DDoS, these other attacks can look a lot like normal traffic.
### Traditional Security Fail
Let's analyze why the traditional security measures cannot detect Botnets effectively.
First of all, traditional signature-based anti-virus systems are not effective, because bot codes are typically packed and they can use rootkit to hide.
And they also use frequent updates to defeat anti-virus tools.
The traditional IDS/IPS are not effective, because they typically look at the specific aspect of an attack For example, let's be specific exploit.
Whereas Botnet typically perform multiple kinds of activities, because they are for long-term use.
That is, although we can detect that a host has been compromised by an exploit, we do not know that it belongs to Botnet.
Because we need to analyze its command control traffic and daily malicious activities.
Honeypots and
Honeynets are also not effective.
First of all, since they only passively waiting for incoming connections they are to be lucky to capture botnet activities.
In addition, sophisticated bot malware can detect a honeypot because the lack of realistic user activities.
And since a Honeypot is a single host it cannot detect a network of bots.
### Botnet Detection
What are the challenges in botnet detection?
First of all bots try to hide themselves.
Second of all, bots are also involved in multiple activities over a period of time.
Bot malware can also get updates frequently.
Botnets can have many different command control methods.
In fact, a bot malware can be programmed to select one of several C&amp;C methods at run time.
So how do we go about detecting botnets?
We need to first focus on the characteristics that botnets are different from normal traffic.
First of all, a bot is not a human.
That is, the activities by bots may look different from the activities by human.
Second of all, the fact that botnet is a network means that the bots are connected, and their activities are somehow coordinated.
We can also distinguish botnets from other traditional attacks.
Botnets are for profits, and they most likely are going to use the compromised computers as resources.
Botnets are for long-term use.
And therefore there will be frequent updates to the bot malware.
And again there must be coordination among the bots to form a botnet.
Let's first discuss how do we detect botnets in the enterprise network.
We can deploy a botnet detection system at a gateway or router.
This is how we deploy firewall in IDS.
There are several detection approaches in a so called vertical correlation.
We are looking for correlated events across a time horizon, even if a bot has multiple activities in its life cycle.
In horizontal correlation we are looking for similar or coordinated behaviors across multiple bots.
In cause and effect correlation, we inject traffic to pay with the bot to conform that the traffic is generated by bot versus human.
In this lesson, we going to discuss two systems, one is BotHunter, the other one is BotMiner.
### Bot Hunter
BotHunter is a system that performs vertical correlation.
We also call it dialog correlation.
That is,
BotHunter correlates multiple events that belong to the life cycle of a bot.
Let's use an example to illustrate the multiple steps or types of activities in a bot's life cycle.
First, the attacker scan the network and identify vulnerable host.
It then sends the exploit to compromise the victim host and opens a back door.
The compromised computer then downloads the real bot malware, it then connects to a command control server.
And from there, it can perform a number of activities.
For example image scan, for other number of hosts.
From the phatbot example, we can extract the life cycle of a botnet.
You can include inbound scan and inbound infection, and then outbound traffic to download the egg or the bot malware and command control traffic, as well as other activities.
Such as outbound scan.
So the main idea behind BotHunter is to analyze network traffic to detect patterns that suggest any of these activities belonging to the BotNet lifecycle.
These observations don't have to follow this strict order, but they do have to appear within the same period of time.
BotHunter uses a table to keep track of the evidence that it collects for each host.
And here's an example for each internal host, BotHunter keeps track of the specific activities that belong to each steps of the botnet life cycle.
There are timers associated with these observations.
That is they are valid as long as a timer has not expired.
The integration is that within a period of time that is before the timer expired, if you see multiple evidence belonging to the botnet life cycle then we can determine that this host is a bot.
And we give more weight to evidence that suggests that an internal machine has been compromised and it is participating in botnet activities such as egg downloading, outbound scanning and outbound spamming.
### Puzzle Quiz
Now let's do a quiz on puzzle.
Which of the following statements are true?
### BotHunter Architecture
Here's the architecture of BotHunter.
He has a number of detection engines.
Each of these engines are disposable for detecting certain activities of the botnet lifecycle.
And the correlator correlates evidence of these activities and makes detection that an internal machine has been compromised and has become a bot and produces a bot infection profile.
Let's discuss the BotHunter detection engines.
The first is SCADE.
SCADE is for scan detection, recur in the bounded lifecycle inbound scan is a first event.
SCADE used different ways for different inbound scan connections, in particular, it gives us higher weight to vulnerable ports.
SCADE also detects outbound scan.
It looks at the rate of outbound connections, how likely such connection fails and the distribution of the destination of these outbound connections.
Collectively this can suggest outbound scan.
Another BotHunter detection engine is SLADE.
SLADE can detect anomalies in network payloads.
The main idea is that we can establish the normal profile of a network service by looking at the n-gram byte distribution of the traffic payload of this network service.
That is, an attack such as an exploit or egg download will cause deviation from this normal profile because the n-gram byte distribution of the attack traffic will be different from the normal traffic.
SLADE has a very efficient implementation of payload anomaly detection.
BotHunter also includes a signature engine.
This signature engine can detect known exploits and know patterns of command control.
The signature rules come form multiple open sources.
Here's an example of infection profile produced by BotHunter.
It list the initial host that infects the internal machine, the internal machine that has become a bot and the command and control server.
It also lists evidence of the lifecycle steps.
### Botminer
Now let's discuss another
Botnet Detection System, Botminer.
The first question is, why do we need another Botnet detection system.
Notice that Bot hunter is based on some specific Botnet infection life cycles.
But Botnet can have different infection life cycles and they can change the protocols and structures of the command control.
For example, Botnet can use a centralized command-control system or fully distributed peer-to-peer control system.
Our goal is to have a Botnet detection system that is independent of the command-control protocol and structure.
In order to achieve this goal, we need to focus on the intrinsic properties of Botnet.
In particular, Bots are for long-term use, and bot with the Botnet have similar or coordinated communication and activities.
Therefore, we need to perform both vertical and horizontal correlation, here's the architecture of BotMiner.
We arrive at this architecture based on the definition of a Botnet.
We coded a botnet is a coordinated group of malware instances, they're controlled via
Command Controlled Channels.
The C-Plane monitor here, is for monitoring Command Controlled Traffic and A-Plane here, is for monitoring malicious activities because these are malware instances.
On both planes, we perform clustering to detect groups they are in correlated or similar ways.
Then we use cross-plane correlation to detect a group of machines that perform similarly in both command control activities and malicious activities.
And these are parts of the same Botnet, here's a workflow of C-plane clustering.
First of all, a flow record for connection between a local host and a remote service is defined by the protocol, source and destination IP Destination port, time, and number of bytes.
All flow records go through a number of steps that include filtering, aggregation, feature extraction, and clustering.
Here are some example of our features, look at bytes per second, flows per hour, bytes per packet, and packets per flow and we perform clustering in two steps.
In step one, we group C-flow records into course-grained clusters.
In step two, within each of these course-grained clusters, we further position them into finer grain groups.
The main idea here is that we can use a small set of features to perform course-grain clustering.
Because the number of features that we use is small, this step is very efficient.
There within each course-grained cluster, you can afford to use the full feature space to perform fine-grained clustering.
In A-plane clustering, we first cluster based on activity type, for example, this is scan, spam, binary downloading or exploit.
Within each activity,refer to use the features that tend traffic to perform clustering.
For example for scan, we can use the destination sump nets and the ports and for spam we can use a spam template.
Again the main idea of A-plane clustering is to capture similar activity patterns among the hosts.
In cross-plane correlation we are looking for the intersection between a-plane and c-plane clusters.
Intuitively, hosts, there in the sections, have similar malicious activities and similar C&amp;C patterns.
In particular, if two machines appear in the same activity clusters and in at least in one common C-cluster.
That means they should be clustered together because they're in the same Botnet.
### Botnet Detection Quiz
Now, let's do a quiz on botnet detection.
Which of these behaviors are indicative of botnets?
### Botnet Detection Quiz Solution
Generating DNS requests by itself is not indicative of Botnet activities.
However, if multiple machines looking up the same domains at the same time and the domain is not on a Y list, that is quite suspicious.
### Botminer Limitations Quiz
Now, let's consider the limitations of BotMiner.
What can botnets do to evade the C-plane clustering?
And, what can a botnet do to evade A-plane clustering?
### Botminer Limitations Quiz Solution
Botnets can vary the CNC communication patterns and they can introduce random noise in their communication traffic.
For A-plane clustering, the botnets can also vary their activities to evade our detection heuristics.
### Botnet Detection
So far, we have discussed botnet detection in the Enterprise network.
Now, let's discuss how we detect botnets on the internet.
We observed that a botnet must use internet protocols and services in order to maintain a network infrastructure.
For example, in order to maintain its network structure must use some sort of look-up services to find command-and-control servers or the peers.
And you know that to support is various kinds of malicious activities, a botnet must use hosting services, for example to store and distribute attack data and for malware download.
A botnet can also use transport services to route or hide its attack traffic.
Therefore by identifying the abnormal use of internet services, we can detect botnet activities on the internet.
In this lesson, let's focus on DNS.
And the reason is that most bots use
DNS to locate command control and hosting service.
### Botnet and Dynamic DNS 1
Many botnets use DNS for command control.
A key advantage is that DNS is used whenever a machine on the internet needs to talk to another, because DNS stores the mapping between domain name and IP address.
That is DNS is always allowed in a network and using DNS for command control won't standout easily.
Suppose a malware infects many machines, that is many machines now have become bots.
The question is how can this bot organize into a botnet?
The bot malware has instructions to connect to this command control server.
But in order to connect to the command control server, it will perform a DNS lookup first.
And with the IP address, the bot can connect to the command control server and that's how the bot becomes part of a botnet.
The DNS service providers preferred by botnets are Dynamic DNS providers, because they allow the frequent changes of the mapping between DNS domain name and IP address.
That is the botmaster can change to use another machine on the internet for command control and all he needs to do is log into his
Dynamic DNS provider, and make changes.
If we can detect that, a domain is used for botnet command control, then we can detect which machine connects to this domain and this machine is a bot, but how do we know this domain is used for botnet command control?
It terms out that way the bots look at the domain is different from how machines look at instrument domain such as a news website, because of normal use activities.
For example, a botnet CNC is looked up by hundreds of thousands of machines across the internet.
And yet, it is so-called unknown according to Google search and that's an anomaly.
We can use anomaly detection at the
Dynamic DNS service provider by examine queries in DNS domains to identify botnet CNC domains.
And once we identify a domain is used for botnet CNC, then a number of responses are available.
One is for the service provider to disable a domain, but it's one thing to occur when none such domain reply.
Another option is for the provider to set a mapping of a domain to a single address.
So that instead of connecting to the botnet command control server, the bots are now connected to a sinkhole.
The sinkhole in addition to disabling the botnet security researchers can also learn where the bots are by looking at the origins of the connections to the sinkhole.
### Botnet and Dynamic DNS 2
Now let's focus on how do we detect that a domain is used for upon as C&amp;C.
There are a number of heuristics based on observations.
First, member masses purchase a domain, they must use credit card, and that leaves traceable financial information.
And the other limit such traceable information as little as possible.
Therefore, they may do the so-called package deal, where for one second level domain, they're going to use it for multiple three level domains for botnets, for example here for the same package deal for the second level domain evilhacker.org, there are multiple botnets using different three level domains, the point is that with a single financial transaction, they can support multiple botnets, therefore we can cluster the three level domains under the same second level domain that's looks similar in their names or they resolved to similar subnets of IPs.
Because they're likely to be botnets they're related.
And we sum up the look-ups to all of these domains within a cluster.
By doing so we will compare the look-up patterns of legitimate domains. which is the Botnet domains they look different.
That is the Botnet domains tend to have larger lookup volumes.
And remember these domains are in dynamic DNS providers and the domains tend to be small and medium sized businesses, therefore legitimate domains will not have a very large lookup volumes.
Another observation is that bots tend to look up their their Command and
Control service as soon as their host machines are connected to the internet.
The intrusion is that bots must maintain communication with the command control server and since they have no control over when the host machines connect to the internet, they must take their first opportunity.
The result is that there is an exponential arrival of DNS request from the bots, whereas legitimate DNS lookups by normal user activities is a lot smoother.
For example, Human uses don't all immediately check the same side.
Therefore, if you sought the lookout volume per hour by 24 hour windows, we can see the exponential arrival rate of the bot's queries, whereas human queries are a lot smoother.
There are other detection heuristics.
For example, the look up's are from all over the internet.
And a C&amp;C server is resolved to many different IP's across the internet.
And the resolved IP address change frequently and so on.
Any of these observations alone cannot effectively detect a Botnet command control domain.
And therefore, we combine them in a detection system.
### Botnet and Dynamic DNS 3
Now let's discuss how we detect botnets in large networks such an ISP.
Here, we can focus on the DNS queries that can be observed by the recursive
DNS server and the ISP.
That is, we can analyze the Internet traffic from the internal host to the DNS server.
In particular, we can detect any abnormal growth of the popularity of a domain name.
It can suggest that this domain name is used for botnet command-control.
Intuitively, the reason that a botnet will grow is that more machines become infected, and become bots.
Therefore, the growth pattern of a botnet corresponds to the propagation pattern of an infection.
According to studies, exploit-based infection grows exponentially.
Email-based infection grows exponentially or linearly.
And dry-by downloads growth likely sublinear.
In a large ISP, there are many domain names being looked up every day.
But we don't have to analyze all domain names.
In fact, we can focus on a few anomalous domain names.
These are domain names that look suspicious.
In particular, many regularly spelled, easily sounding domain names have been taken up by businesses and individuals already.
Therefore botnets are forced to use very random looking domain names.
In other words, these random looking domain names are suspicious.
And then we need to analyze the growth pattern of these suspicious domain names.
In particular, we look for the exponential or linear growth of their popularities.
Here's a sketch of our ideas.
We assume a baseline of N days, and we assume that, within this N days, all domains are legitimate.
Therefore, we record these domains In a Bloom filter.
A Bloom filter is a very efficient representation of set.
That is, we use the Bloom filter to record a set of domains observed within these N days.
We also use a Markov model to model how these domain names are spelled.
After this baseline, whenever we observe a new domain, that is, a domain that is not in our Bloom filter on a set of recorded domains.
And if this domain does not fit our Markov model, that means it is spelled in a different way and looks suspicious.
Then we know that we have a new and suspicious domain.
Then we analyze the lookup sequence to this new and suspicious domain.
And if the growth is linear or exponential, then we know that this domain is used for botnets.
So far we have discussed botnet detection.
The latest threats are more targeted and more advanced.
For example, the use custom built malware on zero-day exploits, their activities are low-and-slow and they move within network and covering their tracks.
Even the existing botnet detection systems are not effective against these targeted advanced threats.
In order to counteract these targeted and advanced threats, we need multifaceted monitoring and analysis.
That is we need malware analysis, host-based monitoring, forensics, and recovery, network monitoring,
Internet monitoring, threat analysis, and attribution.
### Puzzle Quiz Solution
Client puzzles should not be hard for a server to construct, so this is false.
Client puzzles should be stateless, this will keep a client from being able to guess the puzzle and find a solution before even being asked.
Puzzle complexity should increase as the attack volume increases.
### APT Quiz
Now let's do a quiz on APT.
Which of the following information should we consider in order to identify the source of an APT attack?
### APT Quiz Solution
We need all of them.
### DoS Mitigation   CAPTCHAs
Let's discuss another mitigation technique.
You may be already familiar with this.
It is called CAPTCHA, which stands for
Completely Automated Public Turing test to tell Computers and Humans Apart.
The idea is that the server should verify that the connection is from a human instead of, for example, from a bot or a malware.
So I'm sure many of you are familiar with this.
The idea is that only human can interpret this figure and then type in the actual words.
During a denial of service attack, the server can generate CAPTCHAs and process request only if the client presents the actual valid solution to the CAPTCHA challenge.
Because that will prove that there's actual human behind the request.
### DoS Mitigation Source Identification
Another important mitigation is source identification.
The goal is to identify the source of attack packets so that ultimately we can block the attack at each source.
You may think that this problem should be easy because, for example, we discussed that many of the packets involved a denial of service attacks, they have spoof or random source IP addresses.
So the question is, why don't we just ask the ISPs to filter out source IP addresses that are not legitimate or valid for the ISP?
For example, if the router expects that all traffic is from this particular prefix, then it can drop all packets with a source
IP address other than from this prefix.
That way smooth packets can be dropped.
The biggest problem for this proposal is that it requires all ISPs to do this.
Because, as we will show, if only 10% of ISPs do not implement, then there's actually no defense against denial of service for the whole Internet.
Then the problem becomes that every ISP is waiting for everyone else to implement this first.
As we have shown in the previous example, if only 3 ISPs do not implement ingress filtering, the attackers can already launch a big denial of service attack.
As of 2014, a quarter of the autonomous systems are mostly ISPs or big enterprises.
They do not implement ingress filtering.
In total, that means 13% of the IP addresses can be spoofed.
### DoS Mitigation Traceback
Now let's discuss another source identification technique called Traceback.
The goal is that given a set of attack packets, we want to determine the paths of these packets and use a path to determine the source of these packets.
And the way to do this is to change the Internet routers to record some path information into the packet.
There are a few assumptions here.
First, most the routers remain uncompromised, meaning that these routers can record information faithfully.
Second, the attackers send many packets, and the route from the attackers source to the victim remains relatively stable.
Here's a naive strawman method.
We can have each router at its own IP address in the packet.
So, at the end, the victim can read a path from the packet because each router has written its own IP address.
The problem with this is that it requires space in packet and this can be a problem when a path is long.
There's no extra fields in the current
IP format to record this whole path information.
If we expect the packet format to be changed to include this path information it would take years, if ever, to get this implemented.
So here's a better idea.
We observe that the non-service attack involve many, many packets on a same path, so we can have each router to take a probability to store its own address in a packet.
This required only a fixed amount of space regardless of the path length.
### Traceback Quiz
Let's do a quiz on Traceback.
Which of the following are assumptions that can be made about Traceback?
### Traceback Quiz Solution
Attackers can generate unlimited types of packets, so this is false.
Attackers can indeed work alone or in groups.
And the Traceback will work regardless whether the attacker are aware of the tracing mechanisms or not.
So this is false.
### DoS Mitigation Edge Sampling
So now, let's go into the detail of the traceback mechanism.
The main component is the edge sampling algorithm.
An edge includes the start and end IP addresses.
It also includes distance, which is the number of hops since the last edge stored.
Here's the procedure for a router to decide how to record the edge information.
When a packet arrives, it throws a coin.
If it's heads, then it will write its address into the start address and then write 0 into the distance field.
If it's tail, then if distance is 0, then it writes its IP address into the end address field.
And regardless, it will increment the distance field.
So here's an example.
Again, a packet would include edge information, which includes the start address, end address, and distance.
Suppose the packet travels through three routers, R1, R2, and R3.
R1 tosses a coin and it's head.
So R1 writes its address to the start field and 0 in distance.
Now R2, it tosses a coin and it's tail.
The distance was 0.
So according to the process, it should write itself to the end and then increment distance to 1.
Now for R3, it tosses the coin and it's tail again.
But the distance was not 0.
So it does not write itself to the end.
It simply increment the distance.
Now it's 2.
Now, for R3, it tosses a coin, it's tail again, and the distance is greater than 0, so it does not write itself to the end.
It simply increment the distance from 1 to 2.
Now, as you can see, the edge information includes the starting of the edge, which is R1, the end, which is R2, the distance is 2.
That means from R3's perspective, the distance is 2 since the beginning of the edge.
With the edge information, now we can talk about how do we reconstruct the path.
The package arrive at the victim contains edge information.
And this information can be extracted to reconstruct the path that started from the victim all the way to the source of the attack packets.
Again, the edge information contains the starting router and the end router of the edge and the distance from the starting router.
And the number of packets needed to reconstruct the path is given by this formula.
This is the expected number of packets.
And p is the probability of head versus tail, and d is the length of the path.
### Edge Sampling Quiz
Let's do a quiz on edge sampling.
Select all the statements that are true for edge sampling.
### Edge Sampling Quiz Solution
With edge sampling, multiple sources can be identified.
Therefore, multiple attackers can be identified.
As we can see, it's relatively easy for a victim to reconstruct a path given the edge information.
So this second statement is false.
The edge information is stored in the IP packet header, so therefore, the third statement is true.
### Reflector Attack
Let's discuss a more recent type of denial-of-service attack called reflector attack.
So here, the attacker spoofed the victim's source IP address and sends DNS query to many DNS servers.
And all DNS servers will respond to this query and send their response to the victim machine.
And, of course, the result is that the victim is flooded.
In addition to DNS example, there are other examples that use web servers and Gnutella servers.
A reflector attack is typically launched by a bot master.
Commanding many bots, each of them will send a lot of requests to many reflectors, such as DNS servers, web servers and the Gnutella servers.
And these requests will spoof the victim IP address and as a result, the reflectors will send the response to the victim.
Since the actual flooding traffic is from the reflectors to the victim, a traceback scheme will trace the attack packets back to the reflectors.
And the reflectors may not do any marking or keep any state, so there's no traceback from the reflector back to the bots or bot master.
### Reflector Attack Quiz
Now, let's do a quiz on reflector attack.
Self defense against reflector attacks should incorporate which of the following?
### Reflector Attack Quiz Solution
Filtering should take place as far from the victim as possible, so the first statement is false.
Server redundancy is always helpful and rate limiting is always helpful.
### Capability Based Defense
Now let's discuss some novel idea to defend against denial of service attacks.
There are a number of examples for capability-based defenses.
You're welcome to study these papers.
Here's a brief overview of these defenses.
The basic idea is that the receivers, such as a server, can specify what packets they want, and this is called the capability.
When the sender sends a request to the receiver, he must include capability in his SYN packet, meaning that he needs to tell the server that, hey, I am the packet that you want.
When a client wants to connect to a server, it needs to first request capability.
And such a request should be very limited.
And the server can respond with a capability that the sender can later include in his packets.
Furthermore, all the routers will only forward packets with valid capability.
If a source is attacking, then its capability can be revoked, and as a result, the routers will drop or block such packets.
And this can take place as close to the source as possible.
### DoS Reality
So in summary, denial of service attack is a real and present danger on the Internet and to mitigate such attacks, security must be considered at Internet design time.
Therefore, the sad truth is that the current Internet is ill-equipped to handle denial of service attacks.
There are some commercial solutions.
There are many good proposals for internet core redesign such as based blogging.
### Introduction to Cybercrimes
In this lesson, we will examine cyber crime, its economy, and some of the motivations of the players.
When you finish this lesson, you should have a much better understanding of where legitimate Internet commerce ends and Internet crime begins.
### Actors in the Underground
Now let's talk about underground economy.
To understand the underground economy of server crimes we have to first understand who are the actors in the underground.
The first are the ones who write exploits.
They discover bugs that can be exploited to cause security to be compromised and they sell them for a profit.
Then there are the botnet masters, or bad guys that create and operate a malicious network composed of compromised computers.
Essentially, they buy exploits and turn them into malware and they put in the botnet command and control components.
So when they release the malware, they have a botnet under their control.
Then they rent out the botnet to other bad actors for malicious and fraudulent activities.
One of the utilities of a botnet is to send spam.
And so the bot master of a botnet can simply rent out his botnet to a spammer, and the spammer in turn sends out a spam contents on behalf of other bad actors.
One type of bad actors that can use to help of spammers are the phishers.
They set up scam sites to steal information and they ask the spammers to send the URL's to victim users to the scam sites.
Similarly, counterfeiters use spams to sell their counterfeit goods and obviously, they need to be able to collect money from the victim users.
For example, from their credit cards.
A bad actor in a cyberspace needs to consider the possibility that his operation, in particular his websites, may be detected and shut down by the law enforcement.
And so he needs to find a so-called bulletproof hosting providers.
These providers typically operate in lawless places and they are expensive.
A majority of the bad actors are in it for the money.
And on the Internet, what they can steal are the bank accounts and credit cards.
And so they need to turn them into cash.
They allow carders, cashiers, and mules to do just that.
The crowdturfers leverage human powered crowd sourcing platforms to create and manage fake accounts that are not tired to real users.
And they can use crowd sourcing to solve captures.
### Structure of the Underground
As we have discussed, there are quite a few types of bad actors in a cyber space and they form an interconnected ecosystem.
For example, a botnet is created when computers are compromised, a malware is installed and a botnet is used to launch a number of malicious and fraudulent activities.
For example these are activities that can be launched by botnet, in particular spam.
Spam can be used to facilitate a number of other activities such as phishing, selling counterfeit goods or malware installation.
Again, the point here is that the bad actors form an interconnected ecosystem because their activities or even structures support each other.
### Underground Forums
Underground forums are one the entry points of the bad guy's communication systems, especially for those new to the underground.
There are many underground forums on the Internet.
And they're just one search and one click away.
And there are a large number of illicit activities being advertised on these forums.
Obviously law enforcements are watching and can shut down these sites.
However, new forums can always pop up and fill the void.
These forums also provide valuable data sources to researchers.
For example, researchers can study the data to learn about new trends and detect unfolding attacks.
The forums are full of buyers, sellers, and the rippers.
There are honest deal makings but there are also rip-offs of the buyers.
Basically, these forums are as regulated as what administrators can handle.
Most messages on the forums are just advertisements.
For example, one can advertise that he has stolen bank accounts or access to computers or email lists.
One can ask for stolen credit card numbers in exchange for access to a hacked LINIX machine.
Many of these advertisements include evidence of the advertisers capabilities.
For example, to demonstrate that the stolen accounts are valid or show a sample of the stolen information.
Again, the forum is typically useful just advertisement.
The actual due-making is typically done via private messaging.
### Exploits as a Service
Now let's discuss a few underground activities.
The first is Exploits-as-a-Service.
In the past, compromising computer systems and use them for profit are typically done by the same criminal or criminals gangs.
For example, the same criminal gangs will develop their own exploits, launch them, and then use the hacked machines to make money.
Nowadays the bad guys are specialized and do different functions.
For example, there are developers who develop exploit kits and packets, and sell them to other bad guys.
And the other bad guys are responsible for using these exploit kits to compromise computers.
For example, they can send out spam with malware attachment.
Or they can put the malware in a compromised web servers, so that when a victim's computer visit those servers, they will be compromised.
These compromised computers are then sold on the black market so that other bad guys can use them to launch malicious and fraudulent activities.
And the bad actors here are being paid using the pay-per-install model.
Let's discuss exploits-as-a-service, and in particular, the pay-per-install model in more details.
One way to distribute malware, or causing computers to be compromised by the malware, is through so called drive-by-download.
Basically a website is compromised to have malware embedded in their scripts.
And then when a client computer visits the website, the malware will be installed on their computer.
The number of exploit kits that package the malware, and install the malware on the client computers.
There are two components in this malware distribution model.
The first is that the bad guy needs the exploit kit because the exploit kit will be responsible for installing the malware on the victim computers.
The bad guys can buy an exploit kit and deploy it themselves.
Or, they can simply rent access to exploit server that hosts the exploit kit.
In the first option, the bad guy needs to figure out how to distribute the malware themself, and typically that means at least he has to set up a server with exploit kits.
A more convenient option is for the bad guy to rent access to a server that already hosts an exploit kit.
The second component of this malware distribution model is that the bad guy needs to have the kind computers visit the exploit server so that malware will be installed on these computers.
The most common way to accomplish this is to use spam or phishing to attract traffic to this exploit server.
Traffic paper install simplifies this malware dispersion process.
It essentially combine the two elements into a single service.
And pay-per-install is now the most popular way of distributing malware.
### Definition of Cloud Computing
First, let's go over the definition of cloud computing.
Cloud computing is a model for enabling convenient, on-demand network access to a shared pool of configurable computing resources.
For example networks, servers, storage, applications, and services.
What this definition says is that, cloud computing uses resources that can be rapidly provisioned and require low management overhead.
Please note that the cloud computing industry represents a large ecosystem of many models, vendors, and markets.
And therefore our definition here is very general.
### Cloud Characteristics Quiz
Now that we have a general definition of cloud computing, let's do a quiz on the characteristics of cloud computing.
Given out definition of cloud computing, write the five essential cloud computing characteristics.
### Cloud Characteristics Quiz Solution
The first is on demand self service.
The second is broad or wide network access.
The third is resource pooling or sharing.
The fourth is measured service.
The fifth is rapid elasticity.
### Cloud Service Models
There are three cloud service models.
The first one is Software as a Service.
It enables a customer to use a provider's applications running on a cloud infrastructure.
This applications on a cloud can be accessful from various kind devices through a thin client interface such as the web browser.
The second model is
Platform as a Service.
It enables a consumer to deploy on to the cloud infrastructure consumer created applications using programming languages and tools supported by the cloud provider.
The third model is
Infrastructure as a Service.
It enables a consumer to provision processing storage networks and other fundamental computing resources on the cloud where the consumer is able to deploy and run arbitrary software, which can include operating systems and applications.
### Services Quiz
Now let's do a quiz on the cloud computing service models.
Given the definition of these models, determine the service category for each of the products listed below.
### Services Quiz Solution
Google Apps is platform as a service.
Amazon Web Services is infrastructure as a service.
Salesforce is platform as a service.
Knowledge Tree is software as a service.
Microsoft Azure is infrastructure as a service.
### Dark Web Quiz
The fact that there are so many underground forums and malware sites on the internet, it is just one example that the web actually has multiple facets.
So let's do a quiz, match the term with its definition.
### Cloud Deployment Models
There are several cloud deployment models.
The first one is private cloud.
Here, the cloud infrastructure is operated solely for an organization.
It may be managed by the organization or a third party and may exist on-premise or off-premise.
Here, the cloud infrastructure is shared by several organizations and supports a specific community that has shared concerns.
It may be managed by the organizations or a third party, and may exist on-premise or off-premise.
The third model is public cloud.
Here, the cloud infrastructure is made available to the general public or a large industry group, and is owned by an organization selling the cloud services.
The fourth one is hybrid, is a composition of two or more of these models.
### Common Cloud Characteristics Quiz
Now let's do a quiz on the common characteristics of cloud computing.
Please list some of the characteristics that are shared by all four cloud models.
### Common Cloud Characteristics Quiz Solution
These characteristics are massive scale, homogeneity, virtualization, resilient computing, low cost software, geographic distribution, service orientation, and advanced security technologies.
### NIST Cloud
To summarize what we have discussed thus far.
Let's go over the NIST cloud definition framework, there are several deployment models and each can use one of these service models.
Again, the deployment models include
Hybrid, Private, Community and
Public and the service models include software as a service, platform as a service and infrastructure as a service.
All Cloud environments share some essential characteristics.
These include On Demand Self-Service,
Broad Network Access, Resource Pooling,
Rapid Elasticity, Measured Service.
And they also share some common characteristics.
This includes Massive Scale,
Homogeneity,
Virtualization, Low Cost Software,
Resilient Computing,
Geographic Distribution, Service
Orientation, and Advanced Security.
### NIST Risk Identified Quiz
Now let's do a quiz on the risks associated with cloud computing.
Given the risks listed in each circle, please identify the service model associated with each circle.
### NIST Risk Identified Quiz Solution
The blue circle includes risks such as data security, data locality risks and unauthorized access.
And this circle is associated with the model software as a service.
In the orange circle we include SOA related issues,
API related issues and so on.
And this circle is associated with platform as a service model.
In the green circle, we include risks such as virtual machine security, hypervisor security, and so on.
And this circle is associated with infrastructure as a service model.
### Cloud Security Concerns
Now let's discuss cloud security.
The first question is, is security important to cloud computing?
According to this survey, security is the main concern when people consider moving to the cloud.
So, it's obvious that security is one of the most important concerns with cloud computing.
### Analyzing Cloud Security
There are several key security issues.
For example, how do we trust the cloud computing environment because we don't manage it.
Furthermore, multiple different organizations may be using the same cloud computing environment.
And in terms of data protection, obviously, we should use encryption to protect confidentiality.
But we also need to consider various compliance issues.
These security issues become very challenging because the clouds are massively complex systems.
Although the primitives and common functions are simple, the complexity comes from the fact that these primitives and function units are replicated thousands of times.
On the other hand, as we will discuss shortly, cloud security is a tractable problem because there are both advantages and challenges associated with cloud computing.
Let's first discuss the advantages.
First, you can put public data away from the internal network to the cloud.
And it is easy to manage testing and security patches when most systems in a cloud computing environment use the same software.
And recovery is easy and fast because it is easy to set up the same system.
But there are also challenges.
First, you have to trust the cloud providers.
And you cannot respond to all the findings, or investigate directly, because you have to rely on the cloud providers who are the direct admins, and some software running in the cloud is proprietary.
And finally, there is no physical control of the computing resources that you use.
### Security Relevant Cloud Components
All the core components of a cloud computing environment are relevant to security.
This include cloud provisioning services, cloud data storage services, cloud processing infrastructure, cloud support services, cloud network and perimeter security and elastic elements: Storage, processing and virtual networks.
Now, let's discuss the security advantages and challenges for each of these core components.
The first is provisioning services.
There are several security advantages.
This include, rapid reconstitution of services.
Greater data availability because we can provision multiple data centers and advanced honeynet capabilities.
The main security challenge is that, if the provisioning service is compromised, the impact is disruptive.
For data storage services, there are several security advantages.
This include data can be fragmented and dispersed, therefore, data can be more resilient to attacks.
In addition, data can be encrypted at rest and in transit.
There's also automatic backup and replication of data.
But, there are also several security challenges.
For example, data from multiple organizations may be put in the same storage server.
And, the storage server may be in a different country.
For the cloud processing infrastructure, the main security advantage is that we can secure the master copy of a program and then, replicate that copy throughout the cloud computing environment.
But then, there's also several security challenges, for example, multiple applications can be running on the same physical machine.
And therefore, achieving a real isolation is not easy.
For example, cash and memory access are side channels that can leak information.
And of course, we'd assume that the hypervisors or the by virtual monitors are secure.
Cloud Support Services can provide on demand security controls for customer applications.
But now, the cloud providers need to make sure that customer applications will not cause security problems in the cloud environment.
In terms of networks security, since the computing systems are now distributed, denial of service attacks are now harder to succeed.
Furthermore, standard perimeter security measures such as IDS and firewalls are deployed by default.
But since different applications share the same cloud, it is challenging to create security zones where the resources share a common security exposure or security risk.
### Cloud Security Advantages
Let's summarize the security advantages a cloud computing environment can provide.
These include Data Fragmentation and
Dispersal, Dedicated Security Team,
Greater Investment in Security
Infrastructure, Fault Tolerance and
Reliability, Greater Resiliency,
Hypervisor Protection
Against Network Attacks and the Possible Reduction of C&amp;A Activities.
Furthermore, the compliance analysis is simplified and data can be held by unbiased party.
There is Low-Cost associated with
Disaster Recovery and Data Storage.
There are on demand security controls and real time detection of system tampering.
Reconstitution of services is easy and vast.
And an advanced Honeynet can be deployed.
### Dark Web Quiz Solution
A deep web is one that's not indexed by the standard search engines such as Google.
A dark web refers to also invisible web or hidden web where the web content typically only exists on so-called darknets.
And so what is a darknet?
It is an overlayed network that can only be assessed with specific software, configurations or authorization, often using non-standard communication protocols and ports.
Two example darknet are the friend to friend peer to peer networks and the privacy network such as tor,
T-O-R, tor.
And a surface web is one that we are probably most familiar with.
It contains web contents that are public, searchable and indexed by standard search engines.
When we think of the Internet we're usually referring to the surface web.
As you can see in this visual, the surface web is actually a very small part of the Internet.
### Cloud Security Challenges
Let's also summarize the security challenges.
First, we have to consider various international privacy laws.
For example, the Eu Data
Protection Directive and the U.S.
Safe harbor program.
And data can be subject to subpoenas from government, including a foreign government.
And since multiple organizations may be using the same cloud computing environment, we need very strong isolation protection.
And since computation and data can be distributed log in becomes a challenge.
Similarly, since the cloud is a distributed computing environment it is challenging to provide consistent quality of service.
And finally, since the customer does not own the computing environment there could be potential data ownership issues.
For example, who owns the one time data produced by a customer application?
There are additional challenges.
These include, now we have to depend on a secure hypervisor.
And, the cloud is an attractive target to attackers.
And, we sill need the security of the operating systems running in the virtual machines.
And, the potential impact of a successful attack on the cloud can be massive.
And since some organizations now start to use public cloud, it is challenging to reconcile the security policies of the internal network versus the public cloud.
And for public cloud that uses software as a service model, a customer cannot control what software or what version to use.
It is obvious that we should protect data security using encryption.
In particular, we need to encrypt not only the data at rest, but also access to resources because otherwise every service can learn about the computing tasks being performed.
### Cloud Security Quiz
Now let's do a quiz on cloud security, which of the following statements are true?
### Cloud Security Quiz Solution
The first statement, most data in transit is encrypted, this is true.
Close to 90% of the service providers encrypt data in transit.
The second statement, most data at rest is encrypted, this is false.
Only 10% of the providers encrypt data at rest.
The third statement, all data at rest should be encrypted, this is false.
In reality there's plenty of data that does not require security protection, and therefore such data does not need to be encrypted at rest
### Cloud Security Additional Issues
There are some additional issues associated with cloud security.
In particular, we need to consider the privacy impact when PII data is moved to the cloud.
PII stands for personal identifiable information, and it is any data that could potentially identify a specific individual.
Customers should be aware that they need to negotiate with the cloud providers to obtain a security service level agreement.
But then we need to make sure that we have proof that the service level agreements have been satisfied.
Obviously, a cloud provider needs to plan for disaster recovery.
In addition, a cloud provider needs to consider a number of compliance issues.
For example, HIPAA for healthcare data and PCI for payment data.
### Cloud Security Architectures
Let's discuss the foundational elements of cloud computing.
Cloud computing is built on a number of technologies.
These include virtualization, grid technology, service oriented architectures, distributed computing.
Broadband networks, browser as a platform and free and open source software.
Other technologies include autonomic systems, Web 2.0, web application frameworks and service level agreements.
### Virtualization Quiz
Now let's do a quiz on virtualization.
Fill in the blanks with regards to cloud computing virtualization.
### Virtualization Quiz Solution
Virtualization requires at least one instance of an application or resource that is to be shared by different organizations.
Sharing between organizations is accomplished by assigning a logical name to the resource and then giving each request a pointer to the resource.
### Virtualization Quiz 2
Fill in the blanks with regards to cloud computing virtualization.
### Virtualization Quiz 2 Solution
Virtualization involves creating a virtual machine using existing hardware and operating systems.
The virtual machine is logically isolated from the host hardware.
### Virtualization Quiz 3
Let's do another quiz on virtualization.
A hypervisor acts as a Virtual Machine Manager.
Given these two diagrams, answer the question.
### Traffic PPI Example
Let's look at a traffic paper install example.
There are three causes of actors in traffic paper install.
There are the victims, the exploit developers, and the clients, or bad guys that use the exploits to dispute malware.
If you look at the traffic flow, we notice that the payment flows from the clients or the bad guys who buy or rent the exploits to exploit developers.
The malware flows from these attackers to the victim.
The payment amount depends on the volume of malware installation.
### Virtualization Quiz 3 Solution
Which one does not have any host operating system because they are installed on a bare system?
That's a Type 1 hypervisor.
Here, notice that the operating system runs in a virtual machine on top of the hypervisor.
Second question.
Which one emulates the devices with which a system normally interacts?
That's the Type 2 hypervisor.
Here, the hypervisor emulates the hardware.
### Platform Virtualization
The most important technology for cloud computing is virtualization.
This is because cloud computing relies on separating applications from the underlying infrastructure.
The key to virtualization is the hypervisor or the virtual machine monitor in addition to increased utilization.
For example running many virtual machines on a single hardware, virtualization can also improve security and we will discuss this next.
### Kernel Level Attack Tools
Lets's first review what happens when we placed a security tool in the opening system kernel, which has high privilege and user level applications.
A kernel-level security tool has a high privilege, and therefore, it can detect and remove a malware process at a user level.
But since the security tool has a same privilege as the attacker in the kernel, such as a rootkit, it can be compromise.
In other words, the security tool cannot be isolated or protected from a kernel-level attacker.
### Hypervisor Approaches
With virtualization, we can put the security tool in a separate virtual machine.
For example, we call this the security virtual machine dedicated for security analysis.
Now the security tool is isolated from the virtual machine that has the malware.
But then the question is, how can a security tool detect or stop a malware in a different virtual machine?
As we will discuss next, the security tool, with the help of the hypervisor, can perform introspection of the other virtual machine.
### VirtualBox Security Quiz
First, let's take a moment to think about how virtual machines can be exploited.
Here's a quiz on VirtualBox security.
Which of the following steps is considered safe when working with virtual machines?
### VirtualBox Security Quiz Solution
First, set the clipboard sharing between the virtual machine and the host to be bidirectional, this is not safe.
Second, allow the VM to read and write files on the host machine with the same privilege as the host machine, again, this is not safe.
This is similar to allowing an attacker to write files on your machine.
The final statement, disconnect the virtual machine from the internet when opening questionable files.
This is safe because this will prevent potential malware from contacting its command control server.
### Monitoring Memory
One of the most essential tasks of virtual machine security is memory analysis.
This is because memory is the only reliable source of the current state of a computer.
For example, using memory analysis we can find out a list of the running processes.
We can also find out the encryption keys being used and the decrypted data.
We can look at network socket and data.
We can also find OS-level accounting information, as well as user inputs.
We can also read the screen captures and find the graphical elements of an application and so on and so forth.
And these are just a few examples.
### Production Level Systems
Let's discuss memory monitoring and analysis in a virtualization environment.
The security in a controlled virtual machine are smaller, because they can run a stripped down OS.
The security machine gets a raw memory view, meaning that it has seized the physical memory from the other virtual machines.
If you want anything useful, you need to rebuild the obstruction levels on your own.
And this is challenging, and we will discuss this shortly.
There are several types of monitoring.
The first is passive monitoring.
This means that the security virtual machine takes a snapshot of view, of the raw memory of a virtual machine.
The second type is active monitoring.
This means that the security virtual machine takes a view of the memory of another virtual machine, when there's an event being triggered at that virtual machine.
An important goal of memory monitoring is to locate the important data structures in memory for security analysis, for example, examining the process list.
### Passive Monitoring
Here's an example of passive monitoring.
Again, this means that the security virtual machine monitors that application periodically by getting the view of the memory from another virtual machine.
This is known as performing virtual machine introspection.
And here are the main steps in passive monitoring.
In the security virtual machine, the security tool performs an API call to access a kernel symbol.
The address of the kernel symbol has been looked up and then page tables for the memory of the user virtual machines are being traversed to locate the kernel data.
And then, the pointer to the memory is returned to the security monitor.
We use a virtual machine introspection library called libVMI to convert the raw memory view into something meaningful, such as, virtual addresses, kernel symbols, etc, and we will discuss libVMI shortly.
### libVMI
Now we need to address one very important detail.
When you read memory, all you see are 1s and 0s.
But how do you know what the 1s and 0s mean, unless you know the memory layout, according to data structure definitions?
For example, this blob may represent a data structure that you're looking for.
Therefore, as we have discussed in passive monitoring, we need to convert the raw memory view into something meaningful such as virtual addresses kernel symbols, etc.
We use libVMI, or previously called
XenAccess, to analyze memory contents.
This is an example of the code that used libVMI
APIs to obtain the list of learning processes.
And this is the output.
The pull here is that with libVMI or
XenAccess, you don't even write a whole lot of code in order to obtain such useful runtime information of the other virtual machine. libVMI is open source, it provides access and analysis of virtual addresses, kernel symbols.
It was first released as Zeb acess in Spring 2006, and here's the GitHub repository.
Here's a quick summary of the libVMI features, you can perform virtual memory translation, for example so that you can know which are the kernel symbols.
You can also place monitoring hooks into a guest virtual machine, for example, to trap exceptions and page faults.
For example, hooks can be placed in a virtual machine to trap the following events.
For example, memory read-write-execute events, register read-write events, interrupts and single stepping of instructions.
This is useful to trace a log of program execution.
### PPI Quiz
Now let's do a quiz on pay per install.
Match the term with its definition.
### Active Monitoring
Now, let's discuss active monitoring.
Active monitoring is event driven which allows for enforcing security policy and stopping attacks before they happen.
Here's an example of active monitoring.
The security application receives event notification from the guest virtual machine when the code execution, which is one of the hooks, hooks invoke trampoline which transfer the control to the security application.
The hooks in the associated code in the guest virtual machine are protected using the memory protection provided by the hyperviser.
Of course, when a security application receives an event notification, it's going to perform virtual machine inspection, for example, using the lip VMI.
### Active Monitoring  Challenge
There are several challenges emerge in machine monitoring.
The first is high overhead.
The overhead comes from several sources.
The first is invocation.
Switching from a virtual machine to the hypervisor into a virtual machine is very expensive.
The second source overhead is introspection.
Again, accessing the memory of another virtual machine requires calls to the hypervisor.
### Security in VM Monitoring
The question is can we have both the security benefit provided by virtual machine monitoring which means out of VM monitoring and the efficiency of traditional monitoring which means In-VM monitoring.
We have developed a secure
In-VM monitoring approach.
We call this approach SIM for secure In-VM monitoring.
It provides the same security as the out of VM approach.
And its performance is similar to the traditional In-VM approach, the main idea is to use hardware which virtualization features to minimize the need to switch to hypervisor.
In other words we can read or write the memory of an untrusted virtual machine at native speed.
### VM Monitoring
Let's analyze the requirements of SIM.
We want the invocation to be really fast.
This means that there's no need to switch to hypervisor.
We also want data read and write at native speed.
This means that we can rewrite data directly, without going through hypervisor.
### VM Monitoring Requirements
But there are also security requirements.
The code and data of the security tool need to be isolated from the untrusted machine.
The handling of the security events has to be secure.
Furthermore, the security tool should not rely on untrusted code and data.
### SIM Design
Now let's discuss how SIM can satisfy both the performance and security requirements.
Recall that in operating systems, paging-based virtual memory is generated by creating page tables that map virtual addresses to physical addresses.
An operating system creates a separate page table for each process so that it can have its own virtual memory address space.
And the necessary isolation can be achieved.
The SIM address space here contains all kernel code data and also the SIM data in its own address space.
Therefore, the instruction as part of the security monitor can access in native speed.
Notice that the guest operating system has it's own virtual address space.
That is, although we put SIM into the same virtual machine as the guest operating system, they have their own separate and different module address space.
In order to perform security monitoring,
SIM needs to look at the address space of the guest operating system.
And this can only be done through the Entry Gate and the Exit Gate since this requires the switching of address spaces.
We need to modify the CR3 register contents directly.
Intel VT, contains a feature that doesn't check out a VM exit to the hypervisor, if the CR3 is switched to an address space that's predefined and maintained by hypervisor.
Therefore, by predefining the SIM address space and system address space we can achieve fast switching without exiting to hypervisor.
We also use the Hypervisor memory protection to protect the security of the SIM address space and protect the entry and exit gates.
The entry gates and exit gates are the only ways to switch between the SIM address space and the system address space.
We use inter-hardware feature called the last branch recording in the invocation checker.
We last branch recording.
We know the last few basic blocks leading to the entry gate.
The SIM security tool is self contained, meaning that it does not caught any quote or using any data from the kernel of the untrusted region.
The SIM security tool can read my memory in native speeds.
### Protected Address
Let's compare the memory layout between the SIM virtual address space and a system virtual address space.
As you can see the SIM code and data cannot be viewed by the untrusted system.
The entry gate and exit gate are executable in both spaces.
Their security is provided by memory protection in the hypervisor and the invocation checker in SIM.
The kernel code and data from the untrusted system can be read directly by SIMbut y SIM does not execute such untrusted code and data.
### Monitor Overhead
We perform experiments to measure the overhead of SIM and compare it with the out-of-VM monitoring approach.
And here are the results, we an see that SIM is much faster than Out-of-VM approach.
### How Do Data Breaches Happen
Let's discuss data privacy issues in a cloud environment.
First let's review how data breaches happen.
In a cloud environment the users use applications or data stored in a cloud provider.
For example, the users can be doctors and nurses, and the application can be the electronic medical record system.
And the data obviously is the medical records.
And the called EMR here can be a private called such as UCLA Health.
As another example, the users can be average consumers.
And the application can online dating.
And of course, the data can be the dating profiles.
In most cases, including the examples that we just discuss, data is the most valuable target to the attacker.
For example, the attacker may want to steal the data.
Now the question is, how do we protect the data?
Obviously we can encrypt the data.
For example, the users can have their own secret encryption key for their data.
And once the data is encrypted the adversary can no longer read the data.
The problem when the data is encrypted the applications can no longer use the data as it is.
For example if the application is a word processing programm such as Microsoft Word, it cannot process encrypted data directly.
Therefore, the real question is can we protect the data while we also let the application work?
In other words, we want to protect the data by encrypting the data, so that the adversary cannot read our data.
On the other hand, we also want the application to continue to work.
### Encryption Quiz
Before we go on, let's do a quiz on encryption.
Match the characteristics of each encryption.
### PPI Quiz Solution
A doorway page is a web page that lists many keywords in hopes of increasing search engine ranking.
And then, scripts on that page will redirect the visit to attackers website.
A crypter is a program that hides malicious code from anti-virus software.
A Blackhat Search Engine Optimizer, or Blackhat SEO, is one that tries to increase traffic to the attacker's website by manipulating search engines.
A Trojan Download Manager is a piece of software that allows an attacker to update or install malware on a victim's computer.
### Encryption Quiz Solution
In property preserving encryption, some selective properties of the alternate data are preserved, such as the order.
Searchable encryption means that the encrypted data can be searched using the encrypted keywords.
In secure computation, multiple parties can compute a function using inputs that are kept private.
In Homomorphic encryption, computations performed directly on encrypted data, have the same result as the computations on the plaintext.
In functional encryption, the possession of a secret key will allow someone to learn the function that is being encrypted.
### PPE
Property Preserving Encryption is one way to protect data while allowing application to continue to work.
And this approach is widely deployed in various environments including the Cloud.
For example, Microsoft advertises that data is always encrypted.
On the other hand, the applications continue to work.
Property Preserving Encryption has several advantages.
There's no need to change application and database servers, it supports common data retrieval methods, including SQL queries.
It is reasonably efficient, but what about security?
Although it widely believed that it is secure, we should take a closer look.
### PPE Quiz One
To understand the potential security issues of
Property Preserving Encryption, let's do a quiz.
First, let's review standard encryption.
In standard encryption, there is no preserving of properties.
For example, suppose we encrypt the age information.
The encrypted data leaks nothing except the size of the original plain text data.
For example, we know that there are four entries.
Now let's take a look at an example of property preserving encryption.
Again, we want to encrypt the age information, but we preserve equality.
Therefore in encrypted data, we see that these two values are the same, because the original paying tax values are the same.
So what is preserved?
### PPE Quiz One Solution
As we said, equality is preserved, but what is leaked is a frequency.
Because we now know that there's one value that appears twice.
### PPE Quiz Two
Now let’s take a look at another example of property-preserving encryption.
Again, we want to encrypt the age information.
And this time, we preserve the order.
As we can see, in the encrypted data, the order of the original values is preserved.
The question is, what is leaked in order-preserving encryption?
### PPE Quiz Two Solution
Obviously, the order is leaked.
Frequency is also leaked because the same value in plain text will be the same value in encrypted text.
### PPE Leakage
The previous examples are simple.
Now the question is, what does the leakage in property preserving encryption really mean for real applications?
We can take a look at the electronic medical records.
Here are some attributes in electronic medical records.
These attributes are typically used in equality queries or ordering.
In other words, to ensure that the applications will continue to work, these attributes will be encrypted to preserve equality or order.
These attributes are sensitive to either the hospital or the patient or both.
### Data for Attributes
The data as we can obtain from the hospitals is encrypted.
On the other hand, there's information, or auxiliary data that is public.
We will show that using both the encrypted data and auxiliary data, an attacker can launch inference attack to obtain plaintext data.
### Encryption Attacks
Recall that these attributes are encrypted using either
Equality-Preserving Encryption or
Order-Preserving Encryption.
An attacker can use frequency analysis to defeat
Equality-Preserving Encryption.
And this attack can be further optimized.
### Attack Analysis
Lets use an example to illustrate frequency analysis attack.
Here is encrypted data of the number of days a patient stays in hospital.
As you can see the data is encrypted to perform frequency analysis we first sort the data and record the frequency.
We also sort and record the frequency of the auxiliary data.
For example, there's public information of how frequent a patient will stay for one day versus two days and so on.
By matching these two histograms we can link a cyber text value to a plain text value.
For example, for the first cyber attack value the frequency is ten.
And we know that from the auxiliary data, the plain text value one has frequency of 11.
Therefore, we can link the ciphertext value to plaintext value one.
And therefore, with frequency analysis, we can uncover the plaintext data without the encryption key.
### From Malware to Botnets
So we have just discussed how malware can be distributed and installed on victim's computers.
These infected computers are valuable resources.
For example, they have a unique
IP addresses and bandwidth, and they're typically distributed across the internet.
And they have spare CPU cycles that can perform a wide range of activities.
From attackers point of view he wants to control and utilize these infected machines and the way to do this is to turn the compromised computers into a Botnet.
The bad guy or the botmonster will need a command control infrastructure to control the bots.
For example he can then ask the bot to update its malware or can send commands to the bots to launch synchronised activities and the botnet can rent it out to other bad guys to launch their activities, such as sending spams.
Once in place, the botnet now becomes a platform to launch any number of malicious and fraudulent activities.
### Optimization Attack
This attack can be generalized and optimized.
Again, start with the encrypted data, we have obtained a frequency histogram.
We also obtain a frequency histogram from the auxiliary data.
The basic idea is then, to find an assignment from servertext to plaintext that minimizes a gives cost function.
Here the cost function is the distance between the histograms.
This has the effect of minimizing the total mismatch in frequencies across all plaintext- ciphertext pairs.
For example, for this assignment, the cost is this.
Whereas the assignment on mapping, it has the minimum cost is this.
There's an algorithm that can find the assignments that has the minimum cost.
With this algorithm, we can find the assignment from ciphertext to plain text and then decipher the original encrypted data.
### Optimization Attack Analysis
Here are some results of applying this attack on the electronic Medical records.
The x axis is the cumulative fraction of records recovered, and the y axis is the fraction of hospitals.
That is, in all of this parts, our point xy shows that at least x fraction of records was recovered for y fraction of hospitals.
For example, for disease severity at least 40% of the records were recovered for 50% of the hospitals.
The best result we can obtain is that all records, for all hospitals, were recovered.
Here are the highlights of the results.
For example, for sex, 100% of the patients For
95% of the hospitals recovered.
And for major diagnostic category,
40% of the patients for
28% of the hospitals were recovered.
And we show more results here the highlights are, for age 10% of the patients for
85% of the hospitals were recovered.
For length of stay, 83% of the patients for 50% of the hospitals were recovered
### Cumulative Attack
We have discussed on equality preserving inscription.
Now, let's discuss a tax on order preserving inscription.
We can use sorting attack, but a more effective attack is cumulative attack.
Given a data column that has been encrypted using order preserving inscription.
A nemissary can learn not only the frequencies, but also the relative ordering of the encrypted values.
Combining ordering with frequencies, the attacker can tell for each server text C, what fraction of the encrypted values are less than C.
More formally, this is known as the empirical cumulative distribution function of the dataset or
CDF.
In the cumulative attack, an attacker leveraged the CDF to improve the ability to match plaintext to ciphertext.
Intuitively, if a given ciphertext is greater than 90% of the ciphertext in the encrypted data, then we shall match it to a plaintext that is greater than about 90% of the auxiliary data.
This problem belongs to a category of Linear Sum assignment Problem.
Therefore, we can use an algorithm to find the mapping of plaintexts to ciphertext that minimizes the total sum of mismatch in frequency plus the mismatch in CDFs across all plaintext, ciphertext pairs.
### Cumulative Attack Analysis
Here are some results of this attack and the highlights are for disease severity, admission month, mortality risk, length of stay 100% of the patients for
100% of the hospitals were recovered.
And for age, 83% of the patients for
99% of the hospitals were recovered.
### Attack Recap
Here is a summary of the results of attacks on electronic medical records.
As you can see, the confidentiality of many attributes is compromised.
### Suppose We Don't Trust the Cloud
Now let's discuss another data privacy issue in the cloud environment.
Suppose we don't trust the cloud provider?
We can either encrypt our data on the cloud storage server and keep the keys to ourself.
When we need to use the data, we can fetch the encrypted data to our environment, encrypt the data, then use the application in our local environment.
The question is, is this efficient?
No, because the data access patterns can still leak information, such as what kind of computing tasks are being performed.
### Oblivious RAM
A promising approach to eliminate this kind of leakage is to use oblivious RAM, or ORAM.
ORAM can hide access patterns.
The main idea is that using ORAM, while the cloud provider can still observe data access, the access patterns are independent of the actual data requests.
Some of the main techniques include O data access operating on fixed size data blocks.
The data is encrypted, not using property preserving encryption.
In addition, ORAM also use dummy accesses, or re-encrypt data and shuffle data around.
Here's a high level pictorial example of ORAM at work.
The application needs to access confidential data such as getting an encryption key, encrypt and store data, and getting another encryption key.
For each of these access requests, there are multiple requests to the cloud server.
These requests all fixed sized data objects, and they are both read and writes.
That is, regardless whether the original request is for read or write, the actual dummy accesses include both read and writes.
And the data objects are all of fixed size and not distinguishable from each other.
And this is how you hide the access pattern from the cloud provider.
ORAM is an active research area, and if you are interested, here are some papers.
### ORAM Quiz
Now, let's do a quiz on ORAM.
Select the statements that are true with regards to ORAM.
### ORAM Quiz Solution
The first statement, client must have a private source of randomness.
This is true, because the ORAM client must generate random access patterns.
The second statement, data does not have to be encrypted, since there's no access pattern.
This is obviously wrong, because we want to protect data from the cloud provider.
Therefore, encryption is actually the first requirement.
The third statement each access to the remote storage must have a read and a write, this is correct.
Because we want to hide from core providers the fact that we only reading or writing data, therefore we will include dummy reads and writes.
### Command and Control
The key to a botnet success is efficient and robust command and control.
And this is not always easy.
The simplest, most efficient way to perform command control is through centralized control.
For example through IRC command or command, he can instruct the bots to send spam.
However this kind of command control is not robust.
Even though it's very efficient, because it has a single point of failure.
There's only one command channel from the attacker.
For example the IRC channel can be taken down.
Or the twitter account can be shut down.
A more robust command control structure is to use peer to peer network.
Here, the botmaster can connect to a number of bots in this peer to peer network.
And upload his commands, and update to the malware.
And make advertisements, so that other bots can get the command and updates from the peers.
The drawback is that the botmaster does not have direct synchronized communication with autobot.
In fact, the Botmaster does not know how many bots get it's commands and when.
Nowadays, the most popular approach for command control is for all the bots to connect to a command control website.
Obviously, this is very efficient.
And the Botmaster can make this set up more robust.
For example, the Botmaster can map this website to different IP addresses.
The website is not always fixed on one physical server.
It can be moved to different servers.
In fact, in Fast Flux, the Botmaster can change the DNS IP mapping for the website every ten seconds.
This can defeat detection or blocking, based on IP addresses.
But since the domain name is not changed, this domain can still be detected as using for botnet command control.
And the ISPs can't block access to this domain.
Instead of using fixed domains that can be detected and blocked.
Botmaster's now used random domain generation.
On each day, a bot will generate a large number of random looking domain names and lock them up.
The Botmaster will knows exactly the same set of random domain each day.
Because each domains are generated using the same algorithm.
And same random seeker seed straight between the botmaster and the bot malware.
In the botmaster, only register a few of these random domains.
Although each bot generates many random domain names, and look up each of them.
Only few of them will actually connect to the websites.
These are the sites that are registered to the botmaster.
And of course, these sites can use fast flux to move around on the internet.
By mapping to different IP addresses every ten seconds.
This command and control approach is very robust, because it is hard for detection.
This is because each of these command control domains are randomly looking.
And they're new.
And they are only used for a very short period of time.
Say, one day.
### SPAM Quiz
Let's do a quiz on spam.
What are the two defining characteristics of internet spam?
### SPAM Quiz Solution
They are typically inappropriate or irrelevant to the user and typically it's being sent to a large number of recipients.
### SPAM
It is estimated that more than 90% of our email are actually spam.
That will translate into hundreds of billions of spam messages every day.
Spammers play a very key role in the underground economy and cybercrime.
They have contacts of many many people and many organizations.
They send messages on behalf of other bad actors.
They can be used to push malware or phish to steal information.
Spammers typically use botnets to send spam.
They need a large number of IP addresses because otherwise, sending a large number of emails from a few IP addresses will easily trigger detection and blocking by spam filters.
Let's start via few examples of how spam works in the underground economy.
Many spammers are affiliates of various kinds of scam campaigns.
Scammers typically set up websites to sell counterfeit goods.
The scammers try to act legitimately by delivering goods and collecting payments.
They can even have customer services.
But how do the scam websites attract traffic?
They need the spammers to advertise for them.
And in return, the spammers collect commissions.
For example, the commission can be as high as 30 to 50% of the final sales price.
Now the key to the success of both the scammers and the spammers is the spam conversion rate.
The spam conversion rate is the percentage of spam messages that result in a final sale.
We know that there are spam filters around.
And we have the feeling that a lot of them are very effective.
So why do spammers continue to send spam?
And how many messages get past spam filters?
We heard numbers such as more than
99% of the spams are filtered.
Any spam leads to a successful transaction.
How much money can be made?
The only way to precisely answer these questions is to infiltrate and instrument the spam generation and monetization process.
Because by doing so we can find out exactly what's going on.
### 12_SPAM Filter Effectiveness
Let's discuss a case study on Storm botnet.
This botnet was used to send spams.
And this research was performed by the
University of California in San Diego, where the researchers penetrated into the Storm botnet.
The researchers were able to measure the percentage of spam that got through the spam filters.
Here are different campaigns carried out by the spams.
Pharmacy is a spam advertising an online pharmacy.
The postcard and April Fool campaigns are for installing malware.
As we can see here from data that's available, there are spam filters that can actually filter out more than 99% of the spam messages.
On average, only 0.014% of the spam messages that can get through the filters, which translates into 1 in more than 7,000.
Looking at the whole lifecycle of a spam message, some get not delivered, some get blocked by spam filters, some are ignored by the users, and users may just leave the sites.
Of course, some of them will actually commit a transaction.
But some of these traffics are due to crawlers, meaning that they're not actual users.
This table shows that for each campaign, what's the percentage of spams that can be delivered, filtered, result in user visiting the website, and user conversion.
Obviously, user conversion is the most interesting number that we should look at.
For pharmacy, it's 1 in 1,737.
For postcard, it's 1 in 37.
For April Fool, it's 1 in 25.
This conversion rate is computed for the spams that got into the user's inbox.
How many of them result in user transactions?
The pharmacy campaign advertise a fake online pharmacy.
The researchers observed that there were 28 purchases in 26 days.
The average price per purchase is $100.
But the researchers only controlled
1.5% of the bots sending the spams.
If we extrapolate this amount to the whole botnet population, then we get close to $9500 a day, or $3.5 million a year.
Of course, the scammer and spammer will divvy up this money.
So the Storm operators or the spammers will get $1.7 million a year.
### SPAM Revenue Quiz
Now, let's do a quiz on spam revenue.
Name the top three countries where spam directed visitors added items to their shopping cart.
These are the visitors that can make transactions.
### SPAM Revenue Quiz Solution
This may be a surprise to you, but a top country is the United States, followed by Canada, followed by Philippines.
There's an interesting paper called
Show Me the Money: Characterizing
Spam-advertised Revenue, and
I encourage you to study this paper.
### Scamming Ain't Easy
With the example storm botnets, you may think that making money is easy in the underground.
Actually, it is not easy.
In fact, scamming is supported by a whole ecosystem that includes network infrastructure and payment system.
For example, we're going to start the pharmaceutical scams.
Suppose you want to set up a website called canadianpharma.com.
The question is that how do you do this?
What sort of infrastructure do you need?
Because obviously you should worry about law enforcement agencies shutting down your website.
Even before that, you should worry about that legitimate registers may not even let you register your domain name.
So you go to the shady registrars, but they would charge you more.
After you obtain your domain, you want a DNS server that map the domain name into an IP address.
Some DNS providers will shut down your domain if they hear complaints.
So you go to the so-called bulletproof DNS providers, that operates in lawless land, but they are expensive.
Now to set up your website, you need to stand up a web server.
For example, a machine in ISP.
But, the ISP or law enforcement can shut down your website.
So, you want to go to the bulletproof network providers.
Again, they're expensive.
There are indeed service providers that offer very low priced, resilient hosting services, but obviously they are very expensive after you set up the network infrastructure, now you need to consider how do you receive payments.
Basically you need to handle credit card payments and get money out of these accounts.
The trouble is that most banks and credit card processors won't do business with scammers.
Again your solution is to go to a few banks in some lawless countries to handle your payment.
To be successful in scamming, you almost have to learn it like a legitimate business.
For example, you should ship products to customers, why?
Because if the customers are not happy, they will complain and the processors and banks will shut down your accounts.
### Example  Pharmacy Express
Now let's study an example of scam.
First, the Botnet sends scam messages to the victim users.
The user clicks on the link and the link will eventually lead him to website to purchase fake drugs.
And payment will then be withdrawn from his bank account and he will receive shipment of the fake drug.
Using data collected from spam feeds,
Botnet infiltration and various types of honeypot data.
The researchers were able to find some interesting data regarding this Pharmacy Express scam.
In particular, they find that these two accounts for around 35% of all affiliate scams.
And we will look more into these scammers in more details shortly.
### Pharmaleaks
In 2012, some of these scammers got breached and their data were dumped and made publicly available.
The data contained complete logs of sales, customers, and affiliate relationships.
So researchers study this data and publish their findings in this paper.
Here's a look at the transaction volumes per week for these scammers.
We can see that these scammers were around for a long time.
We can see here that the repeat customers or the repeat orders are an important part of the business.
This data presents a counter-point to the conventional wisdom that online pharmacies are pure scams.
They don't simply take credit card and either never providing goods, or providing goods of no quality.
Because if that is true, then we would not see repeat customers.
Here's a breakdown of the different types of drugs being purchased by customers.
Here we see that pharma scams bring in a lot of revenue, but there are also a lot of costs.
The actual net revenue, or profit is not huge.
These costs include payment to the affiliates.
Cost of the network infrastructure, and payment to spammers and botnet operators.
### Introduction to Penatration Testing
In this lesson, we will discuss the first line of network defense.
The basic tools and techniques of penetration testing and security assessments.
We will also discuss one of the most powerful tools of the network hacker, you.
Yes, you and I.
In fact, everyone has a potential to be a hacker's best friend.
Social engineering is a fast, low risk method to gain access to data.
Pay close attention to the methods used and think about how they can be deployed to make a network more secure.
### Overview
Let's have an overview of what penetration testing is all about.
Penetration testing is used to evaluate the security of a network.
More specifically, penetration testing is used to evaluate all security controls.
These include the security procedures, the operations, and the technologies.
With penetration testing, you can find out how secure your network really is.
In particular, you can discover security vulnerabilities.
And by actually exploiting the vulnerabilities, you can also demonstrate how likely the threats can take place and what are the likely damages associated with these threats.
The scope of penetration testing include not just technical or cyber operations, it can also include social engineering, and also gaining physical access to your organization.
The scale of the testing includes the entire network.
For example, the testing may include your mobile devices, or BYOD.
### Methodology
Now let's discuss the methodology of penetration testing.
Penetration testing includes several steps.
The first step is footprinting.
This is about finding the general information of your network.
Next step is scanning.
This is about finding more detailed information about your network, such as the services available on your network.
The third step is enumeration.
It finds more target information such as user account.
The fourth step is gaining access.
It finds vulnerabilities associated with the network services, and then exploit these vulnerabilities to gain access to the network.
The fifth step is escalating privilege.
The goal here is to gain route of super user access.
The sixth step is pilfering.
The goal here is to try to steal information from the network.
This is one of the standard activities that an attacker would do to a network.
The seventh step is covering the tracks.
The goal here is to hide an evidence of a break in so that security amends cannot easily find out that the network has been breached.
The last step here is creating back doors.
The goal is to create easy access for future malicious activities on the network.
The last few steps can be iterated for example to move from one part of the network to another part.
### Footprinting
Now, let's discuss these steps in more details.
The first step is footprinting.
In this step, the attacker, or tester, conducts reconnaissance and information gathering.
The important network information includes network IP addresses, the namespace, and topology.
Even a phone number range can be used for modem access or social engineering.
Such information is critical for planning the next steps of testing or attacks.
Example, you will need the IP addresses to decide how to scan the network.
Here we'll list the different techniques and the corresponding tools for footprinting.
For example, you can use Google to find out the company information, and use Whois to find out the domain name information of the name servers and
IP ranges.
### Scanning
Once you have the general information such as the IP ranges of a network, now you gain more detailed information of the network using scanning.
You can find out which machine is up, and which ports are open.
Similarly on the servers what services are running.
You can even find out the versions and configurations of these services.
Then you can look up the corresponding vulnerability information on the web.
For example for a particular version of the Apache web server, you can look it up on the web to see one of the known vulnerabilities, such as what input can cause a buffer overflow.
Most promising avenues are typically associated with services that are always up, such as the web services, so you want to focus on analyzing these services.
On the other hand, you want to avoid detection so you want to reduce the frequency and volume of your scanning and analysis.
Here are the different techniques and tools for scanning.
As you can see, Nmap is one of the most popular tools It can find out which
IP's up, which port is open and even perform OS finger prints.
### Enumeration
You can also perform more targeted attack or testing by figuring out which user accounts are poorly protected.
And obviously, this is more targeted and intrusive than scanning.
And here are the techniques and tools for enumeration.
For example, you can use these tools to list user accounts and use these other tools to find out file sharing information.
### Gaining Access
Once you have obtained the relevant information of network services and user accounts, now you can exploit and gain access to the network.
Typically, there are all the existing tools and scripts associated with known vulnerabilities.
But of course, you can customize them to suit your needs.
On the other hand, if the vulnerability is new or there does not exist a tool or script, then you have to develop the exploit yourself.
In general, this is a manual process and can be quite difficult.
Here are some examples of techniques and tools for gaining access.
For example, you can use tools to capture and crack password.
And there are tools that will exploit vulnerabilities in widely used services.
### Escalating Privilege
The next step is escalating privilege.
And the goal is to gain super user access so that you can gain complete control of the system.
Here's some examples and tools.
Again, you can capture and crack the super user passwords.
There are tools that will exploit vulnerabilities of privileged services in order to help you gain good access.
### Pilfering
After you've gained access to the system.
Now you can steal valuable information.
Such information can allow you further access to the system.
For example, you can discover the trust relationship among the machines on a network, and you can obtain user credentials such as passwords.
### Covering Tracks
It is important to cover the tracks, so that the attack cannot be detected and stopped easily.
For example, you can use these tools to edit or even clear the system logs, and you can use rootkit to hide your malware.
### Creating Back Doors
The first time gaining access to a network through an exploit is always hard.
And you want subsequent access to be easy and look normal, so you will create trap doors or back doors.
There are many techniques and tools.
For example, you can create fake user accounts, or you can plant remote access services.
You can also schedule your activities at certain time.
### Penetration Testing Quiz
Now let's do a quiz on penetration testing.
Which events should trigger a penetration testing?
### Penetration Testing Quiz Solution
All of these events should trigger a penetration testing.
I should also add that penetration testing should also be done on a regular basis as well as on these triggering events.
### Persistence and Stealth
To simulate the modern attacks, such as the so called advanced persistent threats.
Penetration testing can try to be persistent and stealth.
For example, the tester can install a backdoor through a malware so that there's a permanent foothold in the network.
The malware can be placed in a strategic place such as a proxy.
And the result can be that now the malware can listen and record all traffic within the network.
And by analyzing internal traffic, the malware can capture user credentials and find out valuable information.
These steps can be iterated and moved from one port of the network to the next while hiding the tracks.
### Social Engineering
As we discussed earlier, penetration testing can include social engineering.
So now let's discuss social engineering.
We all know that users are the weakest link in security, so the goal here is to use social engineering techniques to evaluate how vulnerable your user population really is.
In particular, you will want to find out which user groups are particularly vulnerable.
You will likely discover policy gaps, so you will want to fix these policies and develop new mechanisms including educating and training the users.
Social engineering is effective when the users are manipulated into undermining the security of their own systems.
This can be accomplished by abusing the trust relationships among the users.
Social engineering can be very easy and cheap for the attacker because the attacker does not need any specialized tools or technical skills.
### RSA Breach Quiz
Now let's do a quiz.
In 2011, the security company,
RSA, was compromised.
And it began with social engineering.
Once gaining access, the attackers then installed backdoor using Adobe Flash vulnerability.
In this quiz, list the steps the attackers used to access RSAs Adobe Flash software.
### RSA Breach Quiz Solution
The first step is to identify employees that are vulnerable.
The second step was crafting an email with an enticing subject line.
In particular, the subject line was a provocative 2011 recruitment plan.
And one employee was intrigued enough to open it.
The first step is to hide an executable file in the e-mail, so that it will install on the victim's computer when the e-mail is opened.
In this case, the attachment is an Excel spreadsheet, that contains a zero day exploit that leads to a back door through Adobe Flash.
This one e-mail resulted in a loss of $66 million for RSA.
### Common Social Engineering Techniques
Now let's discuss the common social engineering techniques.
The first category is impersonation.
For example, you can impersonate help desks, third-party authorization, technical support.
Or you can roam the halls or tailgate or you can impersonate a trusted authority.
And you can even send snail mail.
The other category of social engineering techniques involve the use of computers.
This include pop-up windows, instant messages and IRC, email attachments, email scams, chain letters, efficient websites.
### Impersonation
Let's discuss the impersonation techniques first.
For example, an attacker can pretend to be an employee and call the help desk, and claim that he has forgotten his password.
A common weakness is that, the help desk does not require adequate authentication.
For example, the help desk may just ask for the mother's maiden name.
And the attacker may only know this, because he has read the Facebook information of the employee.
Another impersonation technique is to fake a third party authorization.
For example, the attacker can claim that a third party has authorized him to access the network.
And if the attacker can provide the fishing information to convince people that he really knows the third party.
Then, he will have easy time gaining the trust and the access to the network.
In particular, if the third party is not present.
Another very effective impersonation technique is to pretend to be a tech support person.
For example, the attacker can claim that the company needs to reconfigure its systems, and ask for user credentials.
If the users have not been properly trained to guard their credentials, then this attack can easily succeed.
Another old fashioned way of impersonation is to just walk around and see what information is valuable.
For example, passwords or sticky notes, or other kind of important documents, or even overhearing important conversations.
An attacker can dress up like a repairman, because a repairman is typically allowed access to the facility.
The attacker can then plant listening devices to capture useful information.
This exploit works because users typically do not question people in uniform.
Similarly, an attacker can pretend to be someone in charge of a department or company.
For example, the attacker can pretend to be a medial personnel, a home inspector, or school superintendent.
In each of these examples, the attacker can actually gain useful information from a user.
The attacker can gain information such as address, mother's maiden name, and so on of an employee.
And this information can then be used to impersonate employee through the call to a help desk.
Again, this exploit works because users tend to trust authority.
Impersonation can also take place in snail mail.
For example, an attacker can send mail to a user pretending to be an authority and ask for personal information.
This exploit works because users tend to trust the printed materials more than webpages and emails.
These are examples that I'm sure you're familiar with.
### Impersonation Quiz
Now let's do a quiz on impersonation.
Match each tool with its description.
### Computer Attacks
Now let's discuss social engineering attacks that involves computers.
The first kind is popup windows.
For example, a popup window can pretend to be a login window.
This exploit will work if the users have not been properly trained to tell the difference between the fake and the legitimate login windows.
The attacker can also use IM or
IRC to fake a technical support desk.
And the users would be redirected to a malicious site and malware can then be downloaded.
An attacker can also check the user to open an email and download email attachment which includes malicious software.
There are many ways to hide malicious programs in email attachments that may appear to be legitimate.
For example, PDF files can include executable macros and a .exe file can be camouflaged into a .doc file.
And of course, we are familiar with various kinds of email scams. the attackers can amplify the effects of email scams using chain emails.
For example, an email can be sent to everybody on your address book.
An attacker can create a website that claims to offer prizes but require the user to create login and passwords.
The goal of the attacker is to harvest user credentials since many users uses same username and password on many websites.
The attacker can then use the credentials obtained from his website on other websites.
### Computer Attacks Quiz
Now let's do a quiz.
On this pie chart, what are the top three industries that were targets of cyber attacks in 2016?
### Computer Attacks Quiz Solution
Defense contractors, restaurants, and software companies.
The other 56% consists of industries.
They are targeted about 5.6% each.
### Counter Social Engineering Attacks
Here's how we should educate users to counter social engineering attacks.
Never disclose passwords to anybody.
Only the IT staff should discussed details of the network and system configurations and IT staff should not answers survey calls.
This also check with the call from the vendor is legitimate.
Also, we should limit information in all auto-reply emails.
Keep information in all auto-reply emails to a bare minimum.
We should always escort our guests.
This protects against attacks such as attackers dressing up like repairmen or trusted authority figure.
We should always question people that we don't know.
We should educate all employees about security, both physical and IT security.
We should have a central reporting and management of all suspicious behavior.
### Motivator Quiz
Let's do a quiz on human behaviors.
Match the motivation with its description.
### Motivator Quiz Solution
Liking is a desire to fit in.
Scarcity is a desire to pursue a limited or exclusive item or service.
Commitment is a desire to act in a consistent manner.
Social proof is looking to others for clues on how to behave.
### Introduction to Security Internet Protocols
Everything on the internet must use internet protocols to communicate.
In this lesson, we will discuss the weaknesses of these protocols and what can be done to improve security.
When we are done with this lesson, you should have a clear understanding of the security and abilities of TCP/IP.
### Internet Infrastructure
You can think of the Internet as a collection of large networks.
These large networks are typically managed by the Internet Service Providers, or the ISPs.
The ISPs work together to allow traffic to flow from one network to another.
So to the users, the Internet is just one big connected network.
Because a user can reach from his computer on one end of the Internet to another computer on the other end of the Internet.
The computers within a local area network use the local and inter-domain routing protocol to communicate with each other.
Computers from different networks, for example, from two different ISP networks, use TCP/IP protocol to communicate.
But in order to decide how to send traffic from host A to host B which may be in two separate ISP networks, there needs to be routing information which is decided by BGP which stands for border gateway protocol.
The domain name system is a distributed, hierarchical database system that provides the mapping between an IP address and a symbol domain name, such as www.cc.gatech.edu.
### Infrastructure Quiz
Now let's do a quiz on internet infrastructure.
Match the different levels of networks to its description.
### Infrastructure Quiz Solution
A Tier One network is one that can reach every other network through peering.
A Tier Two network is one that peers some of its network access and purchase some of its network access.
A Tier Three network is one that purchases all of the transit from other networks.
Just for your information, there are only 17 Tier One networks in the world.
### TCP Protocol Stack
Now let's take a look at
TCP IP network stack.
The Link Layer is a group of protocols that only operate on the length the host is physically connected to.
The network or internet layer is a group of protocols that are used to transport packets from one host to another and may cross network boundaries if necessary.
The Transport layer protocols provide, host to host communication services for applications.
They provide services such as connection oriented data stream support, reliability, flow control and multi tasking.
The Application layer protocols depend upon the underlying
Transport layer protocol to establish host to host data transfer channels.
And manage the data exchange in a client-server or peer-to-peer networking model.
When host A sends traffic data to host B, the data usually starts as Application message.
The Transport layer segments the data and puts TCP header onto the segments.
The IP layer then puts the IP header on these segments, and they become the IP packet.
The Link Layer puts a link header onto the IP packets, and this becomes frames.
And this Link Layer frame can then be sent to the link, connected to the host, such as the ethernet cable.
### Internet Protocol
At the IP layer, the IP Protocol routes packet from host a to host b approaching never boundaries if necessary.
The routing is connectionless because it is best effort only and unreliable.
Meaning that, it's not guaranteed that, all packets from host a will arrive at host b.
And of course, for each IP packet, the source IP address and the destination IP address must be specified.
The ports are not part of the IP header because they're for the transport layer.
Here's an example of IP routing.
Suppose, we have a packet with source and destination IP addresses.
Typically, a route will involve multiple hops.
An IP routing has no guarantee of the order or even delivery of the packets.
In this example, the packet starts from the source IP address reaches the gateway of its ISP, across network boundary to reach the gateway of the destination network and then finally reaches the destination IP address.
The summary from this example, the IP host knows how to reach the gateway and the gateway knows how to reach other networks.
If a data segment is too large, it may be fragmented into multiple IP packets.
At the receiving end, these fragments will be assembled back together.
If the destination did not receive a packet or fragment, you can send an ICMP packet to the source to report the error.
ICMP stands for
Internet Control Message Protocol.
The IP header can also include a TTL field.
TTL stands for Time to Live and this field is decremented after every hop and a packet is dropped if TTL reaches 0.
TTL is useful to prevent infinite loops.
### IP Quiz
Now let's do a quiz on the Internet Protocol.
Select all the true statements about Internet Protocol.
### IP Quiz Solution
The first statement, IP is a connectionless and reliable protocol.
This statement is false because
IP is not a reliable protocol.
The second statement,
IP provides only best effort delivery, it is not guaranteed.
This is true.
The third statement, due to the connectionless nature of IP, data corruption, packet loss, duplication, and out-of-order delivery can occur.
This is true.
### IP Authentication
Record it in the IP header, the source and destination IP addresses must be specified.
However, one can easily override the source IP address using raw sockets.
For example, you can use the Libnet library to format raw packets with arbitrary IP header information including the source IP address.
This means that there's no guarantee that the source ID address is authentic.
This means that anyone who owns the machine, and knows how to use a tool like dimnet, can send packets with arbitrarily sourced IP addresses.
Now of course, a response will be sent back to the forged source IP address.
For example, host A can send packets forging the source IP address of host B and then the response will be sent back to host B.
The ability to forge arbitrary source IP addresses enables anonymous denial-of-service attacks and anonymous infection and malware attacks.
### TCP
Now let's look at the transport layer protocols, in particular, the transmission control protocol or
TCP.
TCP is connection-oriented and it preserves the order of packets, we can use an analogy to explain TCP.
Suppose we want to mail a book, and the way we send the book is to mail each page in envelope.
And that's analogous to breaking application data into TCP packets.
And of course, for each page, there's a page number, so that we know the sequence of these pages in the original book.
Likewise, TCP packets have sequence numbers.
Now, when the pages arrive, they arrive in separate envelopes and may be out of order.
At the destination, we make sure that we receive all the pages, put them back in order and reassemble the book.
Similarly, at the definition host, each packet upon it's receipt, will be acknowledged.
And any lost packet will be notified so that the source can resend the packet and then the packet will be reassembled in the original order.
Now let's take a look at TCP Header, it includes the port numbers, the sequence number of the packet and acknowledgement number.
That is for acknowledging a previously received packet.
It also has a number of flux, these are used to control the TCP connection.
### Review TCP Handshake
Let's review how TCP Handshake works.
The client sends a SYN packet to server.
We randomly generated initial sequence number.
The server sends a SYN/ACK packet to the client.
It also has a randomly generated initial sequence number.
And also acknowledged the sequence number of the SYN packet from the client.
And then the client sends the ACK packet back to the server.
It also acknowledges the sequence number of the SYN/ACK packet from the server.
At this point the connection is established.
Once a connection is established both sides can expect that their next packet will have the sequence number that is increment from the previous packets.
Now of course packets can arrive out of order.
But one can expect that the sequence number should not be too far out of the current window.
Therefore, if packets arrives with a sequence number that's too far out of the current window it would be dropped.
### TCP Security Issues
Now let's review some of the security problems associated with TCP.
Eavesdropping is always a big concern.
And this is quite easy for the attacker, if he can control your router or the Wi-Fi access points.
And such a hijacking is possible if the attacker can learn the TCP state.
And as discussed in our DDoS lesson, TCP is subject to denial service attacks.
### TCP IP Security Issues Quiz
Now let's do a quiz on the security of TCP IP.
Select all the true statements.
### TCP IP Security Issues Quiz Solution
The first statement, application layer controls can protect application data, and IP addresses, this statement is false.
IP addresses exist in a lower layer, and so application layer controls cannot protect IP addresses.
The second statement,
IP information cannot be protect by transport layer controls, this is true.
The third statement, network layer controls can protect the data within the packets as well as the IP information for each packet.
This statement's true, because that is what network layer controls are supposed to do.
The fourth statement, data link layer controls can protect connections comprised of multiple links.
This is false, they cannot protect connections with multiple links.

---
&nbsp; \pagebreak
## 11b - Property-Perserving-Encryption

### Introduction
In this lesson, we continue our focus on The Cloud.
What a concept of shared sources is an excellent idea.
It is also rabbit hole of security issues.
We will examine and analyze a number of Cloud oriented attacks.
In particular, we discussed attacks on data privacy and the challenges in data privacy protection.
### How Do Data Breaches Happen
Let's discuss data privacy issues in a cloud environment.
First let's review how data breaches happen.
In a cloud environment the users use applications or data stored in a cloud provider.
For example, the users can be doctors and nurses, and the application can be the electronic medical record system.
And the data obviously is the medical records.
And the called EMR here can be a private called such as UCLA Health.
As another example, the users can be average consumers.
And the application can online dating.
And of course, the data can be the dating profiles.
In most cases, including the examples that we just discuss, data is the most valuable target to the attacker.
For example, the attacker may want to steal the data.
Now the question is, how do we protect the data?
Obviously we can encrypt the data.
For example, the users can have their own secret encryption key for their data.
And once the data is encrypted the adversary can no longer read the data.
The problem when the data is encrypted the applications can no longer use the data as it is.
For example if the application is a word processing programm such as Microsoft Word, it cannot process encrypted data directly.
Therefore, the real question is can we protect the data while we also let the application work?
In other words, we want to protect the data by encrypting the data, so that the adversary cannot read our data.
On the other hand, we also want the application to continue to work.
### Encryption Quiz
Before we go on, let's do a quiz on encryption.
Match the characteristics of each encryption.
### Encryption Quiz Solution
In property preserving encryption, some selective properties of the alternate data are preserved, such as the order.
Searchable encryption means that the encrypted data can be searched using the encrypted keywords.
In secure computation, multiple parties can compute a function using inputs that are kept private.
In Homomorphic encryption, computations performed directly on encrypted data, have the same result as the computations on the plaintext.
In functional encryption, the possession of a secret key will allow someone to learn the function that is being encrypted.
### PPE
Property Preserving Encryption is one way to protect data while allowing application to continue to work.
And this approach is widely deployed in various environments including the Cloud.
For example, Microsoft advertises that data is always encrypted.
On the other hand, the applications continue to work.
Property Preserving Encryption has several advantages.
There's no need to change application and database servers, it supports common data retrieval methods, including SQL queries.
It is reasonably efficient, but what about security?
Although it widely believed that it is secure, we should take a closer look.
### PPE Quiz One
To understand the potential security issues of
Property Preserving Encryption, let's do a quiz.
First, let's review standard encryption.
In standard encryption, there is no preserving of properties.
For example, suppose we encrypt the age information.
The encrypted data leaks nothing except the size of the original plain text data.
For example, we know that there are four entries.
Now let's take a look at an example of property preserving encryption.
Again, we want to encrypt the age information, but we preserve equality.
Therefore in encrypted data, we see that these two values are the same, because the original paying tax values are the same.
So what is preserved?
### PPE Quiz One Solution
As we said, equality is preserved, but what is leaked is a frequency.
Because we now know that there's one value that appears twice.
### PPE Quiz Two
Now let’s take a look at another example of property-preserving encryption.
Again, we want to encrypt the age information.
And this time, we preserve the order.
As we can see, in the encrypted data, the order of the original values is preserved.
The question is, what is leaked in order-preserving encryption?
### PPE Quiz Two Solution
Obviously, the order is leaked.
Frequency is also leaked because the same value in plain text will be the same value in encrypted text.
### PPE Leakage
The previous examples are simple.
Now the question is, what does the leakage in property preserving encryption really mean for real applications?
We can take a look at the electronic medical records.
Here are some attributes in electronic medical records.
These attributes are typically used in equality queries or ordering.
In other words, to ensure that the applications will continue to work, these attributes will be encrypted to preserve equality or order.
These attributes are sensitive to either the hospital or the patient or both.
### Data for Attributes
The data as we can obtain from the hospitals is encrypted.
On the other hand, there's information, or auxiliary data that is public.
We will show that using both the encrypted data and auxiliary data, an attacker can launch inference attack to obtain plaintext data.
### Encryption Attacks
Recall that these attributes are encrypted using either
Equality-Preserving Encryption or
Order-Preserving Encryption.
An attacker can use frequency analysis to defeat
Equality-Preserving Encryption.
And this attack can be further optimized.
### Attack Analysis
Lets use an example to illustrate frequency analysis attack.
Here is encrypted data of the number of days a patient stays in hospital.
As you can see the data is encrypted to perform frequency analysis we first sort the data and record the frequency.
We also sort and record the frequency of the auxiliary data.
For example, there's public information of how frequent a patient will stay for one day versus two days and so on.
By matching these two histograms we can link a cyber text value to a plain text value.
For example, for the first cyber attack value the frequency is ten.
And we know that from the auxiliary data, the plain text value one has frequency of 11.
Therefore, we can link the ciphertext value to plaintext value one.
And therefore, with frequency analysis, we can uncover the plaintext data without the encryption key.
### Optimization Attack
This attack can be generalized and optimized.
Again, start with the encrypted data, we have obtained a frequency histogram.
We also obtain a frequency histogram from the auxiliary data.
The basic idea is then, to find an assignment from servertext to plaintext that minimizes a gives cost function.
Here the cost function is the distance between the histograms.
This has the effect of minimizing the total mismatch in frequencies across all plaintext- ciphertext pairs.
For example, for this assignment, the cost is this.
Whereas the assignment on mapping, it has the minimum cost is this.
There's an algorithm that can find the assignments that has the minimum cost.
With this algorithm, we can find the assignment from ciphertext to plain text and then decipher the original encrypted data.
### Optimization Attack Analysis
Here are some results of applying this attack on the electronic Medical records.
The x axis is the cumulative fraction of records recovered, and the y axis is the fraction of hospitals.
That is, in all of this parts, our point xy shows that at least x fraction of records was recovered for y fraction of hospitals.
For example, for disease severity at least 40% of the records were recovered for 50% of the hospitals.
The best result we can obtain is that all records, for all hospitals, were recovered.
Here are the highlights of the results.
For example, for sex, 100% of the patients For
95% of the hospitals recovered.
And for major diagnostic category,
40% of the patients for
28% of the hospitals were recovered.
And we show more results here the highlights are, for age 10% of the patients for
85% of the hospitals were recovered.
For length of stay, 83% of the patients for 50% of the hospitals were recovered
### Cumulative Attack
We have discussed on equality preserving inscription.
Now, let's discuss a tax on order preserving inscription.
We can use sorting attack, but a more effective attack is cumulative attack.
Given a data column that has been encrypted using order preserving inscription.
A nemissary can learn not only the frequencies, but also the relative ordering of the encrypted values.
Combining ordering with frequencies, the attacker can tell for each server text C, what fraction of the encrypted values are less than C.
More formally, this is known as the empirical cumulative distribution function of the dataset or
CDF.
In the cumulative attack, an attacker leveraged the CDF to improve the ability to match plaintext to ciphertext.
Intuitively, if a given ciphertext is greater than 90% of the ciphertext in the encrypted data, then we shall match it to a plaintext that is greater than about 90% of the auxiliary data.
This problem belongs to a category of Linear Sum assignment Problem.
Therefore, we can use an algorithm to find the mapping of plaintexts to ciphertext that minimizes the total sum of mismatch in frequency plus the mismatch in CDFs across all plaintext, ciphertext pairs.
### Cumulative Attack Analysis
Here are some results of this attack and the highlights are for disease severity, admission month, mortality risk, length of stay 100% of the patients for
100% of the hospitals were recovered.
And for age, 83% of the patients for
99% of the hospitals were recovered.
### Attack Recap
Here is a summary of the results of attacks on electronic medical records.
As you can see, the confidentiality of many attributes is compromised.
### Suppose We Don't Trust the Cloud
Now let's discuss another data privacy issue in the cloud environment.
Suppose we don't trust the cloud provider?
We can either encrypt our data on the cloud storage server and keep the keys to ourself.
When we need to use the data, we can fetch the encrypted data to our environment, encrypt the data, then use the application in our local environment.
The question is, is this efficient?
No, because the data access patterns can still leak information, such as what kind of computing tasks are being performed.
### Oblivious RAM
A promising approach to eliminate this kind of leakage is to use oblivious RAM, or ORAM.
ORAM can hide access patterns.
The main idea is that using ORAM, while the cloud provider can still observe data access, the access patterns are independent of the actual data requests.
Some of the main techniques include O data access operating on fixed size data blocks.
The data is encrypted, not using property preserving encryption.
In addition, ORAM also use dummy accesses, or re-encrypt data and shuffle data around.
Here's a high level pictorial example of ORAM at work.
The application needs to access confidential data such as getting an encryption key, encrypt and store data, and getting another encryption key.
For each of these access requests, there are multiple requests to the cloud server.
These requests all fixed sized data objects, and they are both read and writes.
That is, regardless whether the original request is for read or write, the actual dummy accesses include both read and writes.
And the data objects are all of fixed size and not distinguishable from each other.
And this is how you hide the access pattern from the cloud provider.
ORAM is an active research area, and if you are interested, here are some papers.
### ORAM Quiz
Now, let's do a quiz on ORAM.
Select the statements that are true with regards to ORAM.
### ORAM Quiz Solution
The first statement, client must have a private source of randomness.
This is true, because the ORAM client must generate random access patterns.
The second statement, data does not have to be encrypted, since there's no access pattern.
This is obviously wrong, because we want to protect data from the cloud provider.
Therefore, encryption is actually the first requirement.
The third statement each access to the remote storage must have a read and a write, this is correct.
Because we want to hide from core providers the fact that we only reading or writing data, therefore we will include dummy reads and writes.

---
&nbsp; \pagebreak
## Attack-Tolerant-Systems

### Introduction
We have networks with valuable data on them.
These networks have been attacked or will be attacked.
We can do everything humanly possible to stop attacks, but we also need to build systems that can withstand attacks.
In this lesson, we learned about attack tolerant systems.
### WWW Robustness Quiz
As we all know, the Internet is vulnerable to attacks.
Since we are going to discuss attack tolerant systems, let's first make sure we understand how the structure of the Internet is both a blessing and a curse.
In this quiz, answer the questions in reference to the Internet.
### WWW Robustness Quiz Solution
The internet is a scale-free network.
We can infer that it has a high degree of tolerance towards random failure and a low degree of tolerance against attacks.
The most successful attacks target the nodes that are the most connected.
When a highly connected node is attacked, the internet begins to fracture and splinter into unconnected networks.
It is this characteristic of the internet that makes attacks so successful.
### Node Connectedness Quiz
Determining which nodes are the most connected is an interesting problem.
There are basically three different methods of determining node connectivities.
In this quiz, match the method of determining no connectivity to its definition.
### Node Connectedness Quiz Solution
Average node degree, look at nodes with the largest number of nodes connected to them.
Node persistence, look at a snapshot of the internet traffic, these nodes are the ones that are most likely to appear.
Temporal closeness, look at nodes that interact with the largest number of nodes.
### Defense in Depth
We all know the principle of defense in depth.
That is, the first layer of defense is prevention.
The second layer is detection, and the third layer is about surviving the attack.
The best way to survive an attack is to able to tolerate the attack.
That is, an attack will not be able to render our network or system ineffective.
When we say our network and systems should tolerate an attack, we mean that our data and our services should tolerate the attacks.
For our data, we want the confidentiality, integrity, and availability to remain intact.
For our system services, we want the availability and integrity to remain intact.
Let's first look at how to make our data tolerate an attack.
Typically, data is stored in one place, for example, a dedicated server.
So, all the attacker needs to do is to compromise that data storage server.
That is, if the attacker can compromise the data storage server, then the confidentiality, integrity, and availability of data are all compromised.
Now, what if we replicate the data and store the copies in multiple, say n different servers, would this scheme improve security?
That is, would this scheme make our data more tolerant towards attacks?
For confidentiality protection, this is actually a weaker scheme because the attacker can get data from any of these n servers.
That is, the attacker now has more opportunities.
Whereas, if we use a majority voting scheme, then integrity and availability are better protected because now the attacker needs to compromise the majority of these n servers.
So, now the question is, for our data, can we have a better confidentiality protection?
### Naive Secret Sharing Quiz
One approach is by secret sharing.
Cryptographic secret sharing involves, giving each party a share of a secret, the secret can only be reconstructed if all parties participate and share their portion.
For example, if the secret is a password.
That is P-A-S-S-W-O-R-D! we can break the secret into shares, and give the shares to three different parties.
That is, now each of these three parties has a share of the secret.
Now, I'm going to ask you what's wrong with this scheme, I'll give you a hint.
If the attacker knows the password has nine characters, how many possible combinations will have to be checked?
What if the attacker doing the guessing, knew one share of the secret.
### Naive Secret Sharing Quiz Solution
The major weakness of this naive secret sharing scheme is that the more shares you have of the secret, the less work you have to do to guess the secret.
In a secure scheme, it should not matter how many shares of a secret a party has.
You should take the same amount of guess work as a party with no shares.
### Secret Sharing
Again, in cryptography, a secret sharing scheme distributes the secret among a group of participants, so that each of the participant has a share of the secret.
The share can only be reconstructed when the shares are combined together.
Most importantly, individual shares are of no use on their own.
We secure sharing.
We can give a tighter control and remove any single point of vulnerability with regard to confidentiality.
This is because even if an attacker has compromised an individual key shareholder he still cannot change or access to data.
And of course we can also improve integrity and availability by replicating each share among the group.
### Mathematical Definition
Now, let's discuss the math behind secure sharing.
The goal of secure sharing is that for some secret data say D, we divide the data into n pieces,
D1, D2, through Dn.
In such a way that, if you know k or more pieces of D, then you can compute D. On the other hand, if you know only k minus one of fewer pieces of D, then you can not determine D. The best you can do is a random guess.
This is the so-called k, n threshold scheme.
If k equal to n, that means all participants are required together to reconstruct the secret.
### Shamir's Secret Sharing
Now let's discuss a threshold secret sharing scheme by Shamir.
Shamir is the S in RSA and in 1979, he invented a (k,n) threshold scheme.
Here's how Shamir's secret sharing scheme works.
We choose a random k-1 coefficients; a1, a2, a3 through a_k1.
We let the secret S be a0.
In other words, we pick a random k-1 degree polynomial and we represent it as this.
Again, a0 is a secret S, and a1, a2 through a_k-1 are randomly chosen.
Then we construct n points on this polynomial.
That is, for i=1,
2 all the way through n, we compute q of i.
Then we construct n points of the polynomial q(x).
That is, for i=1, 2, all the way through n, we compute Si equal to q of i.
For example, if i=1, we set x=1 for q(x).
This Si's are essentially the shares of S.
All arithmetic operations are done modulo a prime number p, and p is greater than S and n. Again, the coefficients a1, a2, through a_k-1 are randomly chosen from a uniform distribution over the integers in the range of 0 and p. Given any subset of k of these pairs or points, we can find the coefficients of the polynomial q(x) by interpolation.
Of course, once we find the coefficients, we have determined the polynomial q(x).
This is guaranteed by the mathematical property that any k points can uniquely determine a polynomial of degree k-1.
Once q(x) is determined, then we set x equal to 0 and compute q(0), that will give us a0, which is the original secret S. In other words, with this scheme given any K shares, we can reconstruct the secret.
### Shamir's Scheme Example
Here's an example. Suppose k equal to two.
That is, the polynomial is a linear function, a line.
Suppose all you know is one point, say S1.
You cannot determine the polynomial because there are infinite number of lines that go through S1.
It is clear that you need two points to determine a line.
For example, if you know both S1 and S2, then you can reconstruct the line and then you can compute S, which is the original secret.
Notice that, this example also shows that obviously, any two points on a line can determine the same line, which means any two of the entries can help you reconstruct the original secret S. In general, when we need to determine q(X), we should use the Lagrange interpolation algorithm.
### Shamir's Scheme Example 2
Let's use an example to illustrate.
Suppose k is three and n is five.
Further, the ultra secret is seven and a0 is seven, a1 is three and a2 is five and the modular prime number p is 11.
That is; qx is 5x squared plus 3x plus seven modular 11.
Since n is five, we compute five shares of five points by setting x to be one, two, three, four, and five, and these are the shares.
Since k is three with three shares, we should be able to reconstruct the secret.
Say we have three shares S1, S2, and S5.
Then we can use this formula due to Lagrange to compute qx.
So, we can plug in these points to the formula that is setting the x, i or j's to be one, two and five and setting the y, i's to be four, zero, and four.
Then we have qx represented as this formula.
With simple arithmetic, you can verify that qx is five x squared plus 3x plus seven.
Then we set x to zero and q of zero is seven which is the original secret and this is how we use Shamir's Secret Sharing Scheme.
### Shamir's Scheme Summation
In practice, if we set n equal to 2k minus one, that will require an attacker to compromise more than half of the shares in order to reconstruct the original secret.
In general, we typically assume that an attacker cannot compromise the majority of our systems.
Let's summarize the security properties of Shamir's secret sharing scheme.
First of all, shares can be dynamically added or deleted without affecting the other shares.
Second, security can be easily enhanced without changing a secret.
For example, we can change the polynomial, recompute the shares, and then, give the new shares to the participants.
Third, in organizations where hierarchy is important, we can supply each participant different number of shares according to their importance.
For example, the CEO can have all the shares so that he alone can reconstruct the secret, whereas three VPs are required together to reconstruct the secret.
Fourth, this scheme cannot be broken even when the adversary has unlimited computing power.
That is, the attacker has to have k shares.
Otherwise, no matter how much power he has, he can only be a random guest.
### Practical Byzantine Fault Tolerance
Now let's discuss how do we make system services tolerate attacks.
First, we will discuss a related area called fault tolerance.
A fault in the system is the cost of an error that leads to a system failure.
Again, a system error is because of a fault, and error leads to a failure.
Fault tolerance can be achieved through a failure masking.
And failure masking can be achieved through redundancy.
For example, let's look at a example system.
Here, a single fault in any of these three components can lead to a failure.
An example of redundancy is triple modular redundancy.
We can put motors at each stage of the system.
And each voter accepts the majority as the correct output from the components.
This scheme can mask any single failure of the components.
### Redundancy of System Services
In a previous example of a redundant system, we see that the motor takes the majority as the correct output.
This assumes that the non-faulty components can reach a consensus.
Therefore, the goal of a redundant system is that a set of non-faulty services can reach a consensus, even in the presence of some corrupted or faulty services.
This consensus is then the correct service that a system will provide.
### Redundancy Quiz
Now, let's do a quiz.
Match these terms with their descriptions.
### Redundancy Quiz Solution
Availability measures how likely a system can operate correctly at any given moment.
Reliability is the ability for system to run correctly for longtime.
Safety means that, failure to operate correctly does not lead to catastrophic events.
Maintainability is the ability to easily repair a failed system.
### Byzantine Generals Problem
Getting a set of non-faulty services to reach consensus is actually quite challenging.
Let's use an example to illustrate.
The Byzantine Generals Problem refers to a hypothetical situation in which a group of generals, each commanding a portion of an army plan to attack a city.
The generals must decide to attack or wait.
Every General must agree on a common decision, anything less will result in a defeat.
The problem is compounded by the fact that there may be traitorous generals that do not vote for the best strategy.
Of course, there can be disagreement among the generals.
For example, some would vote for attack, while others will go for wait.
As you can see, it's not easy to reach consensus.
### System Models
The Byzantine generals problem is an example of asynchronous distributed system.
In such systems, we typically assume that the network is not reliable.
That is, there's no guarantee for reliable communications.
Furthermore, a faulty node may behave arbitrarily.
That means, its behavior is not defined.
Also, the nodes fail independently.
That means, there's no correlation of failures among the nodes.
On the other hand, we also assume that the attackers cannot indefinitely block a node from providing service, and the attacker cannot break crypto.
### System Properties
When we say an asynchronous system achieve fault-tolerance, we typically mean that, it has both safety and liveness.
Safety means that, even if the system fails, nothing series happens.
Liveliness means that, the kinds of the system can eventually receive replies to their requests.
In order for an asynchronous system to provide safety and liveness, it needs to have a minimum 3f plus one replicas.
Here, f is the maximum number of faulty replicas.
We need 3f plus one replicas, it must be possible to proceed after communicating with n minus one replicas, since f replicas might be faulty and not responding.
However, it is possible that the f replicas that did not respond are not faulty, and therefore f of those that respond, might be faulty.
Even so, there must be enough responses, that those from non-faulty replicas out number those from faulty ones, that is, n minus two f is greater than f. Therefore, n has to be greater than 3f.
### System Algorithm
So here is a sketch of how a client can get service from this system.
A client sends a request to invoke a service operation to the primary service replica.
The primary multicasts the request to the backups, meaning the group of replicas.
The replicas execute the request and send a reply to the client.
The client waits for f plus one replies from different replicas with the same result, and that is the result of the operation.
### Attack Tolerance
So far we have discussed fault tolerance for system services, but what about attack tolerance for system services?
Can we apply fault tolerance techniques to achieve attack tolerance? The answer is no.
Because in fault tolerance, we use redundancy which means we use replicas of a system and all replicas runs the same program.
That means the same attack can compromise all replicas.
Therefore, redundancy is not a solution for attack tolerance.
To achieve attack tolerance, we need to use diversification.
That is each instance to use a different implementation and this applies to all layers of the stack.
Which can include network and application protocols, programming languages, operating systems and so on.
Each instance can use a different security protection mechanism or apply a security mechanism to different part of the program.
This can achieve efficiency for example because not all operations are checked all the time.
It can also help us identify the attacks based on which protection mechanism works and which fails.
Of course, it is very costly to implement and very complex to manage diversification.
We can take the idea of diversification one step further to use what we call moving target techniques to achieve attack tolerance.
That is, we can dynamically change our network and system configurations.
For example, we can have many instances of the system and network services.
Each instance can have a different implementation, and these instances can be composed on-the-fly.

---
&nbsp; \pagebreak
## Browser-Security-Model

### Introduction to Advanced Web Security
This is a large lesson because the topic,
Advanced Web Security, is an expansive subject.
By the end of this lesson, you should be familiar with the web security model, defenses against attacks on web applications, HTTPS, its goals and pitfalls and content security policies and web workers.
### Common Application Attacks Quiz
Before we discuss web security, let's remind ourselves as to why we need web security.
In this quiz, match the attacks to their descriptions.
So the attacks are, using components with known vulnerabilities, missing function level access control, sensitive data exposure, security misconfiguration, insecure direct object references, cross site scripting, broken authentication and session, injection.
And the descriptions are, modifies back-end statement through user input, inserts Javaccripts into trusted sites, program flaws allow bypass of authentication methods, attackers modify file names, abuses the lack of data encryption, exploits misconfigured servers, privilege functionality is hidden rather than enforced through access controls, uses unpatched third party components.
### Common Application Attacks Quiz Solution
And the answers are the first attack using components with known vulnerabilities.
The description is uses unpatched third party components because unpatched third party components have known vulnerabilities.
Second, missing function level access control.
For this attack, the description is privilege functionality is hidden rather than enforced through access controls.
Because the attacks here says it's missing function level access control.
The third attack sensitive data exposure.
For that to work, the description is this one.
Abuses the lack of data encryption.
The next attack security misconfiguration.
The description is exploits misconfigured servers.
The next attack insecure direct object references.
The description is that the attacker can modify file names because file names are direct object references.
The next attack, cross site scripting.
The description is, inserts Javascript into trusted sites.
The next one, broken authentication and session.
The description is, program flaws allow bypass of authentication methods.
Because the attack here exploits broken authentication and session.
The last one, injection, the description is modifies back-end statement through user input.
In other words the attack action is injected through user input.
### Goals of Web Security
Now, let's discuss the goals of web security.
Obviously, we need to be able to browse the web safely.
This means that, when browsing a website, sensitive data on the user's computer can not be stolen and uploaded to the web.
And that if the web browser has multiple open sessions with multiple sites.
For example, one session to a bank website, and another session is to a social network site.
The sessions don't interfere with each other.
Intuitively, if the social network site is compromised, it should not affect the user session with the bank site.
In addition, we need to ensure that the web applications can have the same security protection, as applications that run on the operating system on our computers.
### Threat Models
Now let's discuss the Web Security Threat Model.
We use threat model to understand what the web attackers are likely to do.
And we're going to compare the Web Security Threat Model and the Network Security Threat Model.
On the web, attacker can typically setup a malicious website and the attacker waits for users to visit the malicious website so that the attack can be launched through the malicious websites to compromise the user's computers.
A web attacker typically does not control the network.
Now let's look at the Network Security Threat Model.
A network attacker can be much more active.
Typically, we would assume that a network attacker can intercept and control the network.
For example, the attacker can intercept and drop the traffic.
Or he can intercept and perform traffic analysis to crack open the encryption key to read the data that's being transmitted.
Or he can inject malicious traffic into the network.
### Attack Top 10 Quiz
Now let's do a quiz relates to web attacks.
According to the OWASP in 2013, the following are the top
10 attacks on web security.
I would like you to rank them in order,
1 for the most common and 10 for the least common.
These attacks are, security misconfiguration, insecure direct object references, missing function level access control, sensitive data exposure, using components with known vulnerabilities, cross site scripting, unvalidated redirects and forwards, broken authentication and session, injection, cross site request forgery.
### Attack Top 10 Quiz Solution
According to OWASP 2013, injection is the most common.
Unvalidated redirects and forwards is the least common.
And the order of the rest is here.
### Threat Models
Let's go over the various types of attackers in more details.
For the web attacker, the attacker could typically control a suspicious site, say, attacker.com.
He can even obtain certificate for his website so that the website can interact with users' browsers through HTTPS.
And then the attacker can wait for the user to visit attacker.com.
For example, this can be done through phishing and other kinds of redirect.
Or, the attacker can set up some sort of malicious, or fake, web app and wait for the user to download these apps and run these apps.
The point here is that, typically, a web attacker is somewhat passive.
He sets up some attack infrastructure and waits for the users to actually either visit those sites or use those malicious apps.
A network attacker is more powerful.
He can perform both passive and active attacks.
For example, a passive attack means that the attacker simply intercepts and analyze traffic to learn about the communication.
For example, the attacker can perform wireless eavesdropping to crack the encryption key for you're Wi-Fi network.
Examples of active attacks include inserting a malicious router in the network so that traffic can route through the router and be subject to the attackers attack.
That includes both passive like eavesdropping, or active attacks such as traffic injection.
Another example is DNS poisoning, where the attacker changed the DNS entry so that a legitimate site such as cnn.com, now has an IP address of a server that's controlled by the attacker.
That is, legitimate traffic such as to cnn.com will not be redirected, so that legitimate traffic such as those to cnn.com will now be redirected to the attacker's machine.
The most general and powerful attack is through malware.
By injecting a piece of malware on the user's computer, the attacker essentially escapes, the browser's isolation mechanism.
And now, has a program that runs directly under the control of the operating system.
That is, the malware runs as any other applications on your computer.
You may ask, why is that possible?
Isn't the browser supposed to isolate the rest of the computer from the web?
The problem is that browser is a very complex piece of software, and as such, browsers may contain exploitable bugs, and these bugs often enable remote execution of malicious code.
For example, when a browser visits a site that's controlled by the attacker, the attacker can send a webpage that contains malicious input.
And the result is that a bug is being exploited and a piece of malicious software, or malware, is now installed on a computer.
Now, even if the browsers are bug free, there are still lots of vulnerabilities on the web, in particular on the web-server side.
That would enable cross-site scripting,
SQL injection, and cross-site request forgery.
For example, SQL injection would allow the attacker to bypass the control of the web server, and directly inject attackers' code into the back end of the SQL database.
The point is that malware attackers can actually bypass the basic control of web, including browser, to actually attack the users' computers or the web service.
So we will discuss three main types of attackers.
The malware attacker, the network attacker, and the web attacker.
It is obvious that a web attacker is the least lethal because he's mostly passive.
A network attacker is more powerful because he can perform both passive and active attacks.
And a malware attacker is the most lethal and powerful because it can inject code into a user's computer or a server to perform any actions desired by the attacker.
### Modern Websites
Before we go into the details of web security, let's understand how the modern web works.
For typical website, it contains both static and active contents.
The active contents, or the code, can be from many sources and they can be combined in many ways.
Then the security challenges are we have many different types of data and codes for many different sources.
And they run and interact with each other.
For example, on a typical web page we have code or data related to the page itself, the third-party API's, for example to tutor, third-party libraries to how you navigate and scripts that run advertising contents.
And the data and codes on a website can be from many different sources, by many different developers.
For example, a website can have many parties contributing to its data and code.
These include page developers, library developers, service providers, data providers, ad providers, and other users, and extension developers, such as the web app developers and the CDN's, the content distribution networks.
Obviously these parties can be from different vendors and companies.
So the basic security questions are with data and codes from so many different sources, how do we ensure data And integrity when we browse the web?
For example, we need to figure out how to protect page from ads and services because they are from different sources.
On the other hand, maybe there's a legitimate reason to share data when they are from different sources.
That is, how do we share data with cross-origin page and how do we protect one user from another user's content?
How do we protect the page from a third-party library?
How do we protect a page from the content distribution network?
And how do we protect browser extensions from page?
### Website Quiz
Lets take a moment to understand the enormity of the web security problem.
Take your best shot at answering these questions.
First, in 2015 how many active websites were on the internet?
Second, how many websites does
Google quarantine each day?
Third, how many malicious websites are identified every day?
### Website Quiz Solution
The answers are, in 2015, there are 1 billion active websites.
And each day,
Google quarantine 10,000 websites.
And 30,000 malicious websites are identified every day.
As you can see, web security is not a small issue.
Understanding and stopping malicious actions is paramount to network security.
### Browsers
Now, let's discuss browser security model.
Let's take a step back and compare operating system with web browser.
An operating system supports multiple applications to run on a computer at the same time and allows them to share the resources on a computer.
Similarly, a web browser can render multiple webpages to different sites.
And each page can contain data and code from multiple sources.
So it is instructive to compare the operating system and web browser security models.
For Operating System, the primitives are system calls, processes, and disk storage.
For Web Browser, the primitives are Document Object Model or
DOM, frames, cookies and local storage.
The principles on the operating system are users, and associated with users is the discretionary access control policy.
For web browser, the principles are origins and mandatory access control is used.
Vulnerabilities in operating system can lead to buffer overflow, root exploit and so on.
Whereas on web browser, such vulnerabilities can lead to cross-scripting, cross-site request forgery, cache history attacks, and so on.
Now let's take a look at the execution model of web browsers.
Given a webpage, the browser goes through these steps.
First, load the contents.
Second, renders the contents.
That is, the browser processes the HTML pages and runs each JavaScripts to display the contents of the page.
The page may include images and frames and so on.
And then the browser response to events.
What are the events handled by a web browser?
The main events are user actions, such as clicking, moving the mouse.
Rendering, like loading a page.
Timing such as Timeout.
The contents being rendered can be from many sources.
For example, you could have scripts, frames loading HTML pages,
Flash objects, etc.
By specifying allowscriptaccess, the Flash object can communicate with external data, such as external scripts and navigate external frames and opening windows, etc.
The point is that there are many contents from many sources, and they can interact with each other.
Obviously, this makes it challenging for enforcing security policies.
The basic idea of browser security is to Sandbox web contents.
More specifically, we want to safely execute JavaScript code.
Because it can be from a remote website, this means that a JavaScript code cannot access the file system directly.
It can only have limited access to the operating system, the network and browser data, as well as content from other websites.
The main policy is the so-called
Same Origin Policy.
That means active code, such as JavaScript, can only read properties of documents and windows from the same origin defined as the same protocol, domain and port.
Now exceptions to this policy can be allowed.
That means scripts that are assigned by legitimate developers that a user can trust, such as scripts signed by Microsoft, Google, Apple, etc.
For example, the user can grant these privileges such as
UniversalBrowserRead/Write,
UniversalFileRead, and so on.
### Sandbox Quiz 1
Sandboxes and virtual machines are often confused with one another.
Let's use this quiz to try and set the record straight about the two.
Next to each characteristic, put an S for Sandbox, V for virtual machine, and B for both.
First, anything changed or created is not visible beyond its boundaries.
Second, if data is not saved, it is lost when the application closes.
Third, it is a machine within a machine.
Fourth, lightweight and easy to setup.
Fifth, disk space must be allocated to the application.
### Sandbox Quiz 1 Solution
First, anything changed or created is not visible beyond its boundaries.
This can apply to both sandboxes and virtual machines.
Sandboxes will isolate applications so that other applications cannot see it.
To see changes in virtual machines you must be in the virtual machine.
Second, if data is not saved, it is lost when the application closes.
This is an advantage of sandbox.
And you can call it a security strength of the sandbox because any malware downloaded will not be saved.
Third, virtual machines have their own copies of complete operating systems.
There can be multiple operating systems on a single hardware platform.
Four, sandbox is lightweight and easy to set up.
Fifth, for virtual machines, disc space must be allocated to the application.
### Browser SOP
Origin is defined by protocol, domain, and port.
So the same origin means the same protocol, domain, and port.
For document objects or DOM in a browser, the same origin policy says that origin A can access origin B's DOM if A and B have the same origin.
Meaning that they have the same protocol, domain, and port.
For cookies we say two cookies have the same origin if they have the same domain and path.
The protocol is optional.
We're going to discuss in more detail the same origin policy for cookies later.
### Frame Security
Frame and iFrame are like many browser windows.
A frame is typically rigid or fixed on a page, whereas iFrame can be floating.
Here's an example of iFrame.
It essentially says that here is the width and height of the frame window and it will display this page.
So why do we discuss frames in a context of web security?
Or in more general, why do we even use frames?
As the previous simple example shows, we can display a webpage within a frame, or a minute browser window.
So, from this example, it is obvious that frames provide a natural isolation of separation of different web contents.
For example, we can delegate screen area to content from another source.
And a browser provides isolation based on frames.
And, even if a frame is broken, the parent window can still work.
Again, to display web contents from two different sides, A and B, we can have two different browser windows, such as what we see here, A and B.
On the other hand, we can achieve the same result by having just one browser window, let's say B here on the right-hand side.
And within it, we have a frame that display contents from A.
The point is that we should be able to achieve the same kind of isolation whether we use two different browser windows or use a frame within a window.
Again, we apply the same origin policy to achieve frame security.
Specifically, each frame of a page has an origin, that's defined as protocol, host, and port.
A frame can access only the data from its own origin.
That is, a frame cannot access data associated with a different origin.
Therefore, for example, even though we have a frame within a browser window and they display contents from different sites, for example, A and B.
The same-origin policy guarantees that these two sessions, the frame and the browser window, they don't interfere with each other.
So there was the default same origin policy.
In addition, frame-to-frame access control policy can also be specified.
For example, we can say canScript(A,B).
That means Frame A can execute a script that manipulates
DOM elements of Frame B.
We can use canNavigate to specify that
Frame A can change the origin of content for Frame B.
Likewise, we can specify policy for frame to access principle.
For example, we can use readCookie, writeCookie, to specify that can Frame A read/write cookies from a site.
You can read more about the web browser security mottos by following these links.
### Browsing Context
So far we have described the classic web browser security models.
To understand the more modern mechanisms, let's define browsing context.
A browsing context may be a frame with its DOM, that is a frame with web contents.
Or web worker, which does not have a DOM.
A web worker as defined by the World Wide Web Consortium or W3C and the Web Hypertext Application Technology
Working Group is a Javascript executed from HTML page that runs in the background independently of other user interface scripts that may also have been executed from the same HTML page.
In short, a web worker is a Javascript that runs in the background and it is independent of the user interface elements.
Now, every browsing context has an origin.
Again, an origin is determined by protocol, host, and port.
And as such, our browsing context is isolated from another context by the same-origin policy.
Different browsing contexts may communicate using postMessage.
And they can make network requests through XHR or tags.
XHR stands for XML HTTP Request.
It is an API available to Javascript.
Typically, XHR is used to send HTTP or
HTTPS requests to a web server.
And lo, the server responds data back into the script.
That is, a Javascript use XHR to request contents from a web server.
There are similarities between browsing context and process context.
An opening system uses separation and isolation to allow multiple execution context and provide local storage and communication services.
Similarly while a web browser provides common local storage it uses isolation and separation to provide security protection to the browsing contexts.
The modern browser mechanisms that can be used for security protection include
HTML5 iframe Sandbox.
Content security policy.
Cross Origin resource sharing.
And HTML Web Workers.
Sub Resource Integrity.
And we're going to discuss these mechanisms now.
As in operating systems, sandbox is very useful for browser security.
The idea is to restrict frame actions.
When we used a directive Sandbox for frame essentially we are insuring that the iframe has unique origin, cannot submit forms, and
APIs are disabled, and it can prevent contents from plugins.
On the other hand when we create iframe if we use Sandbox allow-scripts directive, then we only ensure that iframe has unique origin.
But we can allow the rest of the actions.
For example, here's a Twitter button in iframe.
In this example, there's no Sandbox related directive.
So this you can call it the classic iframe.
Now we can use a Sandbox directive here.
We specified the Sandbox directive.
But then we also specified that we will allow Javascripts and allow form submissions and so on.
This simple example shows that we can use the Sandbox directive associated with the iframe in order to specify the security policy that's appropriate.
Here are the list of Sandbox permissions that you can specify for iframe.
### Content Security Policy
Now let's discuss, content security policy, or CSP.
The goal of content security policy to prevent or at least limit the damage of Course side scripting.
Recall that we discussed course side scripting attacks in CS
6035: Introduction to
Information Security.
Essentially a course side scripting attack bypasses the same origin policy by tricking a site into delivering some malicious code along with the intended content.
For example, a website is setup to echo the user input as a web page back to a browser.
Such as echoing the user's name.
But if the user input contains malicious code, then the website will be sending malicious code to a web browser.
With CSP, the main idea is that a browser can be instructed to load resources only from a white-list.
CSP prohibits inline scripts embedded in script tags, inline event handlers,
JavaScript, and URLs, etc, and also disables JavaScript eval, new function and so on.
That means all the resources that a browser will load can be statically checked.
And again the resources are loaded only from a white list.
Since there are many different types of web contents, with CSP we can specify the white list for each type of web contents.
The sources of web contents can be specified and matched.
For example, they can be specified by scheme such as HTTPS or
HTTP, host name, then we match any origin on that host.
Or fully qualified URI such as https://example.com:443.
You can also specify how to match the sources listed on a white list, such as, wildcards accepted, none, or self, and so on.
You can even create exceptions or allow inline JavaScripts or allow eval functions.
### CSP Quiz
Now let's do a quiz on CSP.
Which of the following statements are true?
First, if you have third party forum software that has inline script,
CSP cannot be used.
Second, CSP will allow third party widgets, such as Google +1 button, to be embedded on your site.
Third, for a really secure site, start with allowing everything, then restrict once you know which sources will be used on your site.
### CSP Quiz Solution
The second statement is true because you can certainly list
Google + as a trusted source and list it in the white list.
For the first statement, if you use third party software that has inline script, you can still embed it on your site.
You can use script source and style source to allow inline script.
For the third statement, for really secure site, it is best to restrict everything.
Then once you know which sources will be used, add them to the whitelist.
### Web Worker
Now let's discuss Web Worker.
Web Workers were ultimately not intended for security, but they help improve security because they allow
JavaScript to run in isolated threads.
Here's an example of how do you create a Web Worker.
Again, it is loaded from JavaScript.
A Web Worker has the same origin as the frame that creates it, but the Web Worker has no DOM.
It can communicate using postMessage.
So here's a simple example.
The main thread, meaning the main iframe thread, creates a worker.
It then starts the worker thread by sending a message using postMessage.
And here the worker actually performs the work.
### Subresource Integrity
Now let's discuss SubResource Integrity.
Integrity is a very important security goal.
In the context of web browsing, many pages load scripts and styles from a wide variety of service and content delivery networks.
Given that contents can be from many different sources and content delivery networks, how do we ensure the integrity of the contents that we're loading?
For example, how do we protect against loading contents from a malicious server?
For example, the browser gets to the malicious server because of DNS poisoning and how do we ensure that contents that we load from a Content Delivery Network has not been modified, for example, on purpose by the CDN?
The main ideas that the author of the content specifies and makes available the hash of the contents.
And so when the browser loads the contents, it use the hash value to check integrity.
For example, the author of this stylesheet will specify the hash of the file.
Similarly, for JavaScript, the author can also specify its hash.
So basically, to use SubResource
Integrity, our website author who wishes to include a resource from a third party can specify a cryptographic hash of that resource in addition to the location of the resource.
Then when a browser fetches the resource, it can compare the hash provided by the website author with the has computed from the resource.
If the hashes don't match, the resource is discarded.
So, what happens when the integrity check fails?
By default, the browser can report the violation and simply does not render, or execute the resource.
Or if the directive simply says, report that means the browser will report the violation, but can still render or execute the resource.
### Cross Origin Resource Sharing
Now, let's discuss cross origin resource sharing.
We've been discussing the same origin policy, which means that cross origin reading and writing is typically not allowed.
Now, what happens when a website has multiple domains?
For example, Amazon, the company has both the amazon.com and aws.co websites.
These two domains belong to the same company, so we expect that they should be able to share some resources.
Now of course, we want the same origin policy, so that another analytic website cannot easily access resource from Amazon.
Cross Origin Resource Sharing is a technique that we can use to relax the same-origin policy, so that JavaScript on a web page such as on amazon.com now can consume content from different origin.
Let say, aws.com.
It basically uses wireless.
For example, amazon.com can list the domains that it allowed.
Here's how
Cross Origin Resource Sharing works.
The browser sends the options request to the origin HTTP header.
The value of this header is the domain that served the parent page.
For example, when a page from amazon.com attempts to access a users data in aws.com, the following request header will be sent to aws.com.
That is it specifies origin https://amazon.com.
The server can inspect the Origin header and respond whether the access is allowed or not.
For example, the server can send back an error page, if the server does not allowed the cross origin request or it can specify which origin is allowed to access.
For example, in this case, the origin https://amazon.com is allowed or it can use a roll call to say that all domains are allowed.
### CORS Quiz
Now, let's do a quiz.
Select all statements that are true.
First, cross-origin resource sharing allows cross-domain communication from the browser.
Second, it requires coordination between the server and client.
Third, it is not widely supported by browsers.
Fourth, the header can be used to secure resources on a website.
### CORS Quiz Solution
The first two are true.
The first statement is false because it is not widely supported by many browsers.
The fourth is also false because the cross-origin resource sharing header cannot be used as a substitute for sound security.
### SOP Quiz
As a quick review let's do a quiz.
Recall that a same-origin policy requires that requests to access data must be from the same origin.
But what is the definition of an origin?
### SOP Quiz Solution
An origin is the combination of a URI which stands for
UniformResource Identifier scheme, such as HTTP or
HTTPS, and hostname, and port number.
Here are some examples of URI references.
### SOP Review
Let's continue with a review of Same Origin Policy.
We have discussed the Same Origin Policy for
DOM, which stand for
Document Object Model.
The Same Origin Policy for
DOM says that origin A can access origin
B's DOM if A and B have the same protocol, domain and port.
In this lesson, we are going to discuss the Same Origin Policy for cookies.
Here, origin is determined by the combination of scheme, domain, and path, and scheme can be optional
### SOP and Cookies
We call that when a browser connects to a site, the server sets the cookie for the web browsing session.
There are a number of attributes that a server can set for a cookie.
For example SameSite means that do not send cookie on a cross-site post request.
Strict, means that never send cookie on cross-site request.
Therefore, they provide some sort of cross-site request forgery defense.
With HttpOnly, it tells the browser that this particular cookie should only be assessed by the server.
Any attempt to assess the cookie from script is strictly forbidden.
This can provide defense against cross-site scripting attacks.
And the scope of the cookie is determined by the combination of domain and path.
### Setting and Deleting Cookies
In a domain is any domain-suffix of a URL-hostname, except the top level domain.
For example, the web server login.site.com can set cookies for all of site.com.
Because site.com is a suffix, but not another site or the TLD, which is .com.
Using this rule the cookies is set by login.site.com have these allowed domains, login.site.com and site.com.
And these domains are not allowed because they are other domains or the TLD, .com.
And path can be set to anything within that domain.
How are domains identified?
They are identified by name, domain, and path.
Here we have two cookies.
Both cookies store in browser's cookie jar.
And both are in scope of login.site.com, but they're distinct.
What are the policies for a server to read cookies?
In other words, the reading same origin policy.
The browser sends all cookies in URL scope, which is determined by domain and path.
And the goal is that server should only see cookies in its own scope.
Here's an example.
We have two cookies, both set by login.site.com.
The different servers see different cookies depending on their scopes.
For example the server http://checkout.site.com only sees Cookie2 because it's within the scope of site.com.
Another example, http://login.site.com, again, only sees Cookie2.
And the reason is Cookie1 requires secure which means that the connection has to be HTTPS.
The third example here, https://login.site.com, it can use both Cookie1 and Cookie2.
What are the rules for client-side read/write of cookies?
A JavaScript can set cookie values.
It can also read out the attributes of a cookie.
It can even delete a cookie.
The exception is that if the cookie is set as HTTP only, that means it cannot be accessed by client-side scripts.
Which means client-side scripts cannot read or write this HttpOnly cookie.
### SOP Security Quiz
Now let's do a quiz on the same origin policy.
Given this website, for the requests that are submitted from the following
URLs, which of these URLs will result in a successful request, and which will be rejected as not being from the same origin?
Determine the outcome, success or failure, for each URL.
### SOP Security Quiz Solution
The first three are allowed because they have the same protocol, host and port.
The fourth has a different port, port 81, so it's not in the same origin.
The fifth has a different host and the sixth has a different protocol.
### Cookie Quiz
For the following cookies, determine whether they are session cookie, persistent cookie, secure cookie,
HttpOnly cookie, SameSite cookie,
Third-party cookie,
Super cookie, or Zombie cookie.
### Cookie Quiz Solution
In particular, a cookie that can only be sent in requests originating from the same origin as the target domain is a SameSite cookie.
Again, this can be used to defend against cross-site request forgery.
And a cookie that cannot be accessed by client-side APIs is the HTTPOnly cookie.
It can be used to defend against cross-site scripting attacks.
### Cookie Protocol Problem
Now let's discuss some security problems with cookies.
First of all, the server is blind and what do we do mean by that?
It does not see all the cookie attributes.
For example, whether the cookie attributes include secure, which means Https only, or has the attribute HttpOnly.
When a server receives a cookie, it does not see which domain sent the cookie.
Actually, all the server sees is some selected attributes sent by the browser.
This problem can be exploited by attackers.
For example, say Alice wants to submit her homework.
She logs in login.site.com and login.site.com sets the session-id cookie for site.com.
And then, Alice decides to take a break and unknowingly visits a malicious site.
For example, because of a phishing attack.
And evil.site.com can override the .site.com session-id cookie with a session-id of user Badguy.
Then Alice returns to the homework site ready to turn in her homework.
Of course.site.com thinks that it is talking to the badguy because the session-id has been overwritten.
The problem is that course.site.com expects session-id cookie that was set by login.site.com.
It cannot tell that the session-id cookie was overwritten.
Here's another example of cookie security problems.
Suppose Alice logs in https://accounts.google.com, meaning that she logs in into her Google account.
And accounts.google.com will set the cookie.
In particular, it also says that this cookie is Secure, meaning that it should be used for
HTTPS.
Now suppose that due to some phishing attack, Alice visits the create text site, http://www.google.com and because this is a clear text protocol, a network attacker can intercept the traffic and override the cookie attributes.
And the result is that this overwritten cookie can be used for a HTTPS session.
As we can see, a network attacker can intercept and rewrite HTTPS cookies, which means that even a HTTPS cookie, its values cannot be trusted.
We have not talked about the path of a cookie.
The path separation is done only for efficiency, not for security.
For example, x.com/A would tell that if a server only needs to access this path, that only this cookie's needed.
Recall that the scope of a cookie is determined by domain and path.
Which means that x.com/A does not see cookies of x.com/B because they are different paths.
That is, they're in different scopes.
However, this is not a strong security measure.
Because x.com/A still has access to the
DOM, meaning the document object model of x.com/B, because they are the same origin as far as DOM is concerned.
For example, x.com/A can use the following to print out or read the cookie of x.com/B.
Another security problem of cookies is that cookies have no integrity.
For example, a user can change or even delete cookie values.
For example, there are tools that a user can use to change or delete cookie values.
For example, a user can change the shopping cart cookie and change the total dollar amount from $150 to $15.
Similarly, if the website had used a hidden field in the webpage to record the value, a user can still edit the source of the page and change the value.
### Cryptographic Checksums
Obviously, we can use cryptography to provide data integrity protection.
The main idea is that when a server sets a cookie attribute, it will attach a integrity check value for the attribute, and it can later on check whether that attribute has been modified.
So to do this, the server uses a secret key that is unknown to the browser, and for each attribute value that is set, it computes a integrity check.
The courier tag T, that essentially is a message authentication code, using the secret key k, and compute over the session ID the name and value of the attribute.
And when it sets the cookie, we attach the message authentication code to each attribute value.
When a browser, later on, presents the cookie to a server, the server can then check the integrity of that cookie attribute value.
The server essentially uses the secret key and compute over the session ID, name and value of the cookie attribute, and then verify that the result is the same as T.
Again, because T is computed using the secret key, the browser cannot compute it.
So that is, only the server can compute T, and the server can use T to verify that the attribute value of the cookie is not changed.
Here's a example of how this can be done in the real world.
So a server key can be generated and the integrity of a cookie can be protected using this key.
Similarly, integrity can be tracked.
Here, are the example
APIs that you can use to provide cookie integrity protection.
### Checksum Quiz
Now let's do a quick review quiz on cryptographic checksum.
Check all the statements that are true.
First, cryptographic hash functions that are not one-way are vulnerable to preimage attacks.
Second, a difficult hash function is one that takes a long time to calculate.
Third, a good cryptographic hash function should employ an avalanching effect.
### Checksum Quiz Solution
The first and third statements are true.
The second statement is false.
A difficult hash function should be very hard for the attackers to analyze.
But we want all the hash function to be efficient to calculate

---
&nbsp; \pagebreak
## Data-Poisoning-And-Model-Evasion


---
&nbsp; \pagebreak
## Mobile-Malware

### Introduction
In the last lesson, we learned about our enemies through their work, meaning we discussed malware analysis.
We're now going to look at malware analysis for mobile devices.
We have separated malware analysis into two lessons for two reasons.
It's a large topic and mobile devices have some special considerations with regards to malware.
### Mobile Device Quiz
We are going to spend this lesson discussing mobile malware or malware on mobile devices.
So let's take a moment to make sure that we all agree as to what we mean when we say mobile device.
According to Wikipedia, which of these devices is a mobile device?
### Mobile Device Quiz Solution
Wikipedia says that a mobile device must be mobile.
Therefore, a smartphone by itself is not mobile.
However, a smarthone held by a person can be mobile because it is a non mobile device with a mobile host.
These are examples of true mobile devices because either myself can be mobile.
We are not going to use the strict definition of mobile device.
Instead, we're going to use this common definition.
That is a smartphone is a mobile device.
### Forensics Quiz
Before we discuss mobile malware, we should understand the difference between mobile devices and the traditional stationary computers.
Which of the following characteristics are associated with mobile devices versus stationary computers?
### Forensics Quiz Solution
Mobile devices tend to use specialized hardware.
Whereas stationary computers tend to use standardized hardware.
Mobile devices tend to use many different versions of operating systems.
For example, there are many different versions of Android.
Whereas stationary computers tend to run Windows, MAC OS or Linux.
They also have large storage capacity.
On the other hand, mobile devices tend to have a large number of accessories such as cameras and GPS.
### Malware Trends
Since mobile devices are increasingly used for critical functions in our daily lives, and they have become powerful computers with good connectivity, they have become security targets.
This part shows the major categories of mobile malware.
### iOS Malware
Some apps may appear to be providing useful functions but they secretly still uses confidential information.
These apps are considered malware.
Here's an example of such malicious apps and it was taken off the app store.
But malicious apps may still get on victims devices even after it is taken off the app store.
One technique is to exploit the design floor in Apple's DRM scheme.
Apple allows users to purchase and download iOS apps from their app store through the iTunes client running on their computers.
They can then use their computers to install the apps onto their iOS devices.
The iOS devices will request an authorization code for each app installed to prove the app was actually purchased.
In a FairPlay man in the middle attack, attackers purchase an app from the app store, then intercept and save the authorization code.
They then develop a program that simulates the iTunes software, and installs the software on a victim's computer.
And this fake iTunes software can check the victim's iOS devices to believe the app was purchased by the victim.
Therefor the user can install apps they never actually paid for, and the attacker can install malicious apps without the user's knowledge.
This attack continues to work even after the malicious app is removed from the app store.
### Android Malware
There is a large increase of the number of Android malware and the majority is still SMS Trojans.
You can read more about current
Android malware at the link in the instructor's notes.
We discuss a few here.
AccuTrack turns an Android smartphone into a GPS tracker.
Ackposts steals contact information.
Acknetdoor opens a backdoor.
Steek does fraudulent advertising and also steals private information.
Tapsnake posts the phone's current location to a web service.
ZertSecurity steals the user's bank account information.
Similarly, Zitmo also steals the user's bank account information.
And there are many other more.
Again, you can read more about the current Android malware at the link in the instructor's notes.
This plot summarizes the major categories of Android malware and their trends.
There are quite a few free Android antivirus apps, here are a few examples.
The security companies own statements provide some insights of the state of anti malware on mobile phones.
First of all, the risk is relatively low.
In general, mobile devices are still less powerful than desktops and laptops and there are plenty of those that can be targeted by hackers.
Furthermore, the [INAUDIBLE] process and the sandbox space execution model also means that the mobile devices are in general more secure.
Nevertheless, there is still the need to protect mobile devices.
In particular, in addition to protection against malware, a bigger problem is the loss of devices and the loss or the theft of data.
And therefore secure companies also try to protect and manage mobile data.
Mobile malware are becoming more sophisticated and are showing the same advanced features of malware and laptops and desktops.
Here's an example of Android malware that uses social engineering to spread.
It targets a group of activists.
On March 24, 2013, the email account of a high-profile
Tibetan activist was hacked and it was used to send spear phishing emails to people on his contact lists.
This is what the spear phishing email looked like.
The recipient of this email is tricked that he should install this APK file on his Android device which is the malware.
After installation, an application named
Conference appears on the desktop.
After the installation, if the user launches this Conference app, he will be seeing the information about the upcoming event.
While the victim reads this fake message, the malware secretly reports the infection to a command control server.
After that, it begins to harvest information stored on a device.
The stolen data includes contacts, call logs, SMS messages, your location and phone data, which includes phone number,
OS version, phone model, etc.
Know that the stolen data won't be uploaded to the command control center automatically.
The malware waits for incoming SMS messages from the command control center.
And based on the message, the malware knows what data to upload.
### Lifetime of iOS Malware
Now let's review iOS Malware, in particular the lifetime or stages of an iOS malware and how the functions of each stage can be realized.
These stages include produce, distribute, do evil and make profit.
And there are multiple approaches to go about at each stage.
### Toolchain Attacks
Toolchain attack is one approach to produce malware.
Here's a real example, an official distribution of Xcode was compromised with malware.
If a developer used this infected
Xcode library to develop an app, the app will be infected.
The infected app will then collect information on devices and upload the data to a C&C server.
This attack is very potent, because any app that is compiled using this Xcode library now becomes a malicious app.
This XcodeGhost was able to infect many apps, including 39 apps published in the official iOS App Store.
Attacking the App Store review process is one approach to distribute malware.
Here's an example.
We created the Jekyll app in 2013, we planted vulnerability in this app, this vulnerabilities can be exploited at run time with a particular input.
Once the vulnerabilities is exploited the Jekyll app can activate new addition execution path through
Return-Oriented Programming.
And then the app can send SMS, email, tweet, and so on.
On the other hand the App Store review process cannot find these malicious paths, because they cannot review without a correct input and runtime.
To illustrate, the App Store review process finds that the control flow of the app to be safe, that is all the exclusion paths are acceptable.
On the other hand a run time minimal ability planted in the code is exploited, because of the specific input that a new control flows that were not observable in the app view process.
These new control flows allow the Jekyll app to do evil and make profit.
For example, it can do a number of activities.
These can be achieved by calling private
APIs that are not directly accessible to legitimate apps.
But a Jekyll app knows the memory layout and hence the addresses of these APIs and can directly jump to them.
### Toolchain Attacks Quiz
You can read more about the XCodeGhost attack with the link in the instructor's note.
Then you can answer the question, what kind of information can an infected app obtain from the device?
### Toolchain Attacks Quiz Solution
There is quite a bit of information that can be gathered by the infected app.
Information can then be used to craft further attacks, or it can be used to steal passwords and user names.
### Hardening the ToolChain Quiz
We now know that toolchain have occurred and will continue.
So, the question is, can you hold on the toolchain?
In this quiz, list the four areas of the C based toolchain where hardening can occur.
### Hardening the ToolChain Quiz Solution
Essentially, all the main steps of the toolchain can be hardened.
### Mobile Malware Protection
Let's discuss a few approaches to mobile malware detection.
Please check the instructors notes for links to these papers.
Kirin is a very simple system that looks for suspicious combination of permissions.
RiskRanker use heuristics such as cryptos that relates to unpacking code.
Similarly, DroidRanger use heuristics such as loading native code from suspicious websites.
DREBEN uses a machine learning algorithm called SVM, or Support Vector Machine.
And the data attributes used for modeling include permissions,
API calls, and so on.
Many malicious apps are actually repackaged version of legitimate apps.
This is actually the most effective way to distribute malware, because a popular or cool app already has a large number of users.
There are research systems on clone detection.
Here are a few examples.
For example, DroidMOSS use fuzzy hashing of Java methods to match and detect clone code.
DNADroid performs similarity analysis on PDGs.
PDGs are program dependency graphs between methods.
There are a few sandboxes for mobile malware analysis.
And these sandboxes enable dynamic analysis.
Here are a few example sandboxes.
Many dynamic analysis and detection tools use system call information.
Here are a few examples.
For example, PREC stands for particle root explore containment.
It can dynamically identify system calls from high risk components, for example, third party native libraries.
And execute those system calls within isolated threads.
Therefore, PREC can detect and stop root exploits with high accuracy, while imposing very low interference to benign applications.
### Information Leakage Protection
Information leakage is a big concern, and apps that leak sensitive information can often be considered malware even though many think that they are in a gray area.
There are several approaches to detect leakage, for example,
PiOS performs static analysis to detect information leakage.
TaintDroid uses taint tracking to perform information flow analysis.
That is, it analyzes how data from a source, such as address book, flows to the sync, such as the internet.
Another approach is to check if an app does what it promises to do, for example, WhyPer compares the app's permissions against its description.
And the analysis is based on natural language processing techniques.
### STAMP Admission System
Now let's discuss a research system designed to analyze mobile apps and decide if the mobile apps meet security and privacy requirements.
The system is intended to be used in an App Store to decide if an app should be admitted.
The system uses both static and dynamic analysis approaches because they have pros and cons of their own.
### Data Flow Analysis
One of the most important analysis is data flow analysis.
Here's an example of data flow, the source is location data and the sink is SMS or website on the internet.
Data flow analysis can be useful malware or greyware analysis to find out what information is being stolen.
And based on the discoveries, we can improve enterprise specific policies.
Data flow analysis can be used to check the external app to make sure that there's no API abuse or data theft.
Data flows gathered from an app can be used to inform users about potential privacy implications.
Data flow analysis can also be used to discover abilities in applications.
For example, accepting data from untrusted sources.
However, analyzing data flows is a very challenging task.
For example, Android has more than three million lines of very complex code.
Performing data analysis on whole system would take a long time, and it's not practical.
And of course to be useful, data flow analysis has to be accurate.
As we have just discussed, analyzing a app in a context of full Android is very expensive because there is too much code involved.
The STAMP approach is to abstract the Android stack into models.
And these models include the following information.
We are going to focus on data flows.
### Data Flows
There are more than 30 types of sources.
Here are some examples.
There are more than ten types of sinks, and here are some examples.
Each pair of source and sink is a flow type, and there are close to 400 flow types.
Here's an example of data flow analysis on the Facebook app.
The description of the app says that it allows the user to synchronize contacts.
And it says that Facebook does not allow the export of phone numbers or emails.
And the users can plug one or all apps but there's no privacy policy.
Here are the possible flows.
On the left, we have the sources.
On the right, we have the sinks.
That is potentially all resources can go to all the sinks.
>From the Facebook description, we expect to see the state of flow for sinking contacts.
However, the data flows observed from the Facebook app include additional flows that lead to leakage.

---
&nbsp; \pagebreak
## New-and-Alternative-Cryptocurrencies

### Introduction
Now that we know the basics of Bitcoin, let's move on to how Bitcoin operates.
Since this is network security course, we're going to focus on Bitcoin's vulnerabilities and how to hopefully mitigate them.
### Acknowledgements
Before I start, let me acknowledge that the initial slides were created by Joseph Bonneau,
Ed Felten, Arvind Narayanan, and Andrew Miller.
### Bitcoin Operations
Recall that in bitcoin.
A valid transaction has information store in the blockchain, but also the transactional information has to also be signed by the owner's secret signing key, or that's the private key of the public key pair.
Recall that in bitcoin, a transaction information is store in the blockchain and it also contains a signature signed by the owner's private key.
The owners need to keep their private key a secret.
So, this is about key management.
That is, how do you keep your private key secret and secure?
Of course, you can store your public key in a file on your computer or on your phone.
This is a very convenient approach.
On the other hand, if you're KeyStore is lost, that means your private key is lost, which means all your bitcoins are lost.
This is because without the private key, you cannot prove that you're the owner of the matching public key.
Remember, all your coins are associated with that public key.
That is, your public key is your ID or address in bitcoin.
But, you have to use the private key to prove that you're the owner of the public key or the ID.
Of course, your KeyStore can be compromised, which means your public key can be stolen, which means all the bitcoins can also be stolen because now the attacker can claim that he's the owner of that public key or the ID.
Therefore, he has all your bitcoins.
For example, the stolen private key, now the attacker can claim that he's the owner of the ID that the bitcoins are associated with.
He can then pay those bitcoins to another address that he owns.
That way, he can steal all the bitcoins.
### Bitcoin Wallet Quiz
Now, let's do a quiz on bitcoin wallet.
What is the defining characteristic of these bitcoin wallets?
### Bitcoin Wallet Quiz Solution
The so-called hot storage is online, and the so-called cold storage is offline.
Hot storage is online, for example, on your computer or on your phone.
It's very convenient, but it's not very secure.
On the other hand, cold storage is offline, not convenient, but it's safe.
The reason is obvious, if the storage is offline, then a cyber attacker cannot get to it easily.
In general, we can keep a top secret in a cold storage and put the most frequent used keys.
Here's another way to look at the difference between hot storage and cold storage.
We can put a top secret or the less frequently used master secret in a cold storage.
We can put the most frequently used keys in hot storage.
As we just discussed, storing your keys of Bitcoins on computers is storing them in a hot storage.
It is online, convenient, but somewhat risky.
On the other hand, you can put your keys of Bitcoins offline.
This is less convenient, but much safer.
You can have the best of both worlds by having both hot storage and cold storage.
For example, you can move coins back and forth, but then you need to use separate keys and each side needs to know each other's keys or the addresses.
You need to use separate keys because otherwise, the coins in cold storage will be vulnerable if the hot storage is compromised.
You need to use separate keys because otherwise, the coins in a cold storage will be vulnerable if the hot storage is compromised.
You will want to move the coins back and forth between the hot side and the cold side.
So, each side will need to note the others' addresses or public keys.
### Hierarchical Wallet
Suppose for privacy or other reasons, we won't to be able to receive each bitcoin at a separate address.
So, whenever we transfer coin from the hot side to the cold side, we would like to use a fresh cold edges for that purpose.
But, since the cold side is offline, how do the hot side find out those addresses?
The blunt solution is for the cold side to generate a big batch of addresses and send those over to the hot side.
The drawback is that the hot side need to reconnect with the cold side periodically in order to transfer more addresses.
A better solution is to use the so-called hierarchical wallet.
To review, previously we discussed key generation and digital signatures, and we looked at a function called generateKeys.
This function generates a public key which acts as an address and a secret or private key.
In a hierarchical wallet, key generation works in different way.
Instead of generating a single address, we generate what we called address generation information.
Rather than private key, we generate what we call private key generation information.
Given the address generation information, we can generate a sequence of addresses.
Likewise, we can generate a sequence of public keys using the private key generation information.
The cryptographic magic that makes this useful is that for every i, the ith address and the ith secret key match up.
That is, the ith secret or private key controls and can be used to spend bitcoins from the ith address.
That is, the ith private key is paired up with ith address.
In other words, we have a sequence of regular key pairs.
The other important cryptographic property here is security, that is, the address generation information here does not leak any information about the private keys.
On the other hand, not all digital signature schemes can be modified to support hierarchical key generation.
The good news is that the digital signature scheme used by bitcoin, elliptic curve, does support hierarchical key generation.
As a result, the cold side can generate as many keys as it wants and the hot side can generate the corresponding addresses.
To summarize, the cold side create and saves private key generation information and address generation information.
It has a one-time transfer of the address generation information to the hot side.
The hot side generates a new address sequentially every time it wants to send a coin to the cold side.
When a cold side reconnects, it generates addresses sequentially and checks the blockchain for transfers to these addresses.
It can also generate private keys sequentially if it wants to send some coins back to the hot side.
### Cold Storage
Now, the remaining question is, how do we keep the cold storage safe?
There are multiple options.
For example, a user can use his pass phrase to encrypt information.
We can even print information on a piece of paper, or we can use tamperproof device then use hardware to protect the keys.
### Cold Wallet Quiz
Now, let's do a quiz. Match the cold storage to its characteristic.
### Cold Wallet Quiz Solution
First, it can rot or lost, or be torn, or stolen.
That's paper storage.
Second. If make of magnesium, tin, lead, it can be destroyed by fire. That's coin.
Third. Multiple overwriting attempts are not enough to ensure that discarded computers cannot be hacked.
That's online cold storage.
Fourth. Data can be hard to recover if the storage device is old.
That's USB. Fifth. Can be damaged by magnets.
That's offline Bitcoin wallet.
### Online Wallets and Exchanges
Now, let's discuss bitcoin exchange.
Bitcoin exchange accepts deposits of Bitcoins and fiat currency.
For example, dollars, pounds, euros, and so on.
These exchanges let customers make and receive bitcoin payments, and buy and sell bitcoins using fiat currency.
You would typically match a bitcoin buyer with a bitcoin seller.
Of course, it promises to give the money back to the customer, therefore, bitcoin exchanges are similar to banks.
As a result, bitcoin exchanges need to meet a number of minimal requirements or expectations.
For example, bitcoin exchanges should meet the minimum reserve requirements, that means they must hold some fraction of deposits in reserve.
A Bitcoin exchange needs to provide a proof of reserve to give customers some comfort about the money that they have deposited.
The goal is for the exchange to prove that he has a fraction or reserve, for example, from 35 percent to even 100 percent of the deposits that people have made.
We can break the Proof of Reserve problem into two pieces.
The first is to prove how much reserve you are holding.
The exchange can simply publish a valid payment-to-self transaction of the claimed reserve amount.
That is, if he claims to have 100,000 bitcoins, it creates a transaction in which he pays 100,000 bitcoins to herself and show that the transaction is valid.
Strictly speaking, this is not a proof that the exchange really owns this amount, but only that whoever does own this amount is willing to support the exchange.
The second piece of the Proof of Reserve problem is to prove that how many demand deposits you hold.
We will discuss this next.
### Merkle Trees
The second piece of proval reserve is to prove how many demand deposits you hold, and here is a scheme.
Recall that a Merkle tree is a binary tree that is built with hash pointers, so that each of the pointers not only sets where we can get a piece of information, but also what a cryptographic hash of that information is.
A bitcoin exchange executes a prove of how many demand deposits it holds by constructing Merkle tree.
In this Merkle tree, each hash pointer also includes an attribute.
This attribute is a number that represents the total value in bitcoins of all of the deposits that are in a subtree underneath this hash pointer.
For this to be true, the attribute value of each hash pointer has to be the sum of the values of the two hash pointers beneath it.
A bitcoin exchange constructs this tree and size the root pointer along with the route attribute value and publishes it.
The root value is, of course.
The total liabilities. That is, by constructing this tree and publishing its root value, the exchange is making the claim that all users are represented in the leaves of the tree and that the deposit values are represented correctly.
Furthermore, the deposited values are propagated correctly up the tree, so that the root value is the sum of all the users' deposit amounts.
Now, each customer can go to the exchange and ask for proof of correct inclusion of his deposit.
The exchange must then show the customer the puzzle tree from the user's leaf up to the root.
The customers then verifies that first.
The root hash pointer and root value are the same as to what exchange has signed and published.
Second, the hashpointers are consistent all the way down.
That is, each hash value is indeed the cryptographic hash of the node it points to.
Third, the leaves contains correct use account information.
For example, user ID and the deposit amount.
Fourth, each value is the sum of the values of the two values beneath it.
The good news here is that if every customer does this, then every branch of the tree will get explored, and someone will verify that for every hash pointer, its associative value equals the sum of the values of its two children.
It's very important that the exchange cannot present different values in any part of the tree to different customers.
That's because doing so would either imply that the ability to find a hash collision or presenting different root values to different customers which we assume is not possible.
The customer then verifies that, first, the root hash pointer and root value are the same as what the exchange has signed and published.
Second, the hash pointer are consistent all the way down.
That is, each hash value is indeed the cryptographic hash of the node it points to.
Third, the leaf contains correct user account information.
For example, user ID and a deposit amount.
Fourth, each value is the sum of the values of the two values beneath it.
The good news is that if every customer does this, then every branch of the tree will get explored, and somehow we verified that for every hash pointer it's associative value equals the sum of the values of its two children.
It is very important to note that the change cannot present different values in any part of a tree to different customers because that will imply that either the exchange can find a hash collision, or it can present different root values to different customers, which we think is not possible.
### Proof of Reserve
Let's recap. To provide a proof of reserve, first, the exchange proves that they have at least X amount of reserve currency by doing a self transaction of X amount.
Then they prove that the customers have at most amount of Y deposited.
This shows that their reserve fraction is at least X divided by Y.
Notice that a bitcoin exchange can provide this proof, that is independently verifiable by anybody, and therefore, no central regulator is required.
### Anonymity
Now, let's discuss anonymity in Bitcoin.
Some, including WikiLeaks, claims that BitCoins provide anonymity.
Others, believe that Bitcoin does not provide anonymity.
So, what is anonymity?
Literally, anonymous means without a name.
Bitcoin, an ID is an address, which is the hash of a public key.
In computer science, we call this pseudonymity.
In computer science, an anonymity means pseudonymity plus unlinkability.
We know that Bitcoins provides pseudonymity.
Now, the question is does Bitcoin provide unlinkability.
That is, can we be sure that in Bitcoin, different transactions of the same users can be linked together.
More precisely, unlinkability in Bitcoin means that, it is also hard to link different transactions of the same user.
Furthermore, it should be hard to link the sender of a payment to its recipient.
### Bitcoin Anonymity Quiz
Let's do a quiz on bitcoin anonymity.
Check all the true statement.
### Bitcoin Anonymity Quiz Solution
First, a timestamping service prevents people from double-spending Bitcoins, this is true.
Second, each user has a single Bitcoin that is used in all transactions, this is obviously false.
Third, the expenditure of individual coins cannot be tracked, this is false because individual coins can be tracked by their chain of digital signatures.
### De Anonymize Bitcoin
We know that in Bitcoin, it is trivial to create a new address.
That is, all you need to do is to create a new public key public key pair and a hash of the public key becomes a new address.
That is, a single user can own many addresses or many IDs.
In fact, the best practice is to use a fresh new address for the recipient in any new transaction.
So, the question is, can the addresses and the transactions still be linked?
Let's consider an example.
Suppose Alice wants to buy a teapot from a store and a teapot cost eight Bitcoins.
Let's further assume that Alice has some Bitcoins in her different addresses.
In order to pay for this teapot,
Alice has to create a single transaction that includes input from two addresses.
But in doing so, Alice has revealed that these two addresses belong to the same user.
In other words, two previous transactions that use these two addresses as recipients must be to the same user.
This example that if you're sure to spending for multiple addresses, we're linking these addresses together.
This example shows that if multiple addresses are using the same spending transaction, that means that these addresses are under joint control.
In other words, we can link these addresses together.
Further, address linkability is tentative.
Furthermore, we can propagate such linkability.
Let's consider another example.
Suppose now, the price of the teapot has gone up from eight Bitcoins to 8.5 bitcoins.
So, Alice will create a transaction where she will transfer Bitcoins from two of her addresses to pay for the teapot and also send the change to her own address.
Therefore, Alice will create transaction where she transfers Bitcoins from two of her addresses but also send a change to one of her addresses as well.
So, Alice will create a transaction where she would transfer Bitcoins from two of her addresses to pay for a teapot but also send a change to another address of hers.
Now, let's consider the transaction from the viewpoint of an adversary.
He can deduce that these two input addresses belong to the same user.
The attacker might also suspect that one of these output addresses also belongs to the same user.
If the attacker knows that a teapot cost more than 0.5 Bitcoin, then he would know that this address also belong to the same user.
Therefore, in this example, the attacker can know that these three addresses belong to the same user.
We can only link or cast the addresses that belong to the same user.
We can also see if any of these addresses reveals the real identity of a real user.
For example, an address may be used in transaction through a provider that is legally required to know the true user behind the address or a user may have posted an address in a public forum.
For example, because he's making a donation.
### Decentralized Mixing
One mechanism to make transaction link analysis less effective, and let's protect unlinkability, is to use mixing.
The main proposal for decentralized mixing.
Since bitcoin is a decentralized system is called coinjoin.
In this protocol, different users joining, create a single bitcoin transaction that combines all the inputs.
Furthermore, in a transaction that has multiple inputs coming from different addresses, the signatures corresponding to each input are separate from and independent of each other.
This allows a group of users to mix their coins with a single transaction.
Each user supplies an input address and an output address and form a transaction with these addresses.
The order of input and output addresses is randomized, so that an outsider will be unable to determine the mapping between inputs and outputs.
All the participants check that it's outgoing address has been included in the transaction and that it receives the same amount of bitcoin that they are inputting.
Once they have confirmed this, they sign the transaction.
Somebody, say an attacker looking at this transaction on the blockchain, even if they know that it is a coinjoin transaction, would be unable to determine the mapping between the inputs and outputs.
From an outsider's perspective, the coins have been mixed and this is the essence of coinjoin.
Here's the procedure to create coinjoin.
First, a participant needs to find peers who want to mix.
Then, they exchange the input and output addresses to be included in the transaction.
Then, they construct the transaction by mixing the orders.
Then, the transaction is sent around and each peer can check that his or her input and output have been included.
Then, the signatures are collected in a transaction.
Finally, this coinjoin transaction is broadcast to the bitcoin system.
It is important for the participants to exchange these input and output addresses in such a way that even the other members of the peer group do not know the mapping between input and output addresses.
To exchange these addresses in unlinkable way, we need an anonymous communication protocol.
For example, we can use Tor or special purpose protocol.
For example, the peers can use Tor to exchange the input addresses.
Therefore, no one knows what input address each other is using.
Once that is accomplished, it is not necessary to communicate the output addresses in a secure way.
Once that is accomplished, there's no way to link an output address with an input address.
### Bitcoin Append Only Log
The Bitcoin system can be used for other applications.
For example, secure timestamping.
For example, we can prove knowledge of x or we know the value of x at a time t. But we can do so without revealing the actual value or knowledge of x at time t. Of course, if we choose to, we can review x at some later time.
Recall that hash function is a one-way function.
That is, if you publish the hash value of x, you're announcing a commitment to x.
Recall that a cryptographic hash function is a one-way function and also loses in to collision.
Therefore, if we publish the hash value of x, we essentially announcing the commitment to x.
In other words, everyone will know that we actually know the true value of x by publishing the hash value of x, and we don't have to reveal x to anyone.
In other words, we can later prove that we actually knew the value of x because we had published the hash value of x.
### Timestamping
Secure timestamping has many applications.
We have discussed proof of knowledge.
We can also use it as proof of receipt and so on.
As we have discussed, to make a commitment, we need to publish the hash value of the data.
The simplest solution in bitcoin system is that instead of sending money to the hash of a public key, just send it to the hash of your data, and then by announcing the transaction, you're announcing the hash of your data.
The caveat here is that the coin you sent can be lost forever because you don't know who actually happens to own the address that corresponds to the hash of your data.
This approach is indeed very simple, but we have to burn coins.
More importantly, the bitcoin miners don't know that the coin you send to this address is lost forever.
So, they must check it forever just like any other legitimate bitcoins.
A more sophisticated approach is called CommitCoin.
It allows you to encode your data into the private key.
Recall that elliptic curve public key is used in bitcoin.
Just like other public key systems, we need good randomness, otherwise the private key can be leaked.
A property of elliptic curve is that if you use bad randomness in making a signature, it will leak the private key.
CommitCoin exploits this property.
CommitCoin generates a new private key that encodes a commitment and derive its corresponding public key.
We can then send a tiny transaction to that address that corresponds to the public key and then the address also sends back another transaction and we use the same randomness in signing both of these transactions.
In CmomitCoin, we generate a new public key that encodes our commitment, and we derive its corresponding public key.
We then send a tiny transaction to the address that corresponds to the public key and we then send it back two chunks of bitcoins.
When doing so, we'll use the same randomness to sign both chunks in the transaction and when sending it back, we'll use the same randomness both times for signing the transaction.
This allows anyone looking at the blockchain to compute the public key using these two signatures and the private key contains the commitment.
CommitCoin avoids the need to burn coins and the miners don't have to keep track of unspendable output forever.
However, it is quite complex.
As of 2014, the preferred way to do bitcoin timestamping is with the OP_RETURN transaction.
The OP_RETURN instruction returns immediately with an error, so that this script can never be run successfully, and the data that is encoded in the transaction is ignored.
This can be used to encode arbitrary data.
As of 2015, OP_RETURN allows 80 bytes of data to be pushed, which is more than enough for a hash-function output.
For example, shot to 56, the output length is 32 bytes.
As of late 2014, there are already several websites that help with this.
They collect a bunch of commitments from different users and combine them into a large Merkle tree, then they publish one unspendable output containing the Merkle tree root.
This acts like a commitment for all the data that users wanted to timestamp that day.
### Overlay Currencies
Since we can write whatever data we want into Bitcoin, we can also view an entirely new currency system on top of Bitcoin, without needing to develop a new consensus mechanism.
That is, we can simply use Bitcoin as it exists today as an append-only log and write all the data that we need for our new currency system directly into the Bitcoin blockchain.
We call this approach an overlay currency.
That is, Bitcoin serves as the underlying substrate, and the data of the overlay currency is written into the Bitcoin blockchain using unspendable transaction outputs.
Of course, Bitcoin miners will not actually validate what you're writing into the blockchain because they don't know the new currency system.
Also, anyone can write anything as long as they're willing to pay the transaction fees.
Since this is a different new currency system, you must develop your own logic for validating transactions.
### Mastercoin
An example of overlay currency is Mastercoin.
In an overlay currency system, such as Mastercoin, there's no need to develop a new consensus algorithm and, therefore, developers can instead focus on developing interesting features, such as smart contracts.
On the other hand, such an approach can also be inefficient because those on the overlay currency may need to process a lot of data.
This is because bitcoin nodes don't filter these transactions for you.

---
&nbsp; \pagebreak
## Security-of-Internet-Protocols

### Introduction to Security Internet Protocols
Everything on the internet must use internet protocols to communicate.
In this lesson, we will discuss the weaknesses of these protocols and what can be done to improve security.
When we are done with this lesson, you should have a clear understanding of the security and abilities of TCP/IP.
### Internet Infrastructure
You can think of the Internet as a collection of large networks.
These large networks are typically managed by the Internet Service Providers, or the ISPs.
The ISPs work together to allow traffic to flow from one network to another.
So to the users, the Internet is just one big connected network.
Because a user can reach from his computer on one end of the Internet to another computer on the other end of the Internet.
The computers within a local area network use the local and inter-domain routing protocol to communicate with each other.
Computers from different networks, for example, from two different ISP networks, use TCP/IP protocol to communicate.
But in order to decide how to send traffic from host A to host B which may be in two separate ISP networks, there needs to be routing information which is decided by BGP which stands for border gateway protocol.
The domain name system is a distributed, hierarchical database system that provides the mapping between an IP address and a symbol domain name, such as www.cc.gatech.edu.
### Infrastructure Quiz
Now let's do a quiz on internet infrastructure.
Match the different levels of networks to its description.
### Infrastructure Quiz Solution
A Tier One network is one that can reach every other network through peering.
A Tier Two network is one that peers some of its network access and purchase some of its network access.
A Tier Three network is one that purchases all of the transit from other networks.
Just for your information, there are only 17 Tier One networks in the world.
### TCP Protocol Stack
Now let's take a look at
TCP IP network stack.
The Link Layer is a group of protocols that only operate on the length the host is physically connected to.
The network or internet layer is a group of protocols that are used to transport packets from one host to another and may cross network boundaries if necessary.
The Transport layer protocols provide, host to host communication services for applications.
They provide services such as connection oriented data stream support, reliability, flow control and multi tasking.
The Application layer protocols depend upon the underlying
Transport layer protocol to establish host to host data transfer channels.
And manage the data exchange in a client-server or peer-to-peer networking model.
When host A sends traffic data to host B, the data usually starts as Application message.
The Transport layer segments the data and puts TCP header onto the segments.
The IP layer then puts the IP header on these segments, and they become the IP packet.
The Link Layer puts a link header onto the IP packets, and this becomes frames.
And this Link Layer frame can then be sent to the link, connected to the host, such as the ethernet cable.
### Internet Protocol
At the IP layer, the IP Protocol routes packet from host a to host b approaching never boundaries if necessary.
The routing is connectionless because it is best effort only and unreliable.
Meaning that, it's not guaranteed that, all packets from host a will arrive at host b.
And of course, for each IP packet, the source IP address and the destination IP address must be specified.
The ports are not part of the IP header because they're for the transport layer.
Here's an example of IP routing.
Suppose, we have a packet with source and destination IP addresses.
Typically, a route will involve multiple hops.
An IP routing has no guarantee of the order or even delivery of the packets.
In this example, the packet starts from the source IP address reaches the gateway of its ISP, across network boundary to reach the gateway of the destination network and then finally reaches the destination IP address.
The summary from this example, the IP host knows how to reach the gateway and the gateway knows how to reach other networks.
If a data segment is too large, it may be fragmented into multiple IP packets.
At the receiving end, these fragments will be assembled back together.
If the destination did not receive a packet or fragment, you can send an ICMP packet to the source to report the error.
ICMP stands for
Internet Control Message Protocol.
The IP header can also include a TTL field.
TTL stands for Time to Live and this field is decremented after every hop and a packet is dropped if TTL reaches 0.
TTL is useful to prevent infinite loops.
### IP Quiz
Now let's do a quiz on the Internet Protocol.
Select all the true statements about Internet Protocol.
### IP Quiz Solution
The first statement, IP is a connectionless and reliable protocol.
This statement is false because
IP is not a reliable protocol.
The second statement,
IP provides only best effort delivery, it is not guaranteed.
This is true.
The third statement, due to the connectionless nature of IP, data corruption, packet loss, duplication, and out-of-order delivery can occur.
This is true.
### IP Authentication
Record it in the IP header, the source and destination IP addresses must be specified.
However, one can easily override the source IP address using raw sockets.
For example, you can use the Libnet library to format raw packets with arbitrary IP header information including the source IP address.
This means that there's no guarantee that the source ID address is authentic.
This means that anyone who owns the machine, and knows how to use a tool like dimnet, can send packets with arbitrarily sourced IP addresses.
Now of course, a response will be sent back to the forged source IP address.
For example, host A can send packets forging the source IP address of host B and then the response will be sent back to host B.
The ability to forge arbitrary source IP addresses enables anonymous denial-of-service attacks and anonymous infection and malware attacks.
### TCP
Now let's look at the transport layer protocols, in particular, the transmission control protocol or
TCP.
TCP is connection-oriented and it preserves the order of packets, we can use an analogy to explain TCP.
Suppose we want to mail a book, and the way we send the book is to mail each page in envelope.
And that's analogous to breaking application data into TCP packets.
And of course, for each page, there's a page number, so that we know the sequence of these pages in the original book.
Likewise, TCP packets have sequence numbers.
Now, when the pages arrive, they arrive in separate envelopes and may be out of order.
At the destination, we make sure that we receive all the pages, put them back in order and reassemble the book.
Similarly, at the definition host, each packet upon it's receipt, will be acknowledged.
And any lost packet will be notified so that the source can resend the packet and then the packet will be reassembled in the original order.
Now let's take a look at TCP Header, it includes the port numbers, the sequence number of the packet and acknowledgement number.
That is for acknowledging a previously received packet.
It also has a number of flux, these are used to control the TCP connection.
### Review TCP Handshake
Let's review how TCP Handshake works.
The client sends a SYN packet to server.
We randomly generated initial sequence number.
The server sends a SYN/ACK packet to the client.
It also has a randomly generated initial sequence number.
And also acknowledged the sequence number of the SYN packet from the client.
And then the client sends the ACK packet back to the server.
It also acknowledges the sequence number of the SYN/ACK packet from the server.
At this point the connection is established.
Once a connection is established both sides can expect that their next packet will have the sequence number that is increment from the previous packets.
Now of course packets can arrive out of order.
But one can expect that the sequence number should not be too far out of the current window.
Therefore, if packets arrives with a sequence number that's too far out of the current window it would be dropped.
### TCP Security Issues
Now let's review some of the security problems associated with TCP.
Eavesdropping is always a big concern.
And this is quite easy for the attacker, if he can control your router or the Wi-Fi access points.
And such a hijacking is possible if the attacker can learn the TCP state.
And as discussed in our DDoS lesson, TCP is subject to denial service attacks.
### TCP IP Security Issues Quiz
Now let's do a quiz on the security of TCP IP.
Select all the true statements.
### TCP IP Security Issues Quiz Solution
The first statement, application layer controls can protect application data, and IP addresses, this statement is false.
IP addresses exist in a lower layer, and so application layer controls cannot protect IP addresses.
The second statement,
IP information cannot be protect by transport layer controls, this is true.
The third statement, network layer controls can protect the data within the packets as well as the IP information for each packet.
This statement's true, because that is what network layer controls are supposed to do.
The fourth statement, data link layer controls can protect connections comprised of multiple links.
This is false, they cannot protect connections with multiple links.
### Random Initial Sequence Numbers
We call that in TCP handshake, the first packet from the client and the first packet from the server have the sequence numbers randomly generated.
This is very important.
Suppose, these initial sequence numbers are predictable.
Then the attacker can forge a source ID address and still be able to finish the TCP handshake and establish a TCP session.
And this will break IP-based authentication such as SPF, which is Sender Policy Framework that is used to authenticate email.
We can use an example to illustrate the importance of having random initial sequence numbers.
Suppose there's an attacker and he wants to forge the source IP address of the victim to create a TCP session.
So the attacker sends the initial
SYN packet to the server and forge the source IP address to be from the victim.
Now the server is going to send a SYN/ACK packet to the victim with its own sequence number.
Of course, the attacker did not receive the SYN/ACK packet because the SYN/ACK packet is sent to the victim.
Now if this sequence number is predictable, then the attacker can still send ACK packet to ACK this SYN packet as if that the attacker had received the SYN/ACK packet.
And when a server receives this
ACK packet on its SYN/ACK packet, then the server knows that the connection should be established.
>From this point on, the attacker can send command through the server and the server will think that the command is from its victim.
Because the victim and the server hasn't established TCP connection.
Here's an example of attacks on predictable sequence numbers, suppose the attacker can correctly guess the sequence number.
He can then send a reset packet.
This will terminate a connection and result in the null service attack.
### Protocols Quiz
Before we begin our discussion on routing security, let's do a quiz to refresh our knowledge of routing protocols.
Match the protocol with its description.
### Protocols Quiz Solution
Address Resolution Protocol or ARP is a protocol designed to map IP network addresses to the hardware addresses used by the data link protocol.
Open Shortest Path First or
OSPF is a protocol that uses a link state routing algorithm for interior routing.
Border Gateway Protocol or
BGP is a protocol designed to exchange routing and reachability information among autonomous systems or AS.
Here's an example of how op works.
Supposed a router received data with a destination IP address of a host within each local area network.
It needs to know the MAC address or the destination IP address in order to send the data to the host.
This is because machines on the same local area network identify each other via MAC addresses.
Here, the router sends an OP request asking for the MAC address of the specified IP address.
This request will reach all computers on a network because the destination MAC address is one there's accepted by all computers.
The ARP reply essentially says, hey,
I'm the host with the IP address and here's my MAC address.
On OSPF looks for the lowest cost path within nodes.
In this instance, let's assume that all the lengths are of the same cost.
What would be the shortest path between the node R3 and R5?
Obviously, the shortest path is to go from R3 to R4 and then, to R5.
In BPG, the autonomous systems exchange information through peer exchanges.
In this example, each AS talks to a peer to learn the address prefix of the computers within their peer network.
This helps the ASs to work together to determine how to route traffic from one network to the other.
### Routing Security
Again, from the perspective of routing, the Internet is a collection of domains or autonomous systems.
An autonomous system is a connected group of computers where their
IP addresses share some common prefixes, and they're using a single or common routing policy.
The routing between these domains is determined by BGP.
And the routing within each domain is determined by protocols such as OSPF.
Now let's discuss the security of routing protocols.
Recall that the ARP protocol maps IP address to MAC address.
Now, suppose there's an ARP request asking for the MAC address for node B's IP address.
This ARP request is broadcasted to the whole network.
Now if node A is malicious, it can send ARP reply to the gateway with its own Mac address.
If this reply arrives at the gateway before the reply of node B does, then the gateway will think that node A is node B.
Which means that node A now is right in the middle, and you can read or inject packets into node B sessions.
The Border Gateway Protocol, or BGP, decides the routing policy between autonomous systems.
However, in BGP routing information, and in particular route updates, are not authenticated.
Therefore, through a false advertisement, an attacker can cause traffic to a victim host to instead route to the attacker's own address.
There are plenty of examples illustrating the danger of false route advertisement.
Essentially, anyone can hijack route to victim
### BGP
Let's illustrate how BGP works.
Here, the nodes are the autonomous systems.
And the edges represent peering relations.
Here, nod 2 provides transit to node 7, and this information is propagated, so all autonomous systems know how to reach node 7.
The main security issues of BGP are due to the fact that BGP path information is not authenticated which means that anyone can inject false advertisements and such advertisements will be propagated everywhere.
As a result, attackers can shape and route traffic to launch denial of service attacks, send spams and perform eavesdroppings.
Here's an example of BGP path hijacking.
Here's a normal or legitimate path.
And then, there was path hijacking event in February 2013.
In this attack, only the path of this direction is changed.
The other direction is not changed.
Therefore, if you are in DC, because this direction is not changed, you cannot tell by doing traceroute.
### BGP Attacks Quiz
Now, let's do a quiz on BGP attacks.
Match the attack to its characteristics.
### BGP Attacks Quiz Solution
Denial of service attack.
The attacker hacks the routing table and either adds a false route or kills a legitimate one.
Sniffing.
An attacker needs to control a device along the communication route.
To do this, the attacker can BGP to detour traffic through a malicious site.
Routing to endpoints in malicious networks.
This requires that the attacker redirect traffic away from a legitimate host to an attacker-controlled site.
Creating route instabilities.
This has not been exploited by attackers yet.
These instabilities are too unpredictable and can cause attacker to be affected by their own attack.
However, there is a possibility that script kiddies could begin to exploit them.
Revelation of network topologies.
This begins with attacker gaining access to the routing table and can, with patience, discover the peer relations among the ASs.
Now let's discuss some solutions to the BGP security issues.
One solution is around PKI, or Public Key Infrastructure.
Here, each AS obtains a certificate to certify each route origination authority from the regional Internet register, and then attach the ROA to path advertisement.
Essentially, each AS that advertise a path is a route origination authority.
Another solution is to use SBGP.
The main idea here is to sign every hop of a path advertisement.
### S BGP
Let's discuss S-BGP in more detail.
The users IPsec to protect the point-to-point router communication.
It also assumes PKI.
The reason is that it uses public key cotography to provide attestations.
In particular address attestation proves the authorization to advertise certain address blocks.
And route attestations proves the validation of the route update information.
And of course S-BGP requires repositories and tools to manage certificates.
The certificate's revocation lists and the address attestations.
Here's an example of address blocks advertised by autonomous system nodes seven.
That is as the routing information is being publicated. all the nodes need to know that nodes seven is responsible for these addresses.
Now let's discuss attestation in more detail.
In address attestation, the issuer is the organization that owns the address prefixes contained in the attestation and the subject is one or more ASS that are authorized to advertise these prefixes.
For example, this ASS are the organization's internet service providers.
In other words, an AS such as an ASP has to be authorized by the owner of the address blocks to advertise the route to these address blocks.
An address at the station includes the following information.
Essentially it certifies that the owner owns the address blocks and the owner authorizes the AS to advertise for this address blocks.
The owner uses his private key to sign the address blocks.
Address attestation is used to protect BGP from incorrect updates.
The second type of attestation is route attestation.
Here the issuer or the speaker is an AS and the subject or the listener is a transit AS.
Basically, route attestation allows
BGP speaker that receives a route advertisement to verify that each AS along the route has been authorized by the preceding AS along the path to advertise that route.
And that the originating AS has been authorized by the owner of each IP address prefix contained in the update to advertise these prefixes.
Route Attestation includes the following information.
The speakers certificate, the address block and the list of AS's, the neighbor, and the expiration date.
The signature guarantees that the organization owning the IP address space advertised in the update was allocated that address space through a chain of delegation originating at the eye can.
And this can protect BGP from incorrect updates.
In order to validate a route, an AS needs to perform address attestation for each organization owning the address block.
And also, route attestation for each AS along the path.
And of course, all the certificates must be available, and they must be valid.

---
&nbsp; \pagebreak
