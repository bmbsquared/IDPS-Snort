# IDPS-Snort
Term Project- Spring 2023
Content Filtering 
B. Bernard
Dr. Islam 
CS380: Intrusion Detection and Prevention
Final Essay 

Computer security is a fundamental part of any device or network to keep data safe and protect the integrity of the system or network.  By keeping track of what packets are flowing through a network through packet sniffing and content filtering system admins are able to monitor and maintain security protocols and enhance network performance. Also by restricting access to potential malicious web content system admins are able to protect the network as well as keep track of those trying to bypass security protocols. 


Content filtering is a set of security protocols to monitor and restrict access to certain web content deemed malicious or inappropriate by system admins. Content filters are often built into a computer or network’s firewall and can be hardware or software based. Hardware based content filtering can include an external firewall, reverse proxy appliance, or an all encompassing unified threat management appliance. There are also a number of software based content filtering solutions. One popular and user-friendly content filter is parental control softwares that allows parents to monitor their children’s internet usage. Parental users are able to configure a customized set of rules to limit  their children’s internet usage and if content that is deemed restricted in the configuration is attempted to be accessed, parent devices will be alerted. There is also DNS based filtering where traffic to a restricted  DNS request will be intercepted and redirected to a block page. This type of filtering can be used to restrict access to specific categories of content such as gambling or pornographic content. 

   Content can be blocked for a number of different reasons. In the case of a home network, users might add content filtering to prevent children from accessing inappropriate web content. While in a business or organization setting, adding content filters can improve the security of a system following the separation of duties protocol in which no user should be given enough privileges to be able to misuse the system network. Content filtering in industries is often used to comply with industry standards  by preventing access to content that is prohibited by laws or regulations.  Content filtering works by establishing rules and security protocols to monitor and limit web traffic.


 Along with limiting access to certain content deemed inappropriate, content filtering can be used to protect and enhance a network’s security capabilities. Limiting access to content for users allows system admins to protect the network from potentially malicious or insecure web pages and content. It can block malware by analyzing network traffic for signature based malware stored in a database within the content filter. When the known malware signature is detected by the content filter or firewall, access to that content is blocked to minimize the threat of damage to a system. Content filtering can also be used to enhance a network’s performance capabilities in ways such as bandwidth management to reduce latency. By prioritizing traffic that is deemed business critical and blocking traffic that is malicious or unimportant to the functionality of network system administrators can reduce network congestion.  This is to ensure that network resources and connection are used efficiently. Content filtering can also indirectly  reduce latency by blocking traffic to sites known to have high volumes of delays. By blocking these sites through content filtering system administrators are reducing the amount of data transmitted to bandwidth intensive content that would slow down the network. Adding content filtering into a network can enhance the security and performance of the network. Content filtering can also help networks stay compliant with regulations in an industry as well as protecting sensitive information that may be stored in the network. 


There are multiple software providers that have interfaces for content filtering. One popular service is Cisco Umbrella. Cisco Umbrella is “a cloud security platform that provides an additional line of defense against malicious software and threats on the internet by using threat intelligence.” The service is connected to University of Rhode Island’s DNS server which forwards all external TCP requests to the Cisco Umbrella cloud to determine if the website is safe. Users who reach out to sites deemed malicious will be blocked and receive a security notification. Cisco Umbrella’s DNS security helps protect systems against “adware, malware, botnets, phishing attacks, and other known bad websites” by blocking users from known malicious websites. Barracuda Networks also provides a content filter service and is often put in place in businesses and schools. The Barracuda Web Security Gateway provides an interface where system administrators can enforce policies of an organization by blocking unnecessary or inappropriate content. It also helps protect against web based threats by blocking viruses and spyware downloads. The all encompassing service provides an interface where system administrators can monitor network and user activity in a user-friendly dashboard that produces integrated security reports. This allows system administrators to know  what sites end users are accessing and if one attempts to access a restricted site, the connection will be blocked and a security alert logged in a security report for system admins to see. 



Snort Content Filtering Configuration 
Snort is an open source network intrusion detection system that uses rules to help monitor, alert and block malicious network activity. Snort is user defined meaning that system administrators can configure local rules that will best serve the security needs of the network. Snort works by acting as a packet sniffer, packet logger and can be configured to be an all encompassing network intrusion prevention and detection system. 
Snort rules are divided into two sections, the rule header and rule options. The rule’s header contains the rule’s action, protocol, source IP and port ,and  destination IP and port. The rule option contains alert messages and information on what parts of the packet should be inspected to determine if the rule has been broken and if the action should take place.  Snort has several actions that can be used to monitor and protect a system. These include alert, log,pass, activate, dynamic, drop, reject and sdrop. Alert generates an alert then logs the packet while log just logs the packet in the system. Pass ignores the packet, drop blocks and logs the packet, sdrop blocks the packet but does not log it and reject blocks the packet, logs it, then sends a TCP reset if the protocol is TCP or an ICMP port, if the protocol is UDP the message is unreachable. Activate alerts the system and then turns on a dynamic rule which remains idle until it is activated then it acts as a log rule. 

Snort provides two types of content filtering; URL based filtering and category based filtering. System administrators can use these types of content filtering to block specific websites or websites containing keywords deemed inappropriate or malicious. For example you can block specific social media websites one by one or you can block all websites that are deemed social media through preset keywords. In category based filtering system administrators can log keywords relating to a specific category and block all packets containing those keywords. 

For the purposes of my project I will be using the alert and reject action keywords to log and block web content deemed inappropriate to my system. I chose two category based filters for pornographic content and gambling content. For URL specific filtering I chose websites that are known online shopping scams, known neonazi websites and known cryptocurrency scams. These rules can be modified and added to to provide more security to the system. The URL based filters can easily be converted to category based filters however false positives may happen where a site that is not inappropriate or malicious is deemed as such and blocked. 

All of the rules follow a similar format which is as follows;
Snort action | protocol | source address | source port | direction outgoing from host to external servers | destination address | destination port | rule option including message, the content GET where snort is looking for the GET HTTP method, the keywords or URL to look for, a rule specific ID and rev which is the revision number saying this is the first time the rule is being written in case I want to edit or rewrite the rule.

Below is the code block of my local rules file for snort along with screenshots of testing the program 


# $Id: local.rules,v 1.11 2004/07/23 20:15:44 bmc Exp $
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put you$
# additions here.
#Category Based Content Filtering
#Alert for traffic to pornographic content

alert tcp any any -> any any(msg:"Pornographic content is blocked"; content:"GET";http_uri;pcre:"/porn|xxx|adult|sex|sexy|NSFW|MILF)/i";classtype:policy-violation;sid:1000001; rev:1;)

#Block traffic to pornographic content

reject tcp any any -> any any(msg:"Pornographic content is blocked";content:"GET";http_uri;pcre:"/(porn|xxx|adult|sex|sexy|NSFW|MILF)/i";classtype:policy-violation;sid:1000002; rev:1;)

#Alert for traffic to gambling websites

alert tcp any any -> any any(msg:"Gambling content is blocked";content:"GET";http_uri;pcre:"/(gambling|casino|poker|sportsbetting|sportsbook|lottery|betting|parlay)/Ui";classtype:policy-violation;sid:1000003;rev:1;)

#Block traffic to gambling websites

reject tcp any any -> any any(msg:"Gambling content is blocked";content:"GET";http_uri;pcre:"/(gambling|casino|poker|sportsbetting|sportsbook|lottery|betting|parlay)/Ui";classtype:policy-violation;sid:1000004;rev:1;)

#URL Specific Content Filtering

#Alert for traffic to known fraudulent online shopping scams

alerp tcp any any -> any any(msg:"This is a fraudulent site posing as Michael Kors" ;tls_sni:"michaelkors-handbags.com";content:"GET"; classtype:policy-violation; sid:1000005; rev:1;)

alert tcp any any -> any any(msg:"This is a fraudulent site posing as Tiffany&Co";tls_sni:"tiffanycoshop.com";content:"GET"; classtype:policy-violation; sid:1000006; rev:1;)


#Block traffic to known fraudulent online shopping scams

reject tcp any any -> any any(msg:"This is a fraudulent site posing as Michael Kors" ;tls_sni:"michaelkors-handbags.com";content:"GET"; classtype:policy-violation; sid:1000007; 

reject tcp any any -> any any(msg:"This is a fraudulent site posing as Tiffany&Co";tls_sni:"tiffanycoshop.com";content:"GET"; classtype:policy-violation; sid:1000008; rev:1;)

#Alert for traffic to known NeoNazi websites

alert tcp any any -> any any(msg:"The Vanguard News Network is a known NeoNazi website"; content:"GET"; tls_sni:"vnnforum.com"; classtype:policy-violation; sid:1000009; rev:1;)

alert tcp any any -> any any(msg:"The Daily Stormer is a known NeoNazi website"; content:"GET"; tls_sni:"dailystormer.in"; classtype:policy-violation; sid:1000009; rev:1;)

alert tcp any any -> any any(msg:"8Chan is a known NeoNazi website"; content:"GET"; tls_sni:"8ch.net"; classtype:policy-violation; sid:1000010; rev:1;)

#Block traffic to known NeoNazi websites

reject tcp any any -> any any(msg:"The Vanguard News Network is a known NeoNazi website"; content:"GET"; tls_sni:"vnnforum.com"; classtype:policy-violation; sid:1000011; rev:1;)

reject tcp any any -> any any(msg:"The Daily Stormer is a known NeoNazi website"; content:"GET"; tls_sni:"dailystormer.in"; classtype:policy-violation; sid:1000012; rev:1;)

reject tcp any any -> any any(msg:"8Chan is a known NeoNazi website"; content:"GET"; tls_sni:"8ch.net"; classtype:policy-violation; sid:1000013; rev:1;)

#Alert traffic to known cryptocurrency scams

alert any any -> any any(msg:"ZC Exchange is a fraudulent cryptoccurrency trading platform"; content:"GET"; tls_sni:"FTXbuy666.com|Zcorg01.com"; classtype:policy-violation; sid:1000014; rev:1;)

alert any any -> any any(msg:"Sun Bit Proa is a fraudulent cryptocurrency trading platform"; content:"GET"; tls_sni:"sunbitproa.com"; classtype:policy-violation; sid:1000015; rev:1;)

#Block traffic to known cryptocurrency scams
reject any any -> any any(msg:"ZC Exchange is a fraudulent cryptocurrency trading platform"; content:"GET"; tls_sni:"FTXbuy666.com|Zcorg01.com"; classtype:policy-violation; sid:1000016; rev:1;)

reject any any -> any any(msg:"Sun Bit Proa is a fraudulent cryptocurrency trading platform"; content:"GET"; tls_sni:"sunbitproa.com"; classtype:policy-violation; sid:1000017; rev:1;)

Running the command sudo snort you can see alerts being thrown when trying to access a blocked site. The site I chose to test was sportsbook.draftkings.com which is blocked through category based content filtering 






Sources 
justinmartin123. “Snort Website Block Rule.” Stack Overflow, 1 July 1963, https://stackoverflow.com/questions/40401313/snort-website-block-rule. 
Roesch, Martin. Writing Snort Rules, https://paginas.fe.up.pt/~mgi98020/pgr/writing_snort_rules.htm#:~:text=Snort%20rules%20are%20divided%20into,source%20and%20destination%20ports%20information. 
“Web Security and Filtering.” Web Security and Filtering | Barracuda Networks, 27 Mar. 2023, https://www.barracuda.com/products/network-security/web-security-gateway. 
Allen, Kieron. “Best URL Filtering Software of 2023.” TechRadar, TechRadar Pro, 15 Nov. 2021, https://www.techradar.com/best/best-url-filtering-software. 
“Snort 3 Is Available!” Snort, https://www.snort.org/. 
“Snort-Network Intrusion Detection and Prevention System.” Fortinet, https://www.fortinet.com/resources/cyberglossary/snort. 
“What Is Content Filtering? Definition, Types, and Best Practices.” Spiceworks, 31 Aug. 2021, https://www.spiceworks.com/it-security/network-security/articles/what-is-content-filtering-definition-types-and-best-practices/. 
“What Is Content Filtering? Definition and Types of Content Filters.” Fortinet, https://www.fortinet.com/resources/cyberglossary/content-filtering#:~:text=Content%20filtering%20is%20a%20process,used%20by%20home%20computer%20users. 
“What Is Content Filtering & How Does It Block Urls?” GoGuardian, https://www.goguardian.com/glossary/what-is-content-filtering. 
“Malw“Content Filtering.” Barracuda Networks, 21 Oct. 2022, https://www.barracuda.com/support/glossary/content-filtering. are: Types, Examples, and How Modern Anti-Malware Works.” Perception Point, 2 May 2023, https://perception-point.io/guides/malware/malware-types-examples-how-modern-anti-malware-works/. 
“Popular Scam Shopping Sites 2023.” Trend Micro News, 14 Apr. 2023, https://news.trendmicro.com/2023/01/12/popular-scam-shopping-sites-2023/. 
https://securitynguyen.com/snort-challenge-the-basics/
