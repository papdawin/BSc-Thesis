## Website defacement attack detection tool
#### Software engineer BSc Thesis
###### Veszprém, 2023.05.02

[![en](https://img.shields.io/badge/version-English-blue.svg)](https://github.com/papdawin/thesis/blob/master/README.md)
[![hu](https://img.shields.io/badge/version-Hungarian-brown.svg)](https://github.com/papdawin/thesis/blob/master/README.hu.md)

I chose the development of a website defacement attack detection tool as the topic of my
thesis, the task of which is to protect the web server from injection attacks. This is also
an important area nowadays, because the protection of user data is one of the most
important factors for web applications and a WAF can greatly increase the security of our
application. Since injection attacks pose the greatest threat to web applications, I began
implementing the task after a detailed review on them. The developed software includes
a solution to prevent the most common attack vectors, such as SQL injection, XSS, and
Prototype Pollution.
My software solution took the form of a WAF proxy, which forwards requests to the
server web server and then forwards responses to the client. In my thesis, I present the
main concepts of WAF solutions as well as the techniques used in detail. The program
can be customized with the desired settings in a configuration file in order to freely choose
the protection. A log file and an IP database also assist users with feedback. The program
records any intrusion attempts in the log file, saves the attacker's IP address in the IP
database, and if necessary, checks online whether the address is on blacklists.
Protection includes a solution that searches for patterns in the request as well as a machine
learning approach. I thoroughly evaluated and tested both solutions, and I also wrote
about the future possibilities of machine learning in the field. I've gone over the planning,
implementation, and testing processes in great detail.

