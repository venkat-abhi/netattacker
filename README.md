# SETUP
1. Setup virtual env
```bash
python3 -m venv venv
source venv/bin/activate

# in the root dir (to allow package imports without sys.path mods; refer: https://stackoverflow.com/a/50193944/9810349) 
pip install -e .
```

2. Install netaddr, scapy (preferably scapy[complete])

# Information on Various Network Attacks
More information can be found in the blog posts I have written on them.

* [NTP Amplification](https://fsec404.github.io/blog/A-look-at-NTP-traffic-amplification/)
* [DNS Hijacker](https://fsec404.github.io/blog/DNS-hijacking/#results)
* [DoS Attacks](https://fsec404.github.io/blog/Introduction-to-a-few-network-attacks/)
