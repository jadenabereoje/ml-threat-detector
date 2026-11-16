# Home lab

All attack traffic in this project is generated on an isolated host-only network of virtual machines I own. Nothing is sent to machines outside the lab.

## Network

| VM | OS | IP | Role |
|---|---|---|---|
| attacker | Kali Linux | 192.168.56.10 | runs nmap, hydra, hping3 |
| victim-1 | Ubuntu Server | 192.168.56.20 | SSH, HTTP, FTP services |
| victim-2 | Metasploitable 2 | 192.168.56.30 | intentionally vulnerable target |
| sensor | host or Ubuntu | 192.168.56.1 | runs tcpdump / Zeek |

Network type: VirtualBox **host-only** adapter (no NAT, no bridged adapter) so lab traffic cannot reach the internet.

## Capturing a session

```bash
# on the sensor, one pcap per session
sudo tcpdump -i vboxnet0 -w data/lab/pcaps/$(date -u +%F)_<session>.pcap
```

Before each attack, add a row to `data/lab/labels.csv` with the UTC start time; add the end time when it finishes. Also capture benign sessions (browsing the victim web server, SSH logins, file transfers) so the model sees normal traffic.

## Attack log ideas

| Attack | Tool | Example command | ATT&CK |
|---|---|---|---|
| SYN port scan | nmap | `nmap -sS -p 1-1024 <victim>` | T1046 |
| Service/version scan | nmap | `nmap -sV <victim>` | T1046 |
| SSH brute force | hydra | `hydra -l root -P small.txt ssh://<victim>` | T1110.001 |
| FTP brute force | hydra | `hydra -l admin -P small.txt ftp://<victim>` | T1110.001 |
| SYN flood | hping3 | `sudo hping3 -S --flood -p 80 <victim>` (run ≤ 30 s) | T1498 |

Convert captures to flows with `bash scripts/pcap_to_flows.sh`.
