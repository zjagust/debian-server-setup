# Debian Server Setup
**This is a helper script whose purpose is to fully automate basic Debian server system right after initial configuration is complete.**

## Prerequisites
This will only work for Debian customized installations, as described in the following article:
* [Debian 10 Buster initial customizetion](https://zacks.eu/debian-10-buster-initial-customization/)

## Version
10.0.0 - Specifically for Debian 10 Buster release

## Installation
Once you complete Debian initial customization, please execute the following commands:

```bash
apt-get update

apt-get install -y --no-install-recommends git

git clone https://github.com/zjagust/debian-server-setup.git

cd debian-server-setup

. debian-server-setup.sh
```
When script completes all tasks, your machine will reboot so all settings get applied. Once it boots back up, you can delete complete **debian-server-setup** directory.
