#!/usr/bin/env bash
set -eio pipefail

#######################################################################################################
#
# Debian 10 Buster server setup script
#
# This script is only to be run on Debian 10 customized installations, as described on the following link:
# https://zacks.eu/debian-10-buster-initial-customization/
#
# The script has a specific purpose and runs a certain tasks involving operating system environment 
# customization and software installation. Running this script anywhere at any time will leave you 
# with potentially un-bootable OS and software you may not want.
#
# A detailed overview of tasks this script will perform can be seen on the following link:
# https://zacks.eu/debian-10-buster-server-setup/
#
# Please follow the instructions!
#
#######################################################################################################

################
## INITIALIZE ##
################

function initialize ()
{
    # Misc items
    declare -gr SPACER='----------------------------------------------------------------------------------------------------'
    declare -gr E=$'\e[1;31;103m'			# (E) Error: highlighted text.
    declare -gr W=$'\e[1;31;103m'			# (W) Warning: highlighted text.
    declare -gr B=$'\e[1m'				# B for Bold.
    declare -gr R=$'\e[0m'				# R for Reset.

    # Display a warning.
    clear

	# Show a warning.
	cat <<-END
 
        ${SPACER}

            ${B}** WARNING **${R}

            This script is only to be run on Debian 10 customized installations, as described on the following link:
            https://zacks.eu/debian-10-buster-initial-customization/

            The script has a specific purpose and runs a certain tasks involving operating system environment
            customization and software installation. Running this script anywhere at any time will leave you
            with potentially un-bootable OS and software you may not want.

            A detailed overview of tasks this script will perform can be seen on the following link:
            https://zacks.eu/debian-10-buster-server-setup/

            Please make sure you understand what is written above!

        ${SPACER}
 
	END

    # Ask for confirmation.
	local ANSWER
	read -rp "Type ${B}Y${R} to proceed, or anything else to cancel, and press Enter: ${B}" ANSWER
	echo "${R}"

    # Terminate if required.
    if [[ "${ANSWER,}" != 'y' ]]
    then
        echo
        echo 'Terminated. Nothing done.'
        echo
        exit 1
    fi

    # Check if user is root
    if [[ "$(whoami)" != "root" ]]
    then
        echo
        echo "${E}Script must be run as root user! Execution will abort now, please run script again as root user.${R}"
        echo
        exit 1
    fi

} # initialize end

#############################
## INITIALIZE PRESEED FILE ##
#############################

function preseedInitialize ()
{
	cat <<-END
		${SPACER}

		    Script will now initialize a preseed file required for software installation. Since all software installation
		    is unattended (requires no user interaction), we need to give the installer some answers which it would 
		    usually ask for. This file will provide such answers.

		${SPACER}
	
	END

	# Ask for confirmation.
	local ANSWER
	read -rp "Type ${B}Y${R} and press Enter to proceed: ${B}" ANSWER
	echo "${R}"

	# Initialize debian.preseed
	cd "$(dirname -- "$0")"
	debconf-set-selections preseed/debian-server-setup.preseed

} # preseedInitialize end

#########################
## DEBCONF MIN DETAILS ##
#########################

function debconfMinimal ()
{
	cat <<-END
		${SPACER}

		    Script will now set installer detail level to a minimum. Since this is unattended installation,
		    and preseed file is already provided, we don't want no questions asked from installer.

		${SPACER}

	END

	# Ask for confirmation.
	local ANSWER
	read -rp "Type ${B}Y${R} and press Enter to proceed: ${B}" ANSWER
	echo "${R}"

	# Reconfigure debconf - minimal details
	echo -e "debconf debconf/frontend select Noninteractive\ndebconf debconf/priority select critical" | debconf-set-selections

} # debconfMinimal end

#############################
## SSH SERVER INSTALLATION ##
#############################

function sshInstall ()
{
    cat <<-END
        ${SPACER}

            Script will now install openssh-server package. This will enable SSH remote login.
            It will also modify SSH server configuration, so password login is allowed.

        ${SPACER}

	END

    # Ask for confirmation.
    local ANSWER
    read -rp "Type ${B}Y${R} and press Enter to proceed: ${B}" ANSWER
    echo "${R}"

    # Install openssh-server package
    aptitude install -R -y openssh-server

    # Permit password login
    sed -i 's/^#PermitRootLogin prohibit-password/PermitRootLogin yes/g' /etc/ssh/sshd_config

    # Restart sshd service
    service ssh restart

} # sshInstall end

#######################
## LOCAL ROOT ACCESS ##
#######################

function rootSSH ()
{
    cat <<-END
        ${SPACER}

            At this stage, the script will generate private/public RSA keys for root user
            and white list the public portion for local SSH access.

        ${SPACER}

	END

    # Ask for confirmation.
    local ANSWER
    read -rp "Type ${B}Y${R} and press Enter to proceed: ${B}" ANSWER
    echo "${R}"

    # Generate keys for root
    ssh-keygen -t rsa -b 4096 -N "" -f /root/.ssh/id_rsa

    # Generate auth keys file for root
    touch /root/.ssh/authorized_keys
    chmod 0600 /root/.ssh/authorized_keys

    # Add root's pub key to auth files
    echo -n "from=\"127.0.0.1\" $(cat /root/.ssh/id_rsa.pub)" >> /root/.ssh/authorized_keys

} # rootSSH end

########################
## REMOTE USER ACCESS ##
########################

function remoteSSH ()
{
    cat <<-END
        ${SPACER}

            Now that root access is allowed, you need to white list your user. Please check the
            following article on how to generate private/public keys for your user and how to add
            them on the server:

            https://zacks.eu/debian-10-buster-server-setup/

        ${SPACER}

	END

    # Ask for confirmation.
    local ANSWER
    read -rp "Type ${B}Y${R} and press Enter to proceed: ${B}" ANSWER
    echo "${R}"

    # Request user public key
    echo -n "Please paste your public RSA key here in the following format -> \"ssh-rsa XXXXXXXXXXXX username@machine\", or press ENTER to skip for now: "
    read RSA_KEY

    if [ -z "$RSA_KEY" ]
    then
        echo -n "No RSA key provided, will continue without it."
    else
        echo $RSA_KEY >> /root/.ssh/authorized_keys
    fi

} # remoteSSH end

#######################
## SECURE SSH ACCESS ##
#######################

function secureSSH ()
{
	cat <<-END
        ${SPACER}

            With SSH keys in place, script will now set a strict access to your server. Root and user login
            will be allowed only with a proper key and password login will be disabled.

        ${SPACER}

	END

    # Ask for confirmation.
    local ANSWER
    read -rp "Type ${B}Y${R} and press Enter to proceed: ${B}" ANSWER
    echo "${R}"

	# Secure SSH access
	sed -i 's/^PermitRootLogin yes/PermitRootLogin without-password/g' /etc/ssh/sshd_config
	sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config

	# Restart SSH
	service ssh restart

} # secureSSH end

#################################
## LOCAL RESOLVE - NTP SERVERS ##
#################################

function resolveNTP ()
{
	cat <<-END
        ${SPACER}

            Every server depends on a correct time, so script will now set a pool of know servers from
            which we will allow time syncronization. Records will be added to local /etc/hosts file. 
            Dont worry, if you already have any records in your /etc/hosts file, they wont be lost.

        ${SPACER}

	END

    # Ask for confirmation.
    local ANSWER
    read -rp "Type ${B}Y${R} and press Enter to proceed: ${B}" ANSWER
    echo "${R}"

	# Add a comment
	echo -e "\n# Debian NTP Pool Servers" >> /etc/hosts

	# Set NTP variables
	POOL_NTP_0=$(ping -n -c1 0.pool.ntp.org | grep 0.pool.ntp.org | head -n1 | awk '{print $3;}' | tr -d "(" | tr -d ")")
	POOL_NTP_1=$(ping -n -c1 1.pool.ntp.org | grep 1.pool.ntp.org | head -n1 | awk '{print $3;}' | tr -d "(" | tr -d ")")
	POOL_NTP_2=$(ping -n -c1 2.pool.ntp.org | grep 2.pool.ntp.org | head -n1 | awk '{print $3;}' | tr -d "(" | tr -d ")")
	POOL_NTP_3=$(ping -n -c1 3.pool.ntp.org | grep 3.pool.ntp.org | head -n1 | awk '{print $3;}' | tr -d "(" | tr -d ")")
	
	# Gather NTP IPs and add records to /etc/hosts
	echo -e "$POOL_NTP_0 0.debian.pool.ntp.org" >> /etc/hosts
	echo -e "$POOL_NTP_1 1.debian.pool.ntp.org" >> /etc/hosts
	echo -e "$POOL_NTP_2 2.debian.pool.ntp.org" >> /etc/hosts
	echo -e "$POOL_NTP_3 3.debian.pool.ntp.org" >> /etc/hosts

} # resolveNTP end

###################################
## FIREWALL - SET DEFAULT CHAINS ##
###################################

function fwDefaultChains ()
{
	cat <<-END
        ${SPACER}

            At this stage script will set two custom iptables chains. Those chains will contain
            basic firewall rules rquired for this setup. It will also fulsh all rules from default
            chains (INPUT,FORWARD,OUTPUT).

        ${SPACER}

	END

    # Ask for confirmation.
    local ANSWER
    read -rp "Type ${B}Y${R} and press Enter to proceed: ${B}" ANSWER
    echo "${R}"

	# Flush default iptables chains
	iptables -F INPUT
	iptables -F FORWARD
	iptables -F OUTPUT

	# Create default chains
	iptables -N GENERAL-ALLOW
	iptables -N REJECT-ALL

	# INPUT chain jump
	iptables -I INPUT -m comment --comment "No rules of any kind below this rule" -j GENERAL-ALLOW
	iptables -A INPUT -j REJECT-ALL


} # fwDefaultChains end

####################################
## FIREWALL - DEFAULT BASIC RULES ##
####################################

function fwBasicRules ()
{
	cat <<-END
        ${SPACER}

            With default chains in place, script will add default basic rules to those chains now.
            Rules will cover established connections, allow SSH access and communication with
            DNS and NTP servers (services).

        ${SPACER}

	END

    # Ask for confirmation.
    local ANSWER
    read -rp "Type ${B}Y${R} and press Enter to proceed: ${B}" ANSWER
    echo "${R}"

	# Established connections
	iptables -I GENERAL-ALLOW -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -m comment --comment Established -j ACCEPT

	# Allow SSH connections
	iptables -A GENERAL-ALLOW -p tcp -m tcp --dport 22 --tcp-flags FIN,SYN,RST,ACK SYN -m comment --comment sshd -j ACCEPT

	# Allow DNS (Google Servers)
	iptables -A GENERAL-ALLOW -s 8.8.4.4/32 -p udp -m udp --sport 53 -m comment --comment "Google DNS UDP" -j ACCEPT
    iptables -A GENERAL-ALLOW -s 8.8.4.4/32 -p tcp -m tcp --sport 53 -m comment --comment "Google DNS TCP" -j ACCEPT
    iptables -A GENERAL-ALLOW -s 8.8.8.8/32 -p udp -m udp --sport 53 -m comment --comment "Google DNS UDP" -j ACCEPT
    iptables -A GENERAL-ALLOW -s 8.8.8.8/32 -p tcp -m tcp --sport 53 -m comment --comment "Google DNS TCP" -j ACCEPT

	# Allow NTP
	iptables -A GENERAL-ALLOW -s $POOL_NTP_0/32 -p udp -m udp --sport 123 -m comment --comment "NTP Pool Servers" -j ACCEPT
    iptables -A GENERAL-ALLOW -s $POOL_NTP_1/32 -p udp -m udp --sport 123 -m comment --comment "NTP Pool Servers" -j ACCEPT
    iptables -A GENERAL-ALLOW -s $POOL_NTP_2/32 -p udp -m udp --sport 123 -m comment --comment "NTP Pool Servers" -j ACCEPT
    iptables -A GENERAL-ALLOW -s $POOL_NTP_3/32 -p udp -m udp --sport 123 -m comment --comment "NTP Pool Servers" -j ACCEPT

	# Allow ping and loopback communication
	iptables -A GENERAL-ALLOW -p icmp -j ACCEPT
    iptables -A GENERAL-ALLOW -i lo -j ACCEPT

	# Reject everything else
	iptables -A REJECT-ALL -p tcp -j REJECT --reject-with tcp-reset
    iptables -A REJECT-ALL -p udp -j REJECT --reject-with icmp-port-unreachable
    iptables -A REJECT-ALL -p icmp -j DROP

	# Install iptables-persistent and save rules
	aptitude install -R -y iptables-persistent

} # fwBasicRules end

#######################
## GENERAL ASSET LOG ##
#######################

function assetLog ()
{
	cat <<-END
        ${SPACER}

            This is the final step this script will perform. It will set an asset log, a message, that will
            be displayed every time someone logs in to the server. Messages displayed will contain a general
            info and guideline regarding server (and services) administration. Once complete the server will
            reboot to apply all changes made.

        ${SPACER}

	END

    # Ask for confirmation.
    local ANSWER
    read -rp "Type ${B}Y${R} and press Enter to proceed: ${B}" ANSWER
    echo "${R}"

	# Set asset log
	cd "$(dirname -- "$0")"
	cp motd/20-asset-log /etc/update-motd.d/.
	chmod 0755 /etc/update-motd.d/20-asset-log

	# Clean APT cache
	aptitude clean
	aptitude autoclean

	# Reset debconf to full details
	echo -e "debconf debconf/frontend select Dialog\ndebconf debconf/priority select low" | debconf-set-selections

	# Reboot the machines
	shutdown -r now

} # assetLog end

initialize
preseedInitialize
debconfMinimal
sshInstall
rootSSH
remoteSSH
secureSSH
resolveNTP
fwDefaultChains
fwBasicRules
assetLog