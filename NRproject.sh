#!/bin/bash

echo " ____             _           _      ____       ____            "
echo "|   _ \ _ __ ___ (_) ___  ___| |_ _ |  _ \ ___ / ___|___  _ __  " 
echo "| |_) | '__/ _ \| |/ _ \/ __| __(_) | |_) / _ \ |   / _ \| '_ \ "
echo "|  __/| | | (_) | |  __/ (__| |_ _  |  _ <  __/ |__| (_) | | | |"
echo "|_|   |_|  \___// |\___|\___|\__(_) |_| \_\___|\____\___/|_| |_|"
echo "               |__/                                             "
echo "Project ReCon: REmote CONtrol RECONnaissance"
echo "Name: Fransiskus Asisi Bhismobroto | Code: s10"
echo "Class code: 090423 | Lecturer Name: James Lim"
echo "---------------------------------------------------------------------------"
echo "---------------------------------------------------------------------------"
echo ""
sleep 1.5

# STAGE I: PRELIMINARY
sudo -v # Minimize sudo typing via one command (limited time)

# IMPORTANT: Ensure the script is executed from inside nipe directory (where nipe.pl is located)
# For convenience, refer to the function below. It is uncalled in this script (# added), but can be activated when necessary
function install_nipe()
{
git clone https://github.com/htrgouvea/nipe && cd nipe
sudo cpan install Try::Tiny Config::Simple JSON
sudo perl nipe.pl install
}
#install_nipe

function restart_nipe() #Delay design to provide time between stop and start
{
sudo perl nipe.pl stop
sleep 1.5
echo "Restarting nipe in progress..."
sleep 1.5
sudo perl nipe.pl start
}

function exit_from_script()
{
exit 0
}

# Consider updating distribution before updating links and upgrading. As it potentially takes a lot of time, it is not included in the project (should be done regularly instead instead of everytime script is executed)

function update_batch() #Any other Linux distribution update/upgrade can be added here #Function placed before install
{
sudo do-release-upgrade
sudo apt-get update #update first to ensure correct link
sudo apt-get upgrade #upgrade after update to ensure latest packages downloaded
}
# This function is called prior to each application installation function, as we might not know whether any installation is required.
# If no installation is required, this process is not triggered, but the trade-off is if multiple application needs to be installed, there are extra steps

#As it is necessary to show country, outward-facing (public) IP must be displayed for remote server
#This might mean the main machine, VM instances or router, depending on which has outward-facing IP
function display_country_remote_server()
{
echo ""
echo "Performing check of public IP in progress via API: <progress displayed below>"
echo ""
public_ip=$(curl https://api.ipify.org) #Extract the public IP from an available website API
echo ""
echo "Public IP address: $public_ip"
public_ip_country_one=$(geoiplookup $public_ip | awk -F: '{print $2}')
public_ip_country_two=$(whois $public_ip | grep -i country | awk -F: '{print $2}' | tr -s ' '  )
if [ anon_ip_country_one != " IP Address not found" ] 
	then country_ip=$public_ip_country_one
	else country_ip=$public_ip_country_two
fi
echo "Country:$country_ip"
echo ""
}

function display_uptime()
{
pretty_uptime=$(uptime -p | awk '{$1=""; print}')
echo ""
echo "The Remote Server has been up for: $pretty_uptime"
}

# For installation and updates, included command for other linux distribution that I came across (credited)
# These commands can be activated/deactivated by removing/adding back the '#' symbol (for example if nmap scan result provided intel/insight into remote server distribution)
function install_geoipbin() #https://www.thelinuxfaq.com/360-how-to-install-and-use-geoip-on-fedora-centos-ubuntu
{
update_batch
sudo apt-get install geoip-bin
# yum install GeoIP GeoIP-data #Fedora/CentOS/RHEL
}

function install_sshpass() # https://linuxtldr.com/sshpass-command/
{
update_batch
sudo apt-get install sshpass #
# sudo apt install sshpass # Debian/Ubuntu
# sudo dnf install sshpass # Red Hat/Fedora
# sudo pacman -S sshpass # Arch/Manjaro
# sudo zypper install sshpass # openSUSE
# brew install sshpass # Homebrew
}

function install_ts()
{
update_batch
sudo apt-get install moreutils
}

function install_nmap() # https://phoenixnap.com/kb/how-to-install-use-nmap-scanning-linux#ftoc-heading-9
{
update_batch
sudo apt-get install nmap
# sudo yum install nmap # CentOS/RHEL
}

function install_tor() #https://www.golinuxcloud.com/install-tor-browser-on-linux/
{
update_batch
sudo apt-get install tor torbrowser-launcher
}

function install_whois() #https://www.howtogeek.com/680086/how-to-use-the-whois-command-on-linux/
{
update_batch
sudo apt-get install whois
#sudo dnf install whois # Fedora
#sudo pacman -Syu whois # Manjaro
}

#Resource used for command to check file existence: https://stackoverflow.com/questions/10204562/difference-between-if-e-and-if-f
function file_exist_check()
{
if [ -f $1 ]
then echo "File $1 exists" 
else touch $1
fi
}

#Resources helping check if program is installed https://askubuntu.com/questions/433609/how-can-i-list-all-applications-installed-in-my-system
function fill_list_inst() # Repopulating list_inst.txt with list of installed program
{
dpkg --get-selections | grep "install" | grep -v "deinstall" | awk '{print $1}' > list_inst.txt # After checking remote server (ubuntu),"deinstall" indicated for some app. Excluded these (grep -v flag) as this function needs to work on both main attacking machine and remote server
}

file_exist_check list_inst.txt # Temporary file listing all the installed programs to check necessary programs are installed. Will be deleted once checking is done
fill_list_inst # Updates the file, to check downloaded applications
sleep 1.5

# If the program is not installed, "unary operator expected" may occur. This is not issue since the "else" would be executed anyway

function check_geoip
{
geoipcheck=$(cat list_inst.txt | grep -x "geoip-bin") 
if [ $geoipcheck == "geoip-bin" ] 
then echo "" 
	echo "geoip-bin is already installed"
else install_geoipbin
fi
sleep 1.5
}

function check_sshpass
{
sshcheck=$(cat list_inst.txt | grep -x "sshpass")
if [ $sshcheck == "sshpass" ] 
then echo "sshpass is already installed"
else install_sshpass
fi
sleep 1.5
}

function check_ts
{
tscheck=$(cat list_inst.txt | grep -x "moreutils")
if [ $tscheck == "moreutils" ] 
then echo "ts (timestamp) is already installed"
else install_ts
fi
sleep 1.5
}

function check_nmap
{
nmapcheck=$(cat list_inst.txt | grep -x "nmap")
if [ $nmapcheck == "nmap" ]
then echo "Nmap is already installed"
else install_nmap
fi
sleep 1.5
}

function check_tor
{
torcheck=$(cat list_inst.txt | grep -x "tor")  
if [ $torcheck == "tor" ]
then echo "Tor is already installed"
else install_tor
fi
sleep 1.5
}

function check_whois
{
whoischeck=$(cat list_inst.txt | grep -x "whois")
if [ $whoischeck == "whois" ] 
then echo "Whois is already installed"
else install_whois
fi
sleep 1.5
}

#Application checklist
check_geoip
check_sshpass
check_ts
check_nmap
check_tor
check_whois

# Overwrite previous temporary logs
if [ -e NRlogs ]
then rm -r NRlogs 
fi

rm list_inst.txt #Cleanup temporary file for checking application installation status

sudo perl nipe.pl start #command to start perl nipe first prior to anonymous check #If fail, should perform again

nipe_status=$(sudo perl nipe.pl status | grep Status | awk -F" " '{print $NF}')
anon_ip=$(sudo perl nipe.pl status | grep Ip | awk -F" " '{print $NF}')

# As sometimes geoiplookup fail, provided two failsafe for now, by adding -I flag to refer to IANA, or use whois as last resort
anon_ip_country_one=$(geoiplookup $anon_ip | awk -F: '{print $2}')
anon_ip_country_two=$(geoiplookup -I $anon_ip | awk -F: '{print $2}')
anon_ip_country_three=$(whois $anon_ip | grep -i country | awk -F: '{print $2}' | tr -s ' '  ) #tr -s ' ' to squeeze multiple occurence of space to just one for presentation purpose

#The if condition to go in case first retrieved country fails, it goes in descending order of method priority
if [ anon_ip_country_one != " IP Address not found" ] 
then country_ip_anon=$anon_ip_country_one
else 
	if [ anon_ip_country_two != " IP Address not found" ]
	then country_ip_anon=$anon_ip_country_two
	else country_ip_anon=$anon_ip_country_three
	fi
fi

#Checking if network is anonymous
if [ $nipe_status == "false" ] # true means anonymous, false means not anonymous
then echo "WARNING! Connection is not anonymous! Exiting connection..." #Alert the user and exit
		restart_nipe #Attempt to restart nipe before exiting the script for a new trial
		exit_from_script 	 
else echo ""
	echo "You are anonymous!" 
	echo "Your spoofed IP Address is: $anon_ip"
	echo "Your spoofed IP Country is: $country_ip_anon"
	echo ""
	sleep 1.5
	echo "Connecting to Remote Server..."
	sleep 1.5
	echo  "Connecting to Remote Server......"
	sleep 1.5
fi

# Allow user to specify Domain/IP address, save into variable (victim_ip_dom in this case)
function specify_victim_ip_dom
{
echo "Please specify address (in the form of IP or domain) for further action (whois / nmap scan)"
read victim_ip_dom
echo "Address identified as: $victim_ip_dom"
}

# Prepare a (console simulating) function to execute whois/nmap/change given IP or domain/discontinue process on remote server
# Online resource used to know about tee command: https://superuser.com/questions/1174408/can-you-prefix-each-line-written-with-tee-with-the-current-date-and-time, https://phoenixnap.com/kb/linux-tee
function choose_action()
{
echo "
======================================================================
Please choose action to be performed via the remote server 
Victim address identified as: $victim_ip_dom

Input A to Perform Whois on potential victim 
Input B to Perform Nmap scan on potential victim
Input C to Choose a new IP / Domain
Input D to Terminate Connection from Remote Server and Exit the process
======================================================================"
read ACTION
case $ACTION in
A|a)
	echo "Option A) Perform Whois is chosen"
	echo "Performing whois for $victim_ip_dom"
	echo "Performing whois for $victim_ip_dom" | ts | tee -a NRproject.log
	echo "Performing whois for $victim_ip_dom" | ts | tee -a whois_result.txt # Separator for the whois summary file
	whois $victim_ip_dom | ts | tee -a whois_result.txt
	sleep 1.5
	choose_action
;;
B|b)
	echo "Option B) Perform Nmap scan is chosen"
	echo "Performing Nmap scan for $victim_ip_dom"
	echo "Performing Nmap scan for $victim_ip_dom" | ts | tee -a NRproject.log
	nmap -Pn -sV $victim_ip_dom | ts | tee -a nmap_result.txt  #-p<port> #-p- #Consider checking all ports (remove the # sign beside -p-) or name the port when relevant
	# Currently scanning only the most common 1000 ports. To amend port flags if necessary
	sleep 1.5
	choose_action
;;
C|c)
	specify_victim_ip_dom
	choose_action
;;
D|d)
	mkdir NRlogs
	mv whois_result.txt NRlogs
	mv nmap_result.txt NRlogs
	mv NRproject.log NRlogs
	echo "Terminating process."
	sleep 1
	echo "Terminating process..."
	sleep 1
	echo "Terminating process....."
	sleep 1
	exit
;;
*)
	echo "Kindly choose a valid action only:'A/B/C/D' !!!"
	sleep 1
	choose_action
;;
esac
}

# STAGE II: EXECUTION

#Note: Only connect to remote server when we have the authorization/credentials. Considered the brute-force method to access any given remote server, but it might not be ethical in the first place. Abandoned idea.
#Input Username, IP/Domain, Password for SSH purpose
read -p "Please enter Remote Server Username  :     " username_input
read -p "Please enter Remote Server IP/Domain :     " ipdom_input
read -s -p "Please enter Remote Server Password  :     " pw_input #Additional -s switch to hide password from screen

#LIST OF REMOTE COMMANDS (VITAL! update when adding/removing functions)
remote_commands="echo 'Connected to Remote Server!';
sleep 1.5;
sudo -v;
$(declare -f file_exist_check); file_exist_check list_inst.txt; 
$(declare -f file_exist_check); file_exist_check whois_result.txt; 
$(declare -f file_exist_check); file_exist_check nmap_result.txt;
$(declare -f file_exist_check); file_exist_check NRproject.log;
$(declare -f fill_list_inst); fill_list_inst;
$(declare -f update_batch);
$(declare -f install_geoipbin);
$(declare -f install_ts);
$(declare -f install_nmap);
$(declare -f install_whois);
$(declare -f check_geoip); check_geoip;
sleep 1.5
$(declare -f check_ts); check_ts;
sleep 1.5
$(declare -f check_nmap); check_nmap;
sleep 1.5
$(declare -f check_whois); check_whois;
sleep 1.5; 
$(declare -f display_uptime); display_uptime;
sleep 1.5;
$(declare -f display_country_remote_server); display_country_remote_server;
sleep 1.5;
$(declare -f specify_victim_ip_dom); specify_victim_ip_dom;
sleep 1.5;
rm list_inst.txt;
$(declare -f choose_action); choose_action;
/bin/bash"

# Reference used for the syntax of sshpass:o	https://unix.stackexchange.com/questions/671351/how-to-run-commands-after-sshpass-without-closing-connection; https://www.cyberciti.biz/faq/noninteractive-shell-script-ssh-password-provider/
# Actual one-liner to call up list of functions to be executed on remote server and keep connection until otherwise commanded
SSHPASS=$pw_input sshpass -e ssh -t -o StrictHostKeyChecking=no $username_input@$ipdom_input "$remote_commands"

# STAGE III: CLOSING
echo ""
echo "Commencing Clean-up Phase"
echo""

mkdir NRlogs # Previously temporary NRlogs folder (on local machine) were deleted in recursive manner

scp $username_input@$ipdom_input:~/NRlogs/* ./NRlogs #ssh copy to take all the files in the NRlogs folder (created to be downloaded from remote server)
SSHPASS=$pw_input sshpass -e ssh -t -o StrictHostKeyChecking=no $username_input@$ipdom_input "rm -r NRlogs; exit; /bin/bash" #delete the working files from all the NRlogs in remote server, to minimize remnants/artefact of activity in the home folder of remote server 

cd NRlogs # go in NRlogs to tidy up documents locally
mkdir NR_verbose_results # To separate raw data of nmap and whois and the soon-to-be-created summary
touch summary_nmap #Create new files to summarize via text manipulation
touch summary_whois #Create new files to summarize via text manipulation

# Creating a summary of whois results - to adjust accordingly depending on needs
# For the purpose of project, focus on contact details (email, address, phone, name server)
# The "Performing" inside grep acts as a header/separator for whois results (if there are multiple victims)
cat whois_result.txt | grep -E "Performing|Phone|@|Address|Organization|OrgName|Name Server|Registrant|Org" | grep -v -E "Terms|Comment" >> summary_whois

# Creating a summary of only open ports in nmap (if there are multiple victims)
cat nmap_result.txt | grep -E "scan report|open" >> summary_nmap

mv whois_result.txt NR_verbose_results 
mv nmap_result.txt NR_verbose_results 
cd .. # go back to directory outside NRlogs

#Experimented with an idea to that most logs would be in /var/log directory, but script always throw permission issue, thus aborted for now

echo ""
echo "WARNING: log files would be deleted in the next instance script is executed"
echo "Please make copy of the NRlogs directory when necessary"

#-------------------- ||||| End of Script ||||| -----------------------------
#IlNjcmlwdCBpcyBtaWdodGllciB0aGFuIHN3b3JkIg==
#RnJhbnNpc2t1cywgMjAyMw==
