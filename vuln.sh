#!/bin/bash

# set -x

################################################################################
#                                                                              #
# vuln.sh									                                   #
#                                                                              #
# version: 1.0.0                                                               #
#                                                                              #
# VULNER - Cyber units operating in an automated way.                          #
#									                                           #
# Student Name - Michael Ivlev						                           #
# Student Code - S11						                                   #
# Class Code - HMagen773616                                                    #
# Lectures Name - Eliran Berkovich					                           #
#									                                           #
# GNU GENERAL PUBLIC LICENSE                                                   #
#                                                                              #
# This program is free software: you can redistribute it and/or modify         #
# it under the terms of the GNU General Public License as published by         #
# the Free Software Foundation, either version 3 of the License, or            #
# (at your option) any later version.                                          #
#                                                                              #
# This program is distributed in the hope that it will be useful,              #
# but WITHOUT ANY WARRANTY; without even the implied warranty of               #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                #
# GNU General Public License for more details.                                 #
#                                                                              #
# You should have received a copy of the GNU General Public License            #
# along with this program.  If not, see <http://www.gnu.org/licenses/>.        #
#                                                                              #
################################################################################

# Import utils script
declare -rg SCRIPT_DIR="$(dirname $(readlink -f "$0"))"
source "$SCRIPT_DIR/utils.sh"

declare -rg LOG_PATH="/var/log/vuln.log"
declare -rg SCAN_PATH="$(pwd)/vuln_scans" #_$(date +%s)" 
declare -rg USERNAME="${SUDO_USER:-$USER}"

declare -g adapter="eth1"
declare -g user_list 
declare -g pass_list


# Check if running as root
function check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root."
        exit 1
    fi
    return 0
}

# Function to display usage message
function usage() {
    cat <<-EOM
Usage: $0 [-u user_list] [-p pass_list] [-a {all, gateway, eth0, wlan0}] [-h] [-r ipv4]
Options:
  -u  Specify a user list file.
  -p  Specify a password list file.
  -a  Specify an adapter name/range
  -h  Display this help message.
  -r  Run report mode on selected ip
EOM
}

# Function to parse command line arguments
parse_arguments() {
    while getopts "u:p:a:r:h" opt; do
        case "$opt" in
            u)
                parse_user_list "$OPTARG"
                ;;
            p)
                parse_pass_list "$OPTARG"
                ;;
            a)
                parse_adapter "$OPTARG"
                ;;
            h)
                usage
                exit 0
                ;;
            r)
                parse_report "$OPTARG"
                exit 0
                ;;
            *)
                usage
                exit 1
                ;;
        esac
    done

    shift $((OPTIND - 1))
}

parse_adapter() {
    local pattern
    pattern="^(all|gateway)$|^(eth|wlan)[0-9]+$"
    
    [[ $1 =~ $pattern ]] && adapter="$1" || { usage; exit 1; }
    
    for valid_adapter in $(get_valid_adapters)
    do
        [ "$adapter" == "$valid_adapter" ] && return 0
    done
    alert "Invalid adapter ${adapter}"
    usage

    exit 1
}

parse_report() {
    local pattern
    pattern="^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$"
    
    report="aaa"
    [[ $1 =~ $pattern ]] && report="$1" || { usage; exit 1; }
    # [ -f "${SCAN_PATH}/${report}" ] #TODO check if file exists
}

# Function to check if the given user list is valid, if not quit
parse_user_list() {
    local filename
    filename="$1"

    check_readable "$filename"
    [ $? -eq 0 ] && user_list="$filename" || exit 1
}

# Function to check if the given user list is valid, if not quit
parse_pass_list() {
    local filename
    filename="$1"

    check_readable "$filename"
    [ $? -eq 0 ] && pass_list="$filename" || exit 1
}

# Function to check the init condition
init_checks() {
    check_root

    [ ! -d "$SCAN_PATH" ] && mkdir "$SCAN_PATH"
	[ ! -f "$LOG_PATH" ] && sudo touch "$LOG_PATH"

    parse_arguments "$@"
}

get_valid_adapters() {
    ip route | grep -o "dev [^ ]*" | cut -d ' ' -f 2 | sort -u
}

# Function to check and install required apps
check_and_install_apps() {
    local apps=( "arp-scan" "masscan" "nmap" "searchsploit" "hydra" "crunch") #medusa mfsconsole xsltproc
    for app in "${apps[@]}"; do
        if ! command -v "$app" &>/dev/null; then
            echo "$app is not installed. Installing..."
            case "$app" in
                "searchsploit")
                    sudo apt-get install exploitdb -y
                    ;;
                "masscan")
                    sudo apt-get install masscan -y
                    ;;
                *)
                    sudo apt-get install "$app" -y
                    ;;
            esac
        fi
    done
}

# Function to generate a password list using crunch
generate_password_list() {
    local min_length="$1"
    local max_length="$2"
    local charset="$3"
    local pass_list="pass_list.txt"
    
    if [[ "$min_length" -ge "$max_length" || -z "$charset" ]]; then
        echo "Invalid password parameters. Please provide valid values."
        exit 1
    fi
    
    echo "Generating password list using crunch..."
    crunch "$min_length" "$max_length" "$charset" -o "$pass_list"
    echo "Password list created: $pass_list"
}

# DEPRECATED
# Function to check if user_list is provided, if not, create one
check_user_list() {
    check_readable "$user_list"
    if [ $? -eq 0 ]; then
        echo "User list not provided."
        user_list="user_list.txt"
        echo "Creating a default user list: $user_list"
        echo "Enter usernames one per line. Press Ctrl+D when finished."
        
        while read -r username; do
            if [[ -n "$username" ]]; then
                echo "$username" >> "$user_list"
            fi
        done
        
        if [[ ! -s "$user_list" ]]; then
            echo "No valid usernames provided. Please try again."
            rm "$user_list"
            check_user_list
        fi

        return 0
    fi
    return 1
}

# DEPRECATED
# Function to check if pass_list is provided, if not, create one
check_pass_list() {
    if [[ -z "$pass_list" ]]; then
        echo "Password list not provided."
        pass_list="pass_list.txt"
        echo "Generating a default password list..."
        
        read -rp "Enter minimum password length: " min_length
        read -rp "Enter maximum password length: " max_length
        read -rp "Enter character set for passwords (e.g., abc123): " charset
        
        generate_password_list "$min_length" "$max_length" "$charset"
    fi
}

# Function to identify LAN network range
identify_network_range() {
    local interface
    local default_gateway
    # local network_range

    interface="$1"

    case "$interface" in #TODO add 'per adapter interface'
        "gateway")
            default_gateway=$(ip route | awk '{if ($1 ~ /default/) print $5}')
            network_range=$(ip route | awk -v pattern=$default_gateway '{if ($3 ~ pattern) print $3 ":" $1}')
            ;;
        "all")
            network_range=$(ip route | awk '{if ($3 ~ /eth/ || $3 ~ /wlan/) print $3 ":" $1}')
            ;;
        eth*|wlan*)
            network_range=$(ip route | awk -v pattern=$interface '{if ($3 ~ pattern) print $3 ":" $1}')
            ;;
        *)
            alert "$interface is an invalid argument"
            exit 1 #FIXME
            ;;
    esac
}

# Function to perform a quick ARP scan and translate it to IP addresses
arp_scan() {
    local network_range
    local adapters
    local adapter_sockets=()

    network_range=$(echo ${1} | sed 's/\n//g')
    IFS=" " read -ra adapter_sockets <<< "$network_range"

    title "Performing a quick ARP scan..."
    
    local adapter element arp_res 
    for element in "${adapter_sockets[@]}"; do
        adapter=$(echo "$element" | cut -d ':' -f 1)
        note "Scanning $adapter"
        arp_res=$(arp-scan --localnet -I "$adapter" 2>/dev/null | awk 'NR>2 {print $1}' | head -n -3) 
        rhosts+="$arp_res\n"
    done
    rhosts=$(echo -e "$rhosts" | awk '$NF' | sort -u)
    echo
}

# Function to perform enumeration of the target IP addresses
enumerate_targets() {
    local targets_file
    targets_file="$1"

    title "Enumerating live hosts..."

    # for x in "$network_range"; do echo "$x"; echo; done

    while IFS= read -r line; do
        enum4linux -a "$line" > "${SCAN_PATH}/${line}.enum"
        #TODO add -p and -u
        echo
    done < "$targets_file"
    
    echo
}

# Function to scan live hosts for open ports
scan_live_hosts() {
    local network_range="$1"

    local st=$(date +%s)

    if [ "$gw_adapter" == "$adapter" ]
    then
        title "Scanning for open ports using masscan..."

        #TODO add a spoofed ip using --adapter-ip
        masscan -Pn -n -iL "$rhosts_file" -p 0-65535 --rate 10000 --retries 1 -oG "grep.txt" # -oX "xml.txt"

        cat grep.txt | awk '{sub(/open.*/, "", $7); print $4" "$7}' | sed 's|/||' | sort -Vu | head -n -3 \
        | awk '{ip[$1] = ip[$1]","$2} END {for (i in ip) print i" "substr(ip[i], 2)}' > ${sockets_file}
    else
        title "Scanning for open ports using Nmap..."

        nmap -Pn -n -iL "$rhosts_file" -p- -T4 -oG "grep.txt" &>/dev/null # -oX "xml.txt"
        cat grep.txt | awk '/Ports/ {for (i = 5; i <= NF; i++) sub(/open.*/, "", $i); print}' \
        | sed 's|/ |,|g' | sed -n 's/Host: \([^ ]*\) () Ports: \([^ ]*\),Ignored.*/\1 \2/p' > ${sockets_file}
    fi


    # echo "$network_range" > live_hosts.txt

    
    
    
    
    local ed=$(date +%s)
    tt=$((ed - st))
    echo "$tt secs"


    # nmap -n -Pn -T4 -p- -iL "$network_range" -oG nmap_live_hosts.txt

	# echo -n "" > ip_port.txt
	# while IFS= read -r line; do
	# 	echo $line | grep -Eo '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) .*Ports: ([0-9,]+)/' | awk -v ORS='' '{printf "%s:", $1}' >> ip_port.txt 
	# 	echo $line | grep -Eo '([0-9,]+)/' | tr '\n' ',' | tr -d '/' | sed 's/,$/\n/' >> ip_port.txt

	# done < nmap_live_hosts.txt

    echo
}

# Function to perform service scan for open ports
service_scan() {
    # local host="$1"
    # local port="$2"
    title "perform service scan using Nmap..."
    

	while IFS= read -r line; do
		local ip=$(echo ${line} | cut -d ' ' -f 1) 
		local ports=$(echo ${line} | cut -d ' ' -f 2)
        note "scanning $ip"
		nmap -n -Pn -T4 -sV -O --script "*vuln*" -p ${ports} ${ip} -oN nmap_service_scan_${ip}.txt -oX nmap_service_scan_${ip}.xml &>/dev/null
        xsltproc nmap_service_scan_${ip}.xml > nmap_service_scan_${ip}.html
	done < ${sockets_file}
    echo

	# for file in $(find ./ -name "nmap_service_scan_*.txt"); do
	# 	cat ${file} >> nmap_service_scan.txt
	# done

    # for file in $(find ./ -name "nmap_service_scan_*.xml"); do
	# 	cat ${file} >> nmap_service_scan.xml
	# done
    # xsltproc nmap_service_scan.xml > nmap_service_scan.html


}

# Function to brute force weak passwords
brute_force_passwords() {
    local host="$1"
    local user_list="$2"
    local pass_list="$3"
    local open_services="$4"
    
    for service_port in $open_services; do
        # Extract the service name and port number
        service_name="$(echo "$service_port" | cut -d':' -f1)"
        port_number="$(echo "$service_port" | cut -d':' -f2)"
        
        # Perform a brute force attack on the service
        echo "Brute forcing $service_name on $host:$port_number using Hydra..."
        hydra -L "$user_list" -P "$pass_list" "$host" "$service_name" -s "$port_number" -o "result_${host}_${port_number}.txt"
    done
}

# Function to display general statistics
display_statistics() {
    local end_time
    end_time=$(date)
    local live_hosts
    live_hosts=$(wc -l < ip_addresses.txt)
    # local start_time
    # start_time=$(cat script_start_time.txt)
    local total_time
    total_time=$((end_time - start_time))
    echo "Scan completed at: $end_time"
    echo "Total time (secs): $total_time"
    echo "Number of live hosts found: $live_hosts"
}

# Function to save results into a report
save_report() {
    local report_file="scan_report.txt"
    cat nmap_live_hosts.txt > "$report_file"
    { cat vulnerabilities.txt; cat result_*; } >> "$report_file"
}

# Function to display relevant findings for a given IP address
display_findings() {
    local ip="$1"
    grep -A 1 "$ip" nmap_live_hosts.txt
    grep "$ip" vulnerabilities.txt
    grep "$ip" result_*
}

# Main function
main() {
    declare -g network_range rhosts
    declare -rg rhosts_file="${SCAN_PATH}/rhosts.txt"
    declare -rg enums_file="${SCAN_PATH}/enum.txt"
    declare -rg sockets_file="${SCAN_PATH}/open_sockets.txt"

    init_checks "$@"

    [ -z "$pass_list" ] && generate_password_list

    # start_time=$(date +%s)

    
    identify_network_range "$adapter" #FIXME not gateway doesnt masscan
    declare -g gw_adapter=$(ip route | awk '/default/ {print $5}')
    # echo "$network_range"

    arp_scan "$network_range"
    #TODO maybe add ping scan?
    # echo -e "$rhosts"
    echo -e "$rhosts" > "$rhosts_file"

    enumerate_targets "$rhosts_file" &
    local loading_msg_pid=$!
    
    scan_live_hosts "$rhosts"

	service_scan

    # searchsploit -u 
    # nmap --script-updatedb    
    # nmap --script "*vuln*


    wait $loading_msg_pid

    success "done"
	exit 0

    for file in $(find ./ -name "nmap_service_scan_*.txt")
    do
        # cat ${file} | awk '{print $2}' | grep -o "CVE.*" | sort -u | xargs -I{} searchsploit {} 
        #TODO download https://vulners.com/seebug exploits from the ${file}
        # cat nmap_service_scan_10.0.0.66.xml | grep "service name.*version[^ ]*" -o
        echo $file
    done

    display_statistics
    save_report

    read -rp "Enter an IP address to display relevant findings: " ip_address
    display_findings "$ip_address"
}

# Call the main function and pass all script arguments
main "$@"

