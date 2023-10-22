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
declare -rg TEMP_PATH="$(pwd)/temp"

declare -rg USERNAME="${SUDO_USER:-$USER}"

declare -g adapter="eth1"

declare -rg DEFAULT_USR_LST="/usr/share/wordlists/metasploit/ipmi_users.txt"
declare -rg DEFAULT_PAS_LST="/usr/share/wordlists/metasploit/default_pass_for_services_unhash.txt"
declare -g user_list="$DEFAULT_USR_LST"
declare -g pass_list=""

declare -rg IP_PATTERN="((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])"
declare -rg IS_NUM="^[0-9]+$"

#######TEMP###########
echo "msfadmin" > ./user.lst
echo "msfadmin" > ./pass.lst
user_list="./user.lst"
pass_list="./pass.lst"
#######TEMP###########


use_user_privileges() {
	sudo -u "$USERNAME" "$@"
}

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
    local pattern ip
    #TODO assume pareten is type a/b/c
    pattern="^${IP_PATTERN}$"
    ip="$1"
    
    report="aaa"
    [[ ${ip} =~ $pattern ]] && display_findings ${ip} || { usage; exit 1; }
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

update_db() {
    (
        nmap --script-updatedb  
        searchsploit -u
    ) >/dev/null
}

get_valid_adapters() {
    ip -4 route | grep -o "dev [^ ]*" | cut -d ' ' -f 2 | sort -u
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
        return 1
    fi
    
    echo "Generating password list using crunch..."
    crunch "$min_length" "$max_length" "$charset" -o "$pass_list"
    echo "Password list created: $pass_list"

    return 0
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
    local interface default_gateway
    declare -g gw_adapter
    
    title "Identifying LAN network range"

    interface="$1"
    case "$interface" in #TODO add 'per adapter interface'
        "gateway")
            default_gateway=$(ip -4 route | awk '{if ($1 ~ /default/) print $5}')
            network_range=$(ip -4 route | awk -v pattern=$default_gateway '{if ($3 ~ pattern) print $3 ":" $1}')
            ;;
        "all")
            network_range=$(ip -4 route | awk '{if ($3 ~ /eth/ || $3 ~ /wlan/) print $3 ":" $1}')
            ;;
        eth*|wlan*)
            network_range=$(ip -4 route | awk -v pattern=$interface '{if ($3 ~ pattern) print $3 ":" $1}')
            ;;
        *)
            alert "$interface is an invalid argument"
            exit 1 #FIXME
            ;;
    esac
    gw_adapter=$(ip -4 route | awk '/default/ {print $5}')

    echo
}

# Function to perform a quick ARP scan and translate it to IP addresses
arp_scan() {
    local network_range
    local adapters
    local adapter_sockets=()

    title "Performing a quick ARP scan..."

    network_range=$(echo ${1} | sed 's/\n//g')
    IFS=" " read -ra adapter_sockets <<< "$network_range"
    
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
        echo >> "${SCAN_PATH}/${line}.enum"
    done < "$targets_file"
    
    echo
}

# Function to scan live hosts for open ports
scan_live_hosts() {
    local network_range
    network_range="$1"

    # FIXME masscan seems slower then nmap (which should be so)
    if false #[ "$gw_adapter" == "$adapter" ]
    then
        #FIXME adapters that aren't gateway don't masscan
        title "Scanning for open ports using masscan..."

        #TODO add a spoofed ip using --adapter-ip
        masscan -Pn -n -iL "$rhosts_file" -p 0-65535 --rate 1000000 --retries 1 -oG "grep.txt" # -oX "xml.txt"

        cat grep.txt | awk '{sub(/open.*/, "", $7); print $4" "$7}' | sed 's|/||' | sort -Vu | head -n -3 \
        | awk '{ip[$1] = ip[$1]","$2} END {for (i in ip) print i" "substr(ip[i], 2)}' > ${sockets_file}
        #TODO add a sockets_file_plus
        cat grep.txt | awk '{sub("[a-z]*(/){2}", "", $7) sub("/open", "", $7) gsub("/", " ") sub(/\yunknown\y/, ""); print $4" "$7" "$8}' \
        | sort -Vu | head -n -3 | awk '{ip[$1] = ip[$1]","$2"/"$3} END {for (i in ip) print i" "substr(ip[i], 2)}' | sed 's/,/, /g' > ${sockets_file_plus}

    else
        title "Scanning for open ports using Nmap..."

        nmap -Pn -n -iL "$rhosts_file" -p- -T4 -oG "grep.txt" &>/dev/null # -oX "xml.txt"
        cat grep.txt | awk '/Ports/ {for (i = 5; i <= NF; i++) sub(/open.*/, "", $i); print}' \
        | sed 's|/ |,|g' | sed -n 's/Host: \([^ ]*\) () Ports: \([^ ]*\),Ignored.*/\1 \2/p' > ${sockets_file}
        cat grep.txt | awk '/Ports/ {for (i = 5; i <= NF; i++) sub("[a-z]*(/){2}", "", $i) sub("/open", "", $i); print}' \
        | sed 's|///||g; s/Ignored.*//; s/Host: //; s/() Ports: //' > ${sockets_file_plus}
    fi

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

# Function to check for known CVEs based on the service scan
check_cve() {
    title "Checking for possible CVE"
    local file_prefix found_cve cve_payloads cve_sum cve_hosts payload_sum payload_hosts 

    for file in $(find ./ -name "nmap_service_scan_*.txt")
    do
        file_prefix=$(echo "$file" | grep -Eo ${IP_PATTERN})

        found_cve=$(cat ${file} | awk '{print $2}' | grep -o "CVE.*" | sort -u)
        if [ "$found_cve" != "" ]; then
            echo "$found_cve" > "${file_prefix}_CVE.txt"
            ((cve_sum += $(echo "$found_cve" | wc -l)))
            ((cve_hosts += 1))

            cve_payloads=$(echo ${found_cve} | xargs -I{} searchsploit {} | grep -v "No Results")
            if [ "$cve_payloads" != "" ]; then
                echo ${cve_payloads} > "${file_prefix}_CVE_payloads.txt"
                ((payload_sum += $(echo "$cve_payloads" | wc -l)))
                ((payload_hosts += 1))
            fi
        fi

        #TODO download https://vulners.com/seebug exploits from the ${file}
        # cat nmap_service_scan_10.0.0.66.xml | grep "service name.*version[^ ]*" -o
    done

    [[ ${cve_sum} =~ ${IS_NUM} ]] && note "found ${cve_sum} CVEs in ${cve_hosts} targets"
    [[ ${payload_sum} =~ ${IS_NUM} ]] && note "searchsploit found ${payload_sum} payloads for ${payload_hosts} targets"

    echo
}

find_payloads() {
    title "Checking for searchploit payloads for services"
    local file_prefix payloads_file found_services found_payloads payload_sum payload_hosts 

    for file in $(find ./ -name "nmap_service_scan_*.txt")
    do
        file_prefix=$(echo "$file" | grep -Eo ${IP_PATTERN})
        payloads_file="${file_prefix}_payloads.txt"
        echo > ${payloads_file}

        found_services=$(cat "$file" | grep -E "^[0-9]+/" | awk '{ for (i = 4; i <= NF; i++) printf $i " "; print "" }' | awk 'NF' | sort -uV)
        
        while IFS= read -r service; do 
            res=""
            while [ -z "$res" ] && [ -n "$service" ] ; do
                res=$(searchsploit "$service" 2>/dev/null | grep -v "No Results" 2>/dev/null)
                service="$(echo "$service" | awk '{ for (i = 1; i < NF; i++) printf $i " "; print "" }')"

                #TODO check is service was alredy used (even after sort-u differbt services may have a same prefix)
                # temp fix: cat payloads_file | sort -u 
            done
            [ -z "$res" ] && continue

            echo "$res" >> ${payloads_file}
        done <<< "$found_services"

        found_payloads=$(cat ${payloads_file} | sort -u)
        [ -z "$found_payloads" ] && continue

        echo "$found_payloads" > ${payloads_file}
        ((payload_sum += $(echo "$found_payloads" | wc -l)))
        ((payload_hosts += 1))
    done

    [[ ${payload_sum} =~ ${IS_NUM} ]] && note "searchsploit found ${payload_sum} payloads for ${payload_hosts} targets"
    echo
}

# Function to check for the use of weak passwords
online_attack() {
    title "Attempting a bruth force attack"

    while IFS= read -r line; do
        local ip services service port

        # if there are no valid port services contine to the next target
        services=$(echo "$line" | grep -E "[0-9]+/[a-z|-]+" -o)
        [ -n "$services" ] && service=$(echo "$services" | awk 'NR==1') || continue

        ip=$(echo "$line" | awk '{print $1}')
        port=$(echo "$service" | cut -d '/' -f 1)
        service=$(echo "$service" | cut -d '/' -f 2)
        
        # translate specific service name into a generic version
        case "$service" in
            msrpc)
                service="smb"
                ;;
            *)
                ;;
        esac

        brute_force_passwords ${ip} ${service} ${port}
	done < ${sockets_file_plus}

    echo
}

# Function to brute force a given socket
brute_force_passwords() {
    local ip service port result
    ip="$1"
    service="$2"
    port="$3"

    # local user_list="$2"
    # local pass_list="$3"
    # local open_services="$4"

    # Perform a brute force attack on the service
    note "Brute forcing $service on $ip:$port"
    use_user_privileges hydra -L "$user_list" -P "$pass_list" "$ip" "$service" -s "$port" -o "hydra_${ip}_${service}.txt" &>/dev/null
    result="$(grep -w login hydra_${ip}_${service}.txt | tail -n 1)"
    [ -n "$result" ] && success "$result" || alert "attack failed"
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
    local ip report_file
    ip="$1"

    report_file="${SCAN_PATH}/${ip}_report.txt"
    
    # [ -f "${SCAN_PATH}/${report}" ] #TODO check if file exists
    check_readable ${report_file} || { [ $? -eq 1 ] && exit 1; }
    cat ${report_file}

    # grep -A 1 "$ip" nmap_live_hosts.txt
    # grep "$ip" vulnerabilities.txt
    # grep "$ip" result_*
}

function with_loading_animation() {
    local padding msg
    padding="    "
    msg="$1"
    shift

    # echo -ne "${GREEN}[+] ${CYAN}"
    cycle_word_and_chars "${TITLE_PREFIX} ${TITLE_MSG}$msg${NC}" &

    # title "$msg" | cycle_word_and_chars &

    local loading_msg_pid=$!

	"$@" &>/dev/null  # Suppress the command's output
    sleep 10
    kill $loading_msg_pid
    echo -ne "\r" #${GREEN}[+] ${CYAN}"
    title "${msg}${padding}"
}

# Main function
main() {
    declare -g network_range rhosts
    declare -rg rhosts_file="${SCAN_PATH}/rhosts.txt"
    declare -rg enums_file="${SCAN_PATH}/enum.txt"
    declare -rg sockets_file="${SCAN_PATH}/open_sockets.txt"
    declare -rg sockets_file_plus="${SCAN_PATH}/open_sockets_service.txt"

    local start_time end_time

    init_checks "$@"

    # update_db

    if [ -z "$pass_list" ]; then
        while true; do
            generate_password_list

            # [ $? -eq 0 ] && break
            break
        done
    fi

    start_time=$(date +%s)

    # adapter="eth0"
    with_loading_animation "Identifying LAN network range" identify_network_range "$adapter"
    with_loading_animation "Performing a quick ARP scan... " arp_scan "$network_range"
    #TODO maybe add ping scan?
    use_user_privileges echo -e "$rhosts" > "$rhosts_file"    

    run_in_background enumerate_targets ${rhosts_file}
    
    with_loading_animation "Scanning for open ports using Nmap... " scan_live_hosts "$rhosts"

	# service_scan

    # Step 2
    run_in_background check_cve
    run_in_background find_payloads
    run_in_background online_attack
    # online_attack

    # figlet "wait"
    wait_for_all_background
	exit 0

    display_statistics
    save_report
    success "done"
}

# Call the main function and pass all script arguments
main "$@"

