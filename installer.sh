#!/bin/bash

source ./utils.sh

apps=( "arp-scan" "masscan" "nmap" "metasploit-framework" "hydra" "crunch" "xsltproc") # "searchsploit" === "metasploit-framework"

run_installer() {    
    apt update || return 1
    apt install -y ${apps[*]} || return 1
    return 0
}

check_apps() {
    if ! dpkg-query -W -f='${Status}' ${apps[*]} &>/dev/null; then
        alert "missing some apps"; return 1
    fi
    success "All apps are installed"; return 0
}

[ "$1" == "-q" ] && check_apps; exit $?
[ "$1" == "-d" ] && run_installer || run_installer &>/dev/null
[ $? -eq 1 ] && alert "an error has ocurred, try to run with -d to get more info" && exit 1
success "All dependencies have been successfully installed"
