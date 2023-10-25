#!/bin/bash

#declare -rg 
# LOG_PATH="/var/log/"
declare -rg DEFAULT_MSG="loading..."

declare -rg utils_dir="$(dirname $(readlink -f "$0"))"
source "${utils_dir}/color.sh"

# Function to print the message with a specific style: succalertess
# Parameters:
#	message to print
alert() {
	local msg
	msg="$1"

	echo -e "${ALERT_PREFIX} ${ALERT_MSG}${msg}${NC}"
}

# Function to print the message with a specific style: title
# Parameters:
#	message to print
title() {
	local msg
	msg="$1"

	echo -e "${TITLE_PREFIX} ${TITLE_MSG}${msg}${NC}"
}

# Function to print the message with a specific style: note
# Parameters:
#	message to print
note() {
	local msg
	msg="$1"

	echo -e "${NOTE_PREFIX} ${NOTE_MSG}${msg}${NC}"
}

# Function to print the message with a specific style: success
# Parameters:
#	message to print
success() {
	local msg
	msg="$1"

	echo -e "${SUCCESS_PREFIX} ${SUCCESS_MSG}${msg}${NC}"
}

fail() {
	[ $# -eq 0 ] && fail "Invalid use of \"fail\" function"
	[ $# -eq 1 ] && alert "$1" && exit 1
	
	local msg=$1
	local rm_func=$2
	shift 2
	[ -z "$(declare -F "${rm_func}")" ] && fail "The passed function ($rm_func) isn't a valid function"

	alert "$msg" && $rm_func "$@" && exit 1

}

# Function to check if a given file is a readable file
# Parameters:
#	file to check check
check_readable() {
	local filename
	{ [ $# -eq 1 ] && filename="$1"; } || { alert "wrong use of check_readable"; return 1; }

	[ -z "$filename" ] && alert "the given arg is empty" && return 1;
	[ ! -f "$filename" ] && alert "the given file doesnt exist" && return 1;
	# [ ! -s "$filename" ] && alert "the given file is empty" && return 1;
	[ ! -r "$filename" ] && alert "the given file doesnt have read perms" && return 1;

	return 0
}

# check_permissions() {
#     # Numeric representation of desired permissions: rwx (read, write, execute)
#     local desired_permissions=7

#     # Get numeric representation of current directory permissions
#     local current_permissions=$(stat -c '%a' .)

#     [ "$current_permissions" -lt "$desired_permissions" ] && fail "You do not have sufficient permissions in this directory!"
# }

# Function to cycle through a pattern and make a wave with a given word
# Parameters:
#	word to make a wave to it
cycle_word_and_chars() {
	local user_input=$1
	local -r user_input=${user_input,,}
	local -r word="${user_input:-$DEFAULT_MSG}"
	local -r chars="-\|/"
	local -r spaces="      "
	local -r SLEEP_TIME=".1"
		
	text=$(echo "$word" | sed -E 's/\\e([0-9]|;|\\|\[)*m/\n/g' | awk 'NF')
	ansi=$(echo "$word" | grep -E "\\\e([0-9]|;|\\\|\[)*m" -o)

	mapfile -t text_arr <<< "$text"
	mapfile -t ansi_arr <<< "$ansi"
	
	# [[ $word =~ ^\\e ]] && echo "yes" || echo "no"
	while (( ${#ansi_arr[@]} > ${#text_arr[@]} )); do
		text_arr+=(" ")
	done
	local len=${#ansi_arr[@]}
	tput sc

	local i=0 j=0
	local ii=0
	local curr_i=0
	local to_print
	while true; do
		to_print=""
		ii=0
		(( i = i % len ))

		for ((; ii<i; ii++)); do
			to_print+="${ansi_arr[ii]}${text_arr[ii]}"
		done	

		[[ ! ${text_arr[i]:curr_i:1} =~ [[:alpha:]] ]] && \
		{ (( curr_i = (curr_i + 1) % ${#text_arr[i]} )); (( curr_i==0 )) && (( i = (i + 1) % len )); continue; }
		curr_word="${text_arr[i]:0:curr_i}$(echo "${text_arr[i]:curr_i:1}" | tr '[:lower:]' '[:upper:]')${text_arr[i]:curr_i+1}"
		(( curr_i = (curr_i + 1) % ${#curr_word} ))
		to_print+="${ansi_arr[i]}${curr_word}"

		for ((ii=i+1; ii<len; ii++)); do
			to_print+="${ansi_arr[ii]}${text_arr[ii]}"
		done

		to_print+="${chars:j:1}"
		tput rc
		echo -ne "${to_print}"

		(( curr_i==0 )) && (( i = (i + 1) % len ))
		(( j = (j + 1) % ${#chars} ))
		sleep ${SLEEP_TIME}
	done

	# echo -e "\r$word$spaces" #space is used to remove the cycling char
	# stty icanon
}


cycle_title() {
	local user_input=$1
	cycle_word_and_chars "${TITLE_PREFIX} ${TITLE_MSG}${user_input}${NC}"
}

# Function to make a wave with a given word
# Parameters:
#	word to make a wave to it
cycle_word() {
	local user_input=${1,,}
	local word="${user_input:-$DEFAULT_MSG}"
	while true; do
		for (( i=0; i< ${#word}; i++ )); do
			curr_word="${word:0:i}$(echo "${word:i:1}" | tr '[:lower:]' '[:upper:]')${word:i+1}"
			printf "%s\r" "$curr_word"
			read -r -n 1 -t .1 -s && break 2
		done
	done
	echo -e "$word"
}

# Function to cycle through a pattern 
cycle_char() {
	local chars="-\|/"
	local word=$1
	while true; do
		for (( i=0; i< ${#chars}; i++ )); do
			echo -ne "\r$word${chars:i:1}"
			read -r -n 1 -t .1 -s && break 2
		done
	done
	echo
}

# Function to check for internet connectivity without getting blocked
check_connectivity() {
	nslookup google.com &>/dev/null && return 0
	fail "No internet connection available!"
}

# Function to check the validity of the given target address
# Parameters:
#	$1: The given target address
# Return:
#	0 if the input is valid
#	1 if the input is invalid
check_domain_format() {
	local user_input=$1
	[[ $user_input =~ $IP_PATTERN || $user_input =~ $DOMAIN_PATTERN ]] && echo "$user_input" && return 0 || return 1
}

# Function to create a new audit
audit() {
	echo "$(date)- $1" >> "$LOG_PATH"
}

# Function to create a new audit and display to the std
tee_audit() {
	echo "$1"
	audit "$1"
}

# Function to update the apt repositories, run once per execution 
update_apt() {
	! declare -p is_updated &>/dev/null && declare -g is_updated && apt update &>/dev/null
}

# Function to check if a program is available via APT
check_program_available() {
    local program="$1"
    if apt-cache show "$program" &> /dev/null; then
        return 0  # Program is available via APT
    else
        return 1  # Program is not available via APT
    fi
}

# Function to check if a program is installed
check_program_installed_non_apt() {
    local program="$1"
    if command -v "$program" &>/dev/null; then
		return 0  # Program is installed
	else
		return 1  # Program is not installed
	fi
}

# Function to check if a program is installed
check_program_installed() {
    local program="$1"
    if dpkg-query -W -f='${Status}' "$program" 2>/dev/null | grep -q "install ok installed"; then
        return 0  # Program is installed
    else
        return $(check_program_installed_non_apt "${program}")  # Program is not installed OR isnt in APT
    fi
}

# Function to install a program using APT
install_program (){
    local program="$1"
	
    if check_program_installed "$program"; then
        note "$program is already installed."
		return 0
    fi
	if ! check_program_available "$program"; then
		alert "$program is not available via APT."
		return 1
	fi

	note "$program is installing"
	update_apt
	apt install -y "$program" &>/dev/null
	success "$program was installed"
	return 0
}

install_programs() {
	local program programs
	local -i errors
	title "Checking and installing programs"

	programs=("$@")
	[ -z "${programs[0]}" ] && { alert "the given agument isn't an array"; return 1; }
	[ ${#programs[@]} -eq 0 ] && { alert "the given array is empty"; return 1; }

	# Loop through the array and install the programs
	errors=0
	for program in "${programs[@]}"; do
		install_program "$program"
		((errors+=$?))
	done
	echo
	return $([ "$errors" -eq 0 ])
}

#######


# Function to request the user to input the remote server credentials
# Note:
#	the password field is hidden in order to protect the user from over the sholder attacks
#	the port field may be skiped and assumed as the default
get_remote_creds() {
	read -rp "[?] Enter remote user: " rm_user
	read -s -rp "[?] Enter remote password: " rm_pass; echo
	read -rp "[?] Enter remote address: " rm_ip
	read -rp "[?] Enter remote port: " rm_port; [ -z "$rm_port" ] && rm_port=$SSH_PORT
}

ssh_wrapper() {
	[ -z "${rm_user}" ] && fail "\"ssh_wrapper\""

	sshpass -p "${rm_pass}" ssh -o StrictHostKeyChecking=no "${rm_user}@${rm_ip}" "$@" 
}

run_in_background() {
	local std_file
	std_file=$(mktemp)

	"$@" > "$std_file" & add_to_background $! "$std_file"
}

add_to_background() {
	local new_pid temp_file

	{ ! declare -p pid_list &>/dev/null && declare -g pid_list; } || pid_list+=" "

	new_pid="$1"
	temp_file="$2"

	pid_list+="${new_pid}-${temp_file}"
}

wait_for_all_background() {
	for pid_file in ${pid_list}; do
		local pid file
		pid=$(echo "$pid_file" | cut -d '-' -f 1)
		file=$(echo "$pid_file" | cut -d '-' -f 2)
		
		# if pid is already dead remove the std file
		# [ "$(ps -p 4743 -o pid=)" ] || rm "$file"
		# if the std file got corrupted kill the proccess
		check_readable "$file" || { alert "std file for ${pid} (${file} got corrupted)"; \
		rm "$file" 2>/dev/null; kill "${pid}"; }

		wait "$pid"
		cat "$file"
		rm "$file"
	done
}

