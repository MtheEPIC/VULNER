#!/bin/bash

#declare -rg 
# LOG_PATH="/var/log/"
declare -rg DEFAULT_MSG="loading..."

declare -rg utils_dir="$(dirname $(readlink -f "$0"))"
source "${utils_dir}/color.sh"

kt
# msf


# print_color() {
#     local color_code="$1"
#     local message="$2"
#     echo -e "${color_code}${message}${NC}"
# }

# prefixed_message() {
# 	local prefix="$1"
#     local color_code="$2"
#     local message="$3"
#     echo -e "${GREEN}${prefix}${color_code}${message}${NC}"
# }

alert() {
	local msg
	msg="$1"

	echo -e "${ALERT_PREFIX} ${ALERT_MSG}${msg}${NC}"
}

title() {
	local msg
	msg="$1"

	echo -e "${TITLE_PREFIX} ${TITLE_MSG}${msg}${NC}"
}

note() {
	local msg
	msg="$1"

	echo -e "${NOTE_PREFIX} ${NOTE_MSG}${msg}${NC}"
}

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
	[ -z "$(declare -F $rm_func)" ] && fail "The passed function ($rm_func) isn't a valid function"

	alert "$msg" && $rm_func $@ && exit 1

}

check_readable() {
	local filename
	[ $# -eq 1 ] && filename="$1" || { alert "wrong use of check_readable"; return 1; }

	[ -z "$filename" ] && alert "the given arg is empty" && return 1;
	[ ! -f "$filename" ] && alert "the given file doesnt exist" && return 1;
	# [ ! -s "$filename" ] && alert "the given file is empty" && return 1;
	[ ! -r "$filename" ] && alert "the given file doesnt have read perms" && return 1;

	return 0
}

check_permissions() {
    # Numeric representation of desired permissions: rwx (read, write, execute)
    local desired_permissions=7

    # Get numeric representation of current directory permissions
    local current_permissions=$(stat -c '%a' .)

    [ "$current_permissions" -lt "$desired_permissions" ] && fail "You do not have sufficient permissions in this directory!"
}

foo() {
	local word="$1"
	local -r chars="-\|/"
	local -r spaces="      "

	local i
	for ((i=0; i<${#word}; i++ )); do
		# echo "$word -- ${word:i:1} -- $i -- ${#word} -- ${#word[@]}"
		[[ ! ${word:i:1} =~ [[:alpha:]] ]] && continue #{ ((i+1 < ${#word})) && { echo "good"; continue; } || break; }
			
		curr_word="${word:0:i}$(echo ${word:i:1} | tr '[:lower:]' '[:upper:]')${word:i+1}"
		curr_cycle_txt="${curr_word}${chars:j:1}"
		
		echo -ne "$spaces"
		tput rc
		echo -ne "$curr_cycle_txt"

		(( j = (j + 1) % ${#chars} ))
		sleep .1 # read -r -n 1 -t .001 -s && break 2 
	done
	return 0
}

# Function to cycle through a pattern and make a wave with a given word
# Parameters:
#	word to make a wave to it
cycle_word_and_chars() {
	local user_input=$1 #""
	# [ -z "$user_input" ] && read -r user_input
	# for x in "$@"; do
	# 	user_input="$user_input$x"
	# done
	local -r user_input=${user_input,,}
	local word="${user_input:-$DEFAULT_MSG}"
	local -r chars="-\|/"
	local -r spaces="      "
		
	# word="${TITLE_PREFIX} ${TITLE_MSG}running strings${NC}"

	# stty -icanon min 0 time 0
	# local curr_cycle_txt overwrite_length
	# word="${TITLE_PREFIX}hello${SUCCESS_PREFIX}world${ALERT_PREFIX}wuw"
	
	# word # \e[\033[1;34m[+] \e[\033[0mrunning strings\e[\033[0m
	no_ansi=$(echo "$word" | sed -E 's/\\e([0-9]|;|\\|\[)*m/\n/g' | awk 'NF') # ![+] !running strings!
	ansi=$(echo "$word" | grep -E "\\\e([0-9]|;|\\\|\[)*m" -o) # | tr '\n' ' ' | xargs echo) # e[033[1;34m e[033[0m e[033[0m

	mapfile -t text_arr <<< "$no_ansi"
	mapfile -t ansi_arr <<< "$ansi"
	
	# [[ $word =~ ^\\e ]] && echo "yes" || echo "no"
	while (( ${#ansi_arr[@]} > ${#text_arr[@]} )); do
		text_arr+=(" ")
	done
	local len=${#ansi_arr[@]}
	tput sc

	local i=0 j=0
	local ii=0 jj=0
	local curr_i=0
	local to_print
	while true; do
		to_print=""
		ii=0 jj=0
		(( i = i % len ))
		# echo "$i--$curr_i"
		

		for ((; ii<i; ii++)); do
			to_print+="${ansi_arr[ii]}${text_arr[ii]}"
		done	


		# echo "${text_arr[i]:curr_i:1}"
		[[ ! ${text_arr[i]:curr_i:1} =~ [[:alpha:]] ]] && \
		{ (( curr_i = (curr_i + 1) % ${#text_arr[i]} )); (( curr_i==0 )) && (( i = (i + 1) % len )); continue; }
		curr_word="${text_arr[i]:0:curr_i}$(echo ${text_arr[i]:curr_i:1} | tr '[:lower:]' '[:upper:]')${text_arr[i]:curr_i+1}"
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
		sleep .1
	done

	# echo -e "\r$word$spaces" #space is used to remove the cycling char
	# stty icanon
}

# Function to make a wave with a given word
# Parameters:
#	word to make a wave to it
cycle_word() {
	local user_input=${1,,}
	local word="${user_input:-$DEFAULT_MSG}"
	while true; do
		for (( i=0; i< ${#word}; i++ )); do
			curr_word="${word:0:i}$(echo ${word:i:1} | tr '[:lower:]' '[:upper:]')${word:i+1}"
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
	nslookup google.com > /dev/null && return 0
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

# Function to check if an app is already installed
# Parameters:
#	$1: app name to check
check_installed() {
	if dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "ok installed"; then
		audit "[#] $1 is already installed."
		prefixed_message "[#] " "$CYAN" "$1 is already installed."
		return 0  
	else
		audit "[#] $1 isn't installed."
		return 1  
	fi
}

# Function to Loop through the programs array and check/install each program
# Paramets:
#	$1: array of function to install
install_programs() {
	prefixed_message "[*] " "$BLUE" "Checking Installations"
	local array=("$@")

	for program in "${array[@]}"; do
		# Skip installation if program is already installed
		check_installed "$program" && continue 
			
		cycle_word_and_chars "[*] Installing $program..." &
		local load_msg_pid=$!
		
		(
			sudo apt-get update #TODO RUN ONCE
			sudo apt-get install -y "$program" 
		) &>/dev/null

		kill $load_msg_pid
		echo -e "\r[*] Installing $program... "
		audit "[*] $program has been installed"
	done
	echo
}

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
	[ -z "$rm_user" ] && fail "\"ssh_wrapper\""

	sshpass -p $rm_pass ssh -o StrictHostKeyChecking=no $rm_user@$rm_ip $@ 
}

run_in_background() {
	local std_file
	std_file=$(mktemp)

	"$@" > "$std_file" & add_to_background $! "$std_file"
}

add_to_background() {
	local new_pid temp_file

	[ ! declare -p pid_list &>/dev/null ] && declare -g pid_list || pid_list+=" "

	new_pid="$1"
	temp_file="$2"

	pid_list+="${new_pid}-${temp_file}"
	# std_files+=" "
}

wait_for_all_background() {
	for pid_file in ${pid_list}; do
		local pid file
		pid=$(echo "$pid_file" | cut -d '-' -f 1)
		file=$(echo "$pid_file" | cut -d '-' -f 2)
		
		# if pid is already dead remove the std file
		# [ "$(ps -p 4743 -o pid=)" ] || rm "$file"
		# if the std file got corrupted kill the proccess
		check_readable "$file"; [ $? -eq 1 ] && {  alert "std file for ${pid} (${file} got corrupted)"; \
		rm "$file" 2>/dev/null; kill ${pid}; }

		wait "$pid"
		cat "$file"
		rm "$file"
	done
}

