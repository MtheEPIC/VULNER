#!/bin/bash

# Color variables
RED="\e[\033[1;31m"
RED_L="\e[\033[0;31m"
GREEN="\e[\033[1;32m"
GREEN_L="\e[\033[0;32m"
YELLOW="\e[\033[1;33m"
BLUE="\e[\033[1;34m"
MAGENTA="\e[\033[1;35m"
CYAN="\e[\033[1;36m"
WHITE="\e[\033[1;37m"
NC="\e[\033[0m"
NBC="\e[\033[49m"
GR="\e[\033[1;32;41m"

### THEMES ###

full() {
    ALERT_PREFIX="${RED}[!]"
    ALERT_MSG=$RED

    TITLE_PREFIX="${GREEN}[+]"
    TITLE_MSG=$BLUE

    NOTE_PREFIX="${GREEN}[+]"
    NOTE_MSG=$CYAN

    SUCCESS_PREFIX="${GREEN}[✔]"
    SUCCESS_MSG=$GREEN
}

prefix() {
    ALERT_PREFIX="${RED}[!]"
    ALERT_MSG=$NC

    TITLE_PREFIX="${BLUE}[+]"
    TITLE_MSG=$NC

    NOTE_PREFIX="${CYAN}[+]"
    NOTE_MSG=$NC

    SUCCESS_PREFIX="${GREEN}[✔]"
    SUCCESS_MSG=$NC
}

none() {
    ALERT_PREFIX="${NC}"
    ALERT_MSG=""

    TITLE_PREFIX="${NC}"
    TITLE_MSG=""

    NOTE_PREFIX="${NC}"
    NOTE_MSG=""

    SUCCESS_PREFIX="${NC}"
    SUCCESS_MSG=""
}

### PRINTS ###
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

### HANDLERS ###

set_default_style() {
    case $1 in
        full)
            full
            ;;
        prefix)
            prefix
            ;;
        none)
            none
            ;;
        *)
            ;;
    esac
}

get_default_style() {
    prefix
}

get_default_style
