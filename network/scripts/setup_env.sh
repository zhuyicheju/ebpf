#!/bin/bash

# This script sets up the development environment for the DOVE project,
# which involves eBPF programming and kernel compilation.
# It installs necessary tools and dependencies for Ubuntu systems.

set -e  
set -u  

print_info() {
    printf "\n\e[1;34m%s\e[0m\n" "$1"
}
print_error() {
    printf "\e[1;31mError: %s\e[0m\n" "$1"
    exit 1
}


# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    print_error "This script must be run as root. Please use 'sudo'."
fi

# Detect the operating system and package manager
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    ID=$ID
else
    print_error "Cannot detect operating system."
fi

print_info "Detected OS: $OS"


if [ "$ID" = "ubuntu" ] || [ "$ID" = "debian" ] || [ "$ID_LIKE" = "debian" ]; then
    print_info "Installing dependencies for Debian-based system..."
    
    apt-get update -y
    
    # dependencies for kernel compilation and general development
    apt-get install -y \
        git \
        build-essential \
        fakeroot \
        libncurses5-dev \
        libssl-dev \
        ccache \
        flex \
        bison \
        dwarves

    # dependencies for libbpf and eBPF development
    apt-get install -y \
        libelf-dev \
        zlib1g-dev \
        clang \
        llvm \
        pkg-config

    apt-get install -y linux-tools-$(uname -r) linux-tools-generic


else
    print_error "Unsupported operating system: $OS. Please install dependencies manually."
fi

printf "\n\e[1;32m%s\e[0m\n" "Environment setup complete!"

exit 0