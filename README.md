# Ryu Load Balancer

## Overview

This project implements a basic load balancer using the Ryu SDN framework. It dynamically distributes HTTP requests to multiple servers and handles the responses appropriately. The load balancer is designed to be simple yet effective in demonstrating key concepts of SDN (Software-Defined Networking) and packet manipulation.

## Features

- **HTTP Load Balancing**: Distributes incoming HTTP requests across a pool of servers.
- **Packet Logging**: Logs detailed information about packets before and after redirection.
- **Port Status Updates**: Monitors and logs changes in switch port status.
- **Predefined MAC and IP Mappings**: Uses fixed MAC and IP addresses for simplicity.

## How It Works

### 1. Packet In Handling

- **Packet Reception**: The load balancer receives packets from the switch.
- **Packet Inspection**: It inspects the packets to determine their type (ARP, HTTP requests, or responses).
- **Logging**: Logs packet details before processing, including source and destination MAC and IP addresses, and ports.
- **Request Redirection**:
  - If the packet is an HTTP request destined for a specific IP (e.g., `10.0.0.5`), it is redirected to one of the predefined servers.
  - Updates are made to the packet’s destination IP and MAC address to reflect the selected server.
  - Logs updated packet details after redirection.

- **Response Handling**:
  - For HTTP responses from servers, the source IP is rewritten to the original destination IP.
  - Logs the modified packet details.

### 2. Port Status Handling

- **Port Status Events**: Monitors and logs events related to port status changes on the switch, such as addition, deletion, or modification of ports.

## Usage

1. **Installation**:
   - Clone the repository:
     ```bash
     git clone https://github.com/Rajveer6000/Networking-.git
     ```
   - Navigate to the project directory:
     ```bash
     cd Networking-
     ```
   - Install the required dependencies (e.g., Ryu):
     ```bash
     pip install ryu
     ```

2. **Running the Application**:
   - Start the Ryu application with the load balancer:
     ```bash
     ryu-manager load_balancer.py
     ```

3. **Testing**:
   - Configure your network to direct traffic through the switch where the Ryu controller is running.
   - Use tools like `curl` or a web browser to generate HTTP traffic to observe load balancing in action.

## Explanation with Images 

### Packet Flow



### Port Status Changes

- **Port Added**:
 Indicates that a new port has been added to the switch.

- **Port Deleted**:
  Shows that a port has been removed from the switch.

- **Port Modified**:
  Depicts changes to an existing port’s configuration.

## Conclusion

This Ryu-based load balancer demonstrates how SDN can be utilized to manage and optimize network traffic dynamically. By redirecting HTTP requests and managing packet flows, it provides a practical example of load balancing and network monitoring in an SDN environment.


---
