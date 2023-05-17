import os


def Block_Port(name, Pnum, transP, outbound_flag=True):
    """The function receives a rule name, a port number and a protocol(TCP/UDP) as parameters.
    This function is activated when the 'BVP_main' function is called.
    This function blocks in and out packets that have the given port numbers and the given protocol
    by sending block orders,that their name is given, to the firewall."""
    command_in = f"netsh advfirewall firewall add rule name=\"{name}_in\" protocol={transP} dir=in localport={Pnum} action=block"
    command_out = f"netsh advfirewall firewall add rule name=\"{name}_out\" protocol={transP} dir=out localport={Pnum} action=block"
    os.system(command_in)
    if outbound_flag:
        os.system(command_out)  # won't be activated in the first part of the 'high' engine


def BVP_main(block_level, clientPort, serverPort):
    """The function receives a level of protection(high/low) as well as the client's and the
    server's port number.
    If the given level is 'low', the function blocks a pre-defined set of vulnerable ports.
    If the given level is 'high', the function does what it did when the given level was 'low',
    in addition to getting and blocking all the open vulnerable ports. In both cases a number
    representing the amount of ports which been blocked, is returned in the end."""
    portArr = [f"{serverPort}-TCP", f"{clientPort}-TCP"]
    count = 0
    if block_level.lower() == "high":  # Only if the client want's a high level protection
        output = os.popen("netstat -a").read()  # To get all of the open ports
        output_lines = output.split('\n')
        output_lines = output_lines[4:len(output_lines)-1]
        line_flag = False
        char_flag = False
        port = ""
        portArr = []
        for line in output_lines:  # Going through all the list
            if '[' in line:
                index = line.index(']')
            else:
                index = 0
            for char in line[index::]:
                if line_flag:
                    break  # Port is completed so we can break the inner loop for efficiency
                if char_flag:
                    if char != " ":
                        port += char  # Adding each digit of the port
                    else:
                        line_flag = True  # Means the port is successfully completed
                elif char == ':':  # The first time char=':' symbolizes the port is next to come
                    char_flag = True
            if int(port) > 1023 and port not in portArr:  # Unknown port & Haven't been blocked yet
                count += 1
                if 'TCP' in line:
                    Block_Port(f"vulnerable_port{count}", port, 'TCP', False)
                else:
                    Block_Port(f"vulnerable_port{count}", port, 'UDP', False)
                portArr.append(f"{port}-TCP")
            port = ""  # Reset the port variable
            line_flag = False  # Reset the flag
            char_flag = False  # Reset the flag
    # Otherwise, the client entered 'Low'- so skip the first stage and execute only the following code:
    block_dict = {"RPC": [135, 'TCP', 'UDP'],  # The ports are from research that the SANS institute conducted
                  "NetBIOS_137": [137, 'TCP', 'UDP'],
                  "NetBIOS_138": [138, 'TCP', 'UDP'], "NetBIOS_139": [139, 'TCP', 'UDP'],
                  "SMB/IP": [445, 'TCP'], "TFTP": [69, 'UDP'], "FTP20": [20, 'TCP'],
                  "FTP21": [21, 'TCP'], "SysLogUDP": [514, 'UDP'], "SNMP161": [161, 'UDP'],
                  "SNMP162": [162, 'UDP'], "IRC6660": [6660, 'TCP'], "IRC6661": [6661, 'TCP'],
                  "IRC6662": [6662, 'TCP'], "IRC6663": [6663, 'TCP'], "IRC6664": [6664, 'TCP'],
                  "IRC6665": [6665, 'TCP'], "IRC6666": [6666, 'TCP'], "IRC6667": [6667, 'TCP'],
                  "IRC6668": [6668, 'TCP'], "IRC6669": [6669, 'TCP']}
    for name, details in block_dict.items():
        if len(details) == 3:
            Block_Port(name, details[0], details[2])
            if f"{details[0]}-{details[2]}" not in portArr:  # Check if the port number and its protocol have already been blocked
                portArr.append(f"{details[0]}-{details[2]}")
        Block_Port(name, details[0], details[1])
        if f"{details[0]}-{details[1]}" not in portArr:  # Check if the port number and its protocol have already been blocked
            portArr.append(f"{details[0]}-{details[1]}")
    return len(portArr)  # Which ports the system has blocked
