import socket
import struct
import time
import threading

EPC = "E2801191200073D2513373D2"
PWD = "00000000"
# DATA = "0202"   # For writing

# Custom CRC-16 function
def crc16_custom(data):
    crc = 0xFFFF
    polynomial = 0x8408
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ polynomial
            else:
                crc >>= 1
    return crc

# Function to create commands with CRC
def create_command(length, address, command, *args):
    data = struct.pack('B', length) + struct.pack('B', address) + struct.pack('B', command)
    for arg in args:
        if isinstance(arg, int):
            data += struct.pack('B', arg)
        elif isinstance(arg, bytes):
            data += arg

    crc_value = crc16_custom(data)
    # Swap the bytes of the CRC value
    crc_swapped = ((crc_value & 0xFF) << 8) | (crc_value >> 8)
    return data + struct.pack('>H', crc_swapped)  # Append CRC to the command

# Function to parse response from the RFID reader
def parse_response(response):
    if len(response) < 4:
        print("Response is too short to parse.")
        return None

    data = response[4:-2]  # Extract the data portion
    return data

# Function to format inventory data
def format_inventory_data(data):
    if len(data) < 2:
        return "Invalid inventory data"

    num_tags = data[0]  # Number of tags in range
    formatted_data = []
    index = 1

    for _ in range(num_tags):
        if index + 1 >= len(data):
            return "Malformed inventory data"

        tag_length = data[index]
        tag_id = data[index + 1: index + 1 + tag_length]
        formatted_data.append(tag_id.hex().upper())
        index += 1 + tag_length

    return " ".join(formatted_data)

# Function to send commands to the RFID reader
def send_command(sock, command, command_type):
    try:
        sock.sendall(command)
        print(f"Sent {command_type.capitalize()} Command: {command.hex().upper()}")
        return command_type
    except socket.error as e:
        print(f"Socket error while sending {command_type} command: {e}")
        return None

# Function to receive responses from the RFID reader
def receive_responses(sock, command_tracker):
    while True:
        try:
            response = sock.recv(1024)  # Adjust buffer size as necessary
            if response:
                data = parse_response(response)
                if data is not None:
                    # Retrieve the command type from the tracker
                    command_type = command_tracker.pop(0) if command_tracker else "Unknown"

                    if command_type == "inventory":
                        formatted_data = format_inventory_data(data)
                        print(f"Received Response for Inventory Command: {formatted_data}")
                    else:
                        print(f"Received Response for {command_type.capitalize()} Command: {data.hex().upper()}")
            else:
                break  # Connection closed
        except socket.error as e:
            print(f"Socket error while receiving: {e}")
            break

# Function to continuously send commands at a specified interval
# Function to continuously send commands at a specified interval
def continuous_send(sock, command_tracker):
    while True:
        # Example commands
        read_command = create_command(0x18, 0x00, 0x02, 0x06, bytes.fromhex(EPC), 0x00, 0x00, 0x04, bytes.fromhex(PWD))
        inventory_command = create_command(0x06, 0x00, 0x01, 0x00, 0x04)
        # inventory_command = create_command(0x06, 0x00, 0x01)

        # # Write command 
        # write_command = create_command(
        #     0x1A, 0x00, 0x03, 0x01, 0x06, 
        #     bytes.fromhex(EPC), 0x00, 0x00 , 
        #     bytes.fromhex(DATA), bytes.fromhex(PWD)
        # )

        # Send read command
        if send_command(sock, read_command, "read"):
            command_tracker.append("read")
        time.sleep(1)  # Send every 1 second

        # Send inventory command
        if send_command(sock, inventory_command, "inventory"):
            command_tracker.append("inventory")
        time.sleep(1)

        # # For sending the write command 
        # if send_command(sock, write_command, "write"):
        #     command_tracker.append("write")
        # time.sleep(1)

# Main function to set up communication with RFID reader
def main():
    ip_address = '192.168.1.190'  # RFID reader IP
    port = 6000  # RFID reader port
    command_tracker = []  # Tracks the type of sent commands

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)  # Set a timeout for blocking operations
        try:
            sock.connect((ip_address, port))
            print(f"Connected to RFID reader at {ip_address}:{port}")

            # Start the receiving thread
            receiver_thread = threading.Thread(target=receive_responses, args=(sock, command_tracker), daemon=True)
            receiver_thread.start()

            # Start sending commands continuously
            continuous_send(sock, command_tracker)

        except socket.error as e:
            print(f"Connection error: {e}")
        except Exception as ex:
            print(f"An unexpected error occurred: {ex}")

if __name__ == "__main__":
    main()