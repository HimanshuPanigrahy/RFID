import socket
import struct
import time
import threading

EPC_1 = "E2801191A50300674A2673E2"  # E280119120007822  0101
EPC_2 = "E2801191200073D2513332E3"  # E2801191200073D2  0202

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
def receive_responses(sock, command_tracker, inventory_data, lock):
    while True:
        try:
            # Use a larger buffer if necessary
            response = sock.recv(1024)  # Adjust buffer size as necessary
            if response:
                # print(f"Raw Response: {response.hex().upper()}")  # Debug raw response
                data = parse_response(response)
                if data is not None:
                    command_type = command_tracker.pop(0) if command_tracker else "Unknown"
                    if command_type == "inventory":
                        formatted_inventory = format_inventory_data(data)
                        with lock:
                            inventory_data[0] = formatted_inventory
                        print(f"Received Inventory Command Response: {formatted_inventory}")    # Inventory tags/tag ID
                    else:
                        print(f"Received {command_type.capitalize()} Command Response: {data.hex().upper()}")   # Data
            else:
                print("Received empty response")
        except socket.timeout:
            print("Socket timeout - no response received.")
        except socket.error as e:
            print(f"Socket error while receiving: {e}")
            break

# Function to continuously send commands at a specified interval
def continuous_send(sock, command_tracker, inventory_data, lock):
    while True:
        inventory_command = create_command(0x06, 0x00, 0x01, 0x00, 0x04)

        # Send inventory command
        if send_command(sock, inventory_command, "inventory"):
            command_tracker.append("inventory")
        time.sleep(1)

        # Check the inventory data
        with lock:
            inventory_value = inventory_data[0]  # Get the latest inventory data

        if inventory_value == "E280119120007822":
            EPC = EPC_1
        elif inventory_value == "E2801191200073D2":
            EPC = EPC_2
        else:
            print("Unauthorized or multiple tags in range")
            continue  # Skip sending read command if no valid inventory tag

        read_command = create_command(0x18, 0x00, 0x02, 0x06, bytes.fromhex(EPC), 0x00, 0x00, 0x01, b'\x00\x00\x00\x00')

        if send_command(sock, read_command, "read"):
            command_tracker.append("read")
        time.sleep(1)  # Send every 1 second

# Main function to set up communication with RFID reader
def main():
    ip_address = '192.168.1.190'  # RFID reader IP
    port = 6000  # RFID reader port
    command_tracker = []  # Tracks the type of sent commands
    inventory_data = [""]  # List to store inventory data
    lock = threading.Lock()  # Lock for thread-safe access to inventory_data

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)  # Set a timeout for blocking operations
        try:
            sock.connect((ip_address, port))
            print(f"Connected to RFID reader at {ip_address}:{port}")

            # Start the receiving thread
            receiver_thread = threading.Thread(target=receive_responses, args=(sock, command_tracker, inventory_data, lock), daemon=True)
            receiver_thread.start()

            # Start sending commands continuously
            continuous_send(sock, command_tracker, inventory_data, lock)

        except socket.error as e:
            print(f"Connection error: {e}")
        except Exception as ex:
            print(f"An unexpected error occurred: {ex}")

if __name__ == "__main__":
    main()
