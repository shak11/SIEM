import socketserver
import socket
import datetime
import os

import consts as c
from fileIO import FileIO

# Finish sometime
service_threshold_min = 5
service_threshold_number = 500
serviceID_instances_and_time = {}


def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


# Most of the time there will be data
# Add NA to columns that have no data
def add_na(msg):
    for i in range(len(c.Beautify_FW_Parser) - len(msg) - 2):
        msg.append('0')
    return msg


def get_proto(msg):
    return c.proto[int(msg.split(' proto=')[1].split(' ')[0])]


# Parse FireWall logs based on saved keys
def msg_to_arr(msg):
    arr = []
    if "traffic" in msg.split(' type=')[1].split(' ')[0]:
        for line in msg.split(' '):
            temp = line.split('=')
            if len(temp) > 1:
                key, val = temp[0], temp[1]
                if key in c.Syslog_FW_Parser:
                    arr.append(val.replace('"', ''))
        arr.insert(4, get_proto(msg))
    return arr


# Dumb function to find error codes from syslog
def find_code(code):
    fac = c.Facility[int(code / 8)]
    sav = c.Severity[code % 8]
    string = 'x.y'.replace('x', fac).replace('y', sav)
    return string


# Parse windows service ID
def parse_windows_event_code(msg):
    temp = (msg.split()[5])[:-1]
    if str(temp).isdigit():
        return temp
    else:
        return -1


# Parse windows service severity and service description
def parse_windows_event(msg):
    service_id = parse_windows_event_code(msg)
    event = ""
    if service_id != -1:
        if service_id in c.event_id:
            event = c.event_id[service_id]

        # Add service ID and their amounts during a short period of time
        if str(service_id) not in serviceID_instances_and_time.keys():
            serviceID_instances_and_time[str(service_id)] = "0, " + datetime.datetime.now().strftime("%H:%M:%S")

        serviceID_instances_and_time[str(service_id)] = \
            str(int(serviceID_instances_and_time[str(service_id)].split(',')[0]) + 1) + ',' + \
            serviceID_instances_and_time[str(service_id)].split(',')[1]

        # Print services with high severity
        service_warn_show(event, service_id)

    return service_id, event


# Function to show up alerts when the same service has been occurred multiple times in a specific threshold
def service_warn_show(event, service_id):
    if event != "":
        if "Critical" in event:
            print("Critical ALERT!!!")
            print(event, str(service_id))
        elif "Low" in event and int(serviceID_instances_and_time[str(service_id)].split(',')[0]) \
                >= service_threshold_number:
            print("Warning ALERT!!!")
            print(event, str(service_id))


# Function to reArm the counter to services
def service_remove_old_messages():
    for service in serviceID_instances_and_time:
        key, val = service
        if int(datetime.datetime.now().strftime("%H:%M").split(':')[1]) - \
                int(val.split(',')[1].split(':')[1].split(':')[0]) > service_threshold_min:
            serviceID_instances_and_time[str(key)] = "0, " + datetime.datetime.now().strftime("%H:%M:%S")


# Packet handler
class SyslogHandler(socketserver.BaseRequestHandler):
    print("Syslog Handler Created!")

    def handle(self):

        # Decode Message
        recv_msg = self.request[0].decode("utf-8")
        message = recv_msg.split('>')[1]
        line = ""
        syslg_file = 0
        log_type = ""
        # Firewall logs
        if "192.168.68.121" in self.client_address or "10.0.1.254" in self.client_address or \
                "10.0.2.254" in self.client_address or "10.0.3.254" in self.client_address or \
                "10.0.4.254" in self.client_address:
            log_type = "Firewall Package!"
            line = [datetime.datetime.today().strftime("%d/%m/%Y"), datetime.datetime.now().strftime("%H:%M:%S")]

            syslg_file = FileIO(c.FW_FILE_NAME, 'a')
            # print(message)
            msg = msg_to_arr(message)
            if len(msg) > 0:
                line.extend(add_na(msg))
            else:
                syslg_file = 0

        # Windows logs
        elif "10.0.2.1" in str(self.client_address[0]):
            log_type = "Windows Package!"

            code = find_code(int(recv_msg.split('<')[1].split('>')[0]))
            line = [datetime.datetime.today().strftime("%d/%m/%Y"), datetime.datetime.now().strftime("%H:%M:%S"),
                    self.client_address[0], code]

            service_id, event = parse_windows_event(message)

            # Check if service exists
            if event != "":
                syslg_file = FileIO(c.WIN_FILE_NAME, 'a')
                line.append(service_id)
                line.append(event.split(',')[0])
                line.append(event.split(',')[1][1:])
        else:
            print("Got from Unknown end point")

        # Write to file and close file if the service id is in consts or firewall message
        if syslg_file != 0:
            print("Got ", log_type)
            syslg_file.write_to_file(line)
            syslg_file.close_file()
            del syslg_file


# Main program
if __name__ == "__main__":
    try:
        print("Starting...")
        # Set default start for file (Could be ran 1st time only)

        # Create windows csv log file
        if not os.path.exists(c.WIN_FILE_NAME):
            syslog_file = FileIO(c.WIN_FILE_NAME, 'w')
            syslog_file.write_to_file(c.Syslog_Windows_Parser)
            syslog_file.close_file()

        # Create FireWall csv log file
        if not os.path.exists(c.FW_FILE_NAME):
            syslog_file = FileIO(c.FW_FILE_NAME, 'w')
            syslog_file.write_to_file(c.Beautify_FW_Parser)
            syslog_file.close_file()

        print("Files are created successfully")
        # Generic get ip from any linux computer
        # ip = socket.gethostbyname(socket.gethostname() + ".local")
        # Get ip for Windows and Linux computer
        ip = get_ip()
        server = socketserver.UDPServer((ip, c.SYS_PORT), SyslogHandler)
        print("Launched Listener on " + str(ip) + "\n")
        # Start listening
        server.serve_forever()
    # Exit program if cannot open/create the file
    except (IOError, SystemExit):
        print("Error loading or creating files. \r\nShutting down.")
        raise

    # Set default exit method
    except KeyboardInterrupt:
        server.server_close()
        print("Crtl+C Pressed. \r\nShutting down.")
