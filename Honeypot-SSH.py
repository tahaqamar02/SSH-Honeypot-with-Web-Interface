import paramiko
import socket
import threading
import os
import pty
from flask import Flask, render_template, request, redirect, url_for
from rich.console import Console

app = Flask(__name__)

# Function to print the ASCII art banner for "Firewall"
def print_banner():
    console = Console()
    banner_text = """
   █      █      ██████      ███████      ████████     █      █            ███████       ██████    ████████
   █      █     █      █     █      █     █            █      █            █      █     █      █       █
   █      █     █      █     █      █     █            █      █            █      █     █      █       █
   ████████     █      █     █      █     ██████        ██████             ███████      █      █       █
   █      █     █      █     █      █     █               █                █            █      █       █
   █      █     █      █     █      █     █               █                █            █      █       █
   █      █      ██████      █      █     ████████        █                █             ██████        ░

    """
    console.print(banner_text, style="bold blue")

class SSHServer(paramiko.ServerInterface):
    def __init__(self, client_address):
        self.client_address = client_address
        self.event = threading.Event()
        self.shell_event = threading.Event()
        super().__init__()
def check_auth_password(self, username: str, password: str) -> int:
        client_ip = self.client_address[0]
        message = f"Authentication Attempt by: User {username} : Password: {password} from IP: {client_ip}"
        print(message)
        with open('honeypot.log', 'a') as log_file:
            log_file.write(message + '\n')
        if username == "Kali7986" and password == "KaliLinux7986450@?!":
            return paramiko.AUTH_SUCCESSFUL
        else:
            return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str):
        return 'password'

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel) -> int:
        self.shell_event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        message = f"Command Execution Attempt by {channel.get_username()} : Command: {command}"
        print(message)
        with open('honeypot.log', 'a') as log_file:
            log_file.write(message + '\n')
# Fake output response
        fake_output = f"Fake output for command: {command}\n"
        channel.sendall(fake_output.encode('utf-8'))
        channel.send_exit_status(0)
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

def handle_connection(client_sock):
    try:
        client_ip = client_sock.getpeername()[0]
        transport = paramiko.Transport(client_sock)
        server_key = paramiko.RSAKey(filename='key')
        transport.add_server_key(server_key)

        ssh = SSHServer(client_sock.getpeername())
        transport.start_server(server=ssh)

        chan = transport.accept()
        if chan is not None:
            ssh.shell_event.wait(10)
            chan.send("Welcome to the honeypot!\n")

            # Fork a child process for PTY
            pid, fd = pty.fork()
            if pid == 0:  # Child process
                os.execv('/bin/sh', ['/bin/sh'])
            else:  # Parent process
                while transport.is_active():
                    data = chan.recv(1024)
                    if data:
                        os.write(fd, data)
                        with open('honeypot.log', 'a') as log_file:
                            log_file.write(f"Command from {client_ip}: {data.decode('utf-8').strip()}\n")
                    if os.waitpid(pid, os.WNOHANG)[0] != 0:
                        break
                    chan.send(os.read(fd, 1024))

            chan.close()

        transport.close()
    except Exception as e:
        print(f"Exception in handle_connection: {e}")
    finally:
        print("Connection handling completed.")

def start_honeypot(host, port):
    print(f'Starting honeypot on port {port}!')
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(223)

    while True:
        try:
            client_sock, client_addr = server_sock.accept()
            print(f"Connection from {client_addr[0]}:{client_addr[1]}")
            t = threading.Thread(target=handle_connection, args=(client_sock,))
            t.start()
        except KeyboardInterrupt:
       print("Received KeyboardInterrupt. Shutting down the honeypot.")
            break

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        message = f"Authentication Attempt by: User {username} : Password: {password} from IP: {request.remote_addr}"
        print(message)
        with open('honeypot.log', 'a') as log_file:
            log_file.write(message + '\n')
        return redirect(url_for('authenticate', username=username, password=password))
    return render_template('login.html')

@app.route('/authenticate', methods=['POST'])
def authenticate():
    username = request.form.get('username')
    password = request.form.get('password')
    message = f"Authentication Attempt by: User {username} : Password: {password} from IP: {request.remote_addr}"
    print(message)
    with open('honeypot.log', 'a') as log_file:
        log_file.write(message + '\n')

    if username == "Kali7986" and password == "KaliLinux7986450@?!":
        return render_template('dashboard.html', username=username)
    else:
 return render_template('authenticate.html')

def run_flask():
    app.run(host='0.0.0.0', port=80, debug=False, threaded=True)

def main():
    print_banner()  # Print the banner when the program starts

    honeypot_thread = threading.Thread(target=start_honeypot, args=('localhost', 8080))
    honeypot_thread.start()

    try:
        run_flask()
    except KeyboardInterrupt:
        print("Received KeyboardInterrupt. Exiting...")
        honeypot_thread.join()

if __name__ == '__main__':
    main()
