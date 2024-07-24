## SSH Honeypot with Web Interface: Cybersecurity Project Overview (Second Semester 2024)

### Project Summary
This project is an introduction to cybersecurity, focusing on creating a basic honeypot system using Python. A honeypot is a system set up to detect and log unauthorized access attempts, helping to understand potential security threats. This project logs SSH and web login attempts to provide insights into possible attacks.

### Main Parts of the Project

#### SSH Honeypot
The SSH honeypot uses the Paramiko library to create an SSH server that logs all login attempts. It checks the entered usernames and passwords and logs the details into a file called 'honeypot.log'. If the credentials match a predefined set ("Kali7986" and "KaliLinux7986450@?!"), the login is considered successful.

#### Web Interface (Flask)
A simple web interface is created using the Flask framework. It features a login form that captures user credentials. Like the SSH honeypot, unsuccessful login attempts are logged. If the entered credentials match the predefined set, the user is redirected to a dashboard; otherwise, they see an authentication failure page.

### Running Both Components Together
The SSH honeypot and Flask web server run at the same time in separate threads. The Flask server listens on port 80, and the SSH honeypot listens on port 8080.

### Detailed Breakdown

#### SSH Honeypot (SSHServer Class)
The SSHServer class uses Paramiko to manage SSH authentication. It overrides a method to log login attempts and decide if the credentials are correct. A function called handle_connection sets up an SSH server for each incoming connection and logs the attempts to 'honeypot.log'.

#### Flask Web Interface
The Flask app has three routes:
- '/' redirects to the login page.
- '/login' displays the login form.
- '/authenticate' processes the login attempt. If the credentials match, it redirects to the dashboard; otherwise, it shows an authentication failure page.

### Running the Project
The start_honeypot function listens for connections on port 8080, creating a new thread for each connection. The run_flask function runs the Flask server on port 80. The main function starts the SSH honeypot in a separate thread.

### Handling Interrupts
The application can handle a KeyboardInterrupt (like pressing Ctrl+C), printing a message and waiting for the SSH honeypot thread to finish before exiting.

### How to Run the Project
1. Run the script in VScode or Python IDLE.
2. The terminal will show that the honeypot has started on port 8080.
3. The web interface captures and logs credentials and IP addresses for login attempts.

### Important Note
When using honeypots in real-world scenarios, be aware of the legal and ethical considerations.# SSH-Honeypot-with-Web-Interface
