# SSE (Server-Sent Events) Test Project

A simple Go-based web application for testing Server-Sent Events functionality with TLS support.

## How to Run

### Development Mode

1. Make sure you have Go installed (version 1.21 or later)

2. Navigate to the project directory:
   ```bash
   cd /Users/alessandro/Desktop/Code/sse
   ```

3. Run the server:
   ```bash
   sudo go run main.go
   ```
   Note: Requires sudo to bind to port 443

4. Open your browser and navigate to:
   ```
   https://localhost
   ```
   Note: You'll need to accept the self-signed certificate warning in your browser

### Production Deployment with Systemd

1. (On your laptop) Build the binary:
   ```bash
   GOOS=linux GOARCH=amd64 go build -o dist/sse .
   ```

2. (On your laptop) Copy via SSH:
   ```sh
   scp dist/sse 134.33.72.209:~/sse
   ```

3. (On server) Copy the binary to the installation directory:
   ```bash
   sudo cp sse /usr/local/bin
   sudo chmod +x /usr/local/bin/sse
   ```

4. Copy the systemd service file to /etc/systemd/system/sse-server.service

5. Reload systemd and enable/start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now sse-server.service
   ```

6. Check the service status:
   ```bash
   sudo systemctl status sse-server.service
   ```

7. View logs:
   ```bash
   sudo journalctl -u sse-server.service -f
   ```
