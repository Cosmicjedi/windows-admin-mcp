# Windows Admin MCP Server

A Model Context Protocol (MCP) server that provides remote Windows server administration and troubleshooting capabilities via WinRM and SSH PowerShell protocols.

## Purpose

This MCP server provides a secure interface for AI assistants to remotely connect to Windows servers, diagnose issues, and apply solutions using PowerShell commands through WinRM (primary) or SSH (fallback) protocols.

## Features

### Remote Connection Methods

- **WinRM (Primary)** - Windows Remote Management protocol for native Windows remote administration
  - Supports both HTTP (port 5985) and HTTPS (port 5986)
  - NTLM and Basic authentication
  - Native PowerShell command execution
  
- **SSH PowerShell (Fallback)** - SSH-based PowerShell execution for servers with OpenSSH
  - Works with Windows 10/Server 2019+ built-in OpenSSH
  - Automatic fallback when WinRM is unavailable
  - Full PowerShell command support

### Available Tools

- **`test_connection`** - Test connectivity to a Windows server using ping, WinRM, and SSH port checks
- **`diagnose_system`** - Gather comprehensive system information to diagnose issues
- **`execute_command`** - Execute PowerShell or CMD commands on the remote server
- **`check_service`** - Check Windows service status and provide management options
- **`troubleshoot_application`** - Troubleshoot specific applications that are crashing or not working
- **`apply_solution`** - Apply PowerShell solution scripts to fix identified issues
- **`get_performance_metrics`** - Get current CPU, memory, disk, and network metrics
- **`view_logs`** - View troubleshooting logs for specific servers and dates

## Prerequisites

### Docker Environment
- Docker Desktop with MCP Toolkit enabled
- Docker MCP CLI plugin (`docker mcp` command)

### Target Windows Servers
For WinRM access (recommended):
- WinRM enabled and configured (`winrm quickconfig`)
- PowerShell remoting enabled (`Enable-PSRemoting`)
- Firewall rules for WinRM (ports 5985/5986)
- Network connectivity from Docker container

For SSH fallback (optional):
- OpenSSH Server installed and running
- SSH port 22 open in firewall
- PowerShell available via SSH

## Installation

### Step 1: Clone the Repository
```bash
git clone https://github.com/Cosmicjedi/windows-admin-mcp.git
cd windows-admin-mcp
```

### Step 2: Build Docker Image
```bash
docker build -t windows-admin-mcp-server .
```

### Step 3: Set Up Log Directory (Optional)
```bash
# Create a local directory for logs
mkdir -p ~/windows-admin-logs

# Set as environment variable
export WINDOWS_ADMIN_LOG_DIR=~/windows-admin-logs
```

### Step 4: Create Custom Catalog
```bash
# Create catalogs directory if it doesn't exist
mkdir -p ~/.docker/mcp/catalogs

# Create or edit custom.yaml
nano ~/.docker/mcp/catalogs/custom.yaml
```

Add this entry to custom.yaml:
```yaml
version: 2
name: custom
displayName: Custom MCP Servers
registry:
  windows-admin:
    description: "Remote Windows server administration via WinRM and SSH"
    title: "Windows Admin MCP"
    type: server
    dateAdded: "2025-09-24T00:00:00Z"
    image: windows-admin-mcp-server:latest
    ref: ""
    readme: ""
    toolsUrl: ""
    source: ""
    upstream: ""
    icon: ""
    tools:
      - name: test_connection
      - name: diagnose_system
      - name: execute_command
      - name: check_service
      - name: troubleshoot_application
      - name: apply_solution
      - name: get_performance_metrics
      - name: view_logs
    env:
      - name: WINDOWS_ADMIN_LOG_DIR
        value: "/app/logs"
    metadata:
      category: monitoring
      tags:
        - windows
        - administration
        - troubleshooting
        - powershell
        - winrm
        - ssh
        - remote
      license: MIT
      owner: local
```

### Step 5: Update Registry
```bash
# Edit registry file
nano ~/.docker/mcp/registry.yaml
```

Add this entry under the existing `registry:` key:
```yaml
registry:
  # ... existing servers ...
  windows-admin:
    ref: ""
```

### Step 6: Configure Claude Desktop

Find your Claude Desktop config file:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

Edit the file and add your custom catalog:
```json
{
  "mcpServers": {
    "mcp-toolkit-gateway": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-v", "[YOUR_HOME]/.docker/mcp:/mcp",
        "-v", "[YOUR_LOG_DIR]:/app/logs",
        "docker/mcp-gateway",
        "--catalog=/mcp/catalogs/docker-mcp.yaml",
        "--catalog=/mcp/catalogs/custom.yaml",
        "--config=/mcp/config.yaml",
        "--registry=/mcp/registry.yaml",
        "--tools-config=/mcp/tools.yaml",
        "--transport=stdio"
      ]
    }
  }
}
```

### Step 7: Restart Claude Desktop
1. Quit Claude Desktop completely
2. Start Claude Desktop again
3. Your Windows Admin tools should appear!

## Usage Examples

In Claude Desktop, you can ask:

- "Test connection to Windows server 192.168.1.100 with username Administrator and password"
- "Diagnose why the 'Flying Doghouse' application is crashing on server SNOOPY"
- "Check the status of the Windows Update service on server PROD-WEB-01"
- "Get performance metrics from server DB-SERVER-02 using credentials admin/password"
- "Execute Get-Process command on server APP-SERVER with my credentials"
- "Troubleshoot why IIS is not starting on WEB-SERVER-01"
- "Apply a solution to restart the Print Spooler service on PRINT-SERVER"
- "Show me the logs for server SNOOPY from today"
- "Find the test.log file in C:\Users\Administrator and read its contents"

## Architecture

```
Claude Desktop → MCP Gateway → Windows Admin MCP Server
                                         ↓
                                    [WinRM/SSH]
                                         ↓
                                  Windows Servers
                                         ↓
                                   Local Log Files
                            (/app/logs/hostname-MMDDYYYY.log)
```

## Connection Flow

1. **Primary Method: WinRM**
   - Attempts HTTP connection on port 5985
   - Falls back to HTTPS on port 5986 if HTTP fails
   - Uses NTLM authentication by default, falls back to Basic

2. **Fallback Method: SSH PowerShell**
   - Connects via SSH on port 22
   - Executes PowerShell commands through SSH session
   - Works with Windows OpenSSH Server

## Log Management

The server automatically creates daily log files for each server:
- Format: `{hostname}-{MMDDYYYY}.log`
- Location: Configurable via `WINDOWS_ADMIN_LOG_DIR` environment variable
- Default: `/app/logs` in the container
- Contains timestamped entries of all operations performed

## Security Considerations

- Credentials are passed in real-time and not stored
- WinRM connections use NTLM/Basic authentication
- SSH connections use password authentication
- Log files contain operation history but no passwords
- Running as non-root user in Docker container
- Consider using HTTPS WinRM (port 5986) for production
- Implement credential management integration with your secret server

## Windows Server Configuration

### Enable WinRM (Recommended)
```powershell
# Quick configuration
winrm quickconfig

# Or manual configuration
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*"
Set-Service WinRM -StartupType Automatic
Start-Service WinRM

# For HTTPS (more secure)
New-SelfSignedCertificate -DnsName "servername" -CertStoreLocation Cert:\LocalMachine\My
New-Item -Path WSMan:\LocalHost\Listener -Transport HTTPS -Address * -CertificateThumbPrint (Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -eq "CN=servername"}).Thumbprint
```

### Enable SSH PowerShell (Alternative)
```powershell
# Install OpenSSH Server
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# Start and enable SSH
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'

# Configure firewall
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
```

## Troubleshooting

### Connection Issues
1. **WinRM Errors**:
   - Enable WinRM: `winrm quickconfig`
   - Set trusted hosts: `Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*"`
   - Check firewall rules for ports 5985/5986
   - Verify WinRM service is running: `Get-Service WinRM`

2. **SSH Errors**:
   - Check SSH service: `Get-Service sshd`
   - Verify port 22 is open: `Test-NetConnection -Port 22`
   - Check SSH configuration: `C:\ProgramData\ssh\sshd_config`

3. **Authentication Errors**:
   - Verify credentials are correct
   - Check if user has remote management permissions
   - For domain accounts, use format: `DOMAIN\username`

### Tools Not Appearing
- Verify Docker image built successfully
- Check catalog and registry files
- Ensure Claude Desktop config includes custom catalog
- Restart Claude Desktop

### Performance Issues
- Check network connectivity between Docker and target servers
- Verify WinRM/SSH timeout settings
- Monitor server resource usage during operations

## Development

### Adding New Tools

1. Add the function to `windows_admin_server.py`
2. Decorate with `@mcp.tool()`
3. Update the catalog entry with the new tool name
4. Rebuild the Docker image

### Local Testing

```bash
# Set environment variables for testing
export WINDOWS_ADMIN_LOG_DIR="./logs"

# Run directly
python windows_admin_server.py

# Test MCP protocol
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | python windows_admin_server.py

# Test WinRM connection
python -c "from winrm import Session; s = Session('http://server:5985/wsman', auth=('user', 'pass')); print(s.run_ps('hostname').std_out)"
```

## Dependencies

- `mcp[cli]` - MCP server framework
- `pywinrm` - Windows Remote Management library
- `requests-ntlm` - NTLM authentication for WinRM
- `asyncssh` - Asynchronous SSH library for fallback
- `aiofiles` - Asynchronous file operations
- `httpx` - HTTP client library

## License

MIT License

## Changelog

### Version 2.0.0 (Latest)
- **Breaking Change**: Replaced simulated RDP with actual WinRM connections
- **New**: Added SSH PowerShell fallback support
- **New**: Automatic protocol selection (WinRM → SSH)
- **Improved**: Real connectivity testing instead of simulation
- **Enhanced**: Better error handling and logging

### Version 1.0.0
- Initial release with simulated RDP functionality