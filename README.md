# Windows Admin MCP Server

A Model Context Protocol (MCP) server that provides remote Windows server administration and troubleshooting capabilities via RDP protocol and PowerShell command execution.

## Purpose

This MCP server provides a secure interface for AI assistants to remotely connect to Windows servers, diagnose issues, and apply solutions using PowerShell commands through the WinRM protocol.

## Features

### Current Implementation

- **`test_connection`** - Test connectivity to a Windows server using ping and RDP port check
- **`diagnose_system`** - Gather comprehensive system information to diagnose issues
- **`execute_command`** - Execute PowerShell or CMD commands on the remote server
- **`check_service`** - Check Windows service status and provide management options
- **`troubleshoot_application`** - Troubleshoot specific applications that are crashing or not working
- **`apply_solution`** - Apply PowerShell solution scripts to fix identified issues
- **`get_performance_metrics`** - Get current CPU, memory, disk, and network metrics
- **`view_logs`** - View troubleshooting logs for specific servers and dates

## Prerequisites

- Docker Desktop with MCP Toolkit enabled
- Docker MCP CLI plugin (`docker mcp` command)
- Target Windows servers must have:
  - WinRM enabled and configured
  - PowerShell remoting enabled
  - Appropriate firewall rules for WinRM (port 5985/5986)
  - Network connectivity from the Docker container

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
    description: "Remote Windows server administration and troubleshooting"
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

- "Test connection to server 192.168.1.100"
- "Diagnose why the 'Flying Doghouse' application is crashing on server SNOOPY"
- "Check the status of the Windows Update service on server PROD-WEB-01"
- "Get performance metrics from server DB-SERVER-02 using credentials admin/password"
- "Execute Get-Process command on server APP-SERVER with my credentials"
- "Troubleshoot why IIS is not starting on WEB-SERVER-01"
- "Apply a solution to restart the Print Spooler service on PRINT-SERVER"
- "Show me the logs for server SNOOPY from today"

## Architecture

```
Claude Desktop → MCP Gateway → Windows Admin MCP Server → WinRM → Windows Servers
                                           ↓
                                     Local Log Files
                              (/app/logs/hostname-MMDDYYYY.log)
```

## Log Management

The server automatically creates daily log files for each server:
- Format: `{hostname}-{MMDDYYYY}.log`
- Location: Configurable via `WINDOWS_ADMIN_LOG_DIR` environment variable
- Default: `/app/logs` in the container
- Contains timestamped entries of all operations performed

## Security Considerations

- Credentials are passed in real-time and not stored
- All connections use WinRM protocol with NTLM authentication
- Log files contain operation history but no passwords
- Running as non-root user in Docker container
- Consider using HTTPS WinRM (port 5986) for production
- Implement credential management integration with your secret server

## Troubleshooting

### WinRM Connection Issues
1. Enable WinRM on target server: `winrm quickconfig`
2. Set trusted hosts: `Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*"`
3. Check firewall rules for ports 5985/5986
4. Verify network connectivity from Docker container

### Tools Not Appearing
- Verify Docker image built successfully
- Check catalog and registry files
- Ensure Claude Desktop config includes custom catalog
- Restart Claude Desktop

### Authentication Errors
- Verify credentials are correct
- Check if user has remote management permissions
- Ensure WinRM service is running on target server

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
```

## License

MIT License