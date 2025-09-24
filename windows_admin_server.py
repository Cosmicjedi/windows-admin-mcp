#!/usr/bin/env python3
"""
Windows Admin MCP Server - Remote Windows server administration and troubleshooting
"""
import os
import sys
import logging
import json
import subprocess
import asyncio
from datetime import datetime
from pathlib import Path
import aiofiles
from mcp.server.fastmcp import FastMCP
from winrm.protocol import Protocol
import paramiko

# Configure logging to stderr
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger("windows-admin-server")

# Initialize MCP server
mcp = FastMCP("windows-admin")

# Configuration
LOG_DIR = os.environ.get("WINDOWS_ADMIN_LOG_DIR", "/app/logs")
RDP_PORT = 3389
WINRM_PORT = 5985
WINRM_HTTPS_PORT = 5986

# Ensure log directory exists
Path(LOG_DIR).mkdir(parents=True, exist_ok=True)

# === UTILITY FUNCTIONS ===

async def write_log(hostname: str, message: str):
    """Write timestamped log entry to hostname-specific log file."""
    try:
        date_str = datetime.now().strftime("%m%d%Y")
        log_file = Path(LOG_DIR) / f"{hostname}-{date_str}.log"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        async with aiofiles.open(log_file, 'a') as f:
            await f.write(log_entry)
        
        logger.info(f"Logged to {log_file}: {message}")
    except Exception as e:
        logger.error(f"Failed to write log: {e}")

def establish_winrm_connection(hostname: str, username: str, password: str):
    """Establish WinRM connection to Windows server."""
    try:
        endpoint = f"http://{hostname}:{WINRM_PORT}/wsman"
        protocol = Protocol(
            endpoint=endpoint,
            transport='ntlm',
            username=username,
            password=password,
            server_cert_validation='ignore'
        )
        return protocol
    except Exception as e:
        logger.error(f"WinRM connection failed: {e}")
        return None

async def execute_powershell_command(protocol, command: str):
    """Execute PowerShell command via WinRM."""
    try:
        shell_id = protocol.open_shell()
        command_id = protocol.run_command(shell_id, 'powershell', ['-Command', command])
        std_out, std_err, status_code = protocol.get_command_output(shell_id, command_id)
        protocol.cleanup_command(shell_id, command_id)
        protocol.close_shell(shell_id)
        
        return {
            'stdout': std_out.decode('utf-8') if std_out else '',
            'stderr': std_err.decode('utf-8') if std_err else '',
            'status': status_code
        }
    except Exception as e:
        return {
            'stdout': '',
            'stderr': str(e),
            'status': -1
        }

# === MCP TOOLS ===

@mcp.tool()
async def test_connection(hostname: str = "", username: str = "", password: str = "") -> str:
    """Test connectivity to a Windows server using ping and RDP port check."""
    if not hostname.strip():
        return "❌ Error: Hostname is required"
    
    await write_log(hostname, f"Testing connection to {hostname}")
    
    try:
        # Test ping
        ping_result = subprocess.run(
            ["ping", "-c", "4", hostname],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        ping_success = ping_result.returncode == 0
        await write_log(hostname, f"Ping test: {'Success' if ping_success else 'Failed'}")
        
        # Test RDP port
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        rdp_result = sock.connect_ex((hostname, RDP_PORT))
        sock.close()
        
        rdp_open = rdp_result == 0
        await write_log(hostname, f"RDP port {RDP_PORT}: {'Open' if rdp_open else 'Closed'}")
        
        # Test WinRM if credentials provided
        winrm_status = "Not tested (no credentials)"
        if username.strip() and password.strip():
            protocol = establish_winrm_connection(hostname, username, password)
            if protocol:
                winrm_status = "✅ Connected"
                await write_log(hostname, "WinRM connection successful")
            else:
                winrm_status = "❌ Failed"
                await write_log(hostname, "WinRM connection failed")
        
        return f"""🌐 Connection Test Results for {hostname}:
- Ping: {'✅ Successful' if ping_success else '❌ Failed'}
- RDP Port {RDP_PORT}: {'✅ Open' if rdp_open else '❌ Closed'}
- WinRM: {winrm_status}

Logs saved to: {hostname}-{datetime.now().strftime('%m%d%Y')}.log"""
        
    except Exception as e:
        await write_log(hostname, f"Connection test error: {str(e)}")
        return f"❌ Connection test error: {str(e)}"

@mcp.tool()
async def diagnose_system(hostname: str = "", username: str = "", password: str = "", issue_description: str = "") -> str:
    """Diagnose system issues by gathering comprehensive system information."""
    if not hostname.strip() or not username.strip() or not password.strip():
        return "❌ Error: Hostname, username, and password are required"
    
    await write_log(hostname, f"Starting system diagnosis - Issue: {issue_description}")
    
    try:
        protocol = establish_winrm_connection(hostname, username, password)
        if not protocol:
            return "❌ Failed to establish WinRM connection"
        
        diagnostics = {}
        
        # System information
        commands = {
            "OS Info": "Get-WmiObject Win32_OperatingSystem | Select Caption, Version, BuildNumber, LastBootUpTime",
            "CPU Usage": "Get-WmiObject Win32_Processor | Select LoadPercentage, Name",
            "Memory Usage": "Get-WmiObject Win32_OperatingSystem | Select TotalVisibleMemorySize, FreePhysicalMemory",
            "Disk Space": "Get-WmiObject Win32_LogicalDisk -Filter 'DriveType=3' | Select DeviceID, Size, FreeSpace",
            "Running Services": "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select -First 10 Name, DisplayName",
            "Event Log Errors": "Get-EventLog -LogName System -EntryType Error -Newest 5 | Select TimeGenerated, Source, Message",
            "Network Config": "Get-NetIPConfiguration | Select InterfaceAlias, IPv4Address, IPv6Address"
        }
        
        for name, command in commands.items():
            result = await execute_powershell_command(protocol, command)
            diagnostics[name] = result['stdout'] if result['status'] == 0 else result['stderr']
            await write_log(hostname, f"Executed diagnostic: {name}")
        
        # Analyze for specific issues if description provided
        if issue_description.strip():
            if "crash" in issue_description.lower() or "stop" in issue_description.lower():
                # Check application event logs
                app_logs = await execute_powershell_command(
                    protocol,
                    "Get-EventLog -LogName Application -EntryType Error -Newest 10 | Select TimeGenerated, Source, Message"
                )
                diagnostics["Application Errors"] = app_logs['stdout']
                await write_log(hostname, "Checked application event logs for crashes")
        
        await write_log(hostname, "System diagnosis completed")
        
        # Format results
        output = f"📊 System Diagnostics for {hostname}:\n\n"
        for category, data in diagnostics.items():
            output += f"=== {category} ===\n{data[:500]}...\n\n"  # Truncate long outputs
        
        output += f"\n📁 Full logs saved to: {hostname}-{datetime.now().strftime('%m%d%Y')}.log"
        
        return output
        
    except Exception as e:
        await write_log(hostname, f"Diagnosis error: {str(e)}")
        return f"❌ Diagnosis error: {str(e)}"

@mcp.tool()
async def execute_command(hostname: str = "", username: str = "", password: str = "", command: str = "", command_type: str = "powershell") -> str:
    """Execute a PowerShell or CMD command on the remote Windows server."""
    if not all([hostname.strip(), username.strip(), password.strip(), command.strip()]):
        return "❌ Error: All parameters (hostname, username, password, command) are required"
    
    await write_log(hostname, f"Executing {command_type} command: {command}")
    
    try:
        protocol = establish_winrm_connection(hostname, username, password)
        if not protocol:
            return "❌ Failed to establish WinRM connection"
        
        if command_type.lower() == "cmd":
            # Execute as CMD command
            shell_id = protocol.open_shell()
            command_id = protocol.run_command(shell_id, 'cmd', ['/c', command])
            std_out, std_err, status_code = protocol.get_command_output(shell_id, command_id)
            protocol.cleanup_command(shell_id, command_id)
            protocol.close_shell(shell_id)
        else:
            # Execute as PowerShell command (default)
            result = await execute_powershell_command(protocol, command)
            std_out = result['stdout'].encode('utf-8')
            std_err = result['stderr'].encode('utf-8')
            status_code = result['status']
        
        output = std_out.decode('utf-8') if std_out else ''
        error = std_err.decode('utf-8') if std_err else ''
        
        await write_log(hostname, f"Command executed with status {status_code}")
        
        if status_code == 0:
            return f"✅ Command executed successfully:\n\nOutput:\n{output}"
        else:
            return f"⚠️ Command completed with status {status_code}:\n\nOutput:\n{output}\n\nError:\n{error}"
        
    except Exception as e:
        await write_log(hostname, f"Command execution error: {str(e)}")
        return f"❌ Command execution error: {str(e)}"

@mcp.tool()
async def check_service(hostname: str = "", username: str = "", password: str = "", service_name: str = "") -> str:
    """Check the status of a specific Windows service and provide options to manage it."""
    if not all([hostname.strip(), username.strip(), password.strip(), service_name.strip()]):
        return "❌ Error: All parameters are required"
    
    await write_log(hostname, f"Checking service: {service_name}")
    
    try:
        protocol = establish_winrm_connection(hostname, username, password)
        if not protocol:
            return "❌ Failed to establish WinRM connection"
        
        # Get service status
        status_cmd = f"Get-Service -Name '{service_name}' | Select Name, Status, DisplayName, StartType"
        result = await execute_powershell_command(protocol, status_cmd)
        
        if result['status'] != 0:
            await write_log(hostname, f"Service {service_name} not found")
            return f"❌ Service '{service_name}' not found. Error: {result['stderr']}"
        
        # Get service dependencies
        deps_cmd = f"Get-Service -Name '{service_name}' | Select -ExpandProperty DependentServices | Select Name, Status"
        deps_result = await execute_powershell_command(protocol, deps_cmd)
        
        await write_log(hostname, f"Service {service_name} status retrieved")
        
        return f"""🔧 Service Status for '{service_name}' on {hostname}:

{result['stdout']}

Dependent Services:
{deps_result['stdout'] if deps_result['status'] == 0 else 'None'}

Available actions:
- To start: execute_command with 'Start-Service -Name {service_name}'
- To stop: execute_command with 'Stop-Service -Name {service_name}'
- To restart: execute_command with 'Restart-Service -Name {service_name}'"""
        
    except Exception as e:
        await write_log(hostname, f"Service check error: {str(e)}")
        return f"❌ Service check error: {str(e)}"

@mcp.tool()
async def troubleshoot_application(hostname: str = "", username: str = "", password: str = "", app_name: str = "") -> str:
    """Troubleshoot a specific application that is crashing or not working properly."""
    if not all([hostname.strip(), username.strip(), password.strip(), app_name.strip()]):
        return "❌ Error: All parameters are required"
    
    await write_log(hostname, f"Troubleshooting application: {app_name}")
    
    try:
        protocol = establish_winrm_connection(hostname, username, password)
        if not protocol:
            return "❌ Failed to establish WinRM connection"
        
        findings = []
        
        # Check if process is running
        process_cmd = f"Get-Process -Name '*{app_name}*' -ErrorAction SilentlyContinue | Select Name, Id, CPU, WorkingSet"
        process_result = await execute_powershell_command(protocol, process_cmd)
        
        if process_result['stdout'].strip():
            findings.append(f"✅ Application processes found:\n{process_result['stdout']}")
        else:
            findings.append(f"❌ No running processes found for '{app_name}'")
        
        await write_log(hostname, f"Process check completed for {app_name}")
        
        # Check application event logs
        event_cmd = f"Get-EventLog -LogName Application -Source '*{app_name}*' -Newest 10 -ErrorAction SilentlyContinue | Select TimeGenerated, EntryType, Message"
        event_result = await execute_powershell_command(protocol, event_cmd)
        
        if event_result['stdout'].strip():
            findings.append(f"📋 Recent application events:\n{event_result['stdout'][:1000]}")
        
        # Check Windows Error Reporting
        wer_cmd = f"Get-WinEvent -FilterHashtable @{{LogName='Application'; ProviderName='Windows Error Reporting'}} -MaxEvents 5 | Where-Object {{$_.Message -like '*{app_name}*'}} | Select TimeCreated, Message"
        wer_result = await execute_powershell_command(protocol, wer_cmd)
        
        if wer_result['stdout'].strip():
            findings.append(f"⚠️ Windows Error Reports:\n{wer_result['stdout'][:1000]}")
        
        await write_log(hostname, f"Event log check completed for {app_name}")
        
        # Check application files/installation
        install_cmd = f"Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Where-Object {{$_.DisplayName -like '*{app_name}*'}} | Select DisplayName, InstallLocation, DisplayVersion"
        install_result = await execute_powershell_command(protocol, install_cmd)
        
        if install_result['stdout'].strip():
            findings.append(f"📦 Installation info:\n{install_result['stdout']}")
        
        # Provide recommendations
        recommendations = []
        if "No running processes" in ''.join(findings):
            recommendations.append("• Try starting the application service or executable")
        if "Error" in ''.join(findings) or "Exception" in ''.join(findings):
            recommendations.append("• Check application logs for specific error details")
            recommendations.append("• Consider reinstalling or updating the application")
            recommendations.append("• Check for missing dependencies or DLL files")
        
        await write_log(hostname, f"Troubleshooting completed for {app_name}")
        
        output = f"🔍 Troubleshooting Report for '{app_name}' on {hostname}:\n\n"
        output += "\n\n".join(findings)
        
        if recommendations:
            output += "\n\n💡 Recommendations:\n" + "\n".join(recommendations)
        
        output += f"\n\n📁 Full logs saved to: {hostname}-{datetime.now().strftime('%m%d%Y')}.log"
        
        return output
        
    except Exception as e:
        await write_log(hostname, f"Application troubleshooting error: {str(e)}")
        return f"❌ Troubleshooting error: {str(e)}"

@mcp.tool()
async def apply_solution(hostname: str = "", username: str = "", password: str = "", solution_script: str = "") -> str:
    """Apply a PowerShell solution script to fix identified issues on the Windows server."""
    if not all([hostname.strip(), username.strip(), password.strip(), solution_script.strip()]):
        return "❌ Error: All parameters are required"
    
    await write_log(hostname, f"Applying solution script")
    
    try:
        protocol = establish_winrm_connection(hostname, username, password)
        if not protocol:
            return "❌ Failed to establish WinRM connection"
        
        # Execute the solution script
        result = await execute_powershell_command(protocol, solution_script)
        
        await write_log(hostname, f"Solution script executed with status {result['status']}")
        await write_log(hostname, f"Script output: {result['stdout'][:500]}")
        
        if result['status'] == 0:
            return f"""✅ Solution successfully applied on {hostname}:

Script executed:
{solution_script[:500]}{'...' if len(solution_script) > 500 else ''}

Output:
{result['stdout']}

📁 Logs saved to: {hostname}-{datetime.now().strftime('%m%d%Y')}.log"""
        else:
            return f"""⚠️ Solution script completed with warnings:

Status code: {result['status']}

Output:
{result['stdout']}

Errors:
{result['stderr']}

📁 Logs saved to: {hostname}-{datetime.now().strftime('%m%d%Y')}.log"""
        
    except Exception as e:
        await write_log(hostname, f"Solution application error: {str(e)}")
        return f"❌ Solution application error: {str(e)}"

@mcp.tool()
async def get_performance_metrics(hostname: str = "", username: str = "", password: str = "") -> str:
    """Get current performance metrics from the Windows server including CPU, memory, disk, and network."""
    if not all([hostname.strip(), username.strip(), password.strip()]):
        return "❌ Error: Hostname, username, and password are required"
    
    await write_log(hostname, f"Retrieving performance metrics")
    
    try:
        protocol = establish_winrm_connection(hostname, username, password)
        if not protocol:
            return "❌ Failed to establish WinRM connection"
        
        metrics = {}
        
        # CPU metrics
        cpu_cmd = "Get-WmiObject Win32_Processor | Select Name, LoadPercentage, NumberOfCores, MaxClockSpeed"
        cpu_result = await execute_powershell_command(protocol, cpu_cmd)
        metrics['CPU'] = cpu_result['stdout']
        
        # Memory metrics
        mem_cmd = """$OS = Get-WmiObject Win32_OperatingSystem
$TotalMem = [math]::Round($OS.TotalVisibleMemorySize/1MB, 2)
$FreeMem = [math]::Round($OS.FreePhysicalMemory/1MB, 2)
$UsedMem = $TotalMem - $FreeMem
$PercentUsed = [math]::Round(($UsedMem/$TotalMem)*100, 2)
Write-Output "Total Memory: $TotalMem GB"
Write-Output "Used Memory: $UsedMem GB"
Write-Output "Free Memory: $FreeMem GB"
Write-Output "Memory Usage: $PercentUsed%"""
        mem_result = await execute_powershell_command(protocol, mem_cmd)
        metrics['Memory'] = mem_result['stdout']
        
        # Disk metrics
        disk_cmd = """Get-WmiObject Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
    $SizeGB = [math]::Round($_.Size/1GB, 2)
    $FreeGB = [math]::Round($_.FreeSpace/1GB, 2)
    $UsedGB = $SizeGB - $FreeGB
    $PercentFree = [math]::Round(($_.FreeSpace/$_.Size)*100, 2)
    Write-Output "Drive $($_.DeviceID) - Total: $SizeGB GB, Used: $UsedGB GB, Free: $FreeGB GB ($PercentFree% free)"
}"""
        disk_result = await execute_powershell_command(protocol, disk_cmd)
        metrics['Disk'] = disk_result['stdout']
        
        # Network metrics
        net_cmd = "Get-NetAdapterStatistics | Select Name, ReceivedBytes, SentBytes | Format-Table"
        net_result = await execute_powershell_command(protocol, net_cmd)
        metrics['Network'] = net_result['stdout']
        
        # Top processes by CPU
        proc_cmd = "Get-Process | Sort-Object CPU -Descending | Select -First 5 Name, CPU, WorkingSet | Format-Table"
        proc_result = await execute_powershell_command(protocol, proc_cmd)
        metrics['Top Processes'] = proc_result['stdout']
        
        await write_log(hostname, "Performance metrics retrieved successfully")
        
        output = f"📊 Performance Metrics for {hostname}:\n\n"
        for category, data in metrics.items():
            output += f"=== {category} ===\n{data}\n"
        
        output += f"\n📁 Logs saved to: {hostname}-{datetime.now().strftime('%m%d%Y')}.log"
        
        return output
        
    except Exception as e:
        await write_log(hostname, f"Performance metrics error: {str(e)}")
        return f"❌ Performance metrics error: {str(e)}"

@mcp.tool()
async def view_logs(hostname: str = "", date: str = "") -> str:
    """View the troubleshooting logs for a specific server and date."""
    if not hostname.strip():
        return "❌ Error: Hostname is required"
    
    try:
        if date.strip():
            log_file = Path(LOG_DIR) / f"{hostname}-{date}.log"
        else:
            date_str = datetime.now().strftime("%m%d%Y")
            log_file = Path(LOG_DIR) / f"{hostname}-{date_str}.log"
        
        if not log_file.exists():
            available_logs = list(Path(LOG_DIR).glob(f"{hostname}-*.log"))
            if available_logs:
                available = "\n".join([f.name for f in available_logs])
                return f"❌ Log file not found. Available logs:\n{available}"
            else:
                return f"❌ No logs found for {hostname}"
        
        async with aiofiles.open(log_file, 'r') as f:
            content = await f.read()
        
        # Return last 50 lines if log is too long
        lines = content.split('\n')
        if len(lines) > 50:
            content = '\n'.join(lines[-50:])
            return f"📋 Last 50 lines from {log_file.name}:\n\n{content}"
        else:
            return f"📋 Contents of {log_file.name}:\n\n{content}"
        
    except Exception as e:
        return f"❌ Error reading logs: {str(e)}"

# === SERVER STARTUP ===
if __name__ == "__main__":
    logger.info("Starting Windows Admin MCP server...")
    logger.info(f"Log directory: {LOG_DIR}")
    
    try:
        mcp.run(transport='stdio')
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        sys.exit(1)