#!/usr/bin/env python3
"""
Windows Admin MCP Server - Remote Windows server administration via WinRM/SSH
Supports both WinRM (primary) and PowerShell over SSH (fallback)
"""
import os
import sys
import logging
import json
import subprocess
import asyncio
import tempfile
import shlex
import base64
from datetime import datetime
from pathlib import Path
import aiofiles
from mcp.server.fastmcp import FastMCP

# Try to import WinRM
try:
    from winrm import Session
    from winrm.exceptions import WinRMError, WinRMTransportError
    WINRM_AVAILABLE = True
except ImportError:
    WINRM_AVAILABLE = False
    logging.warning("pywinrm not available, will fall back to SSH if needed")

# Try to import asyncssh for SSH fallback
try:
    import asyncssh
    SSH_AVAILABLE = True
except ImportError:
    SSH_AVAILABLE = False
    logging.warning("asyncssh not available for SSH fallback")

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
WINRM_PORT = 5985  # HTTP
WINRM_HTTPS_PORT = 5986  # HTTPS
SSH_PORT = 22
DEFAULT_TIMEOUT = 30

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

async def execute_winrm_command(hostname: str, username: str, password: str, command: str, use_https: bool = False):
    """Execute PowerShell command via WinRM."""
    if not WINRM_AVAILABLE:
        raise Exception("WinRM not available - pywinrm not installed")
    
    try:
        # Construct WinRM URL
        protocol = 'https' if use_https else 'http'
        port = WINRM_HTTPS_PORT if use_https else WINRM_PORT
        url = f'{protocol}://{hostname}:{port}/wsman'
        
        # Create WinRM session
        # Try with NTLM authentication first (most common for Windows domains)
        session = Session(
            url,
            auth=(username, password),
            transport='ntlm',
            server_cert_validation='ignore' if use_https else 'validate',
            read_timeout_sec=DEFAULT_TIMEOUT,
            operation_timeout_sec=DEFAULT_TIMEOUT
        )
        
        # Execute PowerShell command
        result = session.run_ps(command)
        
        return {
            'stdout': result.std_out.decode('utf-8', errors='ignore'),
            'stderr': result.std_err.decode('utf-8', errors='ignore'),
            'status': result.status_code
        }
        
    except WinRMTransportError as e:
        # Try with basic auth if NTLM fails
        try:
            session = Session(
                url,
                auth=(username, password),
                transport='basic',
                server_cert_validation='ignore' if use_https else 'validate',
                read_timeout_sec=DEFAULT_TIMEOUT,
                operation_timeout_sec=DEFAULT_TIMEOUT
            )
            result = session.run_ps(command)
            return {
                'stdout': result.std_out.decode('utf-8', errors='ignore'),
                'stderr': result.std_err.decode('utf-8', errors='ignore'),
                'status': result.status_code
            }
        except Exception as e2:
            logger.error(f"WinRM transport error: {e}, Basic auth also failed: {e2}")
            raise Exception(f"WinRM connection failed: {e}")
    except Exception as e:
        logger.error(f"WinRM execution error: {e}")
        raise

async def execute_ssh_powershell(hostname: str, username: str, password: str, command: str):
    """Execute PowerShell command via SSH (fallback method)."""
    if not SSH_AVAILABLE:
        raise Exception("SSH not available - asyncssh not installed")
    
    try:
        # Connect via SSH
        async with asyncssh.connect(
            hostname,
            port=SSH_PORT,
            username=username,
            password=password,
            known_hosts=None,
            client_keys=None
        ) as conn:
            # Execute PowerShell command via SSH
            # Windows OpenSSH server runs PowerShell by default, but we'll be explicit
            ps_command = f'powershell.exe -NoProfile -NonInteractive -Command "{command}"'
            result = await conn.run(ps_command, timeout=DEFAULT_TIMEOUT)
            
            return {
                'stdout': result.stdout,
                'stderr': result.stderr,
                'status': result.exit_status
            }
    except Exception as e:
        logger.error(f"SSH PowerShell execution error: {e}")
        raise

async def execute_remote_powershell(hostname: str, username: str, password: str, command: str, prefer_winrm: bool = True):
    """Execute PowerShell command remotely, trying WinRM first, then SSH."""
    errors = []
    
    # Try WinRM first if available and preferred
    if prefer_winrm and WINRM_AVAILABLE:
        try:
            logger.info(f"Attempting WinRM connection to {hostname}")
            # Try HTTP first
            result = await asyncio.get_event_loop().run_in_executor(
                None, 
                lambda: asyncio.run(execute_winrm_command(hostname, username, password, command, False))
            )
            await write_log(hostname, f"Command executed via WinRM (HTTP): {command[:50]}")
            return result
        except Exception as e:
            errors.append(f"WinRM HTTP: {str(e)}")
            # Try HTTPS
            try:
                result = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: asyncio.run(execute_winrm_command(hostname, username, password, command, True))
                )
                await write_log(hostname, f"Command executed via WinRM (HTTPS): {command[:50]}")
                return result
            except Exception as e2:
                errors.append(f"WinRM HTTPS: {str(e2)}")
    
    # Try SSH as fallback
    if SSH_AVAILABLE:
        try:
            logger.info(f"Attempting SSH PowerShell connection to {hostname}")
            result = await execute_ssh_powershell(hostname, username, password, command)
            await write_log(hostname, f"Command executed via SSH: {command[:50]}")
            return result
        except Exception as e:
            errors.append(f"SSH: {str(e)}")
    
    # If all methods failed
    error_msg = "All remote execution methods failed:\n" + "\n".join(errors)
    raise Exception(error_msg)

# === MCP TOOLS ===

@mcp.tool()
async def test_connection(hostname: str = "", username: str = "", password: str = "") -> str:
    """Test connectivity to a Windows server using ping, WinRM, and SSH."""
    if not hostname.strip():
        return "❌ Error: Hostname is required"
    
    await write_log(hostname, f"Testing connection to {hostname}")
    
    results = []
    
    try:
        # Test ping
        ping_result = subprocess.run(
            ["ping", "-c", "4", hostname],
            capture_output=True,
            text=True,
            timeout=10
        )
        ping_success = ping_result.returncode == 0
        results.append(f"Ping: {'✅ Successful' if ping_success else '❌ Failed'}")
        await write_log(hostname, f"Ping test: {'Success' if ping_success else 'Failed'}")
    except Exception as e:
        results.append(f"Ping: ❌ Error - {str(e)}")
    
    # Test WinRM port
    import socket
    for port, name in [(WINRM_PORT, "WinRM HTTP"), (WINRM_HTTPS_PORT, "WinRM HTTPS")]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            result = sock.connect_ex((hostname, port))
            port_open = result == 0
            results.append(f"{name} Port {port}: {'✅ Open' if port_open else '❌ Closed'}")
        except:
            results.append(f"{name} Port {port}: ❌ Error")
        finally:
            sock.close()
    
    # Test SSH port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        result = sock.connect_ex((hostname, SSH_PORT))
        ssh_open = result == 0
        results.append(f"SSH Port {SSH_PORT}: {'✅ Open' if ssh_open else '❌ Closed'}")
    except:
        results.append(f"SSH Port {SSH_PORT}: ❌ Error")
    finally:
        sock.close()
    
    # Test actual connection if credentials provided
    if username.strip() and password.strip():
        try:
            # Try a simple command
            test_result = await execute_remote_powershell(
                hostname, username, password, 
                "$env:COMPUTERNAME",
                prefer_winrm=True
            )
            if test_result['status'] == 0:
                results.append(f"Remote PowerShell: ✅ Connected as {username}")
                results.append(f"Computer Name: {test_result['stdout'].strip()}")
            else:
                results.append(f"Remote PowerShell: ⚠️ Connected but command failed")
        except Exception as e:
            results.append(f"Remote PowerShell: ❌ {str(e)[:100]}")
    
    await write_log(hostname, "Connection test completed")
    
    return f"""🌐 Connection Test Results for {hostname}:

""" + "\n".join(results) + f"""

📁 Logs saved to: {hostname}-{datetime.now().strftime('%m%d%Y')}.log"""

@mcp.tool()
async def diagnose_system(hostname: str = "", username: str = "", password: str = "", issue_description: str = "") -> str:
    """Diagnose system issues by gathering comprehensive system information."""
    if not hostname.strip() or not username.strip() or not password.strip():
        return "❌ Error: Hostname, username, and password are required"
    
    await write_log(hostname, f"Starting system diagnosis - Issue: {issue_description}")
    
    try:
        diagnostics = {}
        
        # System information commands
        commands = {
            "OS Info": "Get-WmiObject Win32_OperatingSystem | Select Caption, Version, BuildNumber, LastBootUpTime | Format-List",
            "CPU Usage": "Get-WmiObject Win32_Processor | Select LoadPercentage, Name | Format-List",
            "Memory Usage": "Get-WmiObject Win32_OperatingSystem | Select TotalVisibleMemorySize, FreePhysicalMemory | Format-List",
            "Disk Space": "Get-WmiObject Win32_LogicalDisk -Filter 'DriveType=3' | Select DeviceID, Size, FreeSpace | Format-Table",
            "Running Services": "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select -First 10 Name, DisplayName | Format-Table",
            "Event Log Errors": "Get-EventLog -LogName System -EntryType Error -Newest 5 | Select TimeGenerated, Source, Message | Format-List"
        }
        
        for name, command in commands.items():
            try:
                result = await execute_remote_powershell(hostname, username, password, command)
                diagnostics[name] = result['stdout'] if result['status'] == 0 else f"Error: {result['stderr']}"
                await write_log(hostname, f"Executed diagnostic: {name}")
            except Exception as e:
                diagnostics[name] = f"Failed to execute: {str(e)}"
        
        # Analyze for specific issues if description provided
        if issue_description.strip():
            if "crash" in issue_description.lower() or "stop" in issue_description.lower():
                # Check application event logs
                app_cmd = "Get-EventLog -LogName Application -EntryType Error -Newest 10 | Select TimeGenerated, Source, Message | Format-List"
                try:
                    app_logs = await execute_remote_powershell(hostname, username, password, app_cmd)
                    diagnostics["Application Errors"] = app_logs['stdout']
                    await write_log(hostname, "Checked application event logs for crashes")
                except Exception as e:
                    diagnostics["Application Errors"] = f"Failed: {str(e)}"
        
        await write_log(hostname, "System diagnosis completed")
        
        # Format results
        output = f"📊 System Diagnostics for {hostname}:\n\n"
        for category, data in diagnostics.items():
            output += f"=== {category} ===\n{data[:500]}...\n\n" if len(data) > 500 else f"=== {category} ===\n{data}\n\n"
        
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
        if command_type.lower() == "cmd":
            # Wrap CMD command for execution via PowerShell
            full_command = f"cmd /c {command}"
        else:
            # Execute as PowerShell command (default)
            full_command = command
        
        result = await execute_remote_powershell(hostname, username, password, full_command)
        
        output = result['stdout']
        error = result['stderr']
        status_code = result['status']
        
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
    """Check the status of a specific Windows service."""
    if not all([hostname.strip(), username.strip(), password.strip(), service_name.strip()]):
        return "❌ Error: All parameters are required"
    
    await write_log(hostname, f"Checking service: {service_name}")
    
    try:
        # Get service status
        status_cmd = f"Get-Service -Name '{service_name}' -ErrorAction Stop | Select Name, Status, DisplayName, StartType | Format-List"
        result = await execute_remote_powershell(hostname, username, password, status_cmd)
        
        if result['status'] != 0 or "Cannot find" in result['stderr']:
            await write_log(hostname, f"Service {service_name} not found")
            return f"❌ Service '{service_name}' not found. Error: {result['stderr']}"
        
        # Get service dependencies
        deps_cmd = f"Get-Service -Name '{service_name}' | Select -ExpandProperty DependentServices -ErrorAction SilentlyContinue | Select Name, Status | Format-Table"
        deps_result = await execute_remote_powershell(hostname, username, password, deps_cmd)
        
        await write_log(hostname, f"Service {service_name} status retrieved")
        
        return f"""🔧 Service Status for '{service_name}' on {hostname}:

{result['stdout']}

Dependent Services:
{deps_result['stdout'] if deps_result['status'] == 0 else 'None or error retrieving'}

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
        findings = []
        
        # Check if process is running
        process_cmd = f"Get-Process -Name '*{app_name}*' -ErrorAction SilentlyContinue | Select Name, Id, CPU, WorkingSet | Format-Table"
        process_result = await execute_remote_powershell(hostname, username, password, process_cmd)
        
        if process_result['stdout'].strip() and "Name" in process_result['stdout']:
            findings.append(f"✅ Application processes found:\n{process_result['stdout']}")
        else:
            findings.append(f"❌ No running processes found for '{app_name}'")
        
        await write_log(hostname, f"Process check completed for {app_name}")
        
        # Check application event logs
        event_cmd = f"Get-EventLog -LogName Application -Newest 20 | Where-Object {{$_.Source -like '*{app_name}*' -or $_.Message -like '*{app_name}*'}} | Select -First 5 TimeGenerated, EntryType, Message | Format-List"
        event_result = await execute_remote_powershell(hostname, username, password, event_cmd)
        
        if event_result['stdout'].strip():
            findings.append(f"📋 Recent application events:\n{event_result['stdout'][:1000]}")
        
        # Check Windows Error Reporting
        wer_cmd = f"Get-EventLog -LogName Application -Source 'Application Error' -Newest 10 | Where-Object {{$_.Message -like '*{app_name}*'}} | Select -First 3 TimeGenerated, Message | Format-List"
        wer_result = await execute_remote_powershell(hostname, username, password, wer_cmd)
        
        if wer_result['stdout'].strip():
            findings.append(f"⚠️ Windows Error Reports:\n{wer_result['stdout'][:1000]}")
        
        await write_log(hostname, f"Event log check completed for {app_name}")
        
        # Check application installation
        install_cmd = f"Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Where-Object {{$_.DisplayName -like '*{app_name}*'}} | Select DisplayName, InstallLocation, DisplayVersion | Format-List"
        install_result = await execute_remote_powershell(hostname, username, password, install_cmd)
        
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
    """Apply a PowerShell solution script to fix identified issues."""
    if not all([hostname.strip(), username.strip(), password.strip(), solution_script.strip()]):
        return "❌ Error: All parameters are required"
    
    await write_log(hostname, f"Applying solution script")
    
    try:
        # Execute the solution script
        result = await execute_remote_powershell(hostname, username, password, solution_script)
        
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
    """Get current performance metrics from the Windows server."""
    if not all([hostname.strip(), username.strip(), password.strip()]):
        return "❌ Error: Hostname, username, and password are required"
    
    await write_log(hostname, f"Retrieving performance metrics")
    
    try:
        metrics = {}
        
        # CPU metrics
        cpu_cmd = "Get-WmiObject Win32_Processor | Select Name, LoadPercentage, NumberOfCores, MaxClockSpeed | Format-List"
        cpu_result = await execute_remote_powershell(hostname, username, password, cpu_cmd)
        metrics['CPU'] = cpu_result['stdout']
        
        # Memory metrics
        mem_cmd = """$OS = Get-WmiObject Win32_OperatingSystem
$TotalMem = [math]::Round($OS.TotalVisibleMemorySize/1048576, 2)
$FreeMem = [math]::Round($OS.FreePhysicalMemory/1048576, 2)
$UsedMem = $TotalMem - $FreeMem
$PercentUsed = [math]::Round(($UsedMem/$TotalMem)*100, 2)
Write-Output "Total Memory: $TotalMem GB"
Write-Output "Used Memory: $UsedMem GB"  
Write-Output "Free Memory: $FreeMem GB"
Write-Output "Memory Usage: $PercentUsed%"
"""
        mem_result = await execute_remote_powershell(hostname, username, password, mem_cmd)
        metrics['Memory'] = mem_result['stdout']
        
        # Disk metrics
        disk_cmd = """Get-WmiObject Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
    $SizeGB = [math]::Round($_.Size/1073741824, 2)
    $FreeGB = [math]::Round($_.FreeSpace/1073741824, 2)
    $UsedGB = $SizeGB - $FreeGB
    $PercentFree = if($_.Size -gt 0) {[math]::Round(($_.FreeSpace/$_.Size)*100, 2)} else {0}
    Write-Output "Drive $($_.DeviceID) - Total: $SizeGB GB, Used: $UsedGB GB, Free: $FreeGB GB ($PercentFree% free)"
}"""
        disk_result = await execute_remote_powershell(hostname, username, password, disk_cmd)
        metrics['Disk'] = disk_result['stdout']
        
        # Network metrics
        net_cmd = "Get-NetAdapterStatistics | Select Name, ReceivedBytes, SentBytes | Format-Table"
        net_result = await execute_remote_powershell(hostname, username, password, net_cmd)
        metrics['Network'] = net_result['stdout']
        
        # Top processes by CPU
        proc_cmd = "Get-Process | Sort-Object CPU -Descending | Select -First 5 Name, CPU, WorkingSet | Format-Table"
        proc_result = await execute_remote_powershell(hostname, username, password, proc_cmd)
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
    
    if WINRM_AVAILABLE:
        logger.info("✅ WinRM support available (primary method)")
    else:
        logger.warning("⚠️ WinRM not available - install pywinrm for WinRM support")
    
    if SSH_AVAILABLE:
        logger.info("✅ SSH PowerShell support available (fallback method)")
    else:
        logger.warning("⚠️ SSH not available - install asyncssh for SSH fallback")
    
    if not WINRM_AVAILABLE and not SSH_AVAILABLE:
        logger.error("❌ No remote execution methods available! Install pywinrm or asyncssh")
        sys.exit(1)
    
    try:
        mcp.run(transport='stdio')
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        sys.exit(1)
