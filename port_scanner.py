import asyncio
import socket
import time
import struct
import os
import ipaddress
import requests
from scapy.all import IP, TCP, sr1
from queue import Queue
from vulnerabilities import HIGH_RISK_PORTS
from config import DEFAULT_TIMEOUT, MAX_CONCURRENT, BANNER_BUFFER_SIZE, NVD_API_KEY, NVD_API_URL, NVD_CACHE_TIMEOUT
from analyzer import analyze_results

# Cache for NVD API results
nvd_cache = {}
cache_timestamps = {}

async def check_nvd_vulnerabilities(banner):
    """
    Check for vulnerabilities using NVD API based on banner.
    """
    if not banner or banner == "No banner received" or not NVD_API_KEY:
        return None
    
    # Check cache
    current_time = time.time()
    if banner in nvd_cache and (current_time - cache_timestamps.get(banner, 0)) < NVD_CACHE_TIMEOUT:
        return nvd_cache[banner]
    
    try:
        headers = {"apiKey": NVD_API_KEY}
        # Extract software and version from banner (simplified parsing)
        parts = banner.split('/')
        if len(parts) < 2:
            return None
        software = parts[0].lower()
        version = parts[1].split(' ')[0]
        params = {"keywordSearch": f"{software} {version}"}
        
        response = requests.get(NVD_API_URL, headers=headers, params=params, timeout=5)
        response.raise_for_status()
        data = response.json()
        
        if data.get("vulnerabilities"):
            cve = data["vulnerabilities"][0]["cve"]
            cve_id = cve["id"]
            description = cve["descriptions"][0]["value"][:100] + "..." if len(cve["descriptions"][0]["value"]) > 100 else cve["descriptions"][0]["value"]
            result = f"{cve_id}: {description}"
            nvd_cache[banner] = result
            cache_timestamps[banner] = current_time
            return result
        return None
    except Exception:
        return None

async def scan_tcp_full(target_ip, port, timeout, progress_queue=None, total_tasks=1, tasks_completed=None, cancel_event=None):
    """
    Perform a full TCP connect scan with banner grabbing.
    """
    if cancel_event and cancel_event.is_set():
        raise asyncio.CancelledError("Scan cancelled")
    
    conn = None
    try:
        conn = asyncio.open_connection(target_ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        try:
            service = socket.getservbyport(port, "tcp")
        except:
            service = "Unknown"
        
        banner = None
        try:
            data = await asyncio.wait_for(reader.read(BANNER_BUFFER_SIZE), timeout=1.0)
            if data:
                banner = data.decode('utf-8', errors='ignore').strip()
                banner = banner.replace('\n', ' ').replace('\r', '')[:100]
        except (asyncio.TimeoutError, UnicodeDecodeError):
            banner = "No banner received"

        writer.close()
        await writer.wait_closed()
        result = {"port": port, "protocol": "TCP", "state": "open", "service": service, "banner": banner}
        if port in HIGH_RISK_PORTS:
            result["risk"] = HIGH_RISK_PORTS[port]
        vuln = await check_nvd_vulnerabilities(banner)
        if vuln:
            result["vuln"] = vuln
        if progress_queue and tasks_completed is not None:
            tasks_completed[0] += 1
            progress_queue.put(tasks_completed[0] / total_tasks)
        return result
    except (asyncio.TimeoutError, ConnectionRefusedError):
        return None
    finally:
        if conn and 'writer' in locals():
            writer.close()
            await writer.wait_closed()

async def scan_tcp_syn(target_ip, port, timeout, progress_queue=None, total_tasks=1, tasks_completed=None, cancel_event=None):
    """
    Perform a TCP SYN scan (requires root privileges).
    """
    if cancel_event and cancel_event.is_set():
        raise asyncio.CancelledError("Scan cancelled")
    
    try:
        packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=timeout, verbose=0)
        if response and response.haslayer(TCP) and response[TCP].flags == 18:
            try:
                service = socket.getservbyport(port, "tcp")
            except:
                service = "Unknown"
            result = {"port": port, "protocol": "TCP", "state": "open", "service": service, "banner": None}
            if port in HIGH_RISK_PORTS:
                result["risk"] = HIGH_RISK_PORTS[port]
            if progress_queue and tasks_completed is not None:
                tasks_completed[0] += 1
                progress_queue.put(tasks_completed[0] / total_tasks)
            return result
        return None
    except Exception:
        return None

async def scan_udp(target_ip, port, timeout, progress_queue=None, total_tasks=1, tasks_completed=None, cancel_event=None):
    """
    Perform a UDP scan.
    """
    if cancel_event and cancel_event.is_set():
        raise asyncio.CancelledError("Scan cancelled")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        loop = asyncio.get_event_loop()
        await loop.sock_sendto(sock, b'', (target_ip, port))
        try:
            data, _ = await asyncio.wait_for(
                loop.sock_recvfrom(sock, BANNER_BUFFER_SIZE), timeout=timeout
            )
            try:
                service = socket.getservbyport(port, "udp")
            except:
                service = "Unknown"
            result = {"port": port, "protocol": "UDP", "state": "open", "service": service, "banner": None}
            if progress_queue and tasks_completed is not None:
                tasks_completed[0] += 1
                progress_queue.put(tasks_completed[0] / total_tasks)
            return result
        except asyncio.TimeoutError:
            result = {"port": port, "protocol": "UDP", "state": "open|filtered", "service": "Unknown", "banner": None}
            if progress_queue and tasks_completed is not None:
                tasks_completed[0] += 1
                progress_queue.put(tasks_completed[0] / total_tasks)
            return result
    except Exception:
        return None
    finally:
        sock.close()

async def scan_port(target_ip, port, protocol="TCP", timeout=DEFAULT_TIMEOUT, scan_type="Full Connect", progress_queue=None, total_tasks=1, tasks_completed=None, cancel_event=None):
    """
    Wrapper function to select the appropriate scan method.
    """
    if cancel_event and cancel_event.is_set():
        raise asyncio.CancelledError("Scan cancelled")
    
    if protocol == "TCP":
        if scan_type == "SYN Scan":
            return await scan_tcp_syn(target_ip, port, timeout, progress_queue, total_tasks, tasks_completed, cancel_event)
        return await scan_tcp_full(target_ip, port, timeout, progress_queue, total_tasks, tasks_completed, cancel_event)
    elif protocol == "UDP":
        return await scan_udp(target_ip, port, timeout, progress_queue, total_tasks, tasks_completed, cancel_event)
    return None

async def detect_os(target_ip, timeout=2.0, cancel_event=None):
    """
    Attempt to detect the OS based on ICMP ping TTL value.
    """
    if cancel_event and cancel_event.is_set():
        raise asyncio.CancelledError("Scan cancelled")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.setblocking(False)
        icmp_type = 8
        icmp_code = 0
        icmp_checksum = 0
        icmp_id = os.getpid() & 0xFFFF
        icmp_seq = 1
        header = struct.pack("bbHHh", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
        checksum = 0
        for i in range(0, len(header), 2):
            checksum += (header[i] << 8) + header[i + 1]
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum = ~checksum & 0xFFFF
        header = struct.pack("bbHHh", icmp_type, icmp_code, checksum, icmp_id, icmp_seq)
        loop = asyncio.get_event_loop()
        await loop.sock_sendto(sock, header, (target_ip, 0))
        try:
            start_time = time.time()
            while time.time() - start_time < timeout:
                data, addr = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 1024), timeout=timeout
                )
                ttl = data[8]
                icmp_header = data[20:28]
                icmp_type, _, _, _, _ = struct.unpack("bbHHh", icmp_header)
                if icmp_type == 0:
                    sock.close()
                    if ttl <= 64:
                        return {"os": "Likely Linux/Unix", "ttl": ttl}
                    elif ttl <= 128:
                        return {"os": "Likely Windows", "ttl": ttl}
                    elif ttl <= 255:
                        return {"os": "Likely Solaris/AIX", "ttl": ttl}
                    return {"os": "Unknown", "ttl": ttl}
        except asyncio.TimeoutError:
            sock.close()
            return {"os": "No ICMP response (host may block pings)", "ttl": None}
        finally:
            sock.close()
    except PermissionError:
        return {"os": "Requires root/admin privileges for raw socket", "ttl": None}
    except Exception as e:
        return {"os": f"Failed ({str(e)})", "ttl": None}

def cidr_to_ips(cidr):
    """
    Convert CIDR notation to a list of IP addresses.
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError as e:
        raise ValueError(f"Invalid CIDR notation: {e}")

async def scan_host(target_ip, start_port, end_port, protocol, timeout, scan_type, semaphore, progress_queue=None, total_tasks=1, tasks_completed=None, cancel_event=None):
    """
    Scan a single host for ports and perform OS detection.
    """
    if cancel_event and cancel_event.is_set():
        raise asyncio.CancelledError("Scan cancelled")
    
    async with semaphore:
        os_result = await detect_os(target_ip, timeout, cancel_event)
        results = [{"host": target_ip}, os_result]
        tasks = []
        for port in range(start_port, end_port + 1):
            tasks.append(scan_port(target_ip, port, protocol, timeout, scan_type, progress_queue, total_tasks, tasks_completed, cancel_event))
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)
        results.extend([r for r in scan_results if r])
        return results

async def run_scan(target, start_port, end_port, protocol="TCP", timeout=DEFAULT_TIMEOUT, scan_type="Full Connect", progress_queue=None, total_tasks=1, cancel_event=None):
    """
    Main scanning function to handle single IP or CIDR range.
    """
    if cancel_event and cancel_event.is_set():
        raise asyncio.CancelledError("Scan cancelled")
    
    results = []
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    tasks_completed = [0]
    try:
        if '/' in target:
            ip_list = cidr_to_ips(target)
        else:
            ip = socket.gethostbyname(target)
            ip_list = [ip]
    except (ValueError, socket.gaierror) as e:
        return [{"error": f"Invalid target or could not resolve: {e}"}]
    
    tasks = []
    for ip in ip_list:
        task = scan_host(ip, start_port, end_port, protocol, timeout, scan_type, semaphore, progress_queue, total_tasks, tasks_completed, cancel_event)
        tasks.append(task)
    
    try:
        host_results = await asyncio.gather(*tasks, return_exceptions=True)
        for host_result in host_results:
            if isinstance(host_result, list):
                results.extend(host_result)
    except asyncio.CancelledError:
        results.append({"error": "Scan was cancelled"})
    
    return results

# Test run (CLI)
if __name__ == "__main__":
    async def main():
        target = input("Enter target (IP, domain, or CIDR): ")
        protocol = input("Protocol (TCP/UDP): ").upper()
        start = int(input("Start port: "))
        end = int(input("End port: "))
        scan_type = input("Scan type (Full Connect/SYN Scan): ")
        timeout = float(input("Timeout (seconds): "))
        start_time = time.time()
        cancel_event = asyncio.Event()
        results = await run_scan(target, start, end, protocol, timeout, scan_type, cancel_event=cancel_event)
        for r in results:
            print(r)
        analysis = analyze_results(results)
        print("\nSecurity Analysis:")
        for key, value in analysis.items():
            print(f"{key}: {value}")
        print(f"\nScan finished in {time.time() - start_time:.2f} seconds.")
    asyncio.run(main())