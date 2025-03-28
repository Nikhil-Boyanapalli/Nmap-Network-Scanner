import nmap
import os
import logging
from datetime import datetime
from dotenv import load_dotenv
import socket
import subprocess
import sys
import ipaddress

class NetworkScanner:
    def __init__(self):
        logging.info("Initializing NetworkScanner")
        try:
            # Check if nmap is installed and accessible
            if sys.platform == 'win32':
                # On Windows, check both 'nmap' and 'nmap.exe'
                nmap_path = self._find_nmap_windows()
                if not nmap_path:
                    raise Exception("Nmap not found. Please install Nmap and ensure it's in your PATH")
                logging.info(f"Found Nmap at: {nmap_path}")
            else:
                # On Unix-like systems
                if not self._check_nmap_installed():
                    raise Exception("Nmap not found. Please install Nmap and ensure it's in your PATH")
            
            self.nm = nmap.PortScanner()
            logging.info("Nmap PortScanner initialized successfully")
            
            # Load environment variables
            load_dotenv()
            self.openvas_host = os.getenv('OPENVAS_HOST')
            self.openvas_user = os.getenv('OPENVAS_USER')
            self.openvas_password = os.getenv('OPENVAS_PASSWORD')
            
        except Exception as e:
            logging.error(f"Failed to initialize NetworkScanner: {str(e)}")
            raise

    @staticmethod
    def get_network_range():
        """
        Automatically detect the local network range
        Returns a CIDR notation string (e.g., '192.168.1.0/24')
        """
        try:
            # Get local hostname and IP
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            logging.info(f"Local IP detected: {local_ip}")

            if sys.platform == 'win32':
                # On Windows, use ipconfig to get the subnet mask
                try:
                    output = subprocess.check_output('ipconfig', shell=True).decode()
                    lines = output.split('\n')
                    subnet_mask = None
                    found_ip = False
                    
                    for line in lines:
                        if local_ip in line:
                            found_ip = True
                        if found_ip and 'Subnet Mask' in line:
                            subnet_mask = line.split(':')[-1].strip()
                            break
                    
                    if subnet_mask:
                        # Convert IP and subnet mask to CIDR notation
                        network = ipaddress.IPv4Network(f"{local_ip}/{subnet_mask}", strict=False)
                        logging.info(f"Detected network range: {network}")
                        return str(network)
                except:
                    pass

            # If we couldn't get the subnet mask or not on Windows,
            # use common network masks based on IP class
            ip_parts = local_ip.split('.')
            if len(ip_parts) == 4:
                # Common home/office network ranges
                if ip_parts[0] == '192' and ip_parts[1] == '168':
                    network = f"192.168.{ip_parts[2]}.0/24"
                elif ip_parts[0] == '10':
                    network = f"10.{ip_parts[1]}.{ip_parts[2]}.0/24"
                elif ip_parts[0] == '172' and 16 <= int(ip_parts[1]) <= 31:
                    network = f"172.{ip_parts[1]}.{ip_parts[2]}.0/24"
                else:
                    network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                
                logging.info(f"Using network range: {network}")
                return network
            
            raise Exception("Could not determine network range")
            
        except Exception as e:
            logging.error(f"Error detecting network range: {str(e)}")
            # Fallback to local network if detection fails
            return "192.168.1.0/24"

    def _ping_host(self, host):
        """Test if a host is responsive"""
        try:
            if sys.platform == "win32":
                cmd = ['ping', '-n', '1', '-w', '1000', host]
            else:
                cmd = ['ping', '-c', '1', '-W', '1', host]
            
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return result.returncode == 0
        except:
            return False

    def _find_nmap_windows(self):
        """Find nmap executable on Windows"""
        try:
            # Common installation paths
            common_paths = [
                "C:\\Program Files (x86)\\Nmap",
                "C:\\Program Files\\Nmap",
            ]
            
            # Check PATH
            path = os.environ.get("PATH", "").split(";")
            all_paths = common_paths + path
            
            for directory in all_paths:
                nmap_exe = os.path.join(directory, "nmap.exe")
                if os.path.exists(nmap_exe):
                    return nmap_exe
            
            return None
            
        except Exception as e:
            logging.error(f"Error while searching for nmap: {str(e)}")
            return None

    def _check_nmap_installed(self):
        """Check if nmap is installed on Unix-like systems"""
        try:
            subprocess.run(['nmap', '-V'], capture_output=True, check=True)
            return True
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def run_scan(self, target, scan_type):
        """
        Run the specified type of scan on the target
        """
        logging.info(f"Starting {scan_type} on target: {target}")
        scan_start_time = datetime.now()
        
        try:
            # Configure scan arguments based on scan type
            scan_args = self._get_scan_arguments(scan_type)
            logging.info(f"Using scan arguments: {scan_args}")
            
            # Run the scan
            logging.info("Initiating Nmap scan...")
            self.nm.scan(hosts=target, arguments=scan_args)
            logging.info("Nmap scan completed")
            
            # Process results
            results = {
                'target': target,
                'scan_type': scan_type,
                'scan_start_time': scan_start_time.isoformat(),
                'scan_end_time': datetime.now().isoformat(),
                'hosts': []
            }
            
            # Process each host
            for host in self.nm.all_hosts():
                logging.info(f"Processing results for host: {host}")
                host_info = {
                    'ip': host,
                    'state': self.nm[host].state(),
                    'ports': [],
                    'vulnerabilities': []
                }
                
                # Get OS information if available
                if 'osmatch' in self.nm[host]:
                    host_info['os'] = self.nm[host]['osmatch'][0]['name'] if self.nm[host]['osmatch'] else 'Unknown'
                    logging.info(f"Detected OS: {host_info['os']}")
                
                # Process ports and services
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        port_info = {
                            'port': port,
                            'state': self.nm[host][proto][port]['state'],
                            'service': self.nm[host][proto][port].get('name', 'unknown'),
                            'version': self.nm[host][proto][port].get('version', 'unknown'),
                            'product': self.nm[host][proto][port].get('product', 'unknown'),
                            'extrainfo': self.nm[host][proto][port].get('extrainfo', ''),
                            'cpe': self.nm[host][proto][port].get('cpe', [])
                        }
                        host_info['ports'].append(port_info)
                        logging.debug(f"Port {port}: {port_info['state']} - {port_info['service']}")

                # Process vulnerability scripts results
                if scan_type == "Service Detection":
                    if 'script' in self.nm[host]:
                        for script_name, script_output in self.nm[host]['script'].items():
                            if 'VULNERABLE' in script_output or 'CVE-' in script_output:
                                vuln_info = self._parse_vulnerability(script_name, script_output)
                                if vuln_info:
                                    host_info['vulnerabilities'].append(vuln_info)
                
                results['hosts'].append(host_info)
            
            logging.info("Scan results processed successfully")
            
            # If OpenVAS is configured, run vulnerability scan
            if self._is_openvas_configured():
                vuln_results = self._run_vulnerability_scan(target)
                results['vulnerabilities'] = vuln_results
            
            return results
            
        except Exception as e:
            error_msg = f"Scan failed: {str(e)}"
            logging.error(error_msg)
            raise Exception(error_msg)

    def _get_scan_arguments(self, scan_type):
        """
        Get the appropriate Nmap arguments for the scan type
        """
        scan_args = {
            "Host Discovery": "-sn -T4",  # Fast ping scan
            "Quick Service Scan": "-sV --version-intensity 2 -T4 --max-retries 1",  # Faster service detection
            "Full Service Scan": "-sV -sC --script=vuln,auth,default,exploit --script-args=vulns.showall -T4"  # Complete scan
        }
        return scan_args.get(scan_type, "-sn -T4")  # Default to host discovery if type not found

    def _is_openvas_configured(self):
        """
        Check if OpenVAS credentials are configured
        """
        return all([self.openvas_host, self.openvas_user, self.openvas_password])

    def _run_vulnerability_scan(self, target):
        """
        Run vulnerability scan using OpenVAS
        """
        try:
            # This is a placeholder for OpenVAS integration
            # You would need to implement the actual OpenVAS API calls here
            return {
                'status': 'not_implemented',
                'message': 'OpenVAS integration requires implementation'
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': str(e)
            }

    def _parse_vulnerability(self, script_name, output):
        """
        Parse vulnerability information from Nmap script output
        """
        try:
            vuln_info = {
                'name': script_name,
                'description': output,
                'risk_level': 'Unknown',
                'cve_ids': [],
                'recommendation': 'Update the affected service to the latest version.'
            }

            # Extract CVE IDs
            import re
            cve_pattern = r'CVE-\d{4}-\d{4,7}'
            cve_matches = re.findall(cve_pattern, output)
            if cve_matches:
                vuln_info['cve_ids'] = list(set(cve_matches))

            # Determine risk level based on keywords
            if any(word in output.lower() for word in ['critical', 'high risk']):
                vuln_info['risk_level'] = 'Critical'
            elif 'medium' in output.lower():
                vuln_info['risk_level'] = 'Medium'
            elif 'low' in output.lower():
                vuln_info['risk_level'] = 'Low'

            # Add specific recommendations based on vulnerability type
            if 'ssl' in script_name.lower() or 'tls' in script_name.lower():
                vuln_info['recommendation'] = 'Update SSL/TLS configuration to use secure protocols and ciphers.'
            elif 'auth' in script_name.lower():
                vuln_info['recommendation'] = 'Strengthen authentication mechanisms and update credentials.'
            elif 'rce' in script_name.lower() or 'remote code' in output.lower():
                vuln_info['recommendation'] = 'Immediately patch the system and restrict access to affected services.'

            return vuln_info
        except Exception as e:
            logging.error(f"Error parsing vulnerability info: {str(e)}")
            return None 