import usocket
import utime
import _thread
import dataCall
import log
from misc import USBNET
from misc import Power

class CaptivePortal:
    def __init__(self, target_url, dns_whitelist, real_dns_server=("8.8.8.8", 53)):
        """
        Initializing Captive Portal parameters。
        :param target_url: The target URL for the redirect (如 "https://example.com/")
        :param dns_whitelist: A list of DNS whitelists that allow normal resolution
        :param real_dns_server: Real DNS server address and port
        """
        self.target_url = target_url
        self.dns_whitelist = dns_whitelist
        self.real_dns_server = real_dns_server
        self.portal_active = True
        self.http_thread = None
        self.dns_thread = None
        log.basicConfig(level=log.INFO)
        self.cp_log = log.getLogger("CaptivePortal")

    def get_local_ip(self):
        """Get the local IP address that will be used to bind the forwarding Socket for DNS requests."""
        try:
            return dataCall.getInfo(1, 0)[2][2]
        except Exception as e:
            self.cp_log.warning("Error getting local IP: {}".format(e))
            return "0.0.0.0"

    def forward_to_real_dns(self, request, local_ip):
        """Forward DNS requests to the real DNS server."""
        sock = None
        try:
            sock = usocket.socket(usocket.AF_INET, usocket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.bind((local_ip, 0))
            sock.sendto(request, self.real_dns_server)
            response, _ = sock.recvfrom(512)
            return response
        except Exception as e:
            serr = str(e)
            if serr != "[Errno 113] EHOSTUNREACH":
                self.cp_log.warning("Error forwarding DNS request: {}".format(e))
            return None
        finally:
            if sock:
                sock.close()

    def start_http_server(self):
        """Start the HTTP redirection server."""
        ip = "192.168.43.1"  # USBNET Gateway IP
        addr = (ip, 80)
        s = usocket.socket(usocket.AF_INET, usocket.SOCK_STREAM)
        s.setsockopt(usocket.SOL_SOCKET, usocket.SO_REUSEADDR, 1)
        s.bind(addr)
        s.listen(3)
        self.cp_log.info("HTTP Server running at http://{}:80/".format(ip))

        while self.portal_active:
            try:
                res = s.accept()
                if not res or len(res) < 2:
                    continue
                client_sock = res[0]
                client_addr = (res[1], res[2])
                self.cp_log.debug("Connection from {}".format(client_addr))

                try:
                    request = client_sock.recv(1024).decode('utf-8')
                    if not request:
                        self.cp_log.debug("Empty request, closing connection.")
                        continue

                    self.cp_log.debug("Request: {}".format(request))
                    response = "HTTP/1.1 302 Found\r\nLocation: {}\r\n\r\n".format(self.target_url)
                    client_sock.send(response)
                except Exception as e:
                    self.cp_log.warning("Request handling error: {}".format(e))
                finally:
                    client_sock.close()
                utime.sleep_ms(100)
            except Exception as e:
                self.cp_log.warning("HTTP server error: {}".format(e))
                continue
        if client_sock:
            client_sock.close()
        s.close()

    def start_dns_server(self):
        """Start a DNS hijacking server."""
        ip = "192.168.43.1"  # Captive Portal IP
        local_ip = self.get_local_ip()
        dns_sock = usocket.socket(usocket.AF_INET, usocket.SOCK_DGRAM)
        dns_sock.bind(("0.0.0.0", 53))
        self.cp_log.info("DNS Server running...")

        while self.portal_active:
            try:
                data, addr = dns_sock.recvfrom(1024)
                self.cp_log.debug("DNS request from {}".format(addr))

                # Resolving DNS requests
                p = DNSQuery(data)

                if any(whitelisted in p.domain for whitelisted in self.dns_whitelist):
                    self.cp_log.debug("Domain {} is in whitelist, forwarding to real DNS.".format(p.domain))
                    response = self.forward_to_real_dns(data, local_ip)
                    if response is None:
                        self.cp_log.debug("Failed to get response from real DNS, sending empty response.")
                        response = b"\x00" * len(data)
                else:
                    response = p.response(ip)
                    self.cp_log.debug('Hijacking: {:s} -> {:s}'.format(p.domain, ip))

                dns_sock.sendto(response, addr)
            except Exception as e:
                self.cp_log.warning("DNS handling error: {}".format(e))
                utime.sleep_ms(100)
        dns_sock.close()

    def start(self):
        """Start a Captive Portal, including HTTP and DNS services."""
        self.portal_active = True
        self.dns_thread = _thread.start_new_thread(self.start_dns_server, ())
        self.http_thread = _thread.start_new_thread(self.start_http_server, ())
        self.cp_log.info("Captive Portal started.")

    def stop(self):
        """Close the Captive Portal and stop HTTP and DNS services."""
        self.portal_active = False
        self.cp_log.info("Captive Portal stopped.")


# Resolve the DNS request Class
class DNSQuery:
    def __init__(self, data):
        self.data = data
        self.domain = ''
        try:
            m = data[2]  # Flags
            tipo = (m >> 3) & 15  # Opcode bits
            if tipo == 0:
                ini = 12
                lon = data[ini]
                while lon != 0:
                    self.domain += data[ini+1:ini+lon+1].decode("utf-8") + '.'
                    ini += lon + 1
                    lon = data[ini]
        except Exception as e:
            self.domain = ''
            log.warning("Error parsing DNS query: {}".format(e))

    def response(self, ip):
        """Building a DNS hijacking response"""
        packet = b''
        if self.domain:
            packet += self.data[:2] + b"\x81\x80"
            packet += self.data[4:6] + self.data[4:6] + b'\x00\x00\x00\x00'
            packet += self.data[12:]
            packet += b'\xc0\x0c'
            packet += b'\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'
            packet += bytes(map(int, ip.split('.')))
        return packet

# Example
if __name__ == "__main__":
    # Windows: Type_RNDIS
    # Linux/Android/IOS: Type_ECM
    if (USBNET.get_worktype() != USBNET.Type_RNDIS):
        USBNET.set_worktype(USBNET.Type_RNDIS)
        Power.powerRestart()
    
    portal = CaptivePortal(
        target_url="https://python.quectel.com/",
        dns_whitelist=["www.python.quectel.com", "python.quectel.com"]
    )
    portal.start()
    
    cnt = 0
    while True:
        utime.sleep(1)
        ret = USBNET.open()
        cnt = cnt + 1
        if ret == 0:
            print("USBNET status: ",USBNET.get_status())
            print("USBNET type: ",USBNET.get_worktype())
            break
        if cnt == 60:
            print("USBNET open fail!")
            portal.stop()
            break
    

