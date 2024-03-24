import socket

def port_scan(target):
    """
    Perform a port scan on the target IP address or hostname.

    Parameters:
        target (str): The target IP address or hostname to scan.

    Returns:
        dict: A dictionary containing open ports and associated vulnerabilities.
    """
    open_ports = {}
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        return open_ports
    common_ports = {
       21: """
    Vulnerabilities: Plaintext credentials transmission, FTP bounce attacks
            - Prevention:
              - Use secure FTP (SFTP) or FTPS instead of FTP to encrypt data transmission.
              - Implement strong passwords and limit access to FTP servers.
              - Reference: https://owasp.org/www-community/vulnerabilities/FTP_Bounce_Attack
    """,
22: """
    Vulnerabilities: Brute force attacks, Weak key generation
            - Prevention:
              - Use key-based authentication instead of passwords for SSH.
              - Implement firewall rules to restrict SSH access to trusted IP addresses.
              - Reference: https://www.ssh.com/ssh/keygen
    """,
23: """
    Vulnerabilities: Plaintext credentials transmission, Command injection
            - Prevention:
              - Avoid using Telnet due to its inherent lack of security.
              - Use SSH instead for secure remote access.
              - Reference: https://owasp.org/www-community/attacks/Command_Injection
    """,
25: """
    Vulnerabilities: Email spoofing, Spamming, Open relay
            - Prevention:
              - Implement SPF, DKIM, and DMARC to prevent email spoofing and spamming.
              - Use email filtering software to detect and block spam emails.
              - Reference: https://owasp.org/www-community/controls/Email_Security_CSP
    """,
53: """
    Vulnerabilities: DNS cache poisoning, DNS spoofing
            - Prevention:
              - Keep DNS software up to date to mitigate vulnerabilities.
              - Implement DNSSEC to add security features to DNS.
              - Reference: https://owasp.org/www-community/vulnerabilities/DNS_Cache_Poisoning
    """
,
        53: "DNS - Domain Name System (vulnerability: DNS cache poisoning)",
        80: "HTTP - Hypertext Transfer Protocol (vulnerability: various web-based attacks)",
        110: "POP3 - Post Office Protocol version 3 (vulnerability: plaintext credentials transmission)",
        443: """
    Vulnerabilities: Man-in-the-middle attacks, SSL/TLS vulnerabilities
            - Prevention:"
              - Use HTTPS instead of HTTP to encrypt web traffic.
              - Implement SSL/TLS best practices such as certificate validation and secure cipher suites.
              - Reference:  https://owasp.org/www-community/attacks/Manipulator-in-the-middle_attack 
    """,
    53: """
    Vulnerabilities: DNS cache poisoning, DNS spoofing
            - Prevention:
              - Keep DNS software up to date to mitigate vulnerabilities.
              - Implement DNSSEC to add security features to DNS.
              - Reference: https://owasp.org/www-community/vulnerabilities/DNS_Cache_Poisoning
    """,
80: """
    Vulnerabilities: Cross-site scripting (XSS), SQL injection, Server misconfiguration
            - Prevention:
              - Use HTTPS instead of HTTP to encrypt web traffic.
              - Implement web application firewalls (WAF) to protect against web-based attacks.
              - Reference: https://owasp.org/www-community/attacks/xss
    """,
110: """
    Vulnerability: Plaintext credentials transmission, Email account compromise
            - Prevention:
              - Use POP3 over SSL/TLS (POP3S) to encrypt email transmission.
              - Implement strong passwords and limit access to POP3 servers.
              - Reference: https://owasp.org/www-community/controls/Secure_Email_Transport
    """,
143: """
    Vulnerability: Plaintext credentials transmission, Email account compromise
            - Prevention:
              - Use IMAP over SSL/TLS (IMAPS) to encrypt email transmission.
              - Implement strong passwords and limit access to IMAP servers.
              - Reference: https://owasp.org/www-community/controls/Secure_Email_Transport
    """,
993: """
    Vulnerabilities: Plaintext credentials transmission, Email account compromise
            - Prevention:
              - Use IMAPS to encrypt email transmission.
              - Implement strong passwords and limit access to IMAPS servers.
              - Reference: https://owasp.org/www-community/controls/Secure_Email_Transport
    """,
995: """
    Vulnerabilities: Plaintext credentials transmission, Email account compromise
            - Prevention:
              - Use POP3S to encrypt email transmission.
              - Implement strong passwords and limit access to POP3S servers.
              - Reference: https://owasp.org/www-community/controls/Secure_Email_Transport
    """,
1433: """
    Vulnerabilities: SQL Injection, Brute force attacks
            - Prevention:
              - Use parameterized queries to prevent SQL injection.
              - Implement strong password policies and account lockout mechanisms.
              - Reference: https://owasp.org/www-community/attacks/SQL_Injection
    """,
1521: """
    Vulnerabilities: TNS Poisoning, Default credentials
            - Prevention:
              - Change default credentials and remove unnecessary accounts.
              - Use strong encryption for sensitive data transmission.
              - Reference: https://www.blackhat.com/docs/us-17/thursday/us-17-Petit-Abusing-Oracle-TNS-Listener-For-Fun-And-Profit-wp.pdf
    """,
2049: """
    Vulnerabilities: Insecure configuration, Privilege escalation
            - Prevention:
              - Implement secure NFS configurations with proper access controls.
              - Regularly update NFS software to patch known vulnerabilities.
              - Reference: https://www.us-cert.gov/ncas/alerts/TA19-091a
    """,
3306: """
    Vulnerabilities: SQL Injection, Brute force attacks, Privilege escalation
            - Prevention:
              - Use parameterized queries to prevent SQL injection.
              - Implement strong password policies and account lockout mechanisms.
              - Limit privileges for database users to minimize potential damage.
              - Reference: https://owasp.org/www-community/attacks/SQL_Injection
    """,
3389: """
    Vulnerabilities: Brute force attacks, BlueKeep vulnerability, Credential theft
            - Prevention:
              - Enable Network Level Authentication (NLA) to require authentication before a remote session is established.
              - Apply security patches regularly to protect against known vulnerabilities.
              - Implement account lockout policies to prevent brute force attacks.
              - Reference: https://owasp.org/www-community/attacks/Brute_force_attack
    """,
5432: """
    Vulnerabilities: SQL Injection, Brute force attacks, Privilege escalation
            - Prevention:
              - Use parameterized queries to prevent SQL injection.
              - Implement strong password policies and account lockout mechanisms.
              - Limit privileges for database users to minimize potential damage.
              - Reference: https://owasp.org/www-community/attacks/SQL_Injection
    """,
5900: """
    Vulnerabilities: Weak authentication, Man-in-the-middle attacks
            - Prevention:
              - Use strong passwords or SSH tunneling for VNC connections.
              - Limit VNC access to trusted IP addresses.
              - Reference: https://owasp.org/www-community/attacks/Manipulator-in-the-middle_attack
    """,
6379: """
    Vulnerabilities: Unauthenticated access, Remote code execution
            - Prevention:
              - Implement authentication mechanisms such as password protection or IP whitelisting.
              - Update Redis to the latest version and apply security patches.
              - Reference: https://owasp.org/www-community/vulnerabilities/Remote_Code_Execution
    """,
5901: """
    Vulnerabilities: Weak authentication, Man-in-the-middle attacks
            - Prevention:
              - Use strong passwords or SSH tunneling for VNC connections.
              - Limit VNC access to trusted IP addresses.
              - Reference: https://owasp.org/www-community/attacks/Manipulator-in-the-middle_attack
    """,
6667: """
    Vulnerabilities: IRC flood attacks, Botnet recruitment
            - Prevention:
              - Configure IRC servers to limit message rates and connections per IP address.
              - Regularly monitor IRC channels for suspicious activity.
              - Reference: https://owasp.org/www-community/attacks/IRC_Flood
    """,
8080: """
    Vulnerabilities: Proxy server misconfiguration, HTTP header injection
            - Prevention:
              - Regularly review and update proxy server configurations.
              - Implement input validation and proper encoding to prevent HTTP header injection.
              - Reference: https://owasp.org/www-community/attacks/HTTP_Response_Splitting
    """,
8443: """
    Vulnerabilities: Man-in-the-middle attacks, SSL/TLS vulnerabilities
            - Prevention:
              - Use HTTPS instead of HTTP to encrypt web traffic.
              - Implement SSL/TLS best practices such as certificate validation and secure cipher suites.
              - Reference: https://owasp.org/www-community/attacks/Manipulator-in-the-middle_attack
    """,
9090: """
    Vulnerabilities: Remote code execution, Denial of Service (DoS)
            - Prevention:
              - Apply security patches regularly to mitigate known vulnerabilities.
              - Implement network segmentation to limit exposure of WebSphere servers.
              - Reference: https://www.ibm.com/support/pages/node/657607
    """,
9100: """
    Vulnerabilities: Printer exploitation, Data interception
            - Prevention:
              - Update printer firmware to the latest version to patch known vulnerabilities.
              - Implement network segmentation to restrict access to printer spooler services.
              - Reference: https://www.us-cert.gov/ncas/alerts/TA21-237A
    """,
9418: """
    Vulnerabilities: Unauthorized access, Code injection
            - Prevention:
              - Implement access controls such as SSH keys or authentication tokens.
              - Regularly update Git to patch known vulnerabilities.
              - Reference: https://owasp.org/www-community/vulnerabilities/Git_Hacking
    """,
9999: """
    Vulnerabilities: Remote code execution, Privilege escalation
            - Prevention:
              - Apply security patches regularly to mitigate known vulnerabilities.
              - Implement network segmentation to limit exposure of Control-M servers.
              - Reference: https://www.ibm.com/support/pages/node/657607
    """,
10000: """
    Vulnerabilities: Remote code execution, Authentication bypass
            - Prevention:
              - Update Webmin to the latest version to patch known vulnerabilities.
              - Implement strong authentication mechanisms and IP restrictions.
              - Reference: https://owasp.org/www-community/vulnerabilities/Webmin_Hacking
    """,
11211: """
    Vulnerabilities: DDoS amplification attacks, Unauthorized access
            - Prevention:
              - Restrict access to Memcached servers using firewalls or IP whitelisting.
              - Disable UDP support to prevent DDoS amplification.
              - Reference: https://owasp.org/www-community/attacks/DDoS_Amplification_Attacks
    """
,

      3306: "MySQL database (vulnerability: SQL injection)",
        3389: "Remote Desktop Protocol (vulnerability: remote desktop hijacking)"
    }

    for port, service in common_ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Set a timeout for connection attempt
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            open_ports[port] = service
        sock.close()

    return open_ports


def main():
    target = input("Enter the IP address or hostname to scan: ")
    try:
        open_ports = port_scan(target)
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()