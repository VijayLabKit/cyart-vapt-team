Slack-ready Remediation Checklist (paste into ticket or Slack)

*Remediation Checklist for 192.168.132.135*

1. Isolate host
   - [ ] Remove host from production and untrusted networks or place behind containment firewall.

2. Immediate patching/upgrades
   - [ ] Remove/upgrade vsftpd 2.3.4 (replace with a supported FTP server or disable FTP if unused).
   - [ ] Upgrade Apache to latest 2.4.x and PHP to a supported release (remove PHP 5.2.4).

3. Remove exposed artifacts
   - [ ] Remove all backup/config files from webroot (e.g., *.tar, *.tar.bz2, *.pem, *.jks, *.war, *.egg).
   - [ ] Rotate any keys/credentials found in those files.

4. Disable unnecessary/unsafe services
   - [ ] Disable bind shell on port 1524 and any r-services (512-514) if not required.
   - [ ] Disable HTTP TRACE method.

5. Harden web settings
   - [ ] Add security headers: X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Referrer-Policy etc.
   - [ ] Set cookies with Secure and HttpOnly flags.

6. Network controls
   - [ ] Restrict access to SMB, RMI, DB services to trusted management subnets only.
   - [ ] Apply firewall rules to limit administrative ports (SSH, Telnet, VNC).

7. Verify & validate
   - [ ] Re-scan with Nmap/Nikto/OpenVAS after changes.
   - [ ] Provide sanitized PoC outputs and evidence in ticket for verification.

8. Long-term
   - [ ] Implement regular patching policy and remove intentionally vulnerable images from general-use networks.
