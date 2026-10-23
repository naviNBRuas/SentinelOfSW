use crate::core::findings::EducationalNote;

pub struct KnowledgeBase;

impl KnowledgeBase {
    pub fn for_smb_signing() -> EducationalNote {
        EducationalNote {
            what: "SMB Signing Disabled".into(),
            why: "SMB signing helps prevent man-in-the-middle attacks by digitally signing SMB packets. When disabled, an attacker can relay authentication requests to gain unauthorized access.".into(),
            how: "The tool sent a SMB negotiate request and checked the SecurityMode field in the response. When bit 0 (signing enabled) is not set, signing is disabled.".into(),
            references: vec![
                "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing".into(),
                "https://attack.mitre.org/techniques/T1557/001/".into(),
            ],
            mitigation: "Enable SMB signing via Group Policy or registry. Set 'Microsoft network server: Digitally sign communications (always)' to Enabled.".into(),
        }
    }

    pub fn for_open_port(port: u16, service: &str) -> EducationalNote {
        EducationalNote {
            what: format!("Open Port: {}/{}", port, service),
            why: format!("Port {} ({}) is open. Each open port represents a potential attack surface. Services may have known vulnerabilities, misconfigurations, or weak credentials.", port, service),
            how: format!("The tool sent a TCP SYN packet to port {}. A SYN-ACK response indicates the port is open and accepting connections.", port),
            references: vec![
                "https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers".into(),
            ],
            mitigation: "Close unnecessary ports. For required services, ensure they are properly configured, patched, and behind a firewall if possible.".to_string(),
        }
    }

    pub fn for_directory_listing() -> EducationalNote {
        EducationalNote {
            what: "Directory Listing Enabled".into(),
            why: "Directory listing allows anyone to browse the contents of a web directory. This can expose sensitive files, backup archives, configuration files, and source code.".into(),
            how: "The tool requested a common directory path and received a directory listing in the response body instead of a 403 Forbidden or 404 Not Found.".into(),
            references: vec![
                "https://owasp.org/www-community/attacks/Forced_browsing".into(),
            ],
            mitigation: "Disable directory listing in your web server configuration (e.g., 'Options -Indexes' for Apache, 'autoindex off' for Nginx).".into(),
        }
    }

    pub fn for_robots_txt(disallowed: &[String]) -> EducationalNote {
        EducationalNote {
            what: "Robots.txt Exposes Sensitive Paths".into(),
            why: format!("Robots.txt is meant for search engines but is publicly readable. Attackers use it to discover restricted paths. Disallowed paths: {}", disallowed.join(", ")),
            how: "The tool requested /robots.txt and parsed the Disallow directives to identify potentially sensitive paths.".into(),
            references: vec![
                "https://developers.google.com/search/docs/crawling-indexing/robots/intro".into(),
            ],
            mitigation: "Do not rely on robots.txt for security. Use proper authentication and access controls for sensitive paths.".into(),
        }
    }

    pub fn for_cve(cve_id: &str, description: &str) -> EducationalNote {
        EducationalNote {
            what: format!("Potential Vulnerability: {}", cve_id),
            why: description.into(),
            how: "The tool identified the software version from banners or response headers and matched it against known CVEs.".into(),
            references: vec![
                format!("https://nvd.nist.gov/vuln/detail/{}", cve_id),
                "https://www.exploit-db.com/".into(),
            ],
            mitigation: "Update to the latest patched version. If not possible, implement virtual patching or WAF rules.".to_string(),
        }
    }

    pub fn for_subdomain(subdomain: &str) -> EducationalNote {
        EducationalNote {
            what: format!("Subdomain Discovered: {}", subdomain),
            why: "Subdomains often host different applications or environments (dev, admin, VPN) that may not have the same security posture as the main domain.".into(),
            how: "The tool used DNS brute-forcing with a wordlist and/or certificate transparency logs (crt.sh) to discover subdomains.".into(),
            references: vec![
                "https://crt.sh/".into(),
            ],
            mitigation: "Ensure all subdomains are properly secured. Remove unused subdomains and implement wildcard TLS certificates carefully.".into(),
        }
    }

    pub fn for_default_creds() -> EducationalNote {
        EducationalNote {
            what: "Default Credentials Found".into(),
            why: "Default credentials are well-known and allow immediate unauthorized access to services. They are one of the most common initial access vectors.".into(),
            how: "The tool tested common default username/password combinations against the detected service.".into(),
            references: vec![
                "https://github.com/ihebski/DefaultCreds-cheat-sheet".into(),
            ],
            mitigation: "Change all default credentials immediately. Implement account lockout policies and multi-factor authentication.".into(),
        }
    }
}
