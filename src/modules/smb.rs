use crate::core::config::Settings;
use crate::core::docker::global_docker;
use crate::core::findings::{Finding, Severity};
use crate::core::knowledge::KnowledgeBase;
use crate::core::tools::{run_enum4linux, run_smbmap};
use crate::core::workflow::WorkflowMode;
use crate::modules::Module;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::Sender;
use tokio::time::timeout;

const COMMON_SHARES: &[&str] = &[
    "IPC$", "ADMIN$", "C$", "D$", "PRINT$", "SYSVOL", "NETLOGON",
    "SHARED", "SHARE", "DATA", "FILES", "BACKUP", "HOME", "USERS",
    "PUBLIC", "WWWROOT", "INETPUB", "TEMP", "TMP",
];

// SMBv2 TreeConnect Request for IPC$ (with session_id set)
// Reference: [MS-SMB2] 2.2.9 SMB2 TREE_CONNECT Request
fn build_tree_connect(session_id: u64, share: &str) -> Vec<u8> {
    let share_path = format!("\\\\*\\{}", share);
    let share_bytes = share_path.as_bytes();
    // SMB2 packet: 64 (header) + 12 (body) + path_len
    let smb2_size = 76 + share_bytes.len();
    let total_size = 4 + smb2_size; // NBSS + SMB2
    let mut pkt = vec![0u8; total_size];
    // NBSS header (4 bytes)
    pkt[0..4].copy_from_slice(&(smb2_size as u32).to_be_bytes());
    // SMB2 header
    pkt[4..8].copy_from_slice(b"\xFE\x53\x4D\x42"); // protocol
    // StructureSize (2 bytes) at offset 4+2=6
    pkt[10] = 0x40; // SMB2 header length (64 bytes)
    // CreditCharge at 4+4=8
    // NT Status at 4+12=16
    // Command: SMB2 TREE_CONNECT = 0x03 at 4+16=20
    pkt[24] = 0x03;
    // Credits/MaxCount at 4+18=22
    // Flags at 4+22=26
    // ChainOffset at 4+26=30
    // MessageId at 4+28=32 (keep as 0 for new)
    // ProcessId at 4+36=40
    // TreeId at 4+40=44 (set to 0 for new tree connect)
    // SessionId at 4+44=48
    pkt[52..60].copy_from_slice(&session_id.to_le_bytes());
    // Signature at 4+52=56
    // End of SMB2 header is at offset 4+64=68
    // SMB2 TREE_CONNECT body starts at offset 68 (relative to NBSS start)
    let body_off = 68usize;
    // PathOffset is from start of SMB2 header (offset 4+0=4)
    // SMB2 header (64) + body fixed (12) = 76
    let path_off_smb2: u16 = 76; // relative to SMB2 header start
    pkt[body_off] = 0x09; // StructureSize (9)
    pkt[body_off + 1] = 0x00; // Reserved
    // PathOffset at body_off+2 (2 bytes) - relative to SMB2 header
    pkt[body_off + 2..body_off + 4].copy_from_slice(&path_off_smb2.to_le_bytes());
    // PathLength at body_off+4 (2 bytes)
    pkt[body_off + 4..body_off + 6].copy_from_slice(&(share_bytes.len() as u16).to_le_bytes());
    // Reserved at body_off+6 (4 bytes) - already zeroed
    // Share path at absolute offset 4+76=80
    let abs_path_off = 80usize;
    pkt[abs_path_off..abs_path_off + share_bytes.len()].copy_from_slice(share_bytes);
    pkt
}

// Parse TreeConnect response to get tree_id
fn parse_tree_connect(data: &[u8]) -> Option<u32> {
    if data.len() < 76 { return None; }
    if data[4..8] != [0xFE, 0x53, 0x4D, 0x42] { return None; }
    let status = u32::from_le_bytes(data[12..16].try_into().ok()?);
    if status != 0 { return None; }
    // TreeId at offset 4+40=44
    Some(u32::from_le_bytes(data[48..52].try_into().ok()?))
}

// SMBv2 Negotiate Request (minimal)
// Reference: [MS-SMB2] Protocol Specification
const SMB2_NEGOTIATE_REQUEST: &[u8] = &[
    0x00, 0x00, 0x00, 0x8C,
    0xFE, 0x53, 0x4D, 0x42,
    0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFE, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x24, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x21, 0x02,
    0x00, 0x03,
];

const SMB2_SESSION_SETUP: &[u8] = &[
    0x00, 0x00, 0x00, 0x49,
    0xFE, 0x53, 0x4D, 0x42,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFE, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x19, 0x00, 0x00, 0x59, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00,
];

pub struct SmbEnum;

fn parse_smb_negotiate_response(data: &[u8]) -> (Option<String>, bool, Option<u64>) {
    let offset = 4;
    if data.len() < offset + 68 { return (None, false, None); }
    if data[offset..offset + 4] != [0xFE, 0x53, 0x4D, 0x42] {
        if data.len() > 8 && data[offset] == 0xFF && data[offset + 4] == 0x72 {
            return (Some("SMBv1".into()), false, None);
        }
        return (None, false, None);
    }

    let status = u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap());
    if status != 0 { return (None, false, None); }

    let body_offset = offset + 64;
    if data.len() < body_offset + 2 { return (None, false, None); }

    let struct_size = u16::from_le_bytes([data[body_offset], data[body_offset + 1]]);
    if struct_size < 65 { return (None, false, None); }

    let security_mode = u16::from_le_bytes([data[body_offset + 4], data[body_offset + 5]]);
    let signing_required = (security_mode & 0x02) != 0;

    let dialect_revision = u16::from_le_bytes([data[body_offset + 2], data[body_offset + 3]]);
    let dialect_str = match dialect_revision {
        0x0202 => "SMB 2.0.2", 0x0210 => "SMB 2.1",
        0x0300 => "SMB 3.0", 0x0302 => "SMB 3.0.2", 0x0311 => "SMB 3.1.1",
        _ => "Unknown",
    };

    (Some(format!("{} (dialect 0x{:04X})", dialect_str, dialect_revision)), signing_required, None)
}

fn build_session_setup(msg_id: u64, session_id: u64) -> Vec<u8> {
    let mut pkt = SMB2_SESSION_SETUP.to_vec();
    // Update MessageId at offset 4+24 = 28
    pkt[28..36].copy_from_slice(&msg_id.to_le_bytes());
    // Update SessionId at offset 4+44 = 48
    pkt[48..56].copy_from_slice(&session_id.to_le_bytes());
    // Update NBSS length at offset 0: 0x49 (73) for minimal, 0x6C + bufsize for larger
    pkt
}

fn parse_session_setup_response(data: &[u8]) -> (bool, u64) {
    let offset = 4;
    if data.len() < offset + 68 { return (false, 0); }
    if data[offset..offset + 4] != [0xFE, 0x53, 0x4D, 0x42] { return (false, 0); }
    let status = u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap());
    let session_id = u64::from_le_bytes(data[offset + 44..offset + 52].try_into().unwrap());
    (status == 0, session_id)
}

#[async_trait]
impl Module for SmbEnum {
    fn name(&self) -> &str {
        "SMB Enumeration"
    }

    async fn execute_with_ports(&self, target: &str, _open_ports: &[u16], _mode: &WorkflowMode, tx: Sender<String>) -> Result<Vec<Finding>, anyhow::Error> {
        let _ = tx.send(format!("[SMB] Starting SMB enumeration for {}", target)).await;
        let mut findings = Vec::new();

        // Connect to SMB port 445
        let addr = format!("{}:445", target);
        let _ = tx.send(format!("[SMB] Connecting to {}...", addr)).await;

        match timeout(Settings::global().banner_timeout(), TcpStream::connect(&addr)).await {
            Ok(Ok(mut stream)) => {
                let _ = tx.send("[SMB] Connected to port 445".into()).await;

                // Send SMBv2 Negotiate Request
                let _ = tx.send("[SMB] Sending SMB negotiate request...".into()).await;
                        match timeout(Settings::global().banner_timeout(), stream.write_all(SMB2_NEGOTIATE_REQUEST)).await {
                    Ok(Ok(_)) => {
                        let _ = tx.send("[SMB] Sent negotiate request, reading response...".into()).await;
                        let mut buf = vec![0u8; 4096];
                        match timeout(Settings::global().banner_timeout(), stream.read(&mut buf)).await {
                            Ok(Ok(n)) => {
                                buf.truncate(n);
                                let (dialect, signing_required, _) = parse_smb_negotiate_response(&buf);

                                match dialect {
                                    Some(ref ver) => {
                                        let _ = tx.send(format!("[SMB] Negotiated dialect: {}", ver)).await;

                                        if signing_required {
                                            let _ = tx.send("[SMB] SMB signing is REQUIRED".into()).await;
                                            findings.push(
                                                Finding::new(target, "smb", "SMB Signing Required",
                                                    &format!("SMB signing is required on the target ({}). This increases security against relay attacks.", ver),
                                                    Severity::Info,
                                                ).with_confidence(0.9)
                                                .with_evidence(vec![format!("SMB negotiate response indicates signing required for {}", target)]),
                                            );
                                        } else {
                                            let _ = tx.send("[SMB] SMB signing is NOT required".into()).await;
                                            findings.push(
                                                Finding::new(target, "smb", "SMB Signing Disabled",
                                                    &format!("SMB signing is disabled on the target ({}). This could allow relay attacks.", ver),
                                                    Severity::Medium,
                                                ).with_confidence(0.95)
                                                .with_education(KnowledgeBase::for_smb_signing())
                                                .with_evidence(vec![format!("SMB negotiate response indicates signing not required for {}", target)]),
                                            );
                                        }

                                        if ver.contains("3.1.1") {
                                            let _ = tx.send("[SMB] SMB 3.1.1 detected (modern, secure)".into()).await;
                                        } else if ver.contains("SMBv1") || ver.contains("2.0.2") || ver.contains("2.1") {
                                            let _ = tx.send("[SMB] Older SMB version detected, possible vulnerability".into()).await;
                                            findings.push(
                                                Finding::new(target, "smb",
                                                    &format!("Older SMB Version: {}", ver),
                                                    &format!("SMB version {} is outdated and may be vulnerable to known exploits.", ver),
                                                    Severity::High,
                                                ).with_confidence(0.8)
                                                .with_evidence(vec![format!("SMB negotiate response indicates dialect {}", ver)])
                                                .with_cve(if ver.contains("SMBv1") { "CVE-2017-0144" } else { "" }),
                                            );
                                        }

                                        // Attempt null session authentication
                                        let _ = tx.send("[SMB] Attempting null session authentication...".into()).await;
                                        let session_pkt = build_session_setup(1, 0);
                                        match timeout(Settings::global().banner_timeout(), stream.write_all(&session_pkt)).await {
                                            Ok(Ok(_)) => {
                                                let mut srbuf = vec![0u8; 4096];
                                                match timeout(Settings::global().banner_timeout(), stream.read(&mut srbuf)).await {
                                                    Ok(Ok(sn)) => {
                                                        srbuf.truncate(sn);
                                                        let (null_ok, session_id) = parse_session_setup_response(&srbuf);
                                                        if null_ok {
                                                            let _ = tx.send(format!("[SMB] Null session successful! SessionId: 0x{:016x}", session_id)).await;
                                                            findings.push(
                                                                Finding::new(target, "smb", "SMB Null Session Allowed",
                                                                    "SMB null session (anonymous authentication) is permitted. This allows an unauthenticated attacker to enumerate users, shares, and system information.",
                                                                    Severity::Critical,
                                                                ).with_confidence(0.95)
                                                                .with_evidence(vec![format!("Null session established on {}, SessionId: 0x{:016x}", target, session_id)]),
                                                            );

                                                            // Attempt share enumeration via TreeConnect
                                                            let _ = tx.send("[SMB] Enumerating shares via TreeConnect...".into()).await;
                                                            for share in COMMON_SHARES {
                                                                let tc_pkt = build_tree_connect(session_id, share);
                                                                if let Ok(Ok(_)) = timeout(Settings::global().banner_timeout(), stream.write_all(&tc_pkt)).await {
                                                                    let mut tcbuf = vec![0u8; 1024];
                                                                    if let Ok(Ok(tn)) = timeout(Settings::global().banner_timeout(), stream.read(&mut tcbuf)).await {
                                                                        tcbuf.truncate(tn);
                                                                        if let Some(tree_id) = parse_tree_connect(&tcbuf) {
                                                                            let _ = tx.send(format!("[SMB] Accessible share: {} (TreeId: 0x{:08x})", share, tree_id)).await;
                                                                            findings.push(
                                                                                Finding::new(target, "smb",
                                                                                    &format!("SMB Accessible Share: {}", share),
                                                                                    &format!("Share '{}' is accessible via null session on {}. May contain sensitive data.", share, target),
                                                                                    if share.ends_with('$') { Severity::Medium } else { Severity::High },
                                                                                ).with_confidence(0.9)
                                                                                .with_evidence(vec![format!("TreeConnect to {} succeeded (TreeId: 0x{:08x})", share, tree_id)]),
                                                                            );
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        } else {
                                                            let _ = tx.send("[SMB] Null session rejected (authentication required)".into()).await;
                                                        }
                                                    }
                                                    _ => { let _ = tx.send("[SMB] Timeout reading session setup response".into()).await; }
                                                }
                                            }
                                            _ => { let _ = tx.send("[SMB] Failed to send session setup request".into()).await; }
                                        }

                                        // Docker-based rich SMB enumeration
                                        if let Some(docker) = global_docker() {
                                            let _ = tx.send("[SMB] Running enum4linux-ng (Docker)...".into()).await;
                                            let e4l = run_enum4linux(target, Some(docker), 120).await;
                                            let share_lines: Vec<&str> = e4l.stdout.lines()
                                                .filter(|l| l.contains("Sharename") || l.contains("username") || l.contains("OS:") || l.contains("Domain:") || l.contains("ses-"))
                                                .collect();
                                            if !share_lines.is_empty() {
                                                let _ = tx.send(format!("[SMB] enum4linux found {} relevant lines", share_lines.len())).await;
                                                findings.push(
                                                    Finding::new(target, "smb", "SMB Share & User Enumeration (enum4linux-ng)",
                                                        &format!("enum4linux-ng discovered shares, users, or OS info on {}.", target),
                                                        Severity::High,
                                                    ).with_confidence(0.85)
                                                    .with_evidence(share_lines.iter().take(10).map(|l| format!("enum4linux: {}", l)).collect()),
                                                );
                                            }

                                            let _ = tx.send("[SMB] Running smbmap (Docker)...".into()).await;
                                            let sm = run_smbmap(target, Some(docker), 60).await;
                                            let smbmap_lines: Vec<&str> = sm.stdout.lines()
                                                .filter(|l| l.contains("READ") || l.contains("WRITE") || l.contains("drwx") || l.contains("Disk"))
                                                .collect();
                                            if !smbmap_lines.is_empty() {
                                                let _ = tx.send(format!("[SMB] smbmap found {} shares", smbmap_lines.len())).await;
                                                findings.push(
                                                    Finding::new(target, "smb", "SMB Share Listing (smbmap)",
                                                        &format!("smbmap discovered {} accessible SMB shares on {}.", smbmap_lines.len(), target),
                                                        Severity::Medium,
                                                    ).with_confidence(0.9)
                                                    .with_evidence(smbmap_lines.iter().take(10).map(|l| format!("smbmap: {}", l)).collect()),
                                                );
                                            }
                                        }

                                        findings.push(
                                            Finding::new(target, "smb", "SMB Service Detected",
                                                &format!("SMB service is running on port 445 ({}). Further enumeration recommended.", ver),
                                                Severity::Info,
                                            ).with_confidence(1.0)
                                            .with_evidence(vec![format!("SMB negotiate response received from {}", target)]),
                                        );
                                    }
                                    None => {
                                        let _ = tx.send("[SMB] Could not parse SMB negotiate response".into()).await;
                                        findings.push(
                                            Finding::new(target, "smb", "Unrecognized Service on Port 445",
                                                "Received data on port 445 but could not parse SMB negotiate response.",
                                                Severity::Info,
                                            ).with_confidence(0.5),
                                        );
                                    }
                                }
                            }
                            Ok(Err(e)) => { let _ = tx.send(format!("[SMB] Read error: {}", e)).await; }
                            Err(_) => { let _ = tx.send("[SMB] Timeout reading negotiate response".into()).await; }
                        }
                    }
                    Ok(Err(e)) => { let _ = tx.send(format!("[SMB] Write error: {}", e)).await; }
                    Err(_) => { let _ = tx.send("[SMB] Timeout sending negotiate request".into()).await; }
                }
            }
            Ok(Err(_)) => {
                let _ = tx.send("[SMB] Port 445 is closed or not accessible".into()).await;
                findings.push(
                    Finding::new(
                        target,
                        "smb",
                        "SMB Service Not Detected",
                        "Port 445 is not accessible. SMB service is likely not running.",
                        Severity::Info,
                    )
                    .with_confidence(1.0),
                );
            }
            Err(_) => {
                let _ = tx.send("[SMB] Connection timed out".into()).await;
                findings.push(
                    Finding::new(
                        target,
                        "smb",
                        "SMB Service Not Detected (Timeout)",
                        "Connection to port 445 timed out. SMB may be filtered by a firewall.",
                        Severity::Info,
                    )
                    .with_confidence(0.8),
                );
            }
        }

        let _ = tx.send(format!(
            "[SMB] SMB enumeration complete. {} findings.",
            findings.len()
        )).await;

        Ok(findings)
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_smb_negotiate_response_short_data() {
        let (dialect, signing, _) = parse_smb_negotiate_response(&[0u8; 10]);
        assert!(dialect.is_none());
        assert!(!signing);
    }

    #[test]
    fn test_parse_smb_negotiate_response_no_protocol() {
        let data = [
            0x00, 0x00, 0x00, 0x00, // NBSS
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // not SMB
        ];
        let (dialect, _, _) = parse_smb_negotiate_response(&data);
        assert!(dialect.is_none());
    }

    #[test]
    fn test_build_tree_connect_length() {
        let pkt = build_tree_connect(1, "IPC$");
        assert!(pkt.len() > 72);
        let nbss_len = u32::from_be_bytes(pkt[0..4].try_into().unwrap());
        assert_eq!(nbss_len as usize + 4, pkt.len());
    }

    #[test]
    fn test_parse_session_setup_too_short() {
        let (ok, sid) = parse_session_setup_response(&[0u8; 10]);
        assert!(!ok);
        assert_eq!(sid, 0);
    }

    #[test]
    fn test_parse_tree_connect_short() {
        assert!(parse_tree_connect(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_common_shares_not_empty() {
        assert!(!COMMON_SHARES.is_empty());
        assert!(COMMON_SHARES.contains(&"IPC$"));
        assert!(COMMON_SHARES.contains(&"ADMIN$"));
    }
}
