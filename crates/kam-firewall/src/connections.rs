//! What is talking to the network right now, and what it is.
//!
//! Windows knows every open socket and which process owns it, and offers no
//! way to look. `netstat -b` comes closest, needs an administrator, and prints
//! a wall of text with no idea whether any of it is signed. Resource Monitor
//! shows names without paths. Neither answers the question people actually
//! have, which is *should this be talking to the internet at all*.
//!
//! # What makes this worth building
//!
//! Not the socket list — that is a documented API call. It is the join: every
//! connection carries the owning program's path, its Authenticode signer, and
//! where it lives. "chrome.exe is connected to 142.250.x.x" tells you nothing.
//! "An unsigned program in your AppData folder is connected to an address in
//! Amsterdam" is a sentence worth reading, and it is assembled from three
//! things Windows keeps in three different places.
//!
//! # A snapshot, not a stream
//!
//! This reads the table each time it is asked. An ETW consumer on
//! `Microsoft-Windows-Kernel-Network` would give live events rather than
//! polls, which is a real improvement but a large amount of surface for it;
//! a snapshot every few seconds shows the same connections to a person
//! reading a screen. Prompting *before* a connection opens is a different
//! thing again, needs a WFP callout driver, and is permanently out of scope.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// What a TCP socket is doing.
///
/// Only the states worth showing a person are named. The handshake and
/// teardown states exist for microseconds and would be noise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Waiting for something to connect to it.
    Listening,
    /// Carrying traffic right now.
    Established,
    /// Opening, closing, or waiting out a timeout.
    Transient,
    /// UDP is connectionless, so there is no state to report.
    Connectionless,
}

impl State {
    fn from_tcp(value: u32) -> Self {
        match value {
            2 => Self::Listening,
            5 => Self::Established,
            _ => Self::Transient,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Listening => "listening",
            Self::Established => "connected",
            Self::Transient => "opening or closing",
            Self::Connectionless => "UDP",
        }
    }
}

/// One open socket, joined to whatever owns it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub protocol: String,
    pub state: State,
    pub local_address: String,
    pub local_port: u16,
    /// Absent for a listening socket, which has no peer yet.
    pub remote_address: Option<String>,
    pub remote_port: Option<u16>,
    pub process_id: u32,
    /// The owning program, when it could be read. A process that exited
    /// between reading the table and asking about it leaves this empty.
    pub image_path: Option<String>,
    /// Final component, which is what a person recognises.
    pub name: Option<String>,
    /// What the file says it is, from its own version resource.
    ///
    /// A claim, never evidence: the file was written by whoever made it, and
    /// "Google Chrome" can be typed into a resource by anybody. It is here to
    /// make a list of forty `svchost.exe` rows readable, which the file name
    /// alone cannot do. The verified half is `signer`, and an interface showing
    /// both must not present them as equals.
    pub description: Option<String>,
    /// Who the file says wrote it. Also unverified -- compare against `signer`.
    pub company: Option<String>,
    /// Who signed the program, when Windows accepts the signature.
    pub signer: Option<String>,
    /// `Some(true)` when nothing signed it or the signature does not verify,
    /// `Some(false)` when it does, and `None` when the owning program could
    /// not be identified at all.
    ///
    /// Three states rather than two, because "not signed" and "could not tell"
    /// are different claims and only one of them is about the program. A
    /// socket whose process could not be opened would otherwise be reported as
    /// unsigned, which is an accusation invented from a permissions failure.
    pub unsigned: Option<bool>,
    /// True when the peer is outside this machine and outside private address
    /// ranges — that is, actually on the internet.
    pub external: bool,
}

/// A snapshot of the whole table.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectionReport {
    pub connections: Vec<Connection>,
    pub established: usize,
    pub listening: usize,
    /// How many are talking to an address outside this machine and outside the
    /// local network.
    pub external: usize,
    /// Distinct programs holding at least one socket.
    pub programs: usize,
}

/// Ports arrive with their bytes the other way round.
///
/// The table stores them in network order inside a host-order `u32`, so the
/// low two bytes have to be swapped rather than simply truncated. Getting this
/// wrong turns port 443 into 47873, which looks plausible enough to ship.
fn port(raw: u32) -> u16 {
    u16::from_be((raw & 0xFFFF) as u16)
}

fn ipv4(raw: u32) -> Ipv4Addr {
    Ipv4Addr::from(raw.to_le_bytes())
}

fn ipv6(raw: [u8; 16]) -> Ipv6Addr {
    Ipv6Addr::from(raw)
}

/// Whether an address is somewhere on the internet rather than on this machine
/// or this network.
///
/// The distinction the interface leans on: a program listening on loopback is
/// talking to itself, and one connected to a private address is talking to
/// something in the same building. Neither is what people mean when they ask
/// what is "phoning home".
fn is_external(address: &str) -> bool {
    if let Ok(v4) = address.parse::<Ipv4Addr>() {
        return !(v4.is_loopback()
            || v4.is_private()
            || v4.is_link_local()
            || v4.is_broadcast()
            || v4.is_unspecified()
            || v4.is_multicast());
    }
    if let Ok(v6) = address.parse::<Ipv6Addr>() {
        return !(v6.is_loopback()
            || v6.is_unspecified()
            || v6.is_multicast()
            // Unique-local (fc00::/7) and link-local (fe80::/10).
            || (v6.segments()[0] & 0xFE00) == 0xFC00
            || (v6.segments()[0] & 0xFFC0) == 0xFE80);
    }
    false
}

/// The full path of a running process.
fn image_of(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    // Limited information is enough for the path and is grantable for
    // processes this one could not otherwise open.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;

    let mut buffer = [0_u16; 32_768];
    let mut length = buffer.len() as u32;
    let outcome = unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_FORMAT(0),
            windows::core::PWSTR(buffer.as_mut_ptr()),
            &mut length,
        )
    };
    unsafe {
        let _ = CloseHandle(handle);
    }

    outcome.ok()?;
    let path = String::from_utf16_lossy(&buffer[..length as usize]);
    (!path.is_empty()).then_some(path)
}

/// Ask for a table twice: once for its size, once for its contents.
///
/// Returns the raw bytes. The shape differs per address family and protocol,
/// so the caller casts.
fn table_bytes(fetch: impl Fn(Option<*mut core::ffi::c_void>, *mut u32) -> u32) -> Option<Vec<u8>> {
    let mut size = 0_u32;
    let outcome = fetch(None, &mut size);
    if outcome != ERROR_INSUFFICIENT_BUFFER.0 || size == 0 {
        return None;
    }

    // The table can grow between the two calls, so a second insufficient
    // buffer is retried rather than treated as failure.
    for _ in 0..3 {
        let mut buffer = vec![0_u8; size as usize];
        let outcome = fetch(Some(buffer.as_mut_ptr() as *mut _), &mut size);
        if outcome == NO_ERROR.0 {
            return Some(buffer);
        }
        if outcome != ERROR_INSUFFICIENT_BUFFER.0 {
            return None;
        }
    }
    None
}

/// Rows follow the count field contiguously; this reads them as a slice.
///
/// # Safety
/// `bytes` must hold a `MIB_*TABLE_OWNER_PID` written by the API, whose layout
/// is a `dwNumEntries` followed by that many rows.
unsafe fn rows<Table, Row>(bytes: &[u8]) -> &[Row] {
    if bytes.len() < std::mem::size_of::<Table>() {
        return &[];
    }
    let table = bytes.as_ptr() as *const Table;
    // The count is the first field of every one of these tables.
    let count = unsafe { *(table as *const u32) } as usize;

    // The declared table type already carries one row, so the first row sits
    // at the table's end minus one row rather than at the end.
    let first = unsafe {
        (table as *const u8)
            .add(std::mem::size_of::<Table>())
            .sub(std::mem::size_of::<Row>())
    } as *const Row;

    // Refuse to walk past what was actually returned, whatever the count says.
    let available = (bytes.len() - std::mem::size_of::<Table>() + std::mem::size_of::<Row>())
        / std::mem::size_of::<Row>();
    unsafe { std::slice::from_raw_parts(first, count.min(available)) }
}

/// Read every open TCP and UDP socket, joined to the program that owns it.
pub fn survey() -> ConnectionReport {
    let mut found: Vec<Connection> = Vec::new();

    // --- TCP over IPv4 ----------------------------------------------------
    if let Some(bytes) = table_bytes(|buffer, size| unsafe {
        GetExtendedTcpTable(
            buffer,
            size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    }) {
        for row in unsafe { rows::<MIB_TCPTABLE_OWNER_PID, MIB_TCPROW_OWNER_PID>(&bytes) } {
            let state = State::from_tcp(row.dwState);
            let remote = ipv4(row.dwRemoteAddr).to_string();
            found.push(Connection {
                protocol: "TCP".to_owned(),
                state,
                local_address: ipv4(row.dwLocalAddr).to_string(),
                local_port: port(row.dwLocalPort),
                external: state != State::Listening && is_external(&remote),
                remote_port: (state != State::Listening).then(|| port(row.dwRemotePort)),
                remote_address: (state != State::Listening).then_some(remote),
                process_id: row.dwOwningPid,
                image_path: None,
                name: None,
                description: None,
                company: None,
                signer: None,
                unsigned: None,
            });
        }
    }

    // --- TCP over IPv6 ----------------------------------------------------
    if let Some(bytes) = table_bytes(|buffer, size| unsafe {
        GetExtendedTcpTable(
            buffer,
            size,
            false,
            AF_INET6.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    }) {
        for row in unsafe { rows::<MIB_TCP6TABLE_OWNER_PID, MIB_TCP6ROW_OWNER_PID>(&bytes) } {
            let state = State::from_tcp(row.dwState);
            let remote = ipv6(row.ucRemoteAddr).to_string();
            found.push(Connection {
                protocol: "TCP".to_owned(),
                state,
                local_address: ipv6(row.ucLocalAddr).to_string(),
                local_port: port(row.dwLocalPort),
                external: state != State::Listening && is_external(&remote),
                remote_port: (state != State::Listening).then(|| port(row.dwRemotePort)),
                remote_address: (state != State::Listening).then_some(remote),
                process_id: row.dwOwningPid,
                image_path: None,
                name: None,
                description: None,
                company: None,
                signer: None,
                unsigned: None,
            });
        }
    }

    // --- UDP ---------------------------------------------------------------
    // Connectionless, so there is no peer to report: only who is holding the
    // port open. Still worth showing — an unexpected program bound to a port
    // is exactly the sort of thing this view is for.
    if let Some(bytes) = table_bytes(|buffer, size| unsafe {
        GetExtendedUdpTable(
            buffer,
            size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    }) {
        for row in unsafe { rows::<MIB_UDPTABLE_OWNER_PID, MIB_UDPROW_OWNER_PID>(&bytes) } {
            found.push(Connection {
                protocol: "UDP".to_owned(),
                state: State::Connectionless,
                local_address: ipv4(row.dwLocalAddr).to_string(),
                local_port: port(row.dwLocalPort),
                remote_address: None,
                remote_port: None,
                external: false,
                process_id: row.dwOwningPid,
                image_path: None,
                name: None,
                description: None,
                company: None,
                signer: None,
                unsigned: None,
            });
        }
    }

    if let Some(bytes) = table_bytes(|buffer, size| unsafe {
        GetExtendedUdpTable(
            buffer,
            size,
            false,
            AF_INET6.0 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        )
    }) {
        for row in unsafe { rows::<MIB_UDP6TABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID>(&bytes) } {
            found.push(Connection {
                protocol: "UDP".to_owned(),
                state: State::Connectionless,
                local_address: ipv6(row.ucLocalAddr).to_string(),
                local_port: port(row.dwLocalPort),
                remote_address: None,
                remote_port: None,
                external: false,
                process_id: row.dwOwningPid,
                image_path: None,
                name: None,
                description: None,
                company: None,
                signer: None,
                unsigned: None,
            });
        }
    }

    // --- join to the owning program ---------------------------------------
    //
    // Cached twice over. A browser holds dozens of sockets from one process,
    // and signature verification walks a certificate chain — doing either per
    // socket would turn a snapshot into a stall.
    let mut images: HashMap<u32, Option<String>> = HashMap::new();
    let mut signatures: HashMap<String, (Option<String>, Option<bool>)> = HashMap::new();
    let mut descriptions: HashMap<String, Option<kam_core::version::Claims>> = HashMap::new();

    for connection in &mut found {
        let image = images
            .entry(connection.process_id)
            .or_insert_with(|| image_of(connection.process_id))
            .clone();

        let Some(path) = image else {
            continue;
        };

        let (signer, unsigned) = signatures
            .entry(path.clone())
            .or_insert_with(|| {
                let signature = kam_scanner::signature::of(std::path::Path::new(&path));
                (
                    signature.signer().map(str::to_owned),
                    Some(!signature.is_valid()),
                )
            })
            .clone();

        connection.name = std::path::Path::new(&path)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned());
        // Cached per path like the signature: a machine with forty sockets
        // usually has far fewer distinct programs behind them, and reading a
        // version resource means opening the file.
        let claims = descriptions
            .entry(path.clone())
            .or_insert_with(|| kam_core::version::claims_of(std::path::Path::new(&path)))
            .clone();

        connection.description = claims
            .as_ref()
            .and_then(|claims| claims.best())
            .map(str::to_owned);
        connection.company = claims.as_ref().and_then(|claims| claims.company.clone());
        connection.image_path = Some(path);
        connection.signer = signer;
        connection.unsigned = unsigned;
    }

    // Most interesting first: talking to the internet, then unsigned, then
    // established, then by program so one program's sockets sit together.
    found.sort_by(|a, b| {
        b.external
            .cmp(&a.external)
            // Unknown sorts below both, since it is not a finding.
            .then_with(|| (b.unsigned == Some(true)).cmp(&(a.unsigned == Some(true))))
            .then_with(|| (b.state == State::Established).cmp(&(a.state == State::Established)))
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.local_port.cmp(&b.local_port))
    });

    let programs = found
        .iter()
        .filter_map(|connection| connection.image_path.as_deref())
        .collect::<std::collections::BTreeSet<_>>()
        .len();

    ConnectionReport {
        established: found
            .iter()
            .filter(|c| c.state == State::Established)
            .count(),
        listening: found.iter().filter(|c| c.state == State::Listening).count(),
        external: found.iter().filter(|c| c.external).count(),
        programs,
        connections: found,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The list says what programs *are*, not just what their files are called.
    ///
    /// The reason this exists: a connection list on a real machine is mostly
    /// `svchost.exe` over and over, and that tells a person nothing at all. The
    /// version resource turns those rows into "Host Process for Windows
    /// Services", which is the difference between a list that can be read and
    /// one that cannot.
    ///
    /// Asserted against this machine rather than a fixture, because the claim
    /// being made is about real programs. If a future change silently stopped
    /// reading resources, every row would quietly fall back to a file name and
    /// nothing else would fail.
    #[test]
    fn this_machine_has_connections_that_say_what_they_are() {
        let report = survey();
        let identified: Vec<&Connection> = report
            .connections
            .iter()
            .filter(|connection| connection.image_path.is_some())
            .collect();

        if identified.is_empty() {
            // Nothing to say. Unprivileged runs can see very little, and an
            // empty result is not a failure of this code.
            println!("no connection could be attributed to a program; skipping");
            return;
        }

        let described = identified
            .iter()
            .filter(|connection| connection.description.is_some())
            .count();

        assert!(
            described > 0,
            "not one of {} identified connections said what it was, so the \
             version resource is not being read at all",
            identified.len()
        );

        // And the description is genuinely more than the file name repeated.
        let better =
            identified.iter().any(
                |connection| match (&connection.description, &connection.name) {
                    (Some(description), Some(name)) => {
                        !description.eq_ignore_ascii_case(name) && description.len() > name.len()
                    }
                    _ => false,
                },
            );
        assert!(
            better,
            "every description was just the file name again, which adds nothing"
        );
    }

    #[test]
    fn ports_are_read_from_network_order() {
        // The trap: truncating instead of swapping turns 443 into 47873, which
        // looks like a real port number and would ship unnoticed.
        assert_eq!(port(0x0000_BB01), 443);
        assert_eq!(port(0x0000_5000), 80);
        assert_eq!(port(0), 0);
    }

    #[test]
    fn addresses_are_read_in_the_right_byte_order() {
        // 127.0.0.1 as the table stores it.
        assert_eq!(ipv4(0x0100_007F).to_string(), "127.0.0.1");
    }

    #[test]
    fn local_and_private_addresses_are_not_the_internet() {
        for near in [
            "127.0.0.1",
            "0.0.0.0",
            "10.1.2.3",
            "192.168.0.5",
            "172.16.4.4",
            "169.254.1.1",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
        ] {
            assert!(!is_external(near), "{near} should not count as external");
        }
    }

    #[test]
    fn public_addresses_are_the_internet() {
        for far in ["8.8.8.8", "142.250.180.4", "2606:4700:4700::1111"] {
            assert!(is_external(far), "{far} should count as external");
        }
    }

    #[test]
    fn nonsense_is_not_called_external() {
        // Rather than defaulting an unparseable address to "on the internet",
        // which would be an alarming claim invented from a parse failure.
        assert!(!is_external(""));
        assert!(!is_external("not an address"));
    }

    #[test]
    fn this_machine_has_open_sockets() {
        // Every running Windows machine has listening sockets. None means the
        // table reading is broken rather than the machine being quiet.
        let report = survey();
        println!(
            "{} sockets: {} connected, {} listening, {} external, across {} programs",
            report.connections.len(),
            report.established,
            report.listening,
            report.external,
            report.programs
        );

        assert!(
            !report.connections.is_empty(),
            "no sockets at all; the table reading is broken"
        );
        assert!(
            report.listening > 0,
            "nothing is listening, which cannot be true on Windows"
        );

        // The join is the point of this module. If nothing resolved to a
        // program, the table was read but the interesting half is missing.
        let named = report
            .connections
            .iter()
            .filter(|c| c.image_path.is_some())
            .count();
        assert!(
            named > 0,
            "no socket resolved to a program; the join is broken"
        );
        println!("{named} resolved to a program");

        for connection in report.connections.iter().take(12) {
            println!(
                "  {} {:<22} {:>5} -> {:<24} {} [{}]",
                connection.protocol,
                connection.name.as_deref().unwrap_or("?"),
                connection.local_port,
                connection
                    .remote_address
                    .as_deref()
                    .map(|address| format!("{address}:{}", connection.remote_port.unwrap_or(0)))
                    .unwrap_or_else(|| "-".to_owned()),
                connection.state.label(),
                connection
                    .signer
                    .as_deref()
                    .unwrap_or(match connection.unsigned {
                        Some(true) => "unsigned",
                        Some(false) => "signed, unnamed",
                        None => "unknown",
                    }),
            );
        }
    }

    #[test]
    fn a_socket_with_no_identifiable_program_is_not_called_unsigned() {
        // The distinction this whole field exists for. Running unprivileged,
        // most processes cannot be opened; reporting those as unsigned would
        // manufacture a finding out of a permissions failure.
        let report = survey();
        for connection in &report.connections {
            if connection.image_path.is_none() {
                assert_eq!(
                    connection.unsigned, None,
                    "a socket with no resolved program claimed a signature state"
                );
            } else {
                assert!(
                    connection.unsigned.is_some(),
                    "a resolved program has no signature state"
                );
            }
        }
    }

    #[test]
    fn ports_are_plausible() {
        // A byte-order mistake shows up as a table full of implausible ports.
        let report = survey();
        let well_known = report
            .connections
            .iter()
            .filter(|c| matches!(c.local_port, 135 | 139 | 445 | 443 | 80 | 5353))
            .count();
        println!("{well_known} sockets on well-known ports");
        assert!(
            well_known > 0,
            "no socket on any well-known port, which suggests the port bytes are the wrong way round"
        );
    }
}
