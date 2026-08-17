//! Just enough WMI to read what Defender publishes.
//!
//! Defender's state lives in the `root\Microsoft\Windows\Defender` namespace,
//! and WMI is the supported way to read it. The alternative — shelling out to
//! `Get-MpComputerStatus | ConvertTo-Json` — costs the better part of a second
//! per call in PowerShell start-up alone, from a service that answers a polling
//! interface. So this talks to WMI directly through COM.
//!
//! Deliberately read-only. Invoking WMI methods means `GetMethod`,
//! `SpawnInstance` and `ExecMethod`, a good deal more machinery, and nothing
//! here needs to change Defender's mind about anything yet.
//!
//! # Threading
//!
//! The agent serves each connection on its own thread, so COM is initialised per
//! call rather than once per process. `CoInitializeEx` on an uninitialised
//! thread is cheap, and the guard below uninitialises on the way out — declared
//! before the interfaces it protects so that it drops after them, since Rust
//! drops locals in reverse.
//!
//! `CoInitializeSecurity` is not called. It is process-global, must precede
//! every other COM call, and would make this module's behaviour depend on who
//! ran first. Setting the proxy blanket on each connection achieves the same
//! thing locally, which is what the documented WMI examples do anyway.

use std::collections::HashMap;

use kam_core::{Error, Result};
use windows::core::{BSTR, PCWSTR};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoSetProxyBlanket, CoUninitialize, CLSCTX_INPROC_SERVER,
    COINIT_MULTITHREADED, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
};
use windows::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE};
use windows::Win32::System::Variant::{VariantClear, VARIANT};
use windows::Win32::System::Wmi::{
    IWbemClassObject, IWbemLocator, IWbemServices, WbemLocator, WBEM_FLAG_FORWARD_ONLY,
    WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_INFINITE,
};

/// One property value, reduced to the few shapes Defender actually uses.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Text(String),
    Number(i64),
    Flag(bool),
    /// Present but null, which WMI uses freely and which is not the same as
    /// zero or false.
    Empty,
}

impl Value {
    pub fn text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            _ => None,
        }
    }

    pub fn number(&self) -> Option<i64> {
        match self {
            Self::Number(number) => Some(*number),
            // WMI hands back plenty of numbers as strings, particularly the
            // large ones, and a caller should not have to care which.
            Self::Text(text) => text.parse().ok(),
            _ => None,
        }
    }

    pub fn flag(&self) -> Option<bool> {
        match self {
            Self::Flag(flag) => Some(*flag),
            Self::Number(number) => Some(*number != 0),
            _ => None,
        }
    }
}

pub type Row = HashMap<String, Value>;

/// Uninitialises COM for this thread when it goes out of scope.
struct ComGuard;

impl Drop for ComGuard {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

fn com_error(error: windows::core::Error, context: &str) -> Error {
    Error::Privileged(format!("{context}: {error}"))
}

/// Convert one VARIANT into something ordinary, then release it.
fn take_value(variant: &mut VARIANT) -> Value {
    // The tag lives behind two layers of union in the generated binding.
    let tag = unsafe { variant.Anonymous.Anonymous.vt };
    let inner = unsafe { &variant.Anonymous.Anonymous.Anonymous };

    // VT_EMPTY is 0 and VT_NULL is 1; both mean "nothing here".
    let value = match tag.0 {
        0 | 1 => Value::Empty,
        // VT_BSTR
        8 => {
            let text = unsafe { &inner.bstrVal };
            Value::Text(text.to_string())
        }
        // VT_BOOL, where true is -1.
        11 => Value::Flag(unsafe { inner.boolVal.0 } != 0),
        // VT_I1, VT_I2, VT_I4, VT_INT
        16 => Value::Number(unsafe { inner.cVal } as i64),
        2 => Value::Number(unsafe { inner.iVal } as i64),
        3 | 22 => Value::Number(unsafe { inner.lVal } as i64),
        // VT_UI1, VT_UI2, VT_UI4, VT_UINT
        17 => Value::Number(unsafe { inner.bVal } as i64),
        18 => Value::Number(unsafe { inner.uiVal } as i64),
        19 | 23 => Value::Number(unsafe { inner.ulVal } as i64),
        // VT_I8 / VT_UI8
        20 => Value::Number(unsafe { inner.llVal }),
        21 => Value::Number(unsafe { inner.ullVal } as i64),
        // Arrays and anything else are not read here. Defender uses them only
        // for exclusion lists, which are handled through their own query.
        _ => Value::Empty,
    };

    unsafe {
        let _ = VariantClear(variant);
    }
    value
}

/// Pull every named property off one WMI object.
fn read_object(object: &IWbemClassObject, wanted: &[&str]) -> Row {
    let mut row = Row::new();
    for name in wanted {
        // Kept alive for the duration of the call: PCWSTR borrows it.
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut variant = VARIANT::default();
        let outcome = unsafe { object.Get(PCWSTR(wide.as_ptr()), 0, &mut variant, None, None) };
        if outcome.is_ok() {
            row.insert((*name).to_owned(), take_value(&mut variant));
        }
    }
    row
}

/// Run a WQL query and return the properties named in `wanted`.
///
/// Properties are named rather than enumerated because the caller always knows
/// which it wants, and enumerating means walking every property of every object
/// to discard most of them.
pub fn query(namespace: &str, wql: &str, wanted: &[&str]) -> Result<Vec<Row>> {
    // Declared first so it drops last, after the interfaces below.
    let _guard = unsafe {
        let outcome = CoInitializeEx(None, COINIT_MULTITHREADED);
        if outcome.is_err() {
            return Err(Error::Privileged(format!(
                "could not initialise COM: {outcome:?}"
            )));
        }
        ComGuard
    };

    let locator: IWbemLocator =
        unsafe { CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER) }
            .map_err(|error| com_error(error, "could not create the WMI locator"))?;

    let services: IWbemServices = unsafe {
        locator.ConnectServer(
            &BSTR::from(namespace),
            &BSTR::new(),
            &BSTR::new(),
            &BSTR::new(),
            0,
            &BSTR::new(),
            None,
        )
    }
    .map_err(|error| com_error(error, &format!("could not connect to {namespace}")))?;

    // Without this the call is made with the caller's default identity, which
    // for a service is not necessarily one WMI will accept.
    unsafe {
        CoSetProxyBlanket(
            &services,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            None,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
        )
    }
    .map_err(|error| com_error(error, "could not set the WMI proxy blanket"))?;

    let enumerator = unsafe {
        services.ExecQuery(
            &BSTR::from("WQL"),
            &BSTR::from(wql),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            None,
        )
    }
    .map_err(|error| com_error(error, &format!("query failed: {wql}")))?;

    let mut rows = Vec::new();
    loop {
        let mut objects: [Option<IWbemClassObject>; 1] = [None];
        let mut returned = 0_u32;
        // Next reports the end of the enumeration by returning nothing, not by
        // failing, so the count is what terminates this.
        let _ = unsafe { enumerator.Next(WBEM_INFINITE, &mut objects, &mut returned) };
        if returned == 0 {
            break;
        }
        if let Some(object) = objects[0].take() {
            rows.push(read_object(&object, wanted));
        }
    }

    Ok(rows)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_number_held_as_text_still_reads_as_a_number() {
        // WMI returns large integers as strings often enough that callers
        // should not have to know which shape they got.
        assert_eq!(Value::Text("1234".to_owned()).number(), Some(1234));
        assert_eq!(Value::Number(7).number(), Some(7));
        assert_eq!(Value::Text("not a number".to_owned()).number(), None);
    }

    #[test]
    fn empty_is_not_false_and_not_zero() {
        // A property WMI did not set must not read as "protection is off".
        assert_eq!(Value::Empty.flag(), None);
        assert_eq!(Value::Empty.number(), None);
        assert_eq!(Value::Empty.text(), None);
    }

    #[test]
    fn a_number_reads_as_a_flag_but_text_does_not() {
        assert_eq!(Value::Number(1).flag(), Some(true));
        assert_eq!(Value::Number(0).flag(), Some(false));
        assert_eq!(Value::Flag(true).flag(), Some(true));
        assert_eq!(Value::Text("true".to_owned()).flag(), None);
    }

    #[test]
    fn the_operating_system_answers_a_trivial_query() {
        // Proves the COM plumbing end to end without depending on Defender
        // being in any particular state. Every Windows install has this class.
        let rows = query(
            r"ROOT\CIMV2",
            "SELECT Caption, BuildNumber FROM Win32_OperatingSystem",
            &["Caption", "BuildNumber"],
        )
        .expect("WMI should answer a query about the operating system");

        assert_eq!(rows.len(), 1, "there is exactly one operating system");
        let caption = rows[0].get("Caption").and_then(Value::text).unwrap_or("");
        assert!(
            caption.to_lowercase().contains("windows"),
            "unexpected caption: {caption}"
        );
    }

    #[test]
    fn a_query_against_a_missing_namespace_fails_rather_than_hanging() {
        assert!(query(r"ROOT\NoSuchNamespace", "SELECT * FROM Nothing", &[]).is_err());
    }
}
