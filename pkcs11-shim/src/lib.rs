// SPDX-FileCopyrightText: 2026 Morgan Jones
//
// SPDX-License-Identifier: BlueOak-1.0.0

//! A minimal, sign-only PKCS#11 module that brokers signing to `autopen`.
//!
//! This exposes just enough of the PKCS#11 v2.40 ABI for a consumer (e.g.
//! `apksigner` via Java's SunPKCS11) to find one RSA key and sign with it: a
//! single slot, a single token, one proxy key, and `CKM_SHA256_RSA_PKCS`. The
//! private-key operation is not performed here — it is relayed over the `autopen`
//! capability socket to a [`HardwareSigner`] on the far side (added in a later
//! task). Everything else returns `CKR_FUNCTION_NOT_SUPPORTED`.
//!
//! The ABI types and constants come from `cryptoki-sys`; this crate provides the
//! `CK_FUNCTION_LIST` vtable and the exported `C_GetFunctionList` entry point.

// This is an FFI boundary implementing a C ABI.
#![allow(non_snake_case)]

mod state;

use std::{os::raw::c_void, ptr};

use cryptoki_sys::{
    CK_ATTRIBUTE, CK_ATTRIBUTE_TYPE, CK_NOTIFY, CK_OBJECT_HANDLE, CK_SESSION_HANDLE,
    CK_SESSION_INFO, CK_USER_TYPE, CK_UTF8CHAR, CKF_SERIAL_SESSION, CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_OBJECT_HANDLE_INVALID, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_HANDLE_INVALID,
    CKS_RO_PUBLIC_SESSION,
};
use cryptoki_sys::{
    CK_BBOOL, CK_FLAGS, CK_FUNCTION_LIST, CK_FUNCTION_LIST_PTR_PTR, CK_INFO, CK_MECHANISM_INFO,
    CK_MECHANISM_TYPE, CK_RV, CK_SLOT_ID, CK_SLOT_INFO, CK_TOKEN_INFO, CK_ULONG, CK_VERSION,
    CKF_SIGN, CKF_TOKEN_INITIALIZED, CKF_TOKEN_PRESENT, CKM_SHA256_RSA_PKCS, CKR_ARGUMENTS_BAD,
    CKR_BUFFER_TOO_SMALL, CKR_MECHANISM_INVALID, CKR_OK, CKR_SLOT_ID_INVALID,
};
use cryptoki_sys::{
    CK_BYTE, CK_MECHANISM, CKR_DEVICE_ERROR, CKR_GENERAL_ERROR, CKR_KEY_HANDLE_INVALID,
};

/// Relays a message to `autopen serve` for signing, via the remote signing key
/// at `AUTOPEN_REMOTE_KEY`. Maps failures to PKCS#11 return values.
fn sign_message(message: &[u8]) -> Result<Vec<u8>, CK_RV> {
    let path = match std::env::var("AUTOPEN_REMOTE_KEY") {
        Ok(path) => path,
        Err(_) => {
            eprintln!("autopen-pkcs11: AUTOPEN_REMOTE_KEY is not set");
            return Err(CKR_GENERAL_ERROR);
        }
    };
    autopen::client::sign_with_remote_key(&path, message).map_err(|err| {
        eprintln!("autopen-pkcs11: signing failed: {err:?}");
        CKR_DEVICE_ERROR
    })
}

/// Writes `signature` into a caller buffer following the two-call convention.
///
/// # Safety
///
/// `signature_len` must be valid; `signature` must point to `*signature_len`
/// bytes (or be null for a length query).
unsafe fn write_signature(signature: &[u8], out: *mut CK_BYTE, out_len: &mut CK_ULONG) -> CK_RV {
    let n = signature.len().min(*out_len as usize);
    unsafe { ptr::copy_nonoverlapping(signature.as_ptr(), out, n) };
    *out_len = signature.len() as CK_ULONG;
    CKR_OK
}

/// The single slot this module exposes.
const SLOT_ID: CK_SLOT_ID = 0;
/// The token label reported for the slot.
const TOKEN_LABEL: &str = "autopen";
/// The manufacturer id reported throughout.
const MANUFACTURER: &str = "autopen";
/// PKCS#11 `CK_UNAVAILABLE_INFORMATION` (not exported by `cryptoki-sys`).
const UNAVAILABLE: CK_ULONG = CK_ULONG::MAX;

/// Space‐pads `value` into a fixed‐width PKCS#11 field (no NUL terminator).
fn pad(field: &mut [u8], value: &str) {
    field.fill(b' ');
    let bytes = value.as_bytes();
    let n = bytes.len().min(field.len());
    field[..n].copy_from_slice(&bytes[..n]);
}

/// A version to report for the library/token/hardware/firmware.
const VERSION: CK_VERSION = CK_VERSION { major: 0, minor: 1 };
/// The Cryptoki version this module speaks (2.40).
const CRYPTOKI_VERSION: CK_VERSION = CK_VERSION {
    major: 2,
    minor: 40,
};

unsafe extern "C" fn C_Initialize(_init_args: *mut c_void) -> CK_RV {
    CKR_OK
}

unsafe extern "C" fn C_Finalize(_reserved: *mut c_void) -> CK_RV {
    CKR_OK
}

unsafe extern "C" fn C_GetInfo(info: *mut CK_INFO) -> CK_RV {
    let Some(info) = (unsafe { info.as_mut() }) else {
        return CKR_ARGUMENTS_BAD;
    };
    info.cryptokiVersion = CRYPTOKI_VERSION;
    pad(&mut info.manufacturerID, MANUFACTURER);
    info.flags = 0;
    pad(&mut info.libraryDescription, "autopen pkcs11 shim");
    info.libraryVersion = VERSION;
    CKR_OK
}

unsafe extern "C" fn C_GetSlotList(
    _token_present: CK_BBOOL,
    slot_list: *mut CK_SLOT_ID,
    count: *mut CK_ULONG,
) -> CK_RV {
    let Some(count) = (unsafe { count.as_mut() }) else {
        return CKR_ARGUMENTS_BAD;
    };
    if slot_list.is_null() {
        *count = 1;
        return CKR_OK;
    }
    if *count < 1 {
        *count = 1;
        return CKR_BUFFER_TOO_SMALL;
    }
    unsafe { *slot_list = SLOT_ID };
    *count = 1;
    CKR_OK
}

unsafe extern "C" fn C_GetSlotInfo(slot_id: CK_SLOT_ID, info: *mut CK_SLOT_INFO) -> CK_RV {
    if slot_id != SLOT_ID {
        return CKR_SLOT_ID_INVALID;
    }
    let Some(info) = (unsafe { info.as_mut() }) else {
        return CKR_ARGUMENTS_BAD;
    };
    pad(&mut info.slotDescription, "autopen hardware signing");
    pad(&mut info.manufacturerID, MANUFACTURER);
    info.flags = CKF_TOKEN_PRESENT;
    info.hardwareVersion = VERSION;
    info.firmwareVersion = VERSION;
    CKR_OK
}

unsafe extern "C" fn C_GetTokenInfo(slot_id: CK_SLOT_ID, info: *mut CK_TOKEN_INFO) -> CK_RV {
    if slot_id != SLOT_ID {
        return CKR_SLOT_ID_INVALID;
    }
    let Some(info) = (unsafe { info.as_mut() }) else {
        return CKR_ARGUMENTS_BAD;
    };
    pad(&mut info.label, TOKEN_LABEL);
    pad(&mut info.manufacturerID, MANUFACTURER);
    pad(&mut info.model, "autopen");
    pad(&mut info.serialNumber, "0");
    // Login is not required: the far-side autopen daemon holds the token PIN.
    info.flags = CKF_TOKEN_INITIALIZED;
    info.ulMaxSessionCount = UNAVAILABLE;
    info.ulSessionCount = UNAVAILABLE;
    info.ulMaxRwSessionCount = UNAVAILABLE;
    info.ulRwSessionCount = UNAVAILABLE;
    info.ulMaxPinLen = 0;
    info.ulMinPinLen = 0;
    info.ulTotalPublicMemory = UNAVAILABLE;
    info.ulFreePublicMemory = UNAVAILABLE;
    info.ulTotalPrivateMemory = UNAVAILABLE;
    info.ulFreePrivateMemory = UNAVAILABLE;
    info.hardwareVersion = VERSION;
    info.firmwareVersion = VERSION;
    pad(&mut info.utcTime, "");
    CKR_OK
}

unsafe extern "C" fn C_GetMechanismList(
    slot_id: CK_SLOT_ID,
    mechanism_list: *mut CK_MECHANISM_TYPE,
    count: *mut CK_ULONG,
) -> CK_RV {
    if slot_id != SLOT_ID {
        return CKR_SLOT_ID_INVALID;
    }
    let Some(count) = (unsafe { count.as_mut() }) else {
        return CKR_ARGUMENTS_BAD;
    };
    if mechanism_list.is_null() {
        *count = 1;
        return CKR_OK;
    }
    if *count < 1 {
        *count = 1;
        return CKR_BUFFER_TOO_SMALL;
    }
    unsafe { *mechanism_list = CKM_SHA256_RSA_PKCS };
    *count = 1;
    CKR_OK
}

unsafe extern "C" fn C_GetMechanismInfo(
    slot_id: CK_SLOT_ID,
    mechanism_type: CK_MECHANISM_TYPE,
    info: *mut CK_MECHANISM_INFO,
) -> CK_RV {
    if slot_id != SLOT_ID {
        return CKR_SLOT_ID_INVALID;
    }
    if mechanism_type != CKM_SHA256_RSA_PKCS {
        return CKR_MECHANISM_INVALID;
    }
    let Some(info) = (unsafe { info.as_mut() }) else {
        return CKR_ARGUMENTS_BAD;
    };
    let key_bits = (state::with_state(|s| s.sig_len()) * 8) as CK_ULONG;
    info.ulMinKeySize = key_bits;
    info.ulMaxKeySize = key_bits;
    info.flags = CKF_SIGN as CK_FLAGS;
    CKR_OK
}

/// Copies a PKCS#11 find/attribute template into owned `(type, value)` pairs.
///
/// # Safety
///
/// `template` must point to `count` valid `CK_ATTRIBUTE`s, each with a `pValue`
/// buffer of `ulValueLen` bytes (or null).
unsafe fn read_template(
    template: *mut CK_ATTRIBUTE,
    count: CK_ULONG,
) -> Vec<(CK_ATTRIBUTE_TYPE, Vec<u8>)> {
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let attr = unsafe { &*template.add(i) };
        let value = if attr.pValue.is_null() {
            Vec::new()
        } else {
            unsafe {
                std::slice::from_raw_parts(attr.pValue.cast::<u8>(), attr.ulValueLen as usize)
            }
            .to_vec()
        };
        out.push((attr.type_, value));
    }
    out
}

unsafe extern "C" fn C_OpenSession(
    slot_id: CK_SLOT_ID,
    _flags: CK_FLAGS,
    _application: *mut c_void,
    _notify: CK_NOTIFY,
    session: *mut CK_SESSION_HANDLE,
) -> CK_RV {
    if slot_id != SLOT_ID {
        return CKR_SLOT_ID_INVALID;
    }
    let Some(session) = (unsafe { session.as_mut() }) else {
        return CKR_ARGUMENTS_BAD;
    };
    *session = state::with_state(state::State::open_session);
    CKR_OK
}

unsafe extern "C" fn C_CloseSession(session: CK_SESSION_HANDLE) -> CK_RV {
    if state::with_state(|s| s.close_session(session)) {
        CKR_OK
    } else {
        CKR_SESSION_HANDLE_INVALID
    }
}

unsafe extern "C" fn C_GetSessionInfo(
    session: CK_SESSION_HANDLE,
    info: *mut CK_SESSION_INFO,
) -> CK_RV {
    let Some(info) = (unsafe { info.as_mut() }) else {
        return CKR_ARGUMENTS_BAD;
    };
    if !state::with_state(|s| s.session_mut(session).is_some()) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    info.slotID = SLOT_ID;
    info.state = CKS_RO_PUBLIC_SESSION;
    info.flags = CKF_SERIAL_SESSION;
    info.ulDeviceError = 0;
    CKR_OK
}

unsafe extern "C" fn C_Login(
    session: CK_SESSION_HANDLE,
    _user_type: CK_USER_TYPE,
    _pin: *mut CK_UTF8CHAR,
    _pin_len: CK_ULONG,
) -> CK_RV {
    // No-op: the far-side autopen daemon holds the token PIN.
    if state::with_state(|s| s.session_mut(session).is_some()) {
        CKR_OK
    } else {
        CKR_SESSION_HANDLE_INVALID
    }
}

unsafe extern "C" fn C_Logout(session: CK_SESSION_HANDLE) -> CK_RV {
    if state::with_state(|s| s.session_mut(session).is_some()) {
        CKR_OK
    } else {
        CKR_SESSION_HANDLE_INVALID
    }
}

unsafe extern "C" fn C_FindObjectsInit(
    session: CK_SESSION_HANDLE,
    template: *mut CK_ATTRIBUTE,
    count: CK_ULONG,
) -> CK_RV {
    let template = unsafe { read_template(template, count) };
    if state::with_state(|s| s.find_init(session, &template)) {
        CKR_OK
    } else {
        CKR_SESSION_HANDLE_INVALID
    }
}

unsafe extern "C" fn C_FindObjects(
    session: CK_SESSION_HANDLE,
    object: *mut CK_OBJECT_HANDLE,
    max_object_count: CK_ULONG,
    object_count: *mut CK_ULONG,
) -> CK_RV {
    let Some(object_count) = (unsafe { object_count.as_mut() }) else {
        return CKR_ARGUMENTS_BAD;
    };
    let Some(handles) = state::with_state(|s| s.find_next(session, max_object_count as usize))
    else {
        return CKR_OPERATION_NOT_INITIALIZED;
    };
    for (i, handle) in handles.iter().enumerate() {
        unsafe { *object.add(i) = *handle };
    }
    *object_count = handles.len() as CK_ULONG;
    CKR_OK
}

unsafe extern "C" fn C_FindObjectsFinal(session: CK_SESSION_HANDLE) -> CK_RV {
    if state::with_state(|s| s.find_final(session)) {
        CKR_OK
    } else {
        CKR_SESSION_HANDLE_INVALID
    }
}

unsafe extern "C" fn C_GetAttributeValue(
    _session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    template: *mut CK_ATTRIBUTE,
    count: CK_ULONG,
) -> CK_RV {
    let n = count as usize;
    let types: Vec<CK_ATTRIBUTE_TYPE> = (0..n)
        .map(|i| unsafe { (*template.add(i)).type_ })
        .collect();
    let Some(values) = state::with_state(|s| {
        s.object(object)
            .map(|o| types.iter().map(|t| o.attr(*t)).collect::<Vec<_>>())
    }) else {
        return CKR_OBJECT_HANDLE_INVALID;
    };

    let mut rv = CKR_OK;
    for (i, value) in values.into_iter().enumerate() {
        let attr = unsafe { &mut *template.add(i) };
        match value {
            None => {
                attr.ulValueLen = UNAVAILABLE;
                rv = CKR_ATTRIBUTE_TYPE_INVALID;
            }
            Some(bytes) => {
                if attr.pValue.is_null() {
                    attr.ulValueLen = bytes.len() as CK_ULONG;
                } else if attr.ulValueLen as usize >= bytes.len() {
                    unsafe {
                        ptr::copy_nonoverlapping(
                            bytes.as_ptr(),
                            attr.pValue.cast::<u8>(),
                            bytes.len(),
                        );
                    }
                    attr.ulValueLen = bytes.len() as CK_ULONG;
                } else {
                    attr.ulValueLen = UNAVAILABLE;
                    rv = CKR_BUFFER_TOO_SMALL;
                }
            }
        }
    }
    rv
}

unsafe extern "C" fn C_SignInit(
    session: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
) -> CK_RV {
    let Some(mechanism) = (unsafe { mechanism.as_ref() }) else {
        return CKR_ARGUMENTS_BAD;
    };
    if mechanism.mechanism != CKM_SHA256_RSA_PKCS {
        return CKR_MECHANISM_INVALID;
    }
    if key != state::PRIVATE_KEY_HANDLE {
        return CKR_KEY_HANDLE_INVALID;
    }
    if state::with_state(|s| s.sign_init(session)) {
        CKR_OK
    } else {
        CKR_SESSION_HANDLE_INVALID
    }
}

unsafe extern "C" fn C_SignUpdate(
    session: CK_SESSION_HANDLE,
    part: *mut CK_BYTE,
    part_len: CK_ULONG,
) -> CK_RV {
    let data = if part.is_null() {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(part, part_len as usize) }
    };
    if state::with_state(|s| s.sign_update(session, data)) {
        CKR_OK
    } else {
        CKR_OPERATION_NOT_INITIALIZED
    }
}

unsafe extern "C" fn C_SignFinal(
    session: CK_SESSION_HANDLE,
    signature: *mut CK_BYTE,
    signature_len: *mut CK_ULONG,
) -> CK_RV {
    let Some(signature_len) = (unsafe { signature_len.as_mut() }) else {
        return CKR_ARGUMENTS_BAD;
    };
    if !state::with_state(|s| s.sign_active(session)) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let sig_len = state::with_state(|s| s.sig_len());
    if signature.is_null() {
        *signature_len = sig_len as CK_ULONG;
        return CKR_OK;
    }
    if (*signature_len as usize) < sig_len {
        *signature_len = sig_len as CK_ULONG;
        return CKR_BUFFER_TOO_SMALL;
    }
    let message = state::with_state(|s| s.sign_take(session)).unwrap_or_default();
    match sign_message(&message) {
        Ok(sig) => unsafe { write_signature(&sig, signature, signature_len) },
        Err(rv) => rv,
    }
}

unsafe extern "C" fn C_Sign(
    session: CK_SESSION_HANDLE,
    data: *mut CK_BYTE,
    data_len: CK_ULONG,
    signature: *mut CK_BYTE,
    signature_len: *mut CK_ULONG,
) -> CK_RV {
    let Some(signature_len) = (unsafe { signature_len.as_mut() }) else {
        return CKR_ARGUMENTS_BAD;
    };
    if !state::with_state(|s| s.sign_active(session)) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    let sig_len = state::with_state(|s| s.sig_len());
    if signature.is_null() {
        *signature_len = sig_len as CK_ULONG;
        return CKR_OK;
    }
    if (*signature_len as usize) < sig_len {
        *signature_len = sig_len as CK_ULONG;
        return CKR_BUFFER_TOO_SMALL;
    }
    let message = if data.is_null() {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(data, data_len as usize) }.to_vec()
    };
    // Single-part sign uses the supplied data; clear the operation.
    let _ = state::with_state(|s| s.sign_take(session));
    match sign_message(&message) {
        Ok(sig) => unsafe { write_signature(&sig, signature, signature_len) },
        Err(rv) => rv,
    }
}

/// The module's function list. Implemented entries are `Some`; everything not
/// needed for sign-only operation is `None` (`CKR_FUNCTION_NOT_SUPPORTED`).
static FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CRYPTOKI_VERSION,
    C_Initialize: Some(C_Initialize),
    C_Finalize: Some(C_Finalize),
    C_GetInfo: Some(C_GetInfo),
    C_GetFunctionList: Some(C_GetFunctionList),
    C_GetSlotList: Some(C_GetSlotList),
    C_GetSlotInfo: Some(C_GetSlotInfo),
    C_GetTokenInfo: Some(C_GetTokenInfo),
    C_GetMechanismList: Some(C_GetMechanismList),
    C_GetMechanismInfo: Some(C_GetMechanismInfo),
    C_InitToken: None,
    C_InitPIN: None,
    C_SetPIN: None,
    C_OpenSession: Some(C_OpenSession),
    C_CloseSession: Some(C_CloseSession),
    C_CloseAllSessions: None,
    C_GetSessionInfo: Some(C_GetSessionInfo),
    C_GetOperationState: None,
    C_SetOperationState: None,
    C_Login: Some(C_Login),
    C_Logout: Some(C_Logout),
    C_CreateObject: None,
    C_CopyObject: None,
    C_DestroyObject: None,
    C_GetObjectSize: None,
    C_GetAttributeValue: Some(C_GetAttributeValue),
    C_SetAttributeValue: None,
    C_FindObjectsInit: Some(C_FindObjectsInit),
    C_FindObjects: Some(C_FindObjects),
    C_FindObjectsFinal: Some(C_FindObjectsFinal),
    C_EncryptInit: None,
    C_Encrypt: None,
    C_EncryptUpdate: None,
    C_EncryptFinal: None,
    C_DecryptInit: None,
    C_Decrypt: None,
    C_DecryptUpdate: None,
    C_DecryptFinal: None,
    C_DigestInit: None,
    C_Digest: None,
    C_DigestUpdate: None,
    C_DigestKey: None,
    C_DigestFinal: None,
    C_SignInit: Some(C_SignInit),
    C_Sign: Some(C_Sign),
    C_SignUpdate: Some(C_SignUpdate),
    C_SignFinal: Some(C_SignFinal),
    C_SignRecoverInit: None,
    C_SignRecover: None,
    C_VerifyInit: None,
    C_Verify: None,
    C_VerifyUpdate: None,
    C_VerifyFinal: None,
    C_VerifyRecoverInit: None,
    C_VerifyRecover: None,
    C_DigestEncryptUpdate: None,
    C_DecryptDigestUpdate: None,
    C_SignEncryptUpdate: None,
    C_DecryptVerifyUpdate: None,
    C_GenerateKey: None,
    C_GenerateKeyPair: None,
    C_WrapKey: None,
    C_UnwrapKey: None,
    C_DeriveKey: None,
    C_SeedRandom: None,
    C_GenerateRandom: None,
    C_GetFunctionStatus: None,
    C_CancelFunction: None,
    C_WaitForSlotEvent: None,
};

/// The PKCS#11 entry point: returns a pointer to the module's function list.
///
/// # Safety
///
/// `pp_function_list` must be a valid pointer to a `CK_FUNCTION_LIST_PTR`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetFunctionList(pp_function_list: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    if pp_function_list.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe { *pp_function_list = &raw const FUNCTION_LIST as *mut CK_FUNCTION_LIST };
    CKR_OK
}
