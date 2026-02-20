//! Mach message protocol — replaces MiG-generated code from mach_exc.defs.
//!
//! Three message pairs matching the MiG routines:
//! - 2407: mach_exception_raise_state_identity (main exception handler)
//! - 2408: transfer_ports (custom port transfer for bootstrap trick)
//! - Dispatch function to replace mach_msg_server_once

use crate::ffi::*;

// ============================================================================
// Routine 2407: mach_exception_raise_state_identity
// ============================================================================

/// Request message for mach_exception_raise_state_identity (msgh_id = 2407).
/// This is the primary exception message sent by the kernel.
///
/// NOTE: `code` is `[u32; 4]` instead of `[i64; 2]` to avoid 8-byte alignment
/// padding that `#[repr(C)]` would insert. MIG messages use `#pragma pack(4)`,
/// so no padding exists before the code array in the kernel's wire format.
/// The i64 values are reconstructed in `serve_one_message()`.
#[repr(C)]
pub struct ExcStateIdentityRequest {
    pub header: MachMsgHeaderT,
    pub body: MachMsgBodyT,
    pub thread: MachMsgPortDescriptorT,
    pub task: MachMsgPortDescriptorT,
    pub ndr: NDRRecordT,
    pub exception: i32,
    pub code_count: u32,
    pub code: [u32; 4],
    pub flavor: i32,
    pub old_state_count: u32,
    pub old_state: [u32; THREAD_STATE_MAX],
}

/// Reply message for mach_exception_raise_state_identity (msgh_id = 2507).
#[repr(C)]
pub struct ExcStateIdentityReply {
    pub header: MachMsgHeaderT,
    pub ndr: NDRRecordT,
    pub return_code: KernReturnT,
    pub flavor: i32,
    pub new_state_count: u32,
    pub new_state: [u32; THREAD_STATE_MAX],
}

// ============================================================================
// Routine 2408: transfer_ports
// ============================================================================

/// Request message for transfer_ports (msgh_id = 2408).
/// Used by the child process to request ports from the parent.
#[repr(C)]
pub struct TransferPortsRequest {
    pub header: MachMsgHeaderT,
}

/// Reply message for transfer_ports (msgh_id = 2508).
/// Carries the exception port and original bootstrap port back to the child.
#[repr(C)]
pub struct TransferPortsReply {
    pub header: MachMsgHeaderT,
    pub body: MachMsgBodyT,
    pub exception_port: MachMsgPortDescriptorT,
    pub bootstrap_port: MachMsgPortDescriptorT,
    pub ndr: NDRRecordT,
    pub return_code: KernReturnT,
}

// ============================================================================
// Union type for receiving any message
// ============================================================================

/// Union-like buffer for receiving Mach messages.
/// Large enough to hold the biggest possible message (ExcStateIdentityRequest).
#[repr(C)]
pub union MachMsgBuffer {
    pub header: MachMsgHeaderT,
    pub exc_request: std::mem::ManuallyDrop<ExcStateIdentityRequest>,
    pub transfer_request: std::mem::ManuallyDrop<TransferPortsRequest>,
    pub bytes: [u8; 4096],
}

#[allow(dead_code)]
/// State passed through the exception handling loop.
pub struct ExcHandlerState {
    /// The exception port we listen on.
    pub exception_port: MachPortT,
    /// Original bootstrap port (to restore after fork trick).
    pub original_bootstrap_port: MachPortT,
    /// Server port for the bootstrap trick.
    pub server_port: MachPortT,
    /// Whether we've handled an exception.
    pub exception_received: bool,
    /// The exception data extracted from the message.
    pub exception_data: Option<ExceptionData>,
    /// Deferred exception reply (sent after handle_exception finishes).
    pub pending_reply: Option<PendingReply>,
}

#[allow(dead_code)]
/// Extracted exception data from the Mach message.
#[derive(Debug, Clone)]
pub struct ExceptionData {
    pub task_port: MachPortT,
    pub thread_port: MachPortT,
    pub exception_type: i32,
    pub code_count: u32,
    pub codes: Vec<i64>,
    pub flavor: i32,
    pub state_count: u32,
    pub state: Vec<u32>,
}

/// Saved reply info for deferred exception reply.
/// The child thread stays suspended until this reply is sent.
pub struct PendingReply {
    pub reply_port: MachPortT,
    pub reply_bits: MachMsgBitsT,
    pub flavor: i32,
    pub state_count: u32,
    pub state: [u32; THREAD_STATE_MAX],
}

/// Receives one Mach message and dispatches based on msgh_id.
///
/// For exception messages (2407): extracts data, stores a `PendingReply`,
/// but does NOT send the reply yet. The child thread stays suspended so the
/// caller can read its memory. Call `send_exception_reply()` when done.
///
/// For port transfers (2408): sends the reply immediately.
///
/// `receive_port` — the Mach port to listen on.
/// `timeout_ms`   — 0 means block forever; >0 adds MACH_RCV_TIMEOUT.
///
/// Returns Ok(true) if an exception was received, Ok(false) for port transfer,
/// Err on message receive/send failure (including MACH_RCV_TIMED_OUT on timeout).
pub fn serve_one_message(
    state: &mut ExcHandlerState,
    receive_port: MachPortT,
    timeout_ms: u32,
) -> Result<bool, i32> {
    let mut buffer = MachMsgBuffer { bytes: [0u8; 4096] };

    let options = if timeout_ms > 0 {
        MACH_RCV_MSG | MACH_RCV_LARGE | MACH_RCV_TIMEOUT
    } else {
        MACH_RCV_MSG | MACH_RCV_LARGE
    };

    // Receive a message
    let kr = unsafe {
        mach_msg(
            &mut buffer.header,
            options,
            0,
            std::mem::size_of::<MachMsgBuffer>() as u32,
            receive_port,
            timeout_ms,
            0,
        )
    };

    if kr != KERN_SUCCESS {
        return Err(kr);
    }

    let msg_id = unsafe { buffer.header.msgh_id };

    match msg_id {
        2407 => {
            // mach_exception_raise_state_identity
            let req = unsafe { &buffer.exc_request };
            let code_count = req.code_count.min(2) as usize;
            let state_count = req.old_state_count.min(THREAD_STATE_MAX as u32) as usize;

            // Reconstruct i64 codes from pairs of u32 (little-endian)
            let mut codes = Vec::with_capacity(code_count);
            for i in 0..code_count {
                let lo = req.code[i * 2] as u64;
                let hi = req.code[i * 2 + 1] as u64;
                codes.push((lo | (hi << 32)) as i64);
            }

            state.exception_data = Some(ExceptionData {
                task_port: req.task.name,
                thread_port: req.thread.name,
                exception_type: req.exception,
                code_count: req.code_count,
                codes,
                flavor: req.flavor,
                state_count: req.old_state_count,
                state: req.old_state[..state_count].to_vec(),
            });
            state.exception_received = true;

            // Save reply info — do NOT reply yet so the child stays suspended
            // and the caller can read its process memory.
            state.pending_reply = Some(PendingReply {
                reply_port: unsafe { buffer.header.msgh_remote_port },
                reply_bits: unsafe { buffer.header.msgh_bits & 0xFF },
                flavor: req.flavor,
                state_count: req.old_state_count,
                state: req.old_state,
            });

            Ok(true)
        }
        2408 => {
            // transfer_ports — child is requesting our ports
            let mut reply = TransferPortsReply {
                header: MachMsgHeaderT {
                    msgh_bits: 0x80000012, // complex + move_send_once for reply port
                    msgh_size: std::mem::size_of::<TransferPortsReply>() as u32,
                    msgh_remote_port: unsafe { buffer.header.msgh_remote_port },
                    msgh_local_port: 0,
                    msgh_voucher_port: 0,
                    msgh_id: 2508,
                },
                body: MachMsgBodyT {
                    msgh_descriptor_count: 2,
                },
                exception_port: MachMsgPortDescriptorT {
                    name: state.exception_port,
                    pad1: 0,
                    pad2: 0,
                    disposition: MACH_MSG_TYPE_MAKE_SEND as u8,
                    msg_type: 0, // MACH_MSG_PORT_DESCRIPTOR
                },
                bootstrap_port: MachMsgPortDescriptorT {
                    name: state.original_bootstrap_port,
                    pad1: 0,
                    pad2: 0,
                    disposition: 19, // MACH_MSG_TYPE_COPY_SEND (parent has send right, not receive)
                    msg_type: 0,
                },
                ndr: NDR_RECORD,
                return_code: KERN_SUCCESS,
            };

            let kr = unsafe {
                mach_msg(
                    &mut reply.header,
                    MACH_SEND_MSG,
                    reply.header.msgh_size,
                    0,
                    0,
                    MACH_MSG_TIMEOUT_NONE,
                    0,
                )
            };

            if kr != KERN_SUCCESS {
                return Err(kr);
            }

            Ok(false)
        }
        _ => {
            eprintln!("exc_handler: unknown message id {msg_id}");
            Err(-1)
        }
    }
}

/// Sends the deferred exception reply with KERN_FAILURE.
/// This tells the kernel we did NOT handle the exception, so it delivers the
/// original signal to the process, killing it. Call this after handle_exception
/// has finished reading the child's memory.
pub fn send_exception_reply(state: &mut ExcHandlerState) {
    let Some(pending) = state.pending_reply.take() else {
        return;
    };

    let mut reply = ExcStateIdentityReply {
        header: MachMsgHeaderT {
            msgh_bits: pending.reply_bits,
            msgh_size: std::mem::size_of::<ExcStateIdentityReply>() as u32,
            msgh_remote_port: pending.reply_port,
            msgh_local_port: 0,
            msgh_voucher_port: 0,
            msgh_id: 2507,
        },
        ndr: NDR_RECORD,
        return_code: 5, // KERN_FAILURE — "not handled, deliver the signal"
        flavor: pending.flavor,
        new_state_count: pending.state_count,
        new_state: pending.state,
    };

    unsafe {
        mach_msg(
            &mut reply.header,
            MACH_SEND_MSG,
            reply.header.msgh_size,
            0,
            0,
            MACH_MSG_TIMEOUT_NONE,
            0,
        );
    }
}
