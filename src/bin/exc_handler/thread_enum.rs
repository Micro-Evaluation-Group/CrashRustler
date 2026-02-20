//! Thread enumeration for the target process.
//!
//! Uses `task_threads()` and `thread_get_state()` to enumerate all threads
//! and capture their register states.

use crashrustler::ThreadState;

use crate::ffi;

/// Enumerates all threads in a task, returning their ports and register states.
pub fn enumerate_threads(task: ffi::MachPortT) -> Vec<(ffi::MachPortT, ThreadState)> {
    let mut threads_ptr: *mut ffi::MachPortT = std::ptr::null_mut();
    let mut count: ffi::MachMsgTypeNumberT = 0;

    let kr = unsafe { ffi::task_threads(task, &mut threads_ptr, &mut count) };
    if kr != ffi::KERN_SUCCESS || threads_ptr.is_null() {
        return Vec::new();
    }

    let thread_count = count as usize;
    let mut result = Vec::with_capacity(thread_count);

    for i in 0..thread_count {
        let thread = unsafe { *threads_ptr.add(i) };
        if let Some(state) = get_thread_state(thread) {
            result.push((thread, state));
        }
    }

    // Deallocate the kernel-allocated thread array
    unsafe {
        ffi::vm_deallocate(
            ffi::mach_task_self(),
            threads_ptr as usize,
            (thread_count * std::mem::size_of::<ffi::MachPortT>()) as u64,
        );
    }

    result
}

/// Gets the system-wide unique thread ID via `thread_info(THREAD_IDENTIFIER_INFO)`.
pub fn get_thread_id(thread: ffi::MachPortT) -> Option<u64> {
    unsafe {
        // thread_identifier_info: thread_id(8) + thread_handle(8) + dispatch_qaddr(8) = 24 bytes
        let mut info = [0i32; 6];
        let mut count: ffi::MachMsgTypeNumberT = 6;
        let kr = ffi::thread_info(
            thread,
            ffi::THREAD_IDENTIFIER_INFO,
            info.as_mut_ptr(),
            &mut count,
        );
        if kr == ffi::KERN_SUCCESS && count >= 2 {
            // thread_id is the first u64 (two i32s, little-endian)
            let id = (info[0] as u32 as u64) | ((info[1] as u32 as u64) << 32);
            Some(id)
        } else {
            None
        }
    }
}

fn get_thread_state(thread: ffi::MachPortT) -> Option<ThreadState> {
    unsafe {
        let mut state = [0u32; ffi::THREAD_STATE_MAX];
        let mut count = ffi::THREAD_STATE_MAX as ffi::MachMsgTypeNumberT;
        let kr = ffi::thread_get_state(
            thread,
            ffi::THREAD_STATE_FLAVOR,
            state.as_mut_ptr(),
            &mut count,
        );
        if kr == ffi::KERN_SUCCESS {
            Some(ThreadState {
                flavor: ffi::THREAD_STATE_FLAVOR as u32,
                registers: state[..count as usize].to_vec(),
            })
        } else {
            None
        }
    }
}
