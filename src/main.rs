use crashrustler::{CpuType, CrashParams, CrashRustler, ExceptionState, ThreadState};

fn main() {
    let params = CrashParams {
        task: 0,
        pid: std::process::id() as i32,
        ppid: 1,
        uid: 501,
        is_64_bit: true,
        thread: 0,
        exception_type: 10, // EXC_CRASH
        exception_codes: vec![0x0000_0b00_0004_0000],
        thread_state: ThreadState {
            flavor: 0,
            registers: Vec::new(),
        },
        exception_state: ExceptionState {
            state: Vec::new(),
            count: 0,
        },
        process_name: Some("crashrustler".into()),
        executable_path: None,
        r_process_pid: -1,
        date: Some(
            chrono::Local::now()
                .format("%Y-%m-%d %H:%M:%S%.4f %z")
                .to_string(),
        ),
        awake_system_uptime: 0,
        cpu_type: CpuType::ARM64,
    };

    let cr = CrashRustler::new(params);
    println!("CrashRustler initialized for pid: {}", cr.pid());
    println!("Exception type: {}", cr.exception_type);
    println!("Signal: {}", cr.signal);
}
