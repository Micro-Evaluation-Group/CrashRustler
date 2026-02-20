use std::io::Write;

fn main() {
    // Re-run if entitlements change
    println!("cargo:rerun-if-changed=entitlements/");

    #[cfg(target_os = "macos")]
    detect_codesign_identity();
}

#[cfg(target_os = "macos")]
fn detect_codesign_identity() {
    let output = match std::process::Command::new("security")
        .args(["find-identity", "-p", "codesigning", "-v"])
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            println!("cargo:warning=Could not run `security find-identity`: {e}");
            return;
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Look for a valid identity: lines contain a 40-char hex hash followed by a quoted name.
    // The last line is typically "N valid identities found" — skip it.
    let mut found_identity = None;
    for line in stdout.lines() {
        let trimmed = line.trim();
        // Skip summary line
        if trimmed.ends_with("valid identities found") || trimmed.ends_with("valid identity found")
        {
            continue;
        }
        // Extract 40-char hex hash
        if let Some(hash) = extract_hex_hash(trimmed) {
            found_identity = Some((hash.to_string(), trimmed.to_string()));
            break;
        }
    }

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let identity_path = std::path::Path::new(&out_dir).join("codesign-identity.txt");

    match found_identity {
        Some((hash, line)) => {
            println!("cargo:warning=Codesigning identity found: {line}");
            let mut f =
                std::fs::File::create(&identity_path).expect("failed to create identity file");
            f.write_all(hash.as_bytes())
                .expect("failed to write identity");
        }
        None => {
            println!("cargo:warning=No codesigning identity found — binaries will be unsigned");
            // Write empty file so downstream scripts can check
            std::fs::File::create(&identity_path).expect("failed to create identity file");
        }
    }
}

#[cfg(target_os = "macos")]
fn extract_hex_hash(line: &str) -> Option<&str> {
    // Identity lines look like: "  1) ABCDEF0123456789... \"Developer ID Application: ...\""
    // Find a 40-character hex string
    for word in line.split_whitespace() {
        let candidate = word.trim_end_matches(|c: char| !c.is_ascii_hexdigit());
        if candidate.len() == 40 && candidate.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(candidate);
        }
    }
    None
}
