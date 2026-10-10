//! Test 9 (#11): the worker holds no secrets. Asserted on the real binary,
//! not documented: started with a gateway or control-plane secret it refuses
//! to run, and running, its environment and open files hold none.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const WORKER: &str = env!("CARGO_BIN_EXE_worker");

fn base(dir: &std::path::Path) -> Command {
    let mut command = Command::new(WORKER);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("CLWD_WORKER_SOCKET", dir.join("w.sock"))
        .env("CLWD_ARTIFACT_ROOT", dir.join("artifacts"))
        .env("CLWD_GATEWAY_UID", "0")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    command
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::path::PathBuf::from(format!("/tmp/clwd-w9-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("artifacts")).expect("scratch dir");
    dir
}

#[test]
fn the_worker_refuses_to_start_holding_a_secret() {
    let dir = scratch("refuse");
    for name in worker::FORBIDDEN_ENV {
        let mut child = base(&dir)
            .env(name, "a-secret-value")
            .spawn()
            .expect("the worker runs");
        // A worker that wrongly starts serves forever: bound the wait, so that
        // is a failure here rather than a hang.
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.try_wait().expect("status") {
                break Some(status);
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let status = status.unwrap_or_else(|| panic!("{name}: the worker started anyway"));
        assert!(!status.success(), "{name}: the worker exited cleanly");
        let mut stderr = String::new();
        std::io::Read::read_to_string(&mut child.stderr.take().expect("stderr"), &mut stderr)
            .expect("stderr");
        assert!(stderr.contains(name), "{name}: {stderr}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_running_worker_holds_no_secret_in_its_environment_or_files() {
    let dir = scratch("run");
    let mut child = base(&dir).spawn().expect("the worker starts");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !dir.join("w.sock").exists() {
        assert!(
            child.try_wait().expect("status").is_none(),
            "the worker exited before listening"
        );
        assert!(Instant::now() < deadline, "the worker never listened");
        std::thread::sleep(Duration::from_millis(50));
    }
    let proc = format!("/proc/{}", child.id());

    let environ = std::fs::read(format!("{proc}/environ")).expect("environ");
    let environ = String::from_utf8_lossy(&environ);
    for name in worker::FORBIDDEN_ENV {
        assert!(
            !environ.contains(name),
            "{name} is in the worker's environment"
        );
    }
    assert!(
        !environ.contains("PRIVATE KEY"),
        "key material in the environment"
    );

    let mut files = Vec::new();
    for entry in std::fs::read_dir(format!("{proc}/fd"))
        .expect("fds")
        .flatten()
    {
        if let Ok(target) = std::fs::read_link(entry.path()) {
            files.push(target.display().to_string());
        }
    }
    assert!(!files.is_empty(), "positive control: the fd table was read");
    for file in &files {
        assert!(
            !file.ends_with(".pem") && !file.contains("cert") && !file.contains("key.pem"),
            "the worker holds {file} open"
        );
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
}
