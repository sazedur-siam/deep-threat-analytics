use std::process::Command;
#[test]
fn t() { Command::new("sh").arg("-c").arg("echo test-only"); }
