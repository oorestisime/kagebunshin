//! Shared by the integration tests.

use std::io::Write;
use std::process::Command;

/// Runs `cmd` on a pseudo-terminal that `script` sets up, typing `input`,
/// for the prompts that read /dev/tty. stdout and stderr arrive together,
/// with `\r\n` turned back into `\n`; the exit status is read in band, as
/// BSD `script` does not pass it back.
#[allow(dead_code)] // Not every test binary asks for a passphrase.
pub fn on_terminal(cmd: &Command, input: &str) -> (i32, String) {
    on_terminal_at(cmd, "passphrase", input)
}

/// As [`on_terminal`], typing `input` once `prompt` shows (in any case).
#[allow(dead_code)]
pub fn on_terminal_at(cmd: &Command, prompt: &str, input: &str) -> (i32, String) {
    on_terminal_after(cmd, prompt, || {}, input)
}

/// As [`on_terminal_at`], running `meanwhile` once `prompt` shows, before
/// typing `input`.
#[allow(dead_code)]
pub fn on_terminal_after(
    cmd: &Command,
    prompt: &str,
    meanwhile: impl FnOnce(),
    input: &str,
) -> (i32, String) {
    let mut meanwhile = Some(meanwhile);
    let mut argv = vec![
        "sh".to_owned(),
        "-c".to_owned(),
        r#""$@"; echo "[exit=$?]""#.to_owned(),
        "sh".to_owned(),
        cmd.get_program().to_str().unwrap().to_owned(),
    ];
    argv.extend(cmd.get_args().map(|a| a.to_str().unwrap().to_owned()));
    let mut script = Command::new("script");
    if cfg!(target_os = "macos") {
        script.args(["-q", "/dev/null"]).args(&argv);
    } else {
        let quoted: Vec<String> = argv
            .iter()
            .map(|a| format!("'{}'", a.replace('\'', r"'\''")))
            .collect();
        script.args(["-qec", &quoted.join(" "), "/dev/null"]);
    }
    // Only what `cmd` sets, and PATH: `get_envs` does not show `env_clear`,
    // so nothing of the developer's environment should come through.
    script
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap());
    for (k, v) in cmd.get_envs() {
        match v {
            Some(v) => script.env(k, v),
            None => script.env_remove(k),
        };
    }
    if let Some(dir) = cmd.get_current_dir() {
        script.current_dir(dir);
    }
    let mut child = script
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    // Type the input only once the prompt is up, and keep the terminal open
    // until the command is done: BSD script turns an early end of its stdin
    // into an end of file on the terminal.
    let mut stdout = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = [0; 4096];
        while let Ok(n @ 1..) = stdout.read(&mut buf) {
            if tx.send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    let mut stdin = child.stdin.take();
    let mut raw = Vec::new();
    let mut typed = false;
    loop {
        let chunk = rx
            .recv_timeout(std::time::Duration::from_secs(60))
            .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&raw)));
        raw.extend(chunk);
        let seen = String::from_utf8_lossy(&raw);
        if !typed && seen.to_lowercase().contains(&prompt.to_lowercase()) {
            if let Some(f) = meanwhile.take() {
                f();
            }
            stdin.as_mut().unwrap().write_all(input.as_bytes()).unwrap();
            typed = true;
        }
        if seen
            .rfind("[exit=")
            .is_some_and(|at| seen[at..].contains(']'))
        {
            break;
        }
    }
    drop(stdin);
    child.wait().unwrap();
    while let Ok(chunk) = rx.recv_timeout(std::time::Duration::from_secs(5)) {
        raw.extend(chunk);
    }
    let out = String::from_utf8(raw).unwrap().replace("\r\n", "\n");
    let at = out
        .rfind("[exit=")
        .unwrap_or_else(|| panic!("no exit status: {out}"));
    // Closing stdin can echo a ^D after it on macOS.
    let digits: String = out[at + 6..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    let code = digits
        .parse()
        .unwrap_or_else(|_| panic!("no exit status: {out}"));
    (code, out[..at].to_owned())
}
