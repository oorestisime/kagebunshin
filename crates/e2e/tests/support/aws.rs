//! AWS Secrets Manager for a sandbox: the AWS Emulator when
//! `KAGEBUNSHIN_E2E_AWS_EMULATOR` names its binary, else a small fake in
//! this process that answers the two calls kagebunshin makes.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aws_sdk_secretsmanager::Client;
use aws_sdk_secretsmanager::config::{BehaviorVersion, Credentials, Region};
use aws_smithy_http_client::tls::{self, TlsContext, TrustStore};

/// The path of the `aws-emulator` binary; `scripts/e2e.sh` sets it.
pub const EMULATOR_ENV: &str = "KAGEBUNSHIN_E2E_AWS_EMULATOR";
/// The region of every profile a sandbox has.
pub const REGION: &str = "eu-west-1";

pub enum Aws {
    Fake(Fake),
    Emulator(Emulator),
}

impl Aws {
    /// Holding `secrets`, name and value. `dir` is for the emulator's files.
    pub fn start(dir: &Path, secrets: &[(&str, &str)]) -> Self {
        match std::env::var_os(EMULATOR_ENV) {
            Some(bin) => {
                let emulator = Emulator::start(Path::new(&bin), dir);
                block_on(async {
                    for (name, value) in secrets {
                        (emulator.client().create_secret())
                            .name(*name)
                            .secret_string(*value)
                            .send()
                            .await
                            .unwrap();
                    }
                });
                Self::Emulator(emulator)
            }
            None => Self::Fake(Fake::start(secrets)),
        }
    }

    /// The emulator, for a test that needs more than the fake answers.
    pub fn emulator(&self) -> &Emulator {
        match self {
            Self::Emulator(e) => e,
            Self::Fake(_) => panic!("this test needs the AWS Emulator: run scripts/e2e.sh"),
        }
    }

    pub fn endpoint(&self) -> &str {
        match self {
            Self::Fake(f) => &f.url,
            Self::Emulator(e) => &e.endpoint,
        }
    }

    /// The access key and secret key requests are signed with.
    pub fn keys(&self) -> (&str, &str) {
        match self {
            Self::Fake(_) => ("AKIDFAKE", "fake"),
            Self::Emulator(e) => (&e.access_key, &e.secret_key),
        }
    }

    /// The certificate authority the endpoint's certificate is signed by.
    pub fn ca(&self) -> Option<&Path> {
        match self {
            Self::Fake(_) => None,
            Self::Emulator(e) => Some(&e.ca),
        }
    }
}

/// One AWS Emulator process on a free port, with request signing on. Its
/// state is in memory, so every sandbox starts empty.
pub struct Emulator {
    child: Child,
    pub endpoint: String,
    pub ca: PathBuf,
    pub access_key: String,
    pub secret_key: String,
}

impl Emulator {
    fn start(bin: &Path, dir: &Path) -> Self {
        assert!(
            bin.is_file(),
            "{EMULATOR_ENV} is {}, which is not a file",
            bin.display()
        );
        let home = dir.join("emulator");
        fs::create_dir_all(&home).unwrap();
        let log = home.join("log");
        let out = fs::File::create(&log).unwrap();
        // Its key, certificate and configuration go under HOME.
        let child = Command::new(bin)
            .args(["--port", "0", "--telemetry", "off"])
            .env_clear()
            .env("HOME", &home)
            .stdin(Stdio::null())
            .stdout(out.try_clone().unwrap())
            .stderr(out)
            .spawn()
            .unwrap();
        let start = Instant::now();
        let info = loop {
            let text = fs::read_to_string(&log).unwrap();
            let info = text
                .lines()
                .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
                .find(|l| l["fields"]["endpoint_url"].is_string());
            if let Some(info) = info {
                break info["fields"].clone();
            }
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "the AWS Emulator did not start: {text}"
            );
            std::thread::sleep(Duration::from_millis(50));
        };
        let ca = PathBuf::from(info["ca_file"].as_str().unwrap());
        let credentials = fs::read_to_string(ca.with_file_name("emulator_credentials")).unwrap();
        let key = |name: &str| {
            credentials
                .lines()
                .filter_map(|l| l.split_once('='))
                .find(|(k, _)| k.trim() == name)
                .map(|(_, v)| v.trim().to_owned())
                .unwrap()
        };
        Self {
            child,
            endpoint: info["endpoint_url"].as_str().unwrap().to_owned(),
            ca,
            access_key: key("aws_access_key_id"),
            secret_key: key("aws_secret_access_key"),
        }
    }

    /// A client for the test's own calls: what it puts there for
    /// kagebunshin to find.
    pub fn client(&self) -> Client {
        let trust = TrustStore::empty().with_pem_certificate(fs::read(&self.ca).unwrap());
        let http = aws_smithy_http_client::Builder::new()
            .tls_provider(tls::Provider::Rustls(
                tls::rustls_provider::CryptoMode::AwsLc,
            ))
            .tls_context(
                TlsContext::builder()
                    .with_trust_store(trust)
                    .build()
                    .unwrap(),
            )
            .build_https();
        let conf = aws_sdk_secretsmanager::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(REGION))
            .endpoint_url(&self.endpoint)
            .credentials_provider(Credentials::new(
                &self.access_key,
                &self.secret_key,
                None,
                None,
                "emulator",
            ))
            .http_client(http)
            .build();
        Client::from_conf(conf)
    }
}

/// Runs a test's own calls to the emulator.
pub fn block_on<T>(f: impl Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

impl Drop for Emulator {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Answers `ListSecrets` with every secret it holds (kagebunshin filters the
/// names again, as with AWS's loose name filter) and `GetSecretValue` with
/// one value, by name or ARN. Records each request's `X-Amz-Target`.
pub struct Fake {
    url: String,
    targets: Arc<Mutex<Vec<String>>>,
}

impl Fake {
    fn start(secrets: &[(&str, &str)]) -> Self {
        let secrets: Vec<(String, String)> = secrets
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect();
        let arn = |name: &str| {
            format!("arn:aws:secretsmanager:{REGION}:123456789012:secret:{name}-AbCdEf")
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let targets = Arc::new(Mutex::new(Vec::new()));
        let seen = targets.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let (mut target, mut len) = (String::new(), 0);
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    let (name, value) = line.split_once(':').unwrap_or((&line, ""));
                    match name.to_ascii_lowercase().as_str() {
                        "x-amz-target" => value.trim().clone_into(&mut target),
                        "content-length" => len = value.trim().parse().unwrap(),
                        _ => {}
                    }
                }
                let mut body = vec![0; len];
                if reader.read_exact(&mut body).is_err() {
                    continue;
                }
                let body: serde_json::Value =
                    serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
                seen.lock().unwrap().push(target.clone());
                let (status, reply) = match target.as_str() {
                    "secretsmanager.ListSecrets" => {
                        let list: Vec<_> = secrets
                            .iter()
                            .map(|(name, _)| serde_json::json!({ "Name": name, "ARN": arn(name) }))
                            .collect();
                        ("200 OK", serde_json::json!({ "SecretList": list }))
                    }
                    "secretsmanager.GetSecretValue" => {
                        let id = body["SecretId"].as_str().unwrap_or_default();
                        match secrets.iter().find(|(n, _)| n == id || arn(n) == id) {
                            Some((name, value)) => (
                                "200 OK",
                                serde_json::json!({ "Name": name, "SecretString": value }),
                            ),
                            None => (
                                "400 Bad Request",
                                serde_json::json!({
                                    "__type": "ResourceNotFoundException",
                                    "message": "Secrets Manager can't find the specified secret.",
                                }),
                            ),
                        }
                    }
                    _ => (
                        "400 Bad Request",
                        serde_json::json!({ "__type": "Unknown" }),
                    ),
                };
                let reply = reply.to_string();
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/x-amz-json-1.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                    reply.len()
                );
            }
        });
        Self { url, targets }
    }

    pub fn targets(&self) -> Vec<String> {
        self.targets.lock().unwrap().clone()
    }
}
