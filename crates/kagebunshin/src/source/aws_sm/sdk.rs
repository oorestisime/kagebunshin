//! [`SmApi`] over the AWS SDK.

use std::error::Error;

use async_trait::async_trait;
use aws_config::profile::ProfileFileCredentialsProvider;
use aws_config::provider_config::ProviderConfig;
use aws_credential_types::provider::SharedCredentialsProvider;
use aws_credential_types::provider::error::CredentialsError;
use aws_runtime::env_config::file::EnvConfigFiles;
use aws_sdk_secretsmanager::Client;
use aws_sdk_secretsmanager::config::{BehaviorVersion, Region};
use aws_sdk_secretsmanager::error::{DisplayErrorContext, ProvideErrorMetadata, SdkError};
use aws_sdk_secretsmanager::types::{Filter, FilterNameStringType};

use super::{ApiError, Got, Page, RawSecret, SmApi};
use crate::secret::SecretValue;

/// The largest page `ListSecrets` allows.
const PAGE_SIZE: i32 = 100;

pub struct SdkSm {
    client: Client,
    /// The profile it was loaded for is not in the AWS configuration, so
    /// its missing credentials are not a login away.
    no_profile: bool,
}

impl SdkSm {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            no_profile: false,
        }
    }

    /// A client from the standard AWS configuration chain, for `profile` and
    /// `region` when given.
    /// A `region` wins over `AWS_REGION` and the profile's own region.
    pub async fn load(profile: Option<&str>, region: Option<&str>) -> Self {
        let conf = with_profile_credentials(
            loader(profile, region).load().await,
            profile,
            EnvConfigFiles::default(),
        );
        let no_profile = match profile {
            Some(p) => !profile_exists(p).await,
            None => false,
        };
        Self {
            client: Client::new(&conf),
            no_profile,
        }
    }

    fn map<E>(&self, e: SdkError<E>) -> ApiError
    where
        E: ProvideErrorMetadata + Error + 'static,
    {
        match map_error(e) {
            ApiError::NeedsLogin if self.no_profile => ApiError::NoProfile,
            e => e,
        }
    }
}

/// Whether the AWS configuration has `profile`. True when it cannot be
/// read, so nothing is reported as missing on a guess.
async fn profile_exists(profile: &str) -> bool {
    use aws_types::os_shim_internal::{Env, Fs};
    let files = EnvConfigFiles::default();
    match aws_config::profile::load(&Fs::real(), &Env::real(), &files, None).await {
        Ok(set) => set.get_profile(profile).is_some(),
        Err(_) => true,
    }
}

/// With a profile, its credentials and nothing else, SSO and assumed roles
/// included. The default chain reads `AWS_ACCESS_KEY_ID` before any
/// profile, so with those set every source would use that one account
/// while its errors named the configured profile. Without a profile the
/// default chain stays. `files` is where profiles are read from.
fn with_profile_credentials(
    conf: aws_config::SdkConfig,
    profile: Option<&str>,
    files: EnvConfigFiles,
) -> aws_config::SdkConfig {
    let Some(profile) = profile else {
        return conf;
    };
    let credentials = ProfileFileCredentialsProvider::builder()
        // The resolved region, for an assumed role's STS call.
        .configure(&ProviderConfig::without_region().with_region(conf.region().cloned()))
        .profile_files(files)
        .profile_name(profile)
        .build();
    conf.into_builder()
        .credentials_provider(SharedCredentialsProvider::new(credentials))
        .build()
}

fn loader(profile: Option<&str>, region: Option<&str>) -> aws_config::ConfigLoader {
    let mut loader = aws_config::defaults(BehaviorVersion::latest());
    if let Some(p) = profile {
        loader = loader.profile_name(p);
    }
    if let Some(r) = region {
        loader = loader.region(Region::new(r.to_owned()));
    }
    loader
}

#[async_trait]
impl SmApi for SdkSm {
    async fn list_page(&self, prefix: &str, next_token: Option<String>) -> Result<Page, ApiError> {
        // An empty filter value is rejected; no prefix lists every secret.
        let filter = (!prefix.is_empty()).then(|| {
            Filter::builder()
                .key(FilterNameStringType::Name)
                .values(prefix)
                .build()
        });
        let out = (self.client.list_secrets())
            .set_filters(filter.map(|f| vec![f]))
            .max_results(PAGE_SIZE)
            .set_next_token(next_token)
            .send()
            .await
            .map_err(|e| self.map(e))?;
        let names = out.secret_list.unwrap_or_default();
        Ok(Page {
            names: names.into_iter().filter_map(|s| s.name).collect(),
            next_token: out.next_token.filter(|t| !t.is_empty()),
        })
    }

    async fn get_value(&self, name: &str) -> Result<Got, ApiError> {
        let out = (self.client.get_secret_value())
            .secret_id(name)
            .send()
            .await
            .map_err(|e| self.map(e))?;
        // The string moves into a zeroing SecretValue. The SDK's own response
        // buffers, and any binary blob, are dropped without zeroing.
        let raw = match (out.secret_string, out.secret_binary) {
            (Some(s), _) => RawSecret::String(SecretValue::new(s)),
            (None, Some(_)) => RawSecret::Binary,
            (None, None) => return Err(ApiError::Other("the response has no value".into())),
        };
        Ok(Got {
            raw,
            name: out.name,
        })
    }
}

fn map_error<E>(e: SdkError<E>) -> ApiError
where
    E: ProvideErrorMetadata + Error + 'static,
{
    if let Some(c) = credentials_error(&e) {
        return match c {
            CredentialsError::CredentialsNotLoaded(_) | CredentialsError::ProviderError(_) => {
                ApiError::NeedsLogin
            }
            _ => ApiError::Other(DisplayErrorContext(c).to_string()),
        };
    }
    match &e {
        SdkError::ServiceError(se) => {
            let err = se.err();
            match err.code() {
                Some("ResourceNotFoundException") => ApiError::NotFound,
                Some("AccessDeniedException") => ApiError::AccessDenied,
                Some(
                    "ExpiredTokenException"
                    | "UnrecognizedClientException"
                    | "InvalidSignatureException",
                ) => ApiError::NeedsLogin,
                // A deleted secret is kept, unreadable, for its recovery
                // window; the code is shared with other bad requests.
                Some("InvalidRequestException")
                    if err
                        .message()
                        .is_some_and(|m| m.contains("marked for deletion")) =>
                {
                    ApiError::Deleted
                }
                code => ApiError::Other(format!(
                    "{}: {}",
                    code.unwrap_or("unknown error"),
                    err.message().unwrap_or("no message")
                )),
            }
        }
        // A successful response that failed to parse. Its body may hold the
        // value, so none of the parser's detail is passed on.
        SdkError::ResponseError(_) => {
            ApiError::Other("unreadable response from Secrets Manager".into())
        }
        _ => ApiError::Other(DisplayErrorContext(&e).to_string()),
    }
}

/// Credential failures happen before the request is sent and come back
/// wrapped, e.g. as a dispatch failure; find them anywhere in the chain.
fn credentials_error<'a>(e: &'a (dyn Error + 'static)) -> Option<&'a CredentialsError> {
    let mut cur = Some(e);
    while let Some(err) = cur {
        if let Some(c) = err.downcast_ref::<CredentialsError>() {
            return Some(c);
        }
        cur = err.source();
    }
    None
}

#[cfg(test)]
mod tests {
    //! Against canned HTTP responses, with static fake credentials and an
    //! explicit region: nothing reads the environment, profiles or the network.

    use std::sync::Arc;

    use aws_credential_types::provider::{ProvideCredentials, future};
    use aws_sdk_secretsmanager::config::retry::RetryConfig;
    use aws_sdk_secretsmanager::config::{Config, Credentials};
    use aws_smithy_http_client::test_util::{ReplayEvent, StaticReplayClient};
    use aws_smithy_types::body::SdkBody;

    use super::*;
    use crate::source::ReadAll;
    use crate::source::SourceError;
    use crate::source::aws_sm::{AwsSmSource, Select};
    use crate::test_support::{Canary, assert_no_canary};

    const FAKE_KEY_ID: &str = "AKIDKAGEBUNSHINTEST";

    fn fake_credentials() -> Credentials {
        Credentials::new(FAKE_KEY_ID, "not-a-real-secret-key", None, None, "test")
    }

    #[derive(Debug)]
    struct ExpiredSso;

    impl ProvideCredentials for ExpiredSso {
        fn provide_credentials<'a>(&'a self) -> future::ProvideCredentials<'a>
        where
            Self: 'a,
        {
            // What the SSO provider returns once the cached token has expired.
            future::ProvideCredentials::ready(Err(CredentialsError::provider_error(
                "the SSO token has expired",
            )))
        }
    }

    fn api(http: &StaticReplayClient, creds: impl ProvideCredentials + 'static) -> Arc<SdkSm> {
        let conf = Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .credentials_provider(creds)
            .retry_config(RetryConfig::disabled())
            .http_client(http.clone())
            .build();
        Arc::new(SdkSm::new(Client::from_conf(conf)))
    }

    fn reply(status: u16, body: &str) -> ReplayEvent {
        // Requests are checked by hand below, so the expected one is a stub.
        let req = http::Request::builder()
            .uri("https://secretsmanager.us-east-1.amazonaws.com/")
            .body(SdkBody::empty())
            .unwrap();
        let resp = http::Response::builder()
            .status(status)
            .header("content-type", "application/x-amz-json-1.1")
            .body(SdkBody::from(body.to_owned()))
            .unwrap();
        ReplayEvent::new(req, resp)
    }

    fn service_error(code: &str) -> ReplayEvent {
        let body = format!(r#"{{"__type":"com.amazonaws.secretsmanager#{code}","message":"m"}}"#);
        reply(400, &body)
    }

    /// (X-Amz-Target, JSON body) of each request sent.
    fn sent(http: &StaticReplayClient) -> Vec<(String, serde_json::Value)> {
        http.actual_requests()
            .map(|r| {
                let auth = r.headers().get("authorization").unwrap_or_default();
                assert!(auth.contains(FAKE_KEY_ID), "signed with the fake key");
                let target = r.headers().get("x-amz-target").unwrap().to_owned();
                let body = serde_json::from_slice(r.body().bytes().unwrap()).unwrap();
                (target, body)
            })
            .collect()
    }

    #[tokio::test]
    async fn prefix_source_pages_through_list_secrets_then_reads_matches() {
        let http = StaticReplayClient::new(vec![
            reply(
                200,
                r#"{"SecretList":[{"Name":"p/b"},{"Name":"P/upper"}],"NextToken":"t1"}"#,
            ),
            reply(200, r#"{"SecretList":[],"NextToken":"t2"}"#),
            reply(200, r#"{"SecretList":[{"Name":"xp/no"}]}"#),
            reply(
                200,
                r#"{"Name":"p/b","SecretString":"{\"A\":\"1\",\"N\":2}"}"#,
            ),
        ]);
        let src = AwsSmSource::new(api(&http, fake_credentials()), Select::Prefix("p/".into()));
        let got = src.read_all().await.unwrap();
        let flat: Vec<_> = got
            .iter()
            .map(|e| (e.key.as_str(), e.value.expose(), e.origin.to_string()))
            .collect();
        assert_eq!(
            flat,
            [
                ("A", "1", "aws_sm:p/b".to_owned()),
                ("N", "2", "aws_sm:p/b".to_owned())
            ]
        );

        let filter = serde_json::json!([{"Key": "name", "Values": ["p/"]}]);
        let list = |token: Option<&str>| {
            let mut body = serde_json::json!({"Filters": filter, "MaxResults": 100});
            if let Some(t) = token {
                body["NextToken"] = t.into();
            }
            ("secretsmanager.ListSecrets".to_owned(), body)
        };
        assert_eq!(
            sent(&http),
            [
                list(None),
                list(Some("t1")),
                list(Some("t2")),
                (
                    "secretsmanager.GetSecretValue".to_owned(),
                    serde_json::json!({"SecretId": "p/b"})
                ),
            ]
        );
    }

    #[tokio::test]
    async fn get_value_maps_responses() {
        let cases = [
            (reply(200, r#"{"Name":"x","SecretString":"s"}"#), "string"),
            (
                reply(200, r#"{"Name":"x","SecretBinary":"AAEC"}"#),
                "binary",
            ),
            (service_error("ResourceNotFoundException"), "not found"),
            (service_error("AccessDeniedException"), "access denied"),
            (service_error("ExpiredTokenException"), "needs login"),
            (service_error("UnrecognizedClientException"), "needs login"),
            (service_error("InternalServiceError"), "other"),
            (
                reply(
                    400,
                    r#"{"__type":"InvalidRequestException","message":"You can't perform this operation on the secret because it was marked for deletion."}"#,
                ),
                "deleted",
            ),
            // The same code for anything else stays what AWS said.
            (service_error("InvalidRequestException"), "bad request"),
        ];
        for (event, want) in cases {
            let http = StaticReplayClient::new(vec![event]);
            let got = api(&http, fake_credentials()).get_value("x").await;
            let kind = match &got {
                Ok(Got {
                    raw: RawSecret::String(v),
                    name: Some(n),
                }) if v.expose() == "s" && n == "x" => "string",
                Ok(Got {
                    raw: RawSecret::Binary,
                    ..
                }) => "binary",
                Err(ApiError::NotFound) => "not found",
                Err(ApiError::AccessDenied) => "access denied",
                Err(ApiError::NeedsLogin) => "needs login",
                Err(ApiError::Other(m)) if m == "InternalServiceError: m" => "other",
                Err(ApiError::Deleted) => "deleted",
                Err(ApiError::Other(m)) if m == "InvalidRequestException: m" => "bad request",
                _ => "unexpected",
            };
            assert_eq!(kind, want, "{got:?}");
        }
    }

    #[tokio::test]
    async fn expired_sso_asks_for_a_login_without_sending_anything() {
        let http = StaticReplayClient::new(vec![]);
        let select = Select::Secret {
            name: "app/dev".into(),
            key: None,
        };
        let src = AwsSmSource::new(api(&http, ExpiredSso), select).with_profile("widget-dev");
        let err = src.read_all().await.unwrap_err();
        assert!(matches!(err, SourceError::NeedsLogin { .. }), "{err:?}");
        assert_eq!(
            err.hint(),
            Some("run `aws login --profile widget-dev` (`aws sso login` for an SSO profile)")
        );
        assert_eq!(http.actual_requests().count(), 0);
    }

    /// Credentials that are not there because the profile is not: no login
    /// would bring them, so it is not reported as one.
    #[tokio::test]
    async fn a_profile_that_is_not_there_is_not_a_login() {
        #[derive(Debug)]
        struct NotLoaded;
        impl ProvideCredentials for NotLoaded {
            fn provide_credentials<'a>(&'a self) -> future::ProvideCredentials<'a>
            where
                Self: 'a,
            {
                future::ProvideCredentials::ready(Err(CredentialsError::not_loaded(
                    "profile `nope` was not defined",
                )))
            }
        }
        let http = StaticReplayClient::new(vec![]);
        let there = api(&http, NotLoaded);
        assert_eq!(there.get_value("x").await.err(), Some(ApiError::NeedsLogin));
        let conf = Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .credentials_provider(NotLoaded)
            .retry_config(RetryConfig::disabled())
            .http_client(http.clone())
            .build();
        let gone = Arc::new(SdkSm {
            client: Client::from_conf(conf),
            no_profile: true,
        });
        assert_eq!(gone.get_value("x").await.err(), Some(ApiError::NoProfile));
        assert_eq!(
            gone.list_page("p/", None).await.err(),
            Some(ApiError::NoProfile)
        );
        let select = Select::Secret {
            name: "app/dev".into(),
            key: None,
        };
        let err = AwsSmSource::new(gone, select)
            .with_profile("nope")
            .read_all()
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "AWS profile nope is not in your AWS configuration"
        );
        assert_eq!(err.hint(), None);
        assert_eq!(http.actual_requests().count(), 0);
    }

    /// Against an in-memory environment and `~/.aws/config`: nothing real is
    /// read, and with a region known no lookup leaves the process.
    #[tokio::test]
    async fn a_source_region_wins_over_the_environment_and_the_profile() {
        use aws_types::os_shim_internal::{Env, Fs};
        let fs = Fs::from_slice(&[(
            "/home/fake/.aws/config",
            "[profile eu]\nregion = ap-south-1\n[default]\nregion = sa-east-1\n",
        )]);
        let region = |vars: &[(&str, &str)], profile, region| {
            let (env, fs) = (Env::from_slice(vars), fs.clone());
            async move {
                let conf = loader(profile, region).env(env).fs(fs).load().await;
                conf.region().map(ToString::to_string)
            }
        };
        let home = [("HOME", "/home/fake")];
        let with_env = [("HOME", "/home/fake"), ("AWS_REGION", "us-east-2")];
        let cases = [
            (&home[..], Some("eu"), Some("eu-west-3"), "eu-west-3"),
            (&with_env[..], Some("eu"), Some("eu-west-3"), "eu-west-3"),
            (&with_env[..], None, Some("eu-west-3"), "eu-west-3"),
            // Without one, the chain decides: AWS_REGION, then the profile.
            (&home[..], Some("eu"), None, "ap-south-1"),
            (&with_env[..], Some("eu"), None, "us-east-2"),
            (&home[..], None, None, "sa-east-1"),
        ];
        for (vars, profile, want_region, want) in cases {
            let got = region(vars, profile, want_region).await;
            assert_eq!(
                got.as_deref(),
                Some(want),
                "{vars:?} {profile:?} {want_region:?}"
            );
        }
    }

    /// Against an in-memory environment and profile file: credentials in the
    /// environment are used only by a source without a profile.
    #[tokio::test]
    async fn a_profile_uses_only_its_own_credentials() {
        use aws_runtime::env_config::file::EnvConfigFileKind;
        use aws_types::os_shim_internal::{Env, Fs};
        let env = Env::from_slice(&[
            ("HOME", "/home/fake"),
            ("AWS_ACCESS_KEY_ID", "AKIDFROMENV"),
            ("AWS_SECRET_ACCESS_KEY", "env-secret"),
        ]);
        let files = || {
            EnvConfigFiles::builder()
                .with_contents(
                    EnvConfigFileKind::Credentials,
                    "[billing]\naws_access_key_id = AKIDBILLING\naws_secret_access_key = s\n",
                )
                .build()
        };
        let key_id = |profile: Option<&'static str>| {
            let env = env.clone();
            async move {
                let conf = loader(profile, Some("eu-west-3"))
                    .env(env)
                    .fs(Fs::from_slice(&[]))
                    .load()
                    .await;
                let conf = with_profile_credentials(conf, profile, files());
                let provider = conf.credentials_provider().unwrap();
                provider
                    .provide_credentials()
                    .await
                    .map(|c| c.access_key_id().to_owned())
            }
        };
        assert_eq!(key_id(Some("billing")).await.unwrap(), "AKIDBILLING");
        assert_eq!(key_id(None).await.unwrap(), "AKIDFROMENV");
        // A profile that does not exist fails rather than falling back.
        assert!(key_id(Some("missing")).await.is_err());
    }

    #[tokio::test]
    async fn an_unparseable_success_response_does_not_leak_its_body() {
        let c = Canary::new();
        let body = format!(r#"{{"Name":"x","SecretString":"{}"#, c.value());
        let http = StaticReplayClient::new(vec![reply(200, &body)]);
        let err = api(&http, fake_credentials())
            .get_value("x")
            .await
            .unwrap_err();
        assert_eq!(
            err,
            ApiError::Other("unreadable response from Secrets Manager".into())
        );
        assert_no_canary(&c, &format!("{err:?}"));
    }
}
