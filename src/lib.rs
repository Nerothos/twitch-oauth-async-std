use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use surf::RequestBuilder;
use url::Url;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ValidatedToken {
    pub client_id: String,
    pub login: Option<String>,
    pub user_id: Option<String>,
    pub scopes: Vec<String>,
}

// To use the `{}` marker, the trait `fmt::Display` must be implemented
// manually for the type.
impl fmt::Display for ValidatedToken {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let string1 = format!("access_token: {}\n", self.client_id);
        let string2 = format!("{} token_type: {:?}\n", string1, self.login);
        let string3 = format!("{} expires_in: {:?}\n", string2, self.user_id);
        let string4 = format!("{} expires_in: {:?}\n", string3, self.scopes);

        write!(f, "{}", string4)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AppAccessToken {
    pub access_token: String,
    pub expires_in: usize,
    pub scope: Option<Vec<String>>,
    pub token_type: String,
}
// To use the `{}` marker, the trait `fmt::Display` must be implemented
// manually for the type.
impl fmt::Display for AppAccessToken {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let string1 = format!("access_token: {}\n", self.access_token);
        let string2 = format!("{} expires_in: {}\n", string1, self.expires_in);
        let string3 = format!("{} expires_in: {:?}\n", string2, self.scope);
        let string4 = format!("{} token_type: {}\n", string3, self.token_type);
        write!(f, "{}", string4)
    }
}

/// To retrieve a token, you need to provide your client_id and client_secret as well as a scope array
///
/// ```rust
/// let token = twitch_oauth_async_std::get_app_access_token("client_id", "client_secret");
/// ```
pub async fn get_app_access_token(
    client_id: &str,
    client_secret: &str,
) -> Result<AppAccessToken, Box<dyn std::error::Error>> {
    let mut params = HashMap::new();
    params.insert("grant_type", "client_credentials");
    params.insert("client_id", client_id);
    params.insert("client_secret", client_secret);
    let url = Url::parse_with_params("https://id.twitch.tv/oauth2/token", &params).unwrap();

    let client = surf::Client::new();
    let req = client.post(&url);
    let mut res = client.send(req).await?;
    let resp: AppAccessToken = res.body_json().await?;

    Ok(resp)
}
/// To retrieve a token, you need to provide your client_id and client_secret as well as a scope array
///
/// ```rust
/// let token = twitch_oauth_async_std::get_app_access_token_with_scopes("client_id", "client_secret", vec!["scopes".to_string()]);
/// ```
pub async fn get_app_access_token_with_scopes(
    client_id: &str,
    client_secret: &str,
    scopes: Vec<String>,
) -> Result<AppAccessToken, Box<dyn std::error::Error>> {
    let joinee_scopes = scopes.join(" ");

    let mut params = HashMap::new();
    params.insert("grant_type", "client_credentials");
    params.insert("client_id", client_id);
    params.insert("client_secret", client_secret);
    params.insert("scope", joinee_scopes.as_str());
    let url = Url::parse_with_params("https://id.twitch.tv/oauth2/token", &params).unwrap();

    let client = surf::Client::new();
    let req = client.post(&url);
    let mut res = client.send(req).await?;
    let resp: AppAccessToken = res.body_json().await?;

    Ok(resp)
}

/// To validate a token, you need to provide your access token
///
/// ```rust
/// let token = twitch_oauth_async_std::validate_token("access_token");
/// ```
pub async fn validate_token(
    access_token: &str,
) -> Result<ValidatedToken, Box<dyn std::error::Error>> {
    let auth = format!("OAuth {}", access_token);

    let client = surf::Client::new();
    let req: RequestBuilder = client
        .get("https://id.twitch.tv/oauth2/validate")
        .header("authorization", auth);
    let mut res = client.send(req).await?;
    let resp: ValidatedToken = res.body_json().await?;

    Ok(resp)
}

/// To remoke a token, you need to provide your access token and client_id
///
/// ```rust
/// let token = twitch_oauth_async_std::remoke_token("token", "client_id");
/// ```
pub async fn remoke_token(
    access_token: &str,
    client_id: &str,
) -> Result<surf::StatusCode, Box<dyn std::error::Error>> {
    let mut params = HashMap::new();
    params.insert("token", access_token);
    params.insert("client_id", client_id);

    let url = Url::parse_with_params("https://id.twitch.tv/oauth2/revoke", &params).unwrap();

    let client = surf::Client::new();
    let req: RequestBuilder = client.post(&url);
    let res = client.send(req).await?;
    Ok(res.status())
}
