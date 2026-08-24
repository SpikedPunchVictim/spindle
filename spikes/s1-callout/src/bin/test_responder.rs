//! Throwaway: minimal always-allow callout responder, used only to empirically nail the JWT
//! round trip (natsjwt.rs) before wiring in the real spindle-helper decision core in
//! responder.rs. Not part of the S1 deliverable.
use futures_util::StreamExt;
use nkeys::KeyPair;
use spike_s1_callout::natsjwt;
use std::env;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let callout_seed = env::var("CALLOUT_USER_SEED")?;
    let app_account_seed = env::var("APP_ACCOUNT_SEED")?;
    let url = env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:14222".to_string());

    let _callout_kp = KeyPair::from_seed(&callout_seed)?;
    let app_kp = KeyPair::from_seed(&app_account_seed)?;

    let client = async_nats::ConnectOptions::with_nkey(callout_seed)
        .connect(&url)
        .await?;
    let mut sub = client.subscribe("$SYS.REQ.USER.AUTH").await?;
    println!("test_responder: listening on $SYS.REQ.USER.AUTH");

    while let Some(msg) = sub.next().await {
        let Some(reply) = msg.reply.clone() else {
            continue;
        };
        let jwt_str = String::from_utf8(msg.payload.to_vec())?;
        let claims = natsjwt::decode_claims_unverified(&jwt_str)?;
        let user_nkey = claims["nats"]["user_nkey"].as_str().unwrap().to_string();
        let server_id = claims["nats"]["server_id"]["id"]
            .as_str()
            .unwrap()
            .to_string();

        println!("request for user_nkey={user_nkey}");

        let nats_claims = natsjwt::user_nats_claims(
            &["*".to_string()],
            &["*".to_string()],
            &[],
            None,
            -1,
            -1,
            &["STANDARD", "WEBSOCKET"],
        );
        let exp = natsjwt::now_unix() + 3600;
        let user_claims_val =
            natsjwt::user_claims(&app_kp.public_key(), "APP", &user_nkey, exp, nats_claims);
        let user_jwt = natsjwt::encode(user_claims_val, &app_kp);

        let inner = natsjwt::response_ok(user_jwt);
        let resp_claims =
            natsjwt::authorization_response(&app_kp.public_key(), &server_id, &user_nkey, inner);
        // Signed by the ACCOUNT key, not callout_kp (the responder's own connection identity)
        // — see natsjwt::authorization_response's doc comment for why.
        let resp_jwt = natsjwt::encode(resp_claims, &app_kp);

        client.publish(reply, resp_jwt.into()).await?;
        client.flush().await?;
        println!("replied");
    }
    Ok(())
}
