//! The background scan against a fake router and a fake notification receiver.

#![allow(clippy::unwrap_used)]

use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::{Json, routing};
use http_body_util::BodyExt;
use serde_json::{Map, Value, json};
use tempfile::TempDir;
use tower::ServiceExt;

const FINGERPRINT: &str =
    "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF";

/// The router's static leases; `apply` commits the staged changes at once.
#[derive(Default)]
struct Uci {
    hosts: Map<String, Value>,
    staged: Vec<(String, Value)>,
}

impl Uci {
    fn commit(&mut self) {
        for (method, change) in std::mem::take(&mut self.staged) {
            let values = change["values"].as_object().cloned().unwrap_or_default();
            match method.as_str() {
                "add" => {
                    let name = change["name"].as_str().unwrap().to_owned();
                    let mut section = values;
                    section.insert(".type".to_owned(), json!("host"));
                    section.insert(".name".to_owned(), json!(name));
                    self.hosts.insert(name, Value::Object(section));
                }
                "set" => {
                    let section = change["section"].as_str().unwrap();
                    self.hosts[section].as_object_mut().unwrap().extend(values);
                }
                _ => {
                    self.hosts.remove(change["section"].as_str().unwrap());
                }
            }
        }
    }
}

async fn fake_router() -> (String, Arc<Mutex<Uci>>) {
    let uci: Arc<Mutex<Uci>> = Arc::default();
    let shared = uci.clone();
    let handler = move |Json(request): Json<Value>| {
        let uci = shared.clone();
        async move {
            let params = request["params"].as_array().cloned().unwrap_or_default();
            let mut uci = uci.lock().unwrap();
            let result = match (params[1].as_str().unwrap(), params[2].as_str().unwrap()) {
                ("session", "login") => json!([0, { "ubus_rpc_session": "s" }]),
                ("network.interface", "dump") => json!([0, { "interface": [
                    { "interface": "lan", "ipv4-address": [{ "address": "192.0.2.1", "mask": 24 }] }
                ] }]),
                ("luci-rpc", "getDHCPLeases") => json!([0, { "dhcp_leases": [
                    { "macaddr": "aa:bb:cc:00:00:99", "ipaddr": "192.0.2.99", "hostname": "stranger" }
                ] }]),
                ("uci", "get") => {
                    let mut values = uci.hosts.clone();
                    values.insert("lan".to_owned(), json!({ ".type": "dhcp", "interface": "lan" }));
                    json!([0, { "values": values }])
                }
                ("uci", method @ ("add" | "set" | "delete")) => {
                    uci.staged.push((method.to_owned(), params[3].clone()));
                    json!([0])
                }
                ("uci", "apply") => {
                    uci.commit();
                    json!([0])
                }
                ("uci", "confirm") => json!([0]),
                _ => json!([4]),
            };
            Json(json!({ "jsonrpc": "2.0", "id": 1, "result": result }))
        }
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(
        async move { axum::serve(listener, Router::new().route("/ubus", routing::post(handler))).await },
    );
    (format!("http://127.0.0.1:{}", address.port()), uci)
}

async fn fake_receiver() -> (String, Arc<Mutex<Vec<Value>>>) {
    let received: Arc<Mutex<Vec<Value>>> = Arc::default();
    let shared = received.clone();
    let handler = move |Json(body): Json<Value>| {
        let shared = shared.clone();
        async move {
            shared.lock().unwrap().push(body);
            StatusCode::NO_CONTENT
        }
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(
        async move { axum::serve(listener, Router::new().route("/hook", routing::post(handler))).await },
    );
    (format!("http://127.0.0.1:{}/hook", address.port()), received)
}

async fn setup() -> (TempDir, Arc<Mutex<Uci>>, Arc<Mutex<Vec<Value>>>) {
    let (router, uci) = fake_router().await;
    let (hook, received) = fake_receiver().await;
    let data = tempfile::tempdir().unwrap();
    let path = data.path();
    std::fs::write(
        path.join("groups.toml"),
        "default_group = \"lan\"\n[[group]]\nname = \"lan\"\nvlan = 1\n",
    )
    .unwrap();
    std::fs::write(
        path.join("devices.toml"),
        "[[device]]\nname = \"OMV\"\nmac = \"00:00:00:00:00:01\"\ngroup = \"lan\"\nip = \"192.0.2.2\"\n",
    )
    .unwrap();
    std::fs::write(path.join("router.password"), "secret").unwrap();
    std::fs::set_permissions(
        path.join("router.password"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    std::fs::write(
        path.join("lanlord.toml"),
        format!(
            "[[plugin]]\ntype = \"openwrt\"\nname = \"router\"\nurl = \"{router}\"\nuser = \"lanlord\"\n\
             password_file = \"router.password\"\ncertificate = \"{FINGERPRINT}\"\n\n\
             [[plugin]]\ntype = \"webhook\"\nname = \"hook\"\nurl = \"{hook}\"\n"
        ),
    )
    .unwrap();
    (data, uci, received)
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, String) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

fn post(path: &str, form: &str) -> Request<Body> {
    Request::post(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(form.to_owned()))
        .unwrap()
}

/// Applies the open changes through the page, as a user would.
async fn apply(app: &Router) {
    let (_, page) = send(app, Request::get("/apply").body(Body::empty()).unwrap()).await;
    let start = page.find(r#"name="digest" value=""#).unwrap() + 21;
    let form = format!("digest={}", &page[start..start + 32]);
    assert_eq!(send(app, post("/apply/router", &form)).await.0, StatusCode::OK);
}

fn texts(received: &Mutex<Vec<Value>>) -> Vec<String> {
    received
        .lock()
        .unwrap()
        .iter()
        .map(|body| body["text"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn unknown_devices_and_outside_changes_are_notified_once() {
    let (data, uci, received) = setup().await;
    let state = lanlord::AppState::load_without_login(data.path()).unwrap();
    let app = lanlord::app(state.clone());

    lanlord::watch::run_once(&state).await;
    assert_eq!(
        texts(&received).len(),
        1,
        "open changes before the first apply are no drift"
    );
    assert!(
        texts(&received)[0]
            .contains("Unknown device stranger (aa:bb:cc:00:00:99, 192.0.2.99), seen by router")
    );

    lanlord::watch::run_once(&state).await;
    assert_eq!(texts(&received).len(), 1, "the same device is not reported again");
    let again = lanlord::AppState::load_without_login(data.path()).unwrap();
    lanlord::watch::run_once(&again).await;
    assert_eq!(texts(&received).len(), 1, "not after a restart either");

    apply(&app).await;
    lanlord::watch::run_once(&state).await;
    assert_eq!(texts(&received).len(), 1, "in sync now");

    uci.lock().unwrap().hosts["lanlord_omv"]["ip"] = json!("192.0.2.77");
    lanlord::watch::run_once(&state).await;
    assert_eq!(texts(&received).len(), 2);
    assert!(
        texts(&received)[1].starts_with("router changed outside lanlord, see the Apply page"),
        "{:?}",
        texts(&received)
    );
    assert_eq!(
        uci.lock().unwrap().hosts["lanlord_omv"]["ip"],
        "192.0.2.77",
        "nothing is changed without restore"
    );

    lanlord::watch::run_once(&state).await;
    assert_eq!(texts(&received).len(), 2, "the same drift is reported once");
    let (_, history) = send(&app, Request::get("/history").body(Body::empty()).unwrap()).await;
    assert!(history.contains("router changed outside lanlord"), "{history}");
    let problems = lanlord::plugins::load(&data.path().join("lanlord.toml")).all_problems();
    assert_eq!(problems, Vec::<String>::new());
}

#[tokio::test]
async fn changes_in_the_list_wait_for_apply() {
    let (data, _uci, received) = setup().await;
    let state = lanlord::AppState::load_without_login(data.path()).unwrap();
    let app = lanlord::app(state.clone());
    apply(&app).await;
    lanlord::watch::run_once(&state).await;
    assert_eq!(texts(&received).len(), 1, "only the unknown device");

    let change = "name=OMV&mac=00:00:00:00:00:01&group=lan&ip=192.0.2.3&note=";
    assert_eq!(
        send(&app, post("/devices/OMV", change)).await.0,
        StatusCode::SEE_OTHER
    );
    let (status, _) = send(&app, post("/settings/background", "interval=5&restore=true")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    lanlord::watch::run_once(&state).await;
    assert_eq!(
        texts(&received).len(),
        1,
        "an own change is no drift and is not applied"
    );
}

#[tokio::test]
async fn restore_undoes_outside_changes() {
    let (data, uci, received) = setup().await;
    let state = lanlord::AppState::load_without_login(data.path()).unwrap();
    let app = lanlord::app(state.clone());
    let (status, _) = send(&app, post("/settings/background", "interval=5&restore=true")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, page) = send(&app, Request::get("/settings").body(Body::empty()).unwrap()).await;
    assert!(
        page.contains(r#"name="interval" min="0" max="1440" value="5""#),
        "{page}"
    );

    apply(&app).await;
    lanlord::watch::run_once(&state).await;
    uci.lock().unwrap().hosts["lanlord_omv"]["ip"] = json!("192.0.2.77");
    lanlord::watch::run_once(&state).await;

    assert_eq!(
        uci.lock().unwrap().hosts["lanlord_omv"]["ip"],
        "192.0.2.2",
        "restored"
    );
    assert!(
        texts(&received)
            .last()
            .unwrap()
            .starts_with("Restored after a change outside lanlord: router: 1 change applied")
    );
    let (_, page) = send(&app, Request::get("/settings").body(Body::empty()).unwrap()).await;
    assert!(page.contains("Last scan:"), "{page}");
    let (_, history) = send(&app, Request::get("/history").body(Body::empty()).unwrap()).await;
    assert!(
        history.contains("Background scan changed: every 5 minutes, restore on"),
        "{history}"
    );
}
