//! Setting up the groups through the interface, starting from an empty data directory.

#![allow(clippy::unwrap_used)]

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

fn app(data: &TempDir) -> Router {
    lanlord::app(lanlord::AppState::load_without_login(data.path()).unwrap())
}

fn groups_file(data: &TempDir) -> String {
    std::fs::read_to_string(data.path().join("groups.toml")).unwrap_or_default()
}

async fn post(data: &TempDir, path: &str, form: &str) -> (StatusCode, String) {
    let request = Request::post(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(form.to_owned()))
        .unwrap();
    let response = app(data).oneshot(request).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

async fn setup() -> TempDir {
    let data = tempfile::tempdir().unwrap();
    assert_eq!(
        post(&data, "/groups", "name=lan&vlan=1&label=LAN").await.0,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        post(&data, "/groups", "name=guest&vlan=30").await.0,
        StatusCode::SEE_OTHER
    );
    data
}

#[tokio::test]
async fn first_group_becomes_the_default() {
    let data = setup().await;
    let file = groups_file(&data);
    assert!(file.contains("default_group = \"lan\""), "{file}");
    assert!(file.contains("name = \"guest\""));
    assert!(file.contains("vlan = 30"));
}

#[tokio::test]
async fn default_group_can_be_changed() {
    let data = setup().await;
    assert_eq!(
        post(&data, "/groups/default", "group=guest").await.0,
        StatusCode::SEE_OTHER
    );
    assert!(groups_file(&data).contains("default_group = \"guest\""));
    let (status, page) = post(&data, "/groups/default", "group=office").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(page.contains("unknown default group"));
}

#[tokio::test]
async fn invalid_groups_are_rejected() {
    let data = setup().await;
    let before = groups_file(&data);
    for (form, message) in [
        ("name=iot&vlan=1", "duplicate VLAN"),
        ("name=lan&vlan=20", "duplicate group"),
        ("name=iot&vlan=5000", "VLAN must be 1 to 4094"),
        ("name=iot&vlan=abc", "The VLAN must be a number"),
        ("name=i_ot&vlan=20", "invalid group name"),
    ] {
        let (status, page) = post(&data, "/groups", form).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{form}");
        assert!(page.contains(message), "{form}: {page}");
        assert_eq!(groups_file(&data), before, "{form}");
    }
}

#[tokio::test]
async fn groups_with_devices_and_the_default_cannot_be_deleted() {
    let data = setup().await;
    let device = "name=tv&mac=00:00:00:00:00:01&group=guest";
    assert_eq!(post(&data, "/devices", device).await.0, StatusCode::SEE_OTHER);

    let (status, page) = post(&data, "/groups/guest/delete", "").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(page.contains("still has devices"));

    let (status, page) = post(&data, "/groups/lan/delete", "").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(page.contains("is the default group"));
}

#[tokio::test]
async fn unused_groups_can_be_deleted_down_to_none() {
    let data = setup().await;
    assert_eq!(
        post(&data, "/groups/guest/delete", "").await.0,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        post(&data, "/groups/lan/delete", "").await.0,
        StatusCode::SEE_OTHER
    );
    let file = groups_file(&data);
    assert!(!file.contains("[[group]]"), "{file}");
    assert!(file.contains("default_group = \"\""), "{file}");
}

#[tokio::test]
async fn a_linked_dns_plugin_can_serve_all_networks() {
    let data = setup().await;
    std::fs::write(
        data.path().join("devices.toml"),
        "[[device]]\nname = \"dnsbox\"\nmac = \"00:00:00:00:00:35\"\ngroup = \"lan\"\nip = \"192.0.2.53\"\n",
    )
    .unwrap();
    std::fs::write(
        data.path().join("lanlord.toml"),
        format!(
            "[[plugin]]\ntype = \"pihole\"\nname = \"filter\"\nenabled = true\nurl = \"https://pi.hole\"\n\
             device = \"dnsbox\"\npassword_file = \"pihole.password\"\ncertificate = \"{}\"\n",
            "00".repeat(32)
        ),
    )
    .unwrap();
    let request = Request::get("/settings").body(Body::empty()).unwrap();
    let response = app(&data).oneshot(request).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let page = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        page.contains(r#"<option value="filter">filter (192.0.2.53)</option>"#),
        "{page}"
    );

    assert_eq!(
        post(&data, "/settings/dns", "service=filter").await.0,
        StatusCode::SEE_OTHER
    );
    assert!(
        groups_file(&data).contains("dns_service = \"filter\""),
        "{}",
        groups_file(&data)
    );
    let (status, page) = post(&data, "/settings/dns", "service=other").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(page.contains("other offers no DNS service"), "{page}");
    assert_eq!(
        post(&data, "/settings/dns", "service=").await.0,
        StatusCode::SEE_OTHER
    );
    assert!(!groups_file(&data).contains("dns_service"));
}

#[tokio::test]
async fn a_group_gets_its_own_wifi_with_a_password_file() {
    let data = setup().await;
    let form = "ssid=Home+IoT&password_file=iot.wifi&band_2g=on";
    assert_eq!(
        post(&data, "/groups/guest/network", form).await.0,
        StatusCode::SEE_OTHER
    );
    let file = groups_file(&data);
    assert!(
        file.contains("ssid = \"Home IoT\"\nssid_password_file = \"iot.wifi\""),
        "{file}"
    );

    let (status, page) = post(
        &data,
        "/groups/guest/network",
        "ssid=Home+IoT&password_file=..%2Fsecret&band_2g=on",
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        page.contains("needs a password file in the data directory"),
        "{page}"
    );
    let long = "x".repeat(33);
    let (status, _) = post(
        &data,
        "/groups/guest/network",
        &format!("ssid={long}&password_file=iot.wifi&band_2g=on"),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    assert_eq!(
        post(&data, "/groups/guest/network", "ssid=&password_file=iot.wifi")
            .await
            .0,
        StatusCode::SEE_OTHER
    );
    assert!(!groups_file(&data).contains("ssid"), "{}", groups_file(&data));
}

#[tokio::test]
async fn one_save_keeps_the_subnet_and_the_wifi_of_a_group() {
    let data = setup().await;
    let form = "subnet=192.0.2.0%2F24&ssid=Things&password_file=iot.wifi&band_2g=on&band_5g=on";
    assert_eq!(
        post(&data, "/groups/guest/network", form).await.0,
        StatusCode::SEE_OTHER
    );
    let file = groups_file(&data);
    assert!(file.contains("subnet = \"192.0.2.0/24\""), "{file}");
    assert!(file.contains("ssid = \"Things\""), "{file}");
    let log = std::fs::read_to_string(data.path().join("history.log")).unwrap();
    assert!(
        log.contains("Group guest changed: subnet none → 192.0.2.0/24, SSID none → Things, password file none → iot.wifi"),
        "{log}"
    );
    let request = Request::get("/groups").body(Body::empty()).unwrap();
    let response = app(&data).oneshot(request).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let page = String::from_utf8(body.to_vec()).unwrap();
    let form = page
        .split(r#"action="/groups/guest/network""#)
        .nth(1)
        .and_then(|rest| rest.split("</form>").next())
        .unwrap();
    for field in [
        "subnet",
        "reaches",
        "ssid",
        "password_file",
        "band_2g",
        "band_5g",
        "from_lan",
    ] {
        assert!(form.contains(&format!(r#"name="{field}""#)), "{field}: {form}");
    }
}

#[tokio::test]
async fn a_group_is_reachable_from_the_ticked_groups() {
    let data = setup().await;
    let form = "subnet=192.0.2.0%2F24&from_lan=on";
    assert_eq!(
        post(&data, "/groups/guest/network", form).await.0,
        StatusCode::SEE_OTHER
    );
    let file = groups_file(&data);
    assert!(file.contains("reachable_from = [\"lan\"]"), "{file}");
    let request = Request::get("/groups").body(Body::empty()).unwrap();
    let response = app(&data).oneshot(request).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let page = String::from_utf8(body.to_vec()).unwrap();
    assert!(page.contains(r#"name="from_lan" checked"#), "{page}");
    assert_eq!(
        post(&data, "/groups/guest/network", "subnet=192.0.2.0%2F24")
            .await
            .0,
        StatusCode::SEE_OTHER
    );
    assert!(!groups_file(&data).contains("reachable_from"));
    let log = std::fs::read_to_string(data.path().join("history.log")).unwrap();
    assert!(log.contains("reachable from none → lan"), "{log}");
    assert!(log.contains("reachable from lan → none"), "{log}");
}

#[tokio::test]
async fn a_group_cannot_be_reachable_from_itself() {
    let data = setup().await;
    let form = "from_guest=on";
    assert_eq!(
        post(&data, "/groups/guest/network", form).await.0,
        StatusCode::SEE_OTHER
    );
    assert!(!groups_file(&data).contains("reachable_from"));
}

#[tokio::test]
async fn a_group_reaches_single_ports() {
    let data = setup().await;
    let form = "reaches=Server%3A1883%2Ftcp%2C+Server%3A5683%2Fudp";
    assert_eq!(
        post(&data, "/groups/guest/network", form).await.0,
        StatusCode::SEE_OTHER
    );
    let file = groups_file(&data);
    assert!(file.contains("\"Server:1883/tcp\""), "{file}");
    assert!(file.contains("\"Server:5683/udp\""), "{file}");
    let log = std::fs::read_to_string(data.path().join("history.log")).unwrap();
    assert!(
        log.contains("reaches none → Server:1883/tcp, Server:5683/udp"),
        "{log}"
    );
    let (status, page) = post(&data, "/groups/guest/network", "reaches=Server%3A1883").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        page.contains("Server:1883 must look like Server:1883/tcp"),
        "{page}"
    );
}

#[tokio::test]
async fn the_bands_of_a_groups_wifi_are_chosen_with_two_boxes() {
    let data = setup().await;
    let wifi = "ssid=Things&password_file=iot.wifi";
    let save = |boxes: &str| format!("{wifi}{boxes}");
    assert_eq!(
        post(&data, "/groups/guest/network", &save("&band_5g=on")).await.0,
        StatusCode::SEE_OTHER
    );
    assert!(groups_file(&data).contains("ssid_bands = [\"5g\"]"));
    let log = std::fs::read_to_string(data.path().join("history.log")).unwrap();
    assert!(log.contains("Wi-Fi bands every radio → 5g"), "{log}");
    assert_eq!(
        post(&data, "/groups/guest/network", &save("&band_2g=on&band_5g=on"))
            .await
            .0,
        StatusCode::SEE_OTHER
    );
    assert!(!groups_file(&data).contains("ssid_bands"));
    let (status, page) = post(&data, "/groups/guest/network", wifi).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(page.contains("needs at least one band"), "{page}");
}
