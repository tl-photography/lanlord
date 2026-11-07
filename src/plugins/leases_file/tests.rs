//! Unit tests of `plugins/leases_file`.

use super::*;

#[test]
fn dnsmasq_lines_are_parsed() {
    let content = "\
1793900000 AA:BB:CC:00:11:22 192.0.2.10 phone 01:aa:bb:cc:00:11:22
1793900000 aa:bb:cc:00:11:33 192.0.2.11 * *
duid 00:01:00:01:2c:4f:8f:aa:bb:cc:dd:ee:ff
1793900000 1234 2001:db8::5 laptop 00:01
broken line
";
    assert_eq!(
        parse(content),
        [
            Present {
                mac: "aa:bb:cc:00:11:22".to_owned(),
                ip: Some(Ipv4Addr::new(192, 0, 2, 10)),
                hostname: "phone".to_owned(),
            },
            Present {
                mac: "aa:bb:cc:00:11:33".to_owned(),
                ip: Some(Ipv4Addr::new(192, 0, 2, 11)),
                hostname: String::new(),
            },
        ]
    );
}

#[tokio::test]
async fn missing_file_is_an_error() {
    let plugin = LeasesFile {
        name: "router".to_owned(),
        path: PathBuf::from("/nonexistent/dhcp.leases"),
    };
    assert!(plugin.observe().await.is_err());
}
