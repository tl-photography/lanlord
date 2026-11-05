//! Unit tests of `preview`.

use super::*;

fn step(detail: &str) -> Step {
    Step {
        description: "change".to_owned(),
        details: vec![detail.to_owned()],
    }
}

#[test]
fn the_digest_follows_the_details_only() {
    let first = Preview {
        steps: vec![step("a")],
        notes: vec!["note".to_owned()],
    };
    assert_eq!(first.digest().len(), 32);
    let same = Preview {
        steps: vec![Step {
            description: "other words".to_owned(),
            ..step("a")
        }],
        notes: Vec::new(),
    };
    assert_eq!(first.digest(), same.digest());
    assert_ne!(
        first.digest(),
        Preview {
            steps: vec![step("b")],
            notes: Vec::new()
        }
        .digest()
    );
}
