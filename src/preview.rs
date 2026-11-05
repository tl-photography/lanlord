//! What a target would change, in a form every target shares: steps people can read, the exact operations as
//! details, and a digest so apply only goes ahead if the steps are still the ones shown.

use std::fmt::Write as _;

/// One change of a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// What it does, for people.
    pub description: String,
    /// The exact operations, for example `uci` commands or API calls.
    pub details: Vec<String>,
}

/// The changes of one target and what it leaves as it is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Preview {
    /// Changes, in the order they are made.
    pub steps: Vec<Step>,
    /// Devices that are left as they are, and why.
    pub notes: Vec<String>,
}

impl Preview {
    /// A short fingerprint of the operations.
    #[must_use]
    pub fn digest(&self) -> String {
        let mut text = String::new();
        for step in &self.steps {
            for detail in &step.details {
                text.push_str(detail);
                text.push('\n');
            }
        }
        let digest = ring::digest::digest(&ring::digest::SHA256, text.as_bytes());
        digest.as_ref()[..16].iter().fold(String::new(), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
    }
}

#[cfg(test)]
mod tests;
