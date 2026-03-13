// SPDX-License-Identifier: MIT

/// Errors specific to the OCP SAFE SFR profile.
#[derive(Debug)]
pub enum OcpSafeError {
    /// The SFR extension (key -1) is missing from the measurement-values-map.
    MissingSfrExtension,
    /// A mandatory field is not set.
    UnsetMandatoryField(&'static str, &'static str),
    /// The fw-identifier is empty (at least one field must be set).
    EmptyFwIdentifier,
    /// Wraps an arbitrary error message.
    Custom(String),
}

impl OcpSafeError {
    pub fn unset_mandatory_field(ty: &'static str, field: &'static str) -> Self {
        Self::UnsetMandatoryField(ty, field)
    }

    pub fn custom<T: std::fmt::Display>(msg: T) -> Self {
        Self::Custom(msg.to_string())
    }
}

impl std::fmt::Display for OcpSafeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSfrExtension => {
                write!(
                    f,
                    "ocp-safe-sfr extension (key -1) not found in measurement-values-map"
                )
            }
            Self::UnsetMandatoryField(ty, field) => {
                write!(f, "{ty}: mandatory field '{field}' is not set")
            }
            Self::EmptyFwIdentifier => {
                write!(f, "fw-identifier must have at least one field set")
            }
            Self::Custom(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for OcpSafeError {}
