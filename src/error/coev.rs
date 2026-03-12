// SPDX-License-Identifier: MIT

#[derive(Debug)]
pub enum CoevError {
    EmptyEvTriples,
    InvalidEvidenceId(String),
    UnsetMandatoryField(String, String),
    Custom(String),
    Unknown,
}

impl CoevError {
    pub fn unset_mandatory_field<D: std::fmt::Display>(object: D, field: D) -> Self {
        CoevError::UnsetMandatoryField(object.to_string(), field.to_string())
    }

    pub fn custom<D: std::fmt::Display>(message: D) -> Self {
        CoevError::Custom(message.to_string())
    }
}

impl std::error::Error for CoevError {}

impl std::fmt::Display for CoevError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyEvTriples => {
                write!(f, "an EvTriples must have at least one non-empty field")
            }
            Self::InvalidEvidenceId(id) => write!(f, "invalid evidence ID: {id}"),
            Self::UnsetMandatoryField(object, field) => {
                write!(f, "{object} field(s) {field} must be set")
            }
            Self::Custom(message) => f.write_str(message.as_str()),
            Self::Unknown => write!(f, "unknown CoevError encountered"),
        }
    }
}
