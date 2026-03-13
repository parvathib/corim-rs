// SPDX-License-Identifier: MIT

//! OCP S.A.F.E. Short Form Report (SFR) CoRIM Profile
//!
//! This module implements the OCP S.A.F.E. SFR extension profile for CoRIM,
//! identified by OID `1.3.6.1.4.1.42623.1.1`. The profile extends the
//! `measurement-values-map` at CBOR key `-1` with security review findings.
//!
//! # CDDL
//!
//! ```text
//! $$measurement-values-map-extension //= (
//!   &(ocp-safe-sfr: -1) => ocp-safe-sfr-map
//! )
//! ```
//!
//! # Example
//!
//! ```rust
//! use corim_rs::profiles::ocp_safe::{
//!     OcpSafeSfrMap, OcpSafeSfrMapBuilder, IssueEntry, Cvss,
//! };
//! use corim_rs::IntegerTime;
//!
//! let sfr = OcpSafeSfrMapBuilder::new()
//!     .review_framework_version("1.1".into())
//!     .report_version("1.2".into())
//!     .completion_date(IntegerTime::from(1687651200i64))
//!     .scope_number(1)
//!     .issues(vec![IssueEntry {
//!         title: "Buffer overflow in parser".into(),
//!         description: "Unchecked input length causes stack corruption".into(),
//!         assessment: Cvss {
//!             score: "7.9".into(),
//!             vector: "AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L".into(),
//!             version: Some("3.1".into()),
//!         }.into(),
//!         cwe: Some("CWE-120".into()),
//!         cve: None,
//!         extensions: None,
//!     }])
//!     .build()
//!     .unwrap();
//! ```

use std::borrow::Cow;
use std::marker::PhantomData;

use derive_more::{Constructor, From};
use serde::{
    de::{self, MapAccess, Visitor},
    ser::SerializeMap,
    Deserialize, Deserializer, Serialize, Serializer,
};

use crate::{
    error::ocp_safe::OcpSafeError,
    triples::{DigestsType, VersionMap},
    ExtensionMap, Integer, IntegerTime, Result, Text,
};

/// Profile OID bytes for OCP SAFE SFR: `1.3.6.1.4.1.42623.1.1` in BER/DER encoding.
pub const PROFILE_OID_BYTES: &[u8] = &[
    0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xF4, 0x17, 0x01, 0x01,
];

/// CBOR key used for the SFR extension inside `measurement-values-map`.
pub const SFR_EXTENSION_KEY: i128 = -1;

// ============================================================================
// OcpSafeSfrMap — the main extension structure
// ============================================================================

/// OCP S.A.F.E. SFR extension map embedded at CBOR key `-1` in `measurement-values-map`.
///
/// Contains security review metadata, optional firmware identifiers, and
/// optional security issues found during the review.
#[derive(Debug, From, Constructor, PartialEq, Clone)]
#[repr(C)]
pub struct OcpSafeSfrMap<'a> {
    /// Version of the OCP S.A.F.E. review framework used (key 0)
    pub review_framework_version: Text<'a>,
    /// Version of the specific security review report (key 1)
    pub report_version: Text<'a>,
    /// Date the security review was completed (key 2, CBOR tag 1 epoch)
    pub completion_date: IntegerTime,
    /// Numerical identifier for the review scope (key 3)
    pub scope_number: i64,
    /// Optional firmware identifiers reviewed (key 4)
    pub fw_identifiers: Option<Vec<FwIdentifier<'a>>>,
    /// Optional security issues found (key 5)
    pub issues: Option<Vec<IssueEntry<'a>>>,
    /// Extension attributes
    pub extensions: Option<ExtensionMap<'a>>,
}

impl Serialize for OcpSafeSfrMap<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_hr = serializer.is_human_readable();
        let mut len = 4; // 4 mandatory fields
        if self.fw_identifiers.is_some() {
            len += 1;
        }
        if self.issues.is_some() {
            len += 1;
        }
        if let Some(ext) = &self.extensions {
            len += ext.len();
        }
        let mut map = serializer.serialize_map(Some(len))?;

        if is_hr {
            map.serialize_entry("review-framework-version", &self.review_framework_version)?;
            map.serialize_entry("report-version", &self.report_version)?;
            map.serialize_entry("completion-date", &self.completion_date)?;
            map.serialize_entry("scope-number", &self.scope_number)?;
            if let Some(fw) = &self.fw_identifiers {
                map.serialize_entry("fw-identifiers", fw)?;
            }
            if let Some(issues) = &self.issues {
                map.serialize_entry("issues", issues)?;
            }
        } else {
            map.serialize_entry(&0, &self.review_framework_version)?;
            map.serialize_entry(&1, &self.report_version)?;
            map.serialize_entry(&2, &self.completion_date)?;
            map.serialize_entry(&3, &self.scope_number)?;
            if let Some(fw) = &self.fw_identifiers {
                map.serialize_entry(&4, fw)?;
            }
            if let Some(issues) = &self.issues {
                map.serialize_entry(&5, issues)?;
            }
        }

        if let Some(ext) = &self.extensions {
            ext.serialize_map(&mut map, is_hr)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for OcpSafeSfrMap<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct V<'a> {
            is_hr: bool,
            _p: PhantomData<&'a ()>,
        }
        impl<'de, 'a> Visitor<'de> for V<'a> {
            type Value = OcpSafeSfrMap<'a>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a map containing OcpSafeSfrMap fields")
            }
            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut builder = OcpSafeSfrMapBuilder::new();
                loop {
                    if self.is_hr {
                        match map.next_key::<&str>()? {
                            Some("review-framework-version") => {
                                let v: String = map.next_value()?;
                                builder = builder.review_framework_version(Cow::Owned(v));
                            }
                            Some("report-version") => {
                                let v: String = map.next_value()?;
                                builder = builder.report_version(Cow::Owned(v));
                            }
                            Some("completion-date") => {
                                builder = builder.completion_date(map.next_value::<IntegerTime>()?);
                            }
                            Some("scope-number") => {
                                builder = builder.scope_number(map.next_value::<i64>()?);
                            }
                            Some("fw-identifiers") => {
                                builder =
                                    builder.fw_identifiers(map.next_value::<Vec<FwIdentifier>>()?);
                            }
                            Some("issues") => {
                                builder = builder.issues(map.next_value::<Vec<IssueEntry>>()?);
                            }
                            Some(name) => {
                                return Err(de::Error::custom(format!(
                                    "unexpected field \"{name}\""
                                )))
                            }
                            None => break,
                        }
                    } else {
                        match map.next_key::<i64>()? {
                            Some(0) => {
                                let v: String = map.next_value()?;
                                builder = builder.review_framework_version(Cow::Owned(v));
                            }
                            Some(1) => {
                                let v: String = map.next_value()?;
                                builder = builder.report_version(Cow::Owned(v));
                            }
                            Some(2) => {
                                builder = builder.completion_date(map.next_value::<IntegerTime>()?);
                            }
                            Some(3) => {
                                builder = builder.scope_number(map.next_value::<i64>()?);
                            }
                            Some(4) => {
                                builder =
                                    builder.fw_identifiers(map.next_value::<Vec<FwIdentifier>>()?);
                            }
                            Some(5) => {
                                builder = builder.issues(map.next_value::<Vec<IssueEntry>>()?);
                            }
                            Some(key) => {
                                return Err(de::Error::custom(format!("unexpected key \"{key}\"")))
                            }
                            None => break,
                        }
                    }
                }
                builder.build().map_err(de::Error::custom)
            }
        }
        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(V {
            is_hr,
            _p: PhantomData,
        })
    }
}

/// Builder for [`OcpSafeSfrMap`].
#[derive(Default)]
pub struct OcpSafeSfrMapBuilder<'a> {
    review_framework_version: Option<Text<'a>>,
    report_version: Option<Text<'a>>,
    completion_date: Option<IntegerTime>,
    scope_number: Option<i64>,
    fw_identifiers: Option<Vec<FwIdentifier<'a>>>,
    issues: Option<Vec<IssueEntry<'a>>>,
    extensions: Option<ExtensionMap<'a>>,
}

impl<'a> OcpSafeSfrMapBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn review_framework_version(mut self, v: Text<'a>) -> Self {
        self.review_framework_version = Some(v);
        self
    }
    pub fn report_version(mut self, v: Text<'a>) -> Self {
        self.report_version = Some(v);
        self
    }
    pub fn completion_date(mut self, v: IntegerTime) -> Self {
        self.completion_date = Some(v);
        self
    }
    pub fn scope_number(mut self, v: i64) -> Self {
        self.scope_number = Some(v);
        self
    }
    pub fn fw_identifiers(mut self, v: Vec<FwIdentifier<'a>>) -> Self {
        self.fw_identifiers = Some(v);
        self
    }
    pub fn issues(mut self, v: Vec<IssueEntry<'a>>) -> Self {
        self.issues = Some(v);
        self
    }
    pub fn extensions(mut self, v: ExtensionMap<'a>) -> Self {
        self.extensions = Some(v);
        self
    }
    pub fn build(self) -> Result<OcpSafeSfrMap<'a>> {
        let review_framework_version =
            self.review_framework_version
                .ok_or(OcpSafeError::unset_mandatory_field(
                    "OcpSafeSfrMap",
                    "review-framework-version",
                ))?;
        let report_version = self
            .report_version
            .ok_or(OcpSafeError::unset_mandatory_field(
                "OcpSafeSfrMap",
                "report-version",
            ))?;
        let completion_date = self
            .completion_date
            .ok_or(OcpSafeError::unset_mandatory_field(
                "OcpSafeSfrMap",
                "completion-date",
            ))?;
        let scope_number = self
            .scope_number
            .ok_or(OcpSafeError::unset_mandatory_field(
                "OcpSafeSfrMap",
                "scope-number",
            ))?;
        Ok(OcpSafeSfrMap {
            review_framework_version,
            report_version,
            completion_date,
            scope_number,
            fw_identifiers: self.fw_identifiers,
            issues: self.issues,
            extensions: self.extensions,
        })
    }
}

// ============================================================================
// IssueEntry
// ============================================================================

/// A security issue found during the review.
#[derive(Debug, From, Constructor, PartialEq, Clone)]
#[repr(C)]
pub struct IssueEntry<'a> {
    /// Brief title (key 0)
    pub title: Text<'a>,
    /// Detailed description (key 1)
    pub description: Text<'a>,
    /// Assessment, e.g. CVSS (key 2)
    pub assessment: Assessment<'a>,
    /// Optional CWE identifier (key 3)
    pub cwe: Option<Text<'a>>,
    /// Optional CVE identifier (key 4)
    pub cve: Option<Text<'a>>,
    /// Extension attributes
    pub extensions: Option<ExtensionMap<'a>>,
}

impl Serialize for IssueEntry<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_hr = serializer.is_human_readable();
        let mut len = 3; // title, description, assessment
        if self.cwe.is_some() {
            len += 1;
        }
        if self.cve.is_some() {
            len += 1;
        }
        if let Some(ext) = &self.extensions {
            len += ext.len();
        }
        let mut map = serializer.serialize_map(Some(len))?;

        if is_hr {
            map.serialize_entry("title", &self.title)?;
            map.serialize_entry("description", &self.description)?;
            map.serialize_entry("assessment", &self.assessment)?;
            if let Some(cwe) = &self.cwe {
                map.serialize_entry("cwe", cwe)?;
            }
            if let Some(cve) = &self.cve {
                map.serialize_entry("cve", cve)?;
            }
        } else {
            map.serialize_entry(&0, &self.title)?;
            map.serialize_entry(&1, &self.description)?;
            map.serialize_entry(&2, &self.assessment)?;
            if let Some(cwe) = &self.cwe {
                map.serialize_entry(&3, cwe)?;
            }
            if let Some(cve) = &self.cve {
                map.serialize_entry(&4, cve)?;
            }
        }

        if let Some(ext) = &self.extensions {
            ext.serialize_map(&mut map, is_hr)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for IssueEntry<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct V<'a> {
            is_hr: bool,
            _p: PhantomData<&'a ()>,
        }
        impl<'de, 'a> Visitor<'de> for V<'a> {
            type Value = IssueEntry<'a>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a map containing IssueEntry fields")
            }
            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut title: Option<String> = None;
                let mut description: Option<String> = None;
                let mut assessment: Option<Assessment> = None;
                let mut cwe: Option<String> = None;
                let mut cve: Option<String> = None;

                loop {
                    if self.is_hr {
                        match map.next_key::<&str>()? {
                            Some("title") => title = Some(map.next_value()?),
                            Some("description") => description = Some(map.next_value()?),
                            Some("assessment") => assessment = Some(map.next_value()?),
                            Some("cwe") => cwe = Some(map.next_value()?),
                            Some("cve") => cve = Some(map.next_value()?),
                            Some(name) => {
                                return Err(de::Error::custom(format!(
                                    "unexpected field \"{name}\""
                                )))
                            }
                            None => break,
                        }
                    } else {
                        match map.next_key::<i64>()? {
                            Some(0) => title = Some(map.next_value()?),
                            Some(1) => description = Some(map.next_value()?),
                            Some(2) => assessment = Some(map.next_value()?),
                            Some(3) => cwe = Some(map.next_value()?),
                            Some(4) => cve = Some(map.next_value()?),
                            Some(key) => {
                                return Err(de::Error::custom(format!("unexpected key \"{key}\"")))
                            }
                            None => break,
                        }
                    }
                }

                let title = title.ok_or_else(|| de::Error::missing_field("title"))?;
                let description =
                    description.ok_or_else(|| de::Error::missing_field("description"))?;
                let assessment =
                    assessment.ok_or_else(|| de::Error::missing_field("assessment"))?;

                Ok(IssueEntry {
                    title: Cow::Owned(title),
                    description: Cow::Owned(description),
                    assessment,
                    cwe: cwe.map(Cow::Owned),
                    cve: cve.map(Cow::Owned),
                    extensions: None,
                })
            }
        }
        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(V {
            is_hr,
            _p: PhantomData,
        })
    }
}

// ============================================================================
// Assessment — extensible assessment type choice ($assessment /= cvss)
// ============================================================================

/// Assessment type choice. Currently only CVSS is defined.
///
/// The CDDL allows `$assessment /= cvss`, so this enum can be extended.
/// In CBOR, CVSS is serialized directly as a map (no discriminator tag).
#[derive(Debug, PartialEq, Clone)]
pub enum Assessment<'a> {
    /// CVSS-based assessment
    Cvss(Cvss<'a>),
}

impl<'a> From<Cvss<'a>> for Assessment<'a> {
    fn from(c: Cvss<'a>) -> Self {
        Self::Cvss(c)
    }
}

impl Serialize for Assessment<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Cvss(cvss) => cvss.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for Assessment<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Currently only CVSS is defined; deserialize as CVSS directly.
        let cvss = Cvss::deserialize(deserializer)?;
        Ok(Self::Cvss(cvss))
    }
}

// ============================================================================
// Cvss
// ============================================================================

/// CVSS vulnerability score.
#[derive(Debug, From, Constructor, PartialEq, Clone)]
#[repr(C)]
pub struct Cvss<'a> {
    /// CVSS numerical score, e.g. "7.9" (key 0)
    pub score: Text<'a>,
    /// CVSS vector string (key 1)
    pub vector: Text<'a>,
    /// Optional CVSS version, e.g. "3.1" (key 2)
    pub version: Option<Text<'a>>,
}

impl Serialize for Cvss<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_hr = serializer.is_human_readable();
        let mut len = 2;
        if self.version.is_some() {
            len += 1;
        }
        let mut map = serializer.serialize_map(Some(len))?;

        if is_hr {
            map.serialize_entry("cvss-score", &self.score)?;
            map.serialize_entry("cvss-vector", &self.vector)?;
            if let Some(v) = &self.version {
                map.serialize_entry("cvss-version", v)?;
            }
        } else {
            map.serialize_entry(&0, &self.score)?;
            map.serialize_entry(&1, &self.vector)?;
            if let Some(v) = &self.version {
                map.serialize_entry(&2, v)?;
            }
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for Cvss<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct V<'a> {
            is_hr: bool,
            _p: PhantomData<&'a ()>,
        }
        impl<'de, 'a> Visitor<'de> for V<'a> {
            type Value = Cvss<'a>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a map containing CVSS fields")
            }
            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut score: Option<String> = None;
                let mut vector: Option<String> = None;
                let mut version: Option<String> = None;

                loop {
                    if self.is_hr {
                        match map.next_key::<&str>()? {
                            Some("cvss-score") => score = Some(map.next_value()?),
                            Some("cvss-vector") => vector = Some(map.next_value()?),
                            Some("cvss-version") => version = Some(map.next_value()?),
                            Some(name) => {
                                return Err(de::Error::custom(format!(
                                    "unexpected field \"{name}\""
                                )))
                            }
                            None => break,
                        }
                    } else {
                        match map.next_key::<i64>()? {
                            Some(0) => score = Some(map.next_value()?),
                            Some(1) => vector = Some(map.next_value()?),
                            Some(2) => version = Some(map.next_value()?),
                            Some(key) => {
                                return Err(de::Error::custom(format!("unexpected key \"{key}\"")))
                            }
                            None => break,
                        }
                    }
                }

                let score = score.ok_or_else(|| de::Error::missing_field("cvss-score"))?;
                let vector = vector.ok_or_else(|| de::Error::missing_field("cvss-vector"))?;

                Ok(Cvss {
                    score: Cow::Owned(score),
                    vector: Cow::Owned(vector),
                    version: version.map(Cow::Owned),
                })
            }
        }
        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(V {
            is_hr,
            _p: PhantomData,
        })
    }
}

// ============================================================================
// FwIdentifier — firmware identifier
// ============================================================================

/// Firmware identifier describing a reviewed firmware component.
///
/// At least one field must be set (`non-empty` in CDDL).
#[derive(Debug, From, Constructor, PartialEq, Clone)]
#[repr(C)]
pub struct FwIdentifier<'a> {
    /// Firmware version (key 0)
    pub fw_version: Option<VersionMap<'a>>,
    /// Cryptographic digests of firmware files (key 1)
    pub fw_file_digests: Option<DigestsType>,
    /// Source repository tag or commit (key 2)
    pub repo_tag: Option<Text<'a>>,
    /// Source code manifest (key 3)
    pub src_manifest: Option<SrcManifest<'a>>,
}

impl FwIdentifier<'_> {
    /// Returns true if no fields are set (invalid per CDDL `non-empty`).
    pub fn is_empty(&self) -> bool {
        self.fw_version.is_none()
            && self.fw_file_digests.is_none()
            && self.repo_tag.is_none()
            && self.src_manifest.is_none()
    }
}

impl Serialize for FwIdentifier<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_hr = serializer.is_human_readable();
        let mut len = 0;
        if self.fw_version.is_some() {
            len += 1;
        }
        if self.fw_file_digests.is_some() {
            len += 1;
        }
        if self.repo_tag.is_some() {
            len += 1;
        }
        if self.src_manifest.is_some() {
            len += 1;
        }
        let mut map = serializer.serialize_map(Some(len))?;

        if is_hr {
            if let Some(v) = &self.fw_version {
                map.serialize_entry("fw-version", v)?;
            }
            if let Some(d) = &self.fw_file_digests {
                map.serialize_entry("fw-file-digests", d)?;
            }
            if let Some(t) = &self.repo_tag {
                map.serialize_entry("repo-tag", t)?;
            }
            if let Some(m) = &self.src_manifest {
                map.serialize_entry("src-manifest", m)?;
            }
        } else {
            if let Some(v) = &self.fw_version {
                map.serialize_entry(&0, v)?;
            }
            if let Some(d) = &self.fw_file_digests {
                map.serialize_entry(&1, d)?;
            }
            if let Some(t) = &self.repo_tag {
                map.serialize_entry(&2, t)?;
            }
            if let Some(m) = &self.src_manifest {
                map.serialize_entry(&3, m)?;
            }
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for FwIdentifier<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct V<'a> {
            is_hr: bool,
            _p: PhantomData<&'a ()>,
        }
        impl<'de, 'a> Visitor<'de> for V<'a> {
            type Value = FwIdentifier<'a>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a map containing FwIdentifier fields")
            }
            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut fw_version: Option<VersionMap> = None;
                let mut fw_file_digests: Option<DigestsType> = None;
                let mut repo_tag: Option<String> = None;
                let mut src_manifest: Option<SrcManifest> = None;

                loop {
                    if self.is_hr {
                        match map.next_key::<&str>()? {
                            Some("fw-version") => fw_version = Some(map.next_value()?),
                            Some("fw-file-digests") => fw_file_digests = Some(map.next_value()?),
                            Some("repo-tag") => repo_tag = Some(map.next_value()?),
                            Some("src-manifest") => src_manifest = Some(map.next_value()?),
                            Some(name) => {
                                return Err(de::Error::custom(format!(
                                    "unexpected field \"{name}\""
                                )))
                            }
                            None => break,
                        }
                    } else {
                        match map.next_key::<i64>()? {
                            Some(0) => fw_version = Some(map.next_value()?),
                            Some(1) => fw_file_digests = Some(map.next_value()?),
                            Some(2) => repo_tag = Some(map.next_value()?),
                            Some(3) => src_manifest = Some(map.next_value()?),
                            Some(key) => {
                                return Err(de::Error::custom(format!("unexpected key \"{key}\"")))
                            }
                            None => break,
                        }
                    }
                }

                let result = FwIdentifier {
                    fw_version,
                    fw_file_digests,
                    repo_tag: repo_tag.map(Cow::Owned),
                    src_manifest,
                };

                if result.is_empty() {
                    return Err(de::Error::custom(
                        "fw-identifier must have at least one field set",
                    ));
                }

                Ok(result)
            }
        }
        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(V {
            is_hr,
            _p: PhantomData,
        })
    }
}

// ============================================================================
// SrcManifest — source code manifest
// ============================================================================

/// Source code manifest with an overall digest and individual file entries.
#[derive(Debug, From, Constructor, PartialEq, Clone)]
#[repr(C)]
pub struct SrcManifest<'a> {
    /// Digest of the manifest itself (key 0)
    pub manifest_digest: DigestsType,
    /// Individual file entries (key 1)
    pub manifest: Vec<ManifestEntry<'a>>,
}

impl Serialize for SrcManifest<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_hr = serializer.is_human_readable();
        let mut map = serializer.serialize_map(Some(2))?;

        if is_hr {
            map.serialize_entry("manifest-digest", &self.manifest_digest)?;
            map.serialize_entry("manifest", &self.manifest)?;
        } else {
            map.serialize_entry(&0, &self.manifest_digest)?;
            map.serialize_entry(&1, &self.manifest)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for SrcManifest<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct V<'a> {
            is_hr: bool,
            _p: PhantomData<&'a ()>,
        }
        impl<'de, 'a> Visitor<'de> for V<'a> {
            type Value = SrcManifest<'a>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a map containing SrcManifest fields")
            }
            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut manifest_digest: Option<DigestsType> = None;
                let mut manifest: Option<Vec<ManifestEntry>> = None;

                loop {
                    if self.is_hr {
                        match map.next_key::<&str>()? {
                            Some("manifest-digest") => manifest_digest = Some(map.next_value()?),
                            Some("manifest") => manifest = Some(map.next_value()?),
                            Some(name) => {
                                return Err(de::Error::custom(format!(
                                    "unexpected field \"{name}\""
                                )))
                            }
                            None => break,
                        }
                    } else {
                        match map.next_key::<i64>()? {
                            Some(0) => manifest_digest = Some(map.next_value()?),
                            Some(1) => manifest = Some(map.next_value()?),
                            Some(key) => {
                                return Err(de::Error::custom(format!("unexpected key \"{key}\"")))
                            }
                            None => break,
                        }
                    }
                }

                let manifest_digest =
                    manifest_digest.ok_or_else(|| de::Error::missing_field("manifest-digest"))?;
                let manifest = manifest.ok_or_else(|| de::Error::missing_field("manifest"))?;

                Ok(SrcManifest {
                    manifest_digest,
                    manifest,
                })
            }
        }
        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(V {
            is_hr,
            _p: PhantomData,
        })
    }
}

// ============================================================================
// ManifestEntry — individual source file hash
// ============================================================================

/// An entry in a source manifest: filename + digest.
#[derive(Debug, From, Constructor, PartialEq, Clone)]
#[repr(C)]
pub struct ManifestEntry<'a> {
    /// Source file name (key 0)
    pub filename: Text<'a>,
    /// Cryptographic hash(es) of the file (key 1)
    pub file_hash: DigestsType,
}

impl Serialize for ManifestEntry<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_hr = serializer.is_human_readable();
        let mut map = serializer.serialize_map(Some(2))?;

        if is_hr {
            map.serialize_entry("filename", &self.filename)?;
            map.serialize_entry("file-hash", &self.file_hash)?;
        } else {
            map.serialize_entry(&0, &self.filename)?;
            map.serialize_entry(&1, &self.file_hash)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for ManifestEntry<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct V<'a> {
            is_hr: bool,
            _p: PhantomData<&'a ()>,
        }
        impl<'de, 'a> Visitor<'de> for V<'a> {
            type Value = ManifestEntry<'a>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a map containing ManifestEntry fields")
            }
            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut filename: Option<String> = None;
                let mut file_hash: Option<DigestsType> = None;

                loop {
                    if self.is_hr {
                        match map.next_key::<&str>()? {
                            Some("filename") => filename = Some(map.next_value()?),
                            Some("file-hash") => file_hash = Some(map.next_value()?),
                            Some(name) => {
                                return Err(de::Error::custom(format!(
                                    "unexpected field \"{name}\""
                                )))
                            }
                            None => break,
                        }
                    } else {
                        match map.next_key::<i64>()? {
                            Some(0) => filename = Some(map.next_value()?),
                            Some(1) => file_hash = Some(map.next_value()?),
                            Some(key) => {
                                return Err(de::Error::custom(format!("unexpected key \"{key}\"")))
                            }
                            None => break,
                        }
                    }
                }

                let filename = filename.ok_or_else(|| de::Error::missing_field("filename"))?;
                let file_hash = file_hash.ok_or_else(|| de::Error::missing_field("file-hash"))?;

                Ok(ManifestEntry {
                    filename: Cow::Owned(filename),
                    file_hash,
                })
            }
        }
        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(V {
            is_hr,
            _p: PhantomData,
        })
    }
}

// ============================================================================
// Extraction helpers — decode SFR from MeasurementValuesMap extensions
// ============================================================================

use crate::triples::MeasurementValuesMap;

impl OcpSafeSfrMap<'_> {
    /// Extract and decode the OCP SAFE SFR extension from a
    /// `MeasurementValuesMap`'s extensions at CBOR key `-1`.
    ///
    /// Returns `Err(OcpSafeError::MissingSfrExtension)` if key `-1` is absent.
    pub fn from_measurement_values(mval: &MeasurementValuesMap) -> Result<Self> {
        let ext_value = mval
            .extensions
            .as_ref()
            .and_then(|e| e.get(Integer(SFR_EXTENSION_KEY)))
            .ok_or(OcpSafeError::MissingSfrExtension)?;

        // Round-trip through CBOR: serialize the ExtensionValue to bytes,
        // then deserialize as OcpSafeSfrMap.
        let mut buf: Vec<u8> = Vec::new();
        ciborium::into_writer(ext_value, &mut buf)
            .map_err(|e| OcpSafeError::custom(format!("CBOR serialize: {e}")))?;
        let sfr: OcpSafeSfrMap = ciborium::from_reader(buf.as_slice())
            .map_err(|e| OcpSafeError::custom(format!("CBOR deserialize SFR: {e}")))?;
        Ok(sfr)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IntegerTime;

    fn sample_sfr<'a>() -> OcpSafeSfrMap<'a> {
        OcpSafeSfrMapBuilder::new()
            .review_framework_version("1.1".into())
            .report_version("1.2".into())
            .completion_date(IntegerTime::from(1687651200i64))
            .scope_number(1)
            .issues(vec![IssueEntry {
                title: "Memory corruption".into(),
                description: "Stack buffer overflow in SPI flash reader".into(),
                assessment: Assessment::Cvss(Cvss {
                    score: "7.9".into(),
                    vector: "AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L".into(),
                    version: Some("3.1".into()),
                }),
                cwe: Some("CWE-111".into()),
                cve: None,
                extensions: None,
            }])
            .build()
            .unwrap()
    }

    #[test]
    fn sfr_cbor_roundtrip() {
        let sfr = sample_sfr();
        let mut buf: Vec<u8> = Vec::new();
        ciborium::into_writer(&sfr, &mut buf).unwrap();
        let decoded: OcpSafeSfrMap = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(
            sfr.review_framework_version,
            decoded.review_framework_version
        );
        assert_eq!(sfr.report_version, decoded.report_version);
        assert_eq!(sfr.scope_number, decoded.scope_number);
        assert_eq!(sfr.issues.as_ref().unwrap().len(), 1);
        let issue = &decoded.issues.unwrap()[0];
        assert_eq!(issue.title, "Memory corruption");
        assert_eq!(issue.cwe.as_deref(), Some("CWE-111"));
        assert!(issue.cve.is_none());
    }

    #[test]
    fn sfr_json_roundtrip() {
        let sfr = sample_sfr();
        let json = serde_json::to_string(&sfr).unwrap();
        let decoded: OcpSafeSfrMap = serde_json::from_str(&json).unwrap();
        assert_eq!(
            sfr.review_framework_version,
            decoded.review_framework_version
        );
        assert_eq!(sfr.scope_number, decoded.scope_number);
    }

    #[test]
    fn builder_missing_mandatory_field() {
        let result = OcpSafeSfrMapBuilder::new()
            .review_framework_version("1.0".into())
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn fw_identifier_non_empty() {
        let fw = FwIdentifier {
            fw_version: None,
            fw_file_digests: None,
            repo_tag: None,
            src_manifest: None,
        };
        assert!(fw.is_empty());
    }

    #[test]
    fn cvss_cbor_roundtrip() {
        let cvss = Cvss {
            score: "9.8".into(),
            vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into(),
            version: Some("3.1".into()),
        };
        let mut buf: Vec<u8> = Vec::new();
        ciborium::into_writer(&cvss, &mut buf).unwrap();
        let decoded: Cvss = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(cvss.score, decoded.score);
        assert_eq!(cvss.vector, decoded.vector);
        assert_eq!(cvss.version, decoded.version);
    }

    #[test]
    fn sfr_with_fw_identifiers() {
        let sfr = OcpSafeSfrMapBuilder::new()
            .review_framework_version("1.1".into())
            .report_version("1.0".into())
            .completion_date(IntegerTime::from(1700000000i64))
            .scope_number(2)
            .fw_identifiers(vec![FwIdentifier {
                fw_version: Some(VersionMap {
                    version: "1.2.3".into(),
                    version_scheme: None,
                }),
                fw_file_digests: None,
                repo_tag: Some("v1.2.3".into()),
                src_manifest: None,
            }])
            .build()
            .unwrap();

        let mut buf: Vec<u8> = Vec::new();
        ciborium::into_writer(&sfr, &mut buf).unwrap();
        let decoded: OcpSafeSfrMap = ciborium::from_reader(buf.as_slice()).unwrap();
        let fw = &decoded.fw_identifiers.unwrap()[0];
        assert_eq!(fw.fw_version.as_ref().unwrap().version, "1.2.3");
        assert_eq!(fw.repo_tag.as_deref(), Some("v1.2.3"));
    }
}
