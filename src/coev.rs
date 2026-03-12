// SPDX-License-Identifier: MIT

//! Concise Evidence (CoEV) Implementation
//!
//! This module implements the CoEV (Concise Evidence) data structure for expressing
//! attestation evidence using CBOR encoding. CoEV provides a structured way for attesters
//! to report evidence about their state, complementing CoMID's reference values and endorsements.
//!
//! # Key Components
//!
//! * [`ConciseEvidence`] - The main CoEV structure, tagged with CBOR tag 571
//! * [`EvTriples`] - Container for evidence-specific triples
//! * [`EvidenceIdTypeChoice`] - UUID-based evidence identifier
//! * [`CoevCoswidTripleRecord`] - Links environments to CoSWID evidence
//! * [`CoevCoswidEvidenceMap`] - CoSWID evidence data (tagId, evidence, authorized-by)
//!
//! # Example
//!
//! ```rust
//! use corim_rs::coev::{
//!     ConciseEvidence, EvTriples, EvTriplesBuilder, ConciseEvidenceBuilder,
//!     EvidenceIdTypeChoice,
//! };
//! use corim_rs::triples::{
//!     ReferenceTripleRecord, EnvironmentMap, MeasurementMap,
//! };
//!
//! // Create evidence triples
//! let triples = EvTriplesBuilder::new()
//!     .evidence_triples(vec![ReferenceTripleRecord {
//!         ref_env: EnvironmentMap {
//!             class: None,
//!             instance: None,
//!             group: None,
//!         },
//!         ref_claims: vec![MeasurementMap {
//!             mkey: None,
//!             mval: Default::default(),
//!             authorized_by: None,
//!         }].into(),
//!     }])
//!     .build()
//!     .unwrap();
//!
//! // Create concise evidence
//! let ev = ConciseEvidenceBuilder::new()
//!     .ev_triples(triples)
//!     .build()
//!     .unwrap();
//! ```
//!
//! # CBOR Tag
//!
//! This implementation uses CBOR tag 571 for tagged ConciseEvidence.
//!
//! # Architecture
//!
//! CoEV reuses several types from the CoMID/triples modules:
//! - `ReferenceTripleRecord` for evidence triples (environment → measurements)
//! - `IdentityTripleRecord` for identity triples (environment → keys)
//! - `AttestKeyTripleRecord` for attestation key triples
//! - Introduces `CoevCoswidTripleRecord` for CoSWID evidence triples

use std::marker::PhantomData;

use derive_more::{Constructor, From};
use serde::{
    de::{self, SeqAccess, Visitor},
    ser::{SerializeMap, SerializeSeq},
    Deserialize, Deserializer, Serialize, Serializer,
};

use crate::{
    coswid::EvidenceEntry,
    generate_tagged,
    triples::{CryptoKeyTypeChoice, EnvironmentMap},
    AttestKeyTripleRecord, CoevError, ConciseSwidTagId, DomainDependencyTripleRecord,
    DomainMembershipTripleRecord, ExtensionMap, IdentityTripleRecord, OidType, ProfileTypeChoice,
    ReferenceTripleRecord, Result, UuidType,
};

generate_tagged!((
    571,
    TaggedConciseEvidence,
    ConciseEvidence<'a>,
    'a,
    "coev",
    "A Concise Evidence (CoEV) structure tagged with CBOR tag 571"
));

/// The main Concise Evidence structure.
///
/// Contains evidence triples describing attester state, an optional evidence identifier,
/// and an optional profile.
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct ConciseEvidence<'a> {
    /// Evidence triples (required) — the core evidence data
    pub ev_triples: EvTriples<'a>,
    /// Optional evidence identifier (UUID)
    pub evidence_id: Option<EvidenceIdTypeChoice<'a>>,
    /// Optional profile (URI or OID)
    pub profile: Option<ProfileTypeChoice<'a>>,
    /// Optional extensible attributes
    pub extensions: Option<ExtensionMap<'a>>,
}

impl Default for ConciseEvidence<'_> {
    fn default() -> Self {
        Self {
            ev_triples: EvTriples::default(),
            evidence_id: None,
            profile: None,
            extensions: None,
        }
    }
}

impl Serialize for ConciseEvidence<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut len = 1; // ev_triples is always present
        if self.evidence_id.is_some() {
            len += 1;
        }
        if self.profile.is_some() {
            len += 1;
        }
        if let Some(ext) = &self.extensions {
            len += ext.len();
        }
        let mut map = serializer.serialize_map(Some(len))?;

        if is_human_readable {
            map.serialize_entry("ev-triples", &self.ev_triples)?;
            if let Some(evidence_id) = &self.evidence_id {
                map.serialize_entry("evidence-id", evidence_id)?;
            }
            if let Some(profile) = &self.profile {
                map.serialize_entry("profile", profile)?;
            }
        } else {
            map.serialize_entry(&0, &self.ev_triples)?;
            if let Some(evidence_id) = &self.evidence_id {
                map.serialize_entry(&1, evidence_id)?;
            }
            if let Some(profile) = &self.profile {
                map.serialize_entry(&2, profile)?;
            }
        }

        if let Some(ext) = &self.extensions {
            ext.serialize_map(&mut map, is_human_readable)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for ConciseEvidence<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ConciseEvidenceVisitor<'a> {
            pub is_human_readable: bool,
            data: PhantomData<&'a ()>,
        }

        impl<'de, 'a> Visitor<'de> for ConciseEvidenceVisitor<'a> {
            type Value = ConciseEvidence<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map containing ConciseEvidence fields")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut builder = ConciseEvidenceBuilder::new();

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("ev-triples") => {
                                builder = builder.ev_triples(map.next_value::<EvTriples>()?);
                            }
                            Some("evidence-id") => {
                                builder =
                                    builder.evidence_id(map.next_value::<EvidenceIdTypeChoice>()?);
                            }
                            Some("profile") => {
                                builder = builder.profile(map.next_value::<ProfileTypeChoice>()?);
                            }
                            Some(name) => {
                                return Err(de::Error::custom(format!(
                                    "unexpected field name \"{name}\""
                                )))
                            }
                            None => break,
                        }
                    } else {
                        match map.next_key::<i64>()? {
                            Some(0) => {
                                builder = builder.ev_triples(map.next_value::<EvTriples>()?);
                            }
                            Some(1) => {
                                builder =
                                    builder.evidence_id(map.next_value::<EvidenceIdTypeChoice>()?);
                            }
                            Some(2) => {
                                builder = builder.profile(map.next_value::<ProfileTypeChoice>()?);
                            }
                            Some(key) => {
                                return Err(de::Error::custom(format!(
                                    "unexpected field key \"{key}\""
                                )))
                            }
                            None => break,
                        }
                    }
                }

                builder.build().map_err(de::Error::custom)
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(ConciseEvidenceVisitor {
            is_human_readable: is_hr,
            data: PhantomData,
        })
    }
}

/// Builder for constructing [`ConciseEvidence`] instances.
#[derive(Default)]
pub struct ConciseEvidenceBuilder<'a> {
    ev_triples: Option<EvTriples<'a>>,
    evidence_id: Option<EvidenceIdTypeChoice<'a>>,
    profile: Option<ProfileTypeChoice<'a>>,
    extensions: Option<ExtensionMap<'a>>,
}

impl<'a> ConciseEvidenceBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ev_triples(mut self, ev_triples: EvTriples<'a>) -> Self {
        self.ev_triples = Some(ev_triples);
        self
    }

    pub fn evidence_id(mut self, evidence_id: EvidenceIdTypeChoice<'a>) -> Self {
        self.evidence_id = Some(evidence_id);
        self
    }

    pub fn profile(mut self, profile: ProfileTypeChoice<'a>) -> Self {
        self.profile = Some(profile);
        self
    }

    pub fn extensions(mut self, extensions: ExtensionMap<'a>) -> Self {
        self.extensions = Some(extensions);
        self
    }

    pub fn build(self) -> Result<ConciseEvidence<'a>> {
        let ev_triples = self.ev_triples.ok_or(CoevError::unset_mandatory_field(
            "ConciseEvidence",
            "ev-triples",
        ))?;
        Ok(ConciseEvidence {
            ev_triples,
            evidence_id: self.evidence_id,
            profile: self.profile,
            extensions: self.extensions,
        })
    }
}

// ---------------------------------------------------------------------------
// EvidenceIdTypeChoice — currently only supports UUID (matching Go impl)
// ---------------------------------------------------------------------------

/// Evidence identifier, currently supporting UUID values.
///
/// Mirrors the Go `EvidenceID` type which uses `comid.TaggedUUID`.
#[repr(C)]
#[derive(Debug, From, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum EvidenceIdTypeChoice<'a> {
    /// UUID-based evidence identifier
    Uuid(UuidType),
    /// OID-based evidence identifier (tagged-oid-type, CBOR tag 111)
    Oid(OidType),
    /// Extension value
    Extension(crate::ExtensionValue<'a>),
}

impl Serialize for EvidenceIdTypeChoice<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Uuid(uuid) => uuid.serialize(serializer),
            Self::Oid(oid) => oid.serialize(serializer),
            Self::Extension(ext) => ext.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for EvidenceIdTypeChoice<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            // JSON: expect { "type": "uuid"|"oid", "value": "..." }
            let value = serde_json::Value::deserialize(deserializer)?;
            match &value {
                serde_json::Value::Object(map)
                    if map.contains_key("type") && map.contains_key("value") =>
                {
                    match map.get("type").and_then(|v| v.as_str()) {
                        Some("uuid") => {
                            let uuid_val =
                                serde_json::to_string(&map["value"]).map_err(de::Error::custom)?;
                            let uuid: UuidType =
                                serde_json::from_str(&uuid_val).map_err(de::Error::custom)?;
                            Ok(Self::Uuid(uuid))
                        }
                        Some("oid") => {
                            let oid_val =
                                serde_json::to_string(&map["value"]).map_err(de::Error::custom)?;
                            let oid: OidType =
                                serde_json::from_str(&oid_val).map_err(de::Error::custom)?;
                            Ok(Self::Oid(oid))
                        }
                        _ => Ok(Self::Extension(
                            crate::ExtensionValue::try_from(value).map_err(de::Error::custom)?,
                        )),
                    }
                }
                _ => Ok(Self::Extension(
                    crate::ExtensionValue::try_from(value).map_err(de::Error::custom)?,
                )),
            }
        } else {
            // CBOR: tagged UUID (tag 37) or tagged OID (tag 111)
            let value = ciborium::Value::deserialize(deserializer)?;
            match &value {
                ciborium::Value::Tag(37, _) => {
                    let mut buf: Vec<u8> = Vec::new();
                    ciborium::into_writer(&value, &mut buf).map_err(de::Error::custom)?;
                    let uuid: UuidType =
                        ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                    Ok(Self::Uuid(uuid))
                }
                ciborium::Value::Tag(111, _) => {
                    let mut buf: Vec<u8> = Vec::new();
                    ciborium::into_writer(&value, &mut buf).map_err(de::Error::custom)?;
                    let oid: OidType =
                        ciborium::from_reader(buf.as_slice()).map_err(de::Error::custom)?;
                    Ok(Self::Oid(oid))
                }
                _ => Ok(Self::Extension(
                    crate::ExtensionValue::try_from(value).map_err(de::Error::custom)?,
                )),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// EvTriples — the evidence triples container
// ---------------------------------------------------------------------------

/// Container for evidence-specific triples.
///
/// Maps to the Go `EvTriples` struct. At least one of the triple fields must be populated.
/// Reuses existing triple record types from the CoMID triples module.
#[derive(Default, Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct EvTriples<'a> {
    /// Evidence triples (environment → measurement claims), CBOR key 0
    pub evidence_triples: Option<Vec<ReferenceTripleRecord<'a>>>,
    /// Identity triples (environment → cryptographic keys), CBOR key 1
    pub identity_triples: Option<Vec<IdentityTripleRecord<'a>>>,
    /// Dependency triples (domain → dependent domains), CBOR key 2
    pub dependency_triples: Option<Vec<DomainDependencyTripleRecord<'a>>>,
    /// Membership triples (domain → member environments), CBOR key 3
    pub membership_triples: Option<Vec<DomainMembershipTripleRecord<'a>>>,
    /// CoSWID evidence triples, CBOR key 4
    pub coswid_triples: Option<Vec<CoevCoswidTripleRecord<'a>>>,
    /// Attestation key triples, CBOR key 5
    pub attest_key_triples: Option<Vec<AttestKeyTripleRecord<'a>>>,
    /// Optional extensible attributes
    pub extensions: Option<ExtensionMap<'a>>,
}

impl EvTriples<'_> {
    pub fn is_empty(&self) -> bool {
        self.evidence_triples.is_none()
            && self.identity_triples.is_none()
            && self.dependency_triples.is_none()
            && self.membership_triples.is_none()
            && self.coswid_triples.is_none()
            && self.attest_key_triples.is_none()
    }
}

impl Serialize for EvTriples<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut len = 0;
        if self.evidence_triples.is_some() {
            len += 1;
        }
        if self.identity_triples.is_some() {
            len += 1;
        }
        if self.dependency_triples.is_some() {
            len += 1;
        }
        if self.membership_triples.is_some() {
            len += 1;
        }
        if self.coswid_triples.is_some() {
            len += 1;
        }
        if self.attest_key_triples.is_some() {
            len += 1;
        }
        if let Some(ext) = &self.extensions {
            len += ext.len();
        }
        let mut map = serializer.serialize_map(Some(len))?;

        if is_human_readable {
            if let Some(evidence_triples) = &self.evidence_triples {
                map.serialize_entry("evidence-triples", evidence_triples)?;
            }
            if let Some(identity_triples) = &self.identity_triples {
                map.serialize_entry("identity-triples", identity_triples)?;
            }
            if let Some(dependency_triples) = &self.dependency_triples {
                map.serialize_entry("dependency-triples", dependency_triples)?;
            }
            if let Some(membership_triples) = &self.membership_triples {
                map.serialize_entry("membership-triples", membership_triples)?;
            }
            if let Some(coswid_triples) = &self.coswid_triples {
                map.serialize_entry("coswid-triples", coswid_triples)?;
            }
            if let Some(attest_key_triples) = &self.attest_key_triples {
                map.serialize_entry("attestkey-triples", attest_key_triples)?;
            }
        } else {
            if let Some(evidence_triples) = &self.evidence_triples {
                map.serialize_entry(&0, evidence_triples)?;
            }
            if let Some(identity_triples) = &self.identity_triples {
                map.serialize_entry(&1, identity_triples)?;
            }
            if let Some(dependency_triples) = &self.dependency_triples {
                map.serialize_entry(&2, dependency_triples)?;
            }
            if let Some(membership_triples) = &self.membership_triples {
                map.serialize_entry(&3, membership_triples)?;
            }
            if let Some(coswid_triples) = &self.coswid_triples {
                map.serialize_entry(&4, coswid_triples)?;
            }
            if let Some(attest_key_triples) = &self.attest_key_triples {
                map.serialize_entry(&5, attest_key_triples)?;
            }
        }

        if let Some(ext) = &self.extensions {
            ext.serialize_map(&mut map, is_human_readable)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for EvTriples<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct EvTriplesVisitor<'a> {
            pub is_human_readable: bool,
            data: PhantomData<&'a ()>,
        }

        impl<'de, 'a> Visitor<'de> for EvTriplesVisitor<'a> {
            type Value = EvTriples<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map containing EvTriples fields")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut builder = EvTriplesBuilder::new();

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("evidence-triples") => {
                                builder = builder.evidence_triples(
                                    map.next_value::<Vec<ReferenceTripleRecord>>()?,
                                );
                            }
                            Some("identity-triples") => {
                                builder = builder.identity_triples(
                                    map.next_value::<Vec<IdentityTripleRecord>>()?,
                                );
                            }
                            Some("dependency-triples") => {
                                builder = builder.dependency_triples(
                                    map.next_value::<Vec<DomainDependencyTripleRecord>>()?,
                                );
                            }
                            Some("membership-triples") => {
                                builder = builder.membership_triples(
                                    map.next_value::<Vec<DomainMembershipTripleRecord>>()?,
                                );
                            }
                            Some("coswid-triples") => {
                                builder = builder.coswid_triples(
                                    map.next_value::<Vec<CoevCoswidTripleRecord>>()?,
                                );
                            }
                            Some("attestkey-triples") => {
                                builder = builder.attest_key_triples(
                                    map.next_value::<Vec<AttestKeyTripleRecord>>()?,
                                );
                            }
                            Some(name) => {
                                return Err(de::Error::custom(format!(
                                    "unexpected field name \"{name}\""
                                )))
                            }
                            None => break,
                        }
                    } else {
                        match map.next_key::<i64>()? {
                            Some(0) => {
                                builder = builder.evidence_triples(
                                    map.next_value::<Vec<ReferenceTripleRecord>>()?,
                                );
                            }
                            Some(1) => {
                                builder = builder.identity_triples(
                                    map.next_value::<Vec<IdentityTripleRecord>>()?,
                                );
                            }
                            Some(2) => {
                                builder = builder.dependency_triples(
                                    map.next_value::<Vec<DomainDependencyTripleRecord>>()?,
                                );
                            }
                            Some(3) => {
                                builder = builder.membership_triples(
                                    map.next_value::<Vec<DomainMembershipTripleRecord>>()?,
                                );
                            }
                            Some(4) => {
                                builder = builder.coswid_triples(
                                    map.next_value::<Vec<CoevCoswidTripleRecord>>()?,
                                );
                            }
                            Some(5) => {
                                builder = builder.attest_key_triples(
                                    map.next_value::<Vec<AttestKeyTripleRecord>>()?,
                                );
                            }
                            Some(key) => {
                                return Err(de::Error::custom(format!(
                                    "unexpected field key \"{key}\""
                                )))
                            }
                            None => break,
                        }
                    }
                }

                builder.build().map_err(de::Error::custom)
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(EvTriplesVisitor {
            is_human_readable: is_hr,
            data: PhantomData,
        })
    }
}

/// Builder for constructing [`EvTriples`] instances.
#[derive(Default)]
pub struct EvTriplesBuilder<'a> {
    evidence_triples: Option<Vec<ReferenceTripleRecord<'a>>>,
    identity_triples: Option<Vec<IdentityTripleRecord<'a>>>,
    dependency_triples: Option<Vec<DomainDependencyTripleRecord<'a>>>,
    membership_triples: Option<Vec<DomainMembershipTripleRecord<'a>>>,
    coswid_triples: Option<Vec<CoevCoswidTripleRecord<'a>>>,
    attest_key_triples: Option<Vec<AttestKeyTripleRecord<'a>>>,
    extensions: Option<ExtensionMap<'a>>,
}

impl<'a> EvTriplesBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn evidence_triples(mut self, triples: Vec<ReferenceTripleRecord<'a>>) -> Self {
        self.evidence_triples = Some(triples);
        self
    }

    pub fn add_evidence_triple(mut self, triple: ReferenceTripleRecord<'a>) -> Self {
        self.evidence_triples
            .get_or_insert_with(Vec::new)
            .push(triple);
        self
    }

    pub fn identity_triples(mut self, triples: Vec<IdentityTripleRecord<'a>>) -> Self {
        self.identity_triples = Some(triples);
        self
    }

    pub fn add_identity_triple(mut self, triple: IdentityTripleRecord<'a>) -> Self {
        self.identity_triples
            .get_or_insert_with(Vec::new)
            .push(triple);
        self
    }

    pub fn dependency_triples(mut self, triples: Vec<DomainDependencyTripleRecord<'a>>) -> Self {
        self.dependency_triples = Some(triples);
        self
    }

    pub fn add_dependency_triple(mut self, triple: DomainDependencyTripleRecord<'a>) -> Self {
        self.dependency_triples
            .get_or_insert_with(Vec::new)
            .push(triple);
        self
    }

    pub fn membership_triples(mut self, triples: Vec<DomainMembershipTripleRecord<'a>>) -> Self {
        self.membership_triples = Some(triples);
        self
    }

    pub fn add_membership_triple(mut self, triple: DomainMembershipTripleRecord<'a>) -> Self {
        self.membership_triples
            .get_or_insert_with(Vec::new)
            .push(triple);
        self
    }

    pub fn coswid_triples(mut self, triples: Vec<CoevCoswidTripleRecord<'a>>) -> Self {
        self.coswid_triples = Some(triples);
        self
    }

    pub fn add_coswid_triple(mut self, triple: CoevCoswidTripleRecord<'a>) -> Self {
        self.coswid_triples
            .get_or_insert_with(Vec::new)
            .push(triple);
        self
    }

    pub fn attest_key_triples(mut self, triples: Vec<AttestKeyTripleRecord<'a>>) -> Self {
        self.attest_key_triples = Some(triples);
        self
    }

    pub fn add_attest_key_triple(mut self, triple: AttestKeyTripleRecord<'a>) -> Self {
        self.attest_key_triples
            .get_or_insert_with(Vec::new)
            .push(triple);
        self
    }

    pub fn extensions(mut self, extensions: ExtensionMap<'a>) -> Self {
        self.extensions = Some(extensions);
        self
    }

    pub fn build(self) -> Result<EvTriples<'a>> {
        if self.evidence_triples.is_none()
            && self.identity_triples.is_none()
            && self.dependency_triples.is_none()
            && self.membership_triples.is_none()
            && self.coswid_triples.is_none()
            && self.attest_key_triples.is_none()
        {
            return Err(CoevError::EmptyEvTriples)?;
        }
        Ok(EvTriples {
            evidence_triples: self.evidence_triples,
            identity_triples: self.identity_triples,
            dependency_triples: self.dependency_triples,
            membership_triples: self.membership_triples,
            coswid_triples: self.coswid_triples,
            attest_key_triples: self.attest_key_triples,
            extensions: self.extensions,
        })
    }
}

// ---------------------------------------------------------------------------
// CoevCoswidTripleRecord — CoSWID evidence triple for CoEV
// ---------------------------------------------------------------------------

/// Record linking an environment to CoSWID evidence entries.
///
/// Each record associates an `EnvironmentMap` with one or more `CoevCoswidEvidenceMap`
/// entries describing observed software evidence.
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct CoevCoswidTripleRecord<'a> {
    /// The environment the evidence pertains to
    pub environment: EnvironmentMap<'a>,
    /// One or more CoSWID evidence entries
    pub coswid_evidence: Vec<CoevCoswidEvidenceMap<'a>>,
}

impl Serialize for CoevCoswidTripleRecord<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.environment)?;
        seq.serialize_element(&self.coswid_evidence)?;
        seq.end()
    }
}

impl<'de, 'a> Deserialize<'de> for CoevCoswidTripleRecord<'a> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<CoevCoswidTripleRecord<'a>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CoevCoswidTripleRecordVisitor<'a> {
            marker: PhantomData<&'a str>,
        }

        impl<'de, 'a> Visitor<'de> for CoevCoswidTripleRecordVisitor<'a> {
            type Value = CoevCoswidTripleRecord<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a sequence of [EnvironmentMap, Vec<CoevCoswidEvidenceMap>]")
            }

            fn visit_seq<A>(
                self,
                mut seq: A,
            ) -> std::result::Result<CoevCoswidTripleRecord<'a>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let environment = seq
                    .next_element::<EnvironmentMap>()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let coswid_evidence = seq
                    .next_element::<Vec<CoevCoswidEvidenceMap>>()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                Ok(CoevCoswidTripleRecord::new(environment, coswid_evidence))
            }
        }

        deserializer.deserialize_seq(CoevCoswidTripleRecordVisitor {
            marker: PhantomData,
        })
    }
}

// ---------------------------------------------------------------------------
// CoevCoswidEvidenceMap — individual CoSWID evidence entry for CoEV
// ---------------------------------------------------------------------------

/// A CoSWID evidence map entry containing tag identification and evidence data.
///
/// Maps to the Go `CoSWIDEvidenceMap` struct with fields:
/// - `tag_id` (CBOR key 0): optional CoSWID tag identifier
/// - `evidence` (CBOR key 1): the evidence entry
/// - `authorized_by` (CBOR key 2): optional list of authorizing cryptographic keys
#[derive(Debug, From, Constructor, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[repr(C)]
pub struct CoevCoswidEvidenceMap<'a> {
    /// Optional CoSWID tag identifier
    pub tag_id: Option<ConciseSwidTagId<'a>>,
    /// Evidence entry describing the observed state
    pub evidence: EvidenceEntry<'a>,
    /// Optional cryptographic keys authorizing this evidence
    pub authorized_by: Option<Vec<CryptoKeyTypeChoice<'a>>>,
}

impl Serialize for CoevCoswidEvidenceMap<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut len = 1; // evidence is always present
        if self.tag_id.is_some() {
            len += 1;
        }
        if self.authorized_by.is_some() {
            len += 1;
        }
        let mut map = serializer.serialize_map(Some(len))?;

        if is_human_readable {
            if let Some(tag_id) = &self.tag_id {
                map.serialize_entry("tagId", tag_id)?;
            }
            map.serialize_entry("evidence", &self.evidence)?;
            if let Some(authorized_by) = &self.authorized_by {
                map.serialize_entry("authorized-by", authorized_by)?;
            }
        } else {
            if let Some(tag_id) = &self.tag_id {
                map.serialize_entry(&0, tag_id)?;
            }
            map.serialize_entry(&1, &self.evidence)?;
            if let Some(authorized_by) = &self.authorized_by {
                map.serialize_entry(&2, authorized_by)?;
            }
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for CoevCoswidEvidenceMap<'_> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CoevCoswidEvidenceMapVisitor<'a> {
            pub is_human_readable: bool,
            data: PhantomData<&'a ()>,
        }

        impl<'de, 'a> Visitor<'de> for CoevCoswidEvidenceMapVisitor<'a> {
            type Value = CoevCoswidEvidenceMap<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a map containing CoevCoswidEvidenceMap fields")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut tag_id: Option<ConciseSwidTagId> = None;
                let mut evidence: Option<EvidenceEntry> = None;
                let mut authorized_by: Option<Vec<CryptoKeyTypeChoice>> = None;

                loop {
                    if self.is_human_readable {
                        match map.next_key::<&str>()? {
                            Some("tagId") => {
                                tag_id = Some(map.next_value()?);
                            }
                            Some("evidence") => {
                                evidence = Some(map.next_value()?);
                            }
                            Some("authorized-by") => {
                                authorized_by = Some(map.next_value()?);
                            }
                            Some(name) => {
                                return Err(de::Error::custom(format!(
                                    "unexpected field name \"{name}\""
                                )))
                            }
                            None => break,
                        }
                    } else {
                        match map.next_key::<i64>()? {
                            Some(0) => {
                                tag_id = Some(map.next_value()?);
                            }
                            Some(1) => {
                                evidence = Some(map.next_value()?);
                            }
                            Some(2) => {
                                authorized_by = Some(map.next_value()?);
                            }
                            Some(key) => {
                                return Err(de::Error::custom(format!(
                                    "unexpected field key \"{key}\""
                                )))
                            }
                            None => break,
                        }
                    }
                }

                let evidence = evidence
                    .ok_or_else(|| de::Error::custom("missing required field 'evidence'"))?;

                Ok(CoevCoswidEvidenceMap {
                    tag_id,
                    evidence,
                    authorized_by,
                })
            }
        }

        let is_hr = deserializer.is_human_readable();
        deserializer.deserialize_map(CoevCoswidEvidenceMapVisitor {
            is_human_readable: is_hr,
            data: PhantomData,
        })
    }
}

// ---------------------------------------------------------------------------
// TaggedConciseEvidence helpers
// ---------------------------------------------------------------------------

impl TaggedConciseEvidence<'_> {
    pub fn from_cbor<R: std::io::Read>(src: R) -> std::result::Result<Self, CoevError> {
        ciborium::from_reader(src).map_err(CoevError::custom)
    }

    pub fn to_cbor(&self) -> std::result::Result<Vec<u8>, CoevError> {
        let mut buf: Vec<u8> = vec![];
        ciborium::into_writer(&self, &mut buf).map_err(CoevError::custom)?;
        Ok(buf)
    }

    pub fn from_json<R: std::io::Read>(mut src: R) -> std::result::Result<Self, CoevError> {
        let mut buf = String::new();
        src.read_to_string(&mut buf).map_err(CoevError::custom)?;
        serde_json::from_str(&buf).map_err(CoevError::custom)
    }

    pub fn to_json(&self) -> std::result::Result<String, CoevError> {
        serde_json::to_string(&self).map_err(CoevError::custom)
    }

    pub fn to_json_pretty(&self) -> std::result::Result<String, CoevError> {
        serde_json::to_string_pretty(&self).map_err(CoevError::custom)
    }
}
