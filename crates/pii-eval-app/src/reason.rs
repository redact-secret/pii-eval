//! Stable reason codes and the result of handling one delivery.
//!
//! A [`Reason`] is a fixed enum: it carries no payload text, no header value
//! and no secret, so formatting or logging one cannot leak. The metadata that
//! accompanies an outcome ([`Meta`]) holds only validated delivery ids,
//! numeric ids from an authenticated payload and a job id.

use crate::request::JobId;

/// Why a delivery was rejected or ignored. Codes are stable; a retired code
/// stays reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    // Transport and authenticity (nothing from the payload is trusted yet).
    PayloadTooLarge,
    SignatureMissing,
    SignatureMalformed,
    SignatureMismatch,
    DeliveryIdInvalid,
    EventInvalid,
    // Replay.
    DuplicateDelivery,
    // Parsing.
    PayloadMalformed,
    CommandMalformed,
    // Not for us (authenticated, harmless).
    EventNotApproved,
    ActionNotApproved,
    NotACommand,
    NotAPullRequest,
    // Authorization.
    InstallationNotAllowlisted,
    InstallationRepositoryMismatch,
    RepositoryNotAllowlisted,
    RepositoryNameMismatch,
    ActorNotAuthorized,
    ProfileNotAllowed,
    ForkHeadNotAllowed,
    // Freshness and replay of a request.
    CommentTooOld,
    DuplicateComment,
    RetryCooldown,
    StaleHead,
    HeadUnresolvable,
    // Capacity.
    QueueFull,
    JobStoreFull,
    RetryLimit,
    ShuttingDown,
}

impl Reason {
    /// The stable code.
    pub const fn code(self) -> &'static str {
        match self {
            Reason::PayloadTooLarge => "payload-too-large",
            Reason::SignatureMissing => "signature-missing",
            Reason::SignatureMalformed => "signature-malformed",
            Reason::SignatureMismatch => "signature-mismatch",
            Reason::DeliveryIdInvalid => "delivery-id-invalid",
            Reason::EventInvalid => "event-invalid",
            Reason::DuplicateDelivery => "duplicate-delivery",
            Reason::PayloadMalformed => "payload-malformed",
            Reason::CommandMalformed => "command-malformed",
            Reason::EventNotApproved => "event-not-approved",
            Reason::ActionNotApproved => "action-not-approved",
            Reason::NotACommand => "not-a-command",
            Reason::NotAPullRequest => "not-a-pull-request",
            Reason::InstallationNotAllowlisted => "installation-not-allowlisted",
            Reason::InstallationRepositoryMismatch => "installation-repository-mismatch",
            Reason::RepositoryNotAllowlisted => "repository-not-allowlisted",
            Reason::RepositoryNameMismatch => "repository-name-mismatch",
            Reason::ActorNotAuthorized => "actor-not-authorized",
            Reason::ProfileNotAllowed => "profile-not-allowed",
            Reason::ForkHeadNotAllowed => "fork-head-not-allowed",
            Reason::CommentTooOld => "comment-too-old",
            Reason::DuplicateComment => "duplicate-comment",
            Reason::RetryCooldown => "retry-cooldown",
            Reason::StaleHead => "stale-head",
            Reason::HeadUnresolvable => "head-unresolvable",
            Reason::QueueFull => "queue-full",
            Reason::JobStoreFull => "job-store-full",
            Reason::RetryLimit => "retry-limit",
            Reason::ShuttingDown => "shutting-down",
        }
    }

    /// The HTTP status a transport should answer with.
    pub const fn http_status(self) -> u16 {
        match self {
            Reason::PayloadTooLarge => 413,
            Reason::SignatureMissing | Reason::SignatureMalformed | Reason::SignatureMismatch => {
                401
            }
            Reason::DeliveryIdInvalid
            | Reason::EventInvalid
            | Reason::PayloadMalformed
            | Reason::CommandMalformed => 400,
            Reason::DuplicateDelivery
            | Reason::DuplicateComment
            | Reason::CommentTooOld
            | Reason::StaleHead => 409,
            Reason::EventNotApproved
            | Reason::ActionNotApproved
            | Reason::NotACommand
            | Reason::NotAPullRequest => 200,
            Reason::InstallationNotAllowlisted
            | Reason::InstallationRepositoryMismatch
            | Reason::RepositoryNotAllowlisted
            | Reason::RepositoryNameMismatch
            | Reason::ActorNotAuthorized
            | Reason::ProfileNotAllowed
            | Reason::ForkHeadNotAllowed => 403,
            Reason::RetryLimit | Reason::RetryCooldown => 429,
            Reason::HeadUnresolvable
            | Reason::QueueFull
            | Reason::JobStoreFull
            | Reason::ShuttingDown => 503,
        }
    }

    /// Whether the same delivery may succeed when GitHub redelivers it. A
    /// transient rejection does not consume the delivery id.
    pub const fn is_transient(self) -> bool {
        matches!(
            self,
            Reason::HeadUnresolvable
                | Reason::QueueFull
                | Reason::JobStoreFull
                | Reason::ShuttingDown
        )
    }
}

/// What was done with a job request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// A new job was queued.
    Queued,
    /// An earlier failed or stale job with the same identity was queued again.
    Requeued,
    /// The same identity is already queued or running; nothing was added.
    Coalesced,
    /// The same identity already completed; its published result stands.
    AlreadyComplete,
    /// The same identity was already handed to the custodian.
    AlreadyRouted,
}

/// The decision for one delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A job exists for the request.
    Accepted {
        /// Deterministic job id.
        job_id: JobId,
        /// What happened.
        disposition: Disposition,
    },
    /// Authentic and understood, but not a request for this service.
    Ignored(Reason),
    /// Refused.
    Rejected(Reason),
}

impl Outcome {
    /// The HTTP status for the transport.
    pub fn http_status(&self) -> u16 {
        match self {
            Outcome::Accepted { .. } => 202,
            Outcome::Ignored(r) | Outcome::Rejected(r) => r.http_status(),
        }
    }

    /// A stable code: the reason, or `accepted`.
    pub fn code(&self) -> &'static str {
        match self {
            Outcome::Accepted { .. } => "accepted",
            Outcome::Ignored(r) | Outcome::Rejected(r) => r.code(),
        }
    }
}

/// Bounded, safe metadata for logs and responses. Every field is either
/// validated text (a delivery id of at most 64 characters from `[0-9A-Za-z-]`)
/// or a number taken from a payload whose signature verified. Nothing is
/// copied from the body, and nothing is set before the signature verifies.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Meta {
    /// The `X-GitHub-Delivery` value, once validated.
    pub delivery_id: Option<String>,
    /// Installation id from the authenticated payload.
    pub installation_id: Option<u64>,
    /// Repository id from the authenticated payload.
    pub repository_id: Option<u64>,
    /// The job, when one exists.
    pub job_id: Option<JobId>,
}

/// The outcome of handling one delivery plus its safe metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// What was decided.
    pub outcome: Outcome,
    /// Safe metadata.
    pub meta: Meta,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_unique_kebab_case() {
        let all = [
            Reason::PayloadTooLarge,
            Reason::SignatureMissing,
            Reason::SignatureMalformed,
            Reason::SignatureMismatch,
            Reason::DeliveryIdInvalid,
            Reason::EventInvalid,
            Reason::DuplicateDelivery,
            Reason::PayloadMalformed,
            Reason::CommandMalformed,
            Reason::EventNotApproved,
            Reason::ActionNotApproved,
            Reason::NotACommand,
            Reason::NotAPullRequest,
            Reason::InstallationNotAllowlisted,
            Reason::InstallationRepositoryMismatch,
            Reason::RepositoryNotAllowlisted,
            Reason::RepositoryNameMismatch,
            Reason::ActorNotAuthorized,
            Reason::ProfileNotAllowed,
            Reason::ForkHeadNotAllowed,
            Reason::CommentTooOld,
            Reason::DuplicateComment,
            Reason::RetryCooldown,
            Reason::StaleHead,
            Reason::HeadUnresolvable,
            Reason::QueueFull,
            Reason::JobStoreFull,
            Reason::RetryLimit,
            Reason::ShuttingDown,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for r in all {
            let c = r.code();
            assert!(c.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'));
            assert!(seen.insert(c), "duplicate code {c}");
        }
    }
}
