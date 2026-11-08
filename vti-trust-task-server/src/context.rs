//! Who sent a document, and how it arrived.

/// The transport a document arrived over.
///
/// Deliberately exhaustive: the spine's sender binding (VTI-OPS-021/093)
/// treats the messaging transports differently from HTTPS, and a new transport
/// must be placed on one side of that line by every match, not defaulted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// HTTPS (`POST /v1/trust-tasks`): the holder is proven by the document's
    /// own proof.
    Rest,
    /// DIDComm: the authcrypt sender is a claim until the proof binds it.
    DIDComm,
    /// Trust Spanning Protocol: as DIDComm.
    Tsp,
}

impl Transport {
    /// `rest`, `didcomm` or `tsp`, as audit records name it.
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Rest => "rest",
            Transport::DIDComm => "didcomm",
            Transport::Tsp => "tsp",
        }
    }

    /// Whether the transport reports a sender the spine must bind to the
    /// document's proof (DIDComm and TSP).
    pub fn reports_sender(self) -> bool {
        matches!(self, Transport::DIDComm | Transport::Tsp)
    }
}

/// The transport-resolved caller identity threaded into the dispatcher.
///
/// `sender_did` is the transport-reported sender (DIDComm, TSP): a claim the
/// spine accepts only once the document's own proof binds it. It is `None`
/// over HTTPS, where the holder is recovered from the document proof instead.
#[derive(Debug, Clone)]
pub struct ArrivalCtx {
    /// The transport the document arrived over.
    pub transport: Transport,
    /// The transport-reported sender, if the transport reports one.
    pub sender_did: Option<String>,
    /// The DID that signed this document's Data-Integrity proof, verified by
    /// the spine against the document **as received**.
    ///
    /// `None` when the document carried no proof, or when the context was built
    /// by a transport rather than by the spine.
    ///
    /// # Why the spine and not the handler
    ///
    /// A proof covers the document as it was sent. A handler holding a typed
    /// payload can only re-derive those bytes if its payload type round-trips
    /// losslessly, and none promises to: a member the type does not know is
    /// dropped, the canonicalisation differs, and a valid proof fails.
    /// Verifying once, here, against the bytes that arrived, is what makes
    /// typed handlers possible at all.
    pub verified_signer: Option<String>,
}

impl ArrivalCtx {
    /// The DIDComm context. The sender is only a claim until the spine binds
    /// it to the document proof.
    pub fn didcomm(sender_did: String) -> Self {
        Self {
            transport: Transport::DIDComm,
            sender_did: Some(sender_did),
            verified_signer: None,
        }
    }

    /// The HTTPS context: the holder is proven by the document proof.
    pub fn rest() -> Self {
        Self {
            transport: Transport::Rest,
            sender_did: None,
            verified_signer: None,
        }
    }

    /// The same context with `verified_signer` filled in.
    pub fn with_verified_signer(&self, signer: Option<String>) -> Self {
        Self {
            transport: self.transport,
            sender_did: self.sender_did.clone(),
            verified_signer: signer,
        }
    }
}
