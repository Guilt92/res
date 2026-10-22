//! DNS message parsing, validation and local error-response construction.
//!
//! Wire format handling is delegated to `hickory-proto`; res owns the
//! validation policy and the gateway-level responses (REFUSED, SERVFAIL, ...).

use std::str::FromStr;

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};

/// Gateway-level response code classification (bounded label set).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rcode {
    NoError,
    FormErr,
    ServFail,
    NXDomain,
    NotImp,
    Refused,
    Other,
}

impl Rcode {
    pub fn as_str(self) -> &'static str {
        match self {
            Rcode::NoError => "NOERROR",
            Rcode::FormErr => "FORMERR",
            Rcode::ServFail => "SERVFAIL",
            Rcode::NXDomain => "NXDOMAIN",
            Rcode::NotImp => "NOTIMP",
            Rcode::Refused => "REFUSED",
            Rcode::Other => "OTHER",
        }
    }

    pub fn from_response_code(rc: ResponseCode) -> Self {
        match rc {
            ResponseCode::NoError => Rcode::NoError,
            ResponseCode::FormErr => Rcode::FormErr,
            ResponseCode::ServFail => Rcode::ServFail,
            ResponseCode::NXDomain => Rcode::NXDomain,
            ResponseCode::NotImp => Rcode::NotImp,
            ResponseCode::Refused => Rcode::Refused,
            _ => Rcode::Other,
        }
    }

    fn to_response_code(self) -> ResponseCode {
        match self {
            Rcode::NoError => ResponseCode::NoError,
            Rcode::FormErr => ResponseCode::FormErr,
            Rcode::ServFail => ResponseCode::ServFail,
            Rcode::NXDomain => ResponseCode::NXDomain,
            Rcode::NotImp => ResponseCode::NotImp,
            Rcode::Refused => ResponseCode::Refused,
            Rcode::Other => ResponseCode::ServFail,
        }
    }
}

/// Why an incoming packet was rejected before reaching the pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryReject {
    TooShort,
    Malformed,
    NotAQuery,
    NoQuestion,
    MultiQuestion,
    UnsupportedOpcode,
}

/// A validated inbound query.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedQuery {
    pub id: u16,
    pub op_code: OpCode,
    pub recursion_desired: bool,
    pub has_edns: bool,
    pub dnssec_ok: bool,
    /// Client's Checking Disabled (CD) bit: part of the cache key.
    pub checking_disabled: bool,
    /// EDNS advertised UDP payload size, when the client sent an OPT record.
    pub edns_payload: Option<u16>,
    /// True when the query carries any EDNS option (ECS, COOKIE, ...).
    /// Such queries bypass the shared cache: their responses may be specific
    /// to the requesting client and must never be served to another one.
    pub has_edns_options: bool,
    pub queries: Vec<Query>,
}

impl ParsedQuery {
    pub fn question(&self) -> &Query {
        &self.queries[0]
    }

    pub fn qtype(&self) -> RecordType {
        self.question().query_type()
    }
}

/// Minimal view of an upstream response used for correlation and metrics.
#[derive(Debug, Clone)]
pub struct ResponseView {
    pub id: u16,
    pub rcode: Rcode,
    pub truncated: bool,
    pub question: Option<(String, u16, u16)>,
}

/// Parse and validate an inbound DNS query.
pub fn parse_query(bytes: &[u8]) -> Result<ParsedQuery, QueryReject> {
    if bytes.len() < 12 {
        return Err(QueryReject::TooShort);
    }
    let mut decoder = BinDecoder::new(bytes);
    let msg = Message::read(&mut decoder).map_err(|_| QueryReject::Malformed)?;
    if !decoder.is_empty() {
        return Err(QueryReject::Malformed);
    }
    if msg.metadata.message_type != MessageType::Query {
        return Err(QueryReject::NotAQuery);
    }
    if msg.metadata.op_code != OpCode::Query {
        // Well-formed but unsupported (UPDATE, NOTIFY, ...): answered with NOTIMP.
        return Err(QueryReject::UnsupportedOpcode);
    }
    match msg.queries.len() {
        0 => return Err(QueryReject::NoQuestion),
        1 => {}
        _ => return Err(QueryReject::MultiQuestion),
    }
    let has_edns = msg.edns.is_some();
    let dnssec_ok = msg
        .edns
        .as_ref()
        .map(|e| e.flags().dnssec_ok)
        .unwrap_or(false);
    let edns_payload = msg.edns.as_ref().map(|e| e.max_payload());
    let has_edns_options = msg
        .edns
        .as_ref()
        .map(|e| !e.options().options.is_empty())
        .unwrap_or(false);
    Ok(ParsedQuery {
        id: msg.metadata.id,
        op_code: msg.metadata.op_code,
        recursion_desired: msg.metadata.recursion_desired,
        has_edns,
        dnssec_ok,
        checking_disabled: msg.metadata.checking_disabled,
        edns_payload,
        has_edns_options,
        queries: msg.queries,
    })
}

/// Build a local gateway response for a rejected/failed query. The question
/// section is echoed, as most resolvers expect. When the client advertised
/// EDNS(0), the response carries an OPT record too (RFC 6891 §6.1.1: a
/// response to an EDNS query without OPT is indistinguishable from a server
/// that does not support EDNS at all).
pub fn error_response(req: &ParsedQuery, rcode: Rcode) -> Vec<u8> {
    let mut msg = Message::error_msg(req.id, req.op_code, rcode.to_response_code());
    msg.metadata.recursion_desired = req.recursion_desired;
    msg.metadata.recursion_available = true;
    msg.queries = req.queries.clone();
    if req.has_edns {
        let mut edns = Edns::new();
        edns.set_max_payload(req.edns_payload.unwrap_or(512).max(512));
        edns.set_dnssec_ok(req.dnssec_ok);
        msg.edns = Some(edns);
    }
    msg.to_vec().unwrap_or_default()
}

/// Minimal TC=1 response echoing the query (question + EDNS), telling the
/// client to retry over TCP. Used both for oversized UDP answers and for
/// response-rate limiting.
pub fn truncated_response(req: &ParsedQuery) -> Vec<u8> {
    let mut stub = error_response(req, Rcode::NoError);
    if stub.len() >= 4 {
        stub[2] |= 0x02; // TC
    }
    stub
}

/// Build a local SERVFAIL for a query whose header could still be read.
pub fn servfail_for_id(id: u16, op_code: OpCode) -> Vec<u8> {
    let msg = Message::error_msg(id, op_code, ResponseCode::ServFail);
    msg.to_vec().unwrap_or_default()
}

/// Inspect and validate an upstream response (id, rcode, truncation, question).
///
/// Security-critical: the whole message is decoded, not just the header. A
/// response must be a QR=1 Query-opcode message with exactly one question;
/// malformed sections, compression loops, trailing garbage and QDCOUNT=0 are
/// rejected instead of being correlated by transaction id alone.
pub fn parse_response(bytes: &[u8]) -> Result<ResponseView, String> {
    if bytes.len() < 12 {
        return Err("short response".into());
    }
    let mut decoder = BinDecoder::new(bytes);
    let msg = Message::read(&mut decoder).map_err(|e| format!("decode error: {e}"))?;
    if !decoder.is_empty() {
        return Err(format!(
            "trailing bytes after DNS message ({} unread)",
            decoder.len()
        ));
    }
    if msg.metadata.message_type != MessageType::Response {
        return Err("message is not a response".into());
    }
    if msg.metadata.op_code != OpCode::Query {
        return Err("response has a non-query opcode".into());
    }
    if msg.queries.len() != 1 {
        return Err(format!(
            "response must contain exactly one question (got {})",
            msg.queries.len()
        ));
    }
    let q = &msg.queries[0];
    Ok(ResponseView {
        id: msg.metadata.id,
        rcode: Rcode::from_response_code(msg.metadata.response_code),
        truncated: msg.metadata.truncation,
        question: Some((
            q.name().to_ascii().to_lowercase(),
            u16::from(q.query_type()),
            u16::from(q.query_class()),
        )),
    })
}

/// Correlate an upstream response with the query we sent.
pub fn correlates(query: &ParsedQuery, resp: &ResponseView) -> bool {
    if resp.id != query.id {
        return false;
    }
    match &resp.question {
        // parse_response requires a question; a view without one can never be
        // correlated (defence in depth for internal callers).
        None => false,
        Some((name, qtype, qclass)) => {
            let q = query.question();
            *name == q.name().to_ascii().to_lowercase()
                && *qtype == u16::from(q.query_type())
                && *qclass == u16::from(q.query_class())
        }
    }
}

/// Build a standard recursive query (used by health checks and tests).
pub fn build_query(name: &str, qtype: &str) -> Result<Vec<u8>, String> {
    let record_type = parse_record_type(qtype)?;
    let qname = if name == "." {
        Name::root()
    } else {
        Name::from_ascii(name).map_err(|e| format!("invalid name '{name}': {e}"))?
    };
    let mut msg = Message::query();
    msg.metadata.recursion_desired = true;
    msg.queries.push(Query::query(qname, record_type));
    msg.to_vec().map_err(|e| format!("encode error: {e}"))
}

/// Parse a textual record type (`A`, `AAAA`, `DNSSEC`-related, ...).
pub fn parse_record_type(s: &str) -> Result<RecordType, String> {
    let trimmed = s.trim();
    // Bounded set of types the gateway and health checks may generate.
    let upper = trimmed.to_ascii_uppercase();
    match upper.as_str() {
        "A" => Ok(RecordType::A),
        "AAAA" => Ok(RecordType::AAAA),
        "CNAME" => Ok(RecordType::CNAME),
        "MX" => Ok(RecordType::MX),
        "TXT" => Ok(RecordType::TXT),
        "NS" => Ok(RecordType::NS),
        "SOA" => Ok(RecordType::SOA),
        "SRV" => Ok(RecordType::SRV),
        "PTR" => Ok(RecordType::PTR),
        "CAA" => Ok(RecordType::CAA),
        "DNSKEY" => Ok(RecordType::DNSKEY),
        "DS" => Ok(RecordType::DS),
        "RRSIG" => Ok(RecordType::RRSIG),
        "NSEC" => Ok(RecordType::NSEC),
        "NSEC3" => Ok(RecordType::NSEC3),
        "NSEC3PARAM" => Ok(RecordType::NSEC3PARAM),
        "TLSA" => Ok(RecordType::TLSA),
        "HTTPS" => Ok(RecordType::HTTPS),
        "SVCB" => Ok(RecordType::SVCB),
        "ANY" => Ok(RecordType::ANY),
        "AXFR" => Ok(RecordType::AXFR),
        "IXFR" => Ok(RecordType::IXFR),
        "NAPTR" => Ok(RecordType::NAPTR),
        "SSHFP" => Ok(RecordType::SSHFP),
        "CDS" => Ok(RecordType::CDS),
        "CDNSKEY" => Ok(RecordType::CDNSKEY),
        other => RecordType::from_str(other).map_err(|_| format!("unsupported record type '{s}'")),
    }
}

/// Parse a textual rcode (`NOERROR`, `NXDOMAIN`, `SERVFAIL`, ...). Case
/// insensitive. Returns `None` for unknown names (including `OTHER`, which
/// is a gateway-internal bucket, not a wire rcode).
pub fn parse_rcode(s: &str) -> Option<Rcode> {
    match s.trim().to_ascii_uppercase().as_str() {
        "NOERROR" => Some(Rcode::NoError),
        "FORMERR" => Some(Rcode::FormErr),
        "SERVFAIL" => Some(Rcode::ServFail),
        "NXDOMAIN" => Some(Rcode::NXDomain),
        "NOTIMP" => Some(Rcode::NotImp),
        "REFUSED" => Some(Rcode::Refused),
        _ => None,
    }
}

/// Question key used by the cache (lowercased name, type, class, RD, CD).
pub fn question_key(
    q: &Query,
    checking_disabled: bool,
    recursion_desired: bool,
) -> crate::cache::CacheKey {
    crate::cache::CacheKey {
        name: q.name().to_ascii().to_lowercase(),
        qtype: u16::from(q.query_type()),
        qclass: u16::from(q.query_class()),
        cd: checking_disabled,
        rd: recursion_desired,
    }
}

/// Bounded metric label for a question type: common types keep their name,
/// everything else collapses into `OTHER` (cardinality stays fixed).
pub fn qtype_label(t: RecordType) -> &'static str {
    match t {
        RecordType::A => "A",
        RecordType::AAAA => "AAAA",
        RecordType::NS => "NS",
        RecordType::CNAME => "CNAME",
        RecordType::SOA => "SOA",
        RecordType::PTR => "PTR",
        RecordType::MX => "MX",
        RecordType::TXT => "TXT",
        RecordType::SRV => "SRV",
        RecordType::CAA => "CAA",
        RecordType::ANY => "ANY",
        _ => "OTHER",
    }
}

/// Compute the effective TTL for caching a positive (NOERROR, non-empty
/// answer) response.
///
/// * TTLs are never *extended*: `min_ttl_secs` acts as a **skip threshold**
///   (responses with a shorter TTL are not cached at all) and
///   `max_ttl_secs` only caps longer TTLs downwards. This keeps the gateway
///   honest about upstream data freshness (RFC 1035/2181).
/// * Truncated, non-NOERROR, or answer-less responses return `None` (use
///   [`negative_ttl`] for NXDOMAIN/NODATA).
pub fn cacheable_ttl(resp_bytes: &[u8], min_ttl: u64, max_ttl: u64) -> Option<u64> {
    let msg = Message::from_vec(resp_bytes).ok()?;
    if msg.metadata.truncation {
        return None;
    }
    if msg.metadata.response_code != ResponseCode::NoError {
        return None;
    }
    if msg.queries.len() != 1 {
        return None;
    }
    if msg.answers.is_empty() {
        return None;
    }
    // A NOERROR response whose answer section contains only CNAMEs is
    // *positive* only when a CNAME was actually requested. For every other
    // qtype the CNAME(s) are an alias chain and any SOA in the authority
    // section marks NODATA: negative caching must use the shorter SOA
    // MINIMUM-derived lifetime instead of the CNAME's own TTL.
    let qtype = msg.queries[0].query_type();
    let has_requested_data = msg.answers.iter().any(|r| {
        r.record_type() != RecordType::CNAME
            || qtype == RecordType::CNAME
            || qtype == RecordType::ANY
    });
    if !has_requested_data
        && msg
            .authorities
            .iter()
            .any(|r| r.record_type() == RecordType::SOA)
    {
        return None;
    }
    // RFC 2181 §5.2: TTLs of *every* section bound the cache lifetime —
    // a long-lived answer paired with a short-lived authority/additional
    // record must not be served beyond the shortest of them. The OPT
    // pseudo-record is excluded (its TTL field carries EDNS flags, and
    // hickory may already have lifted it out of `additionals`).
    let min = msg
        .answers
        .iter()
        .chain(msg.authorities.iter())
        .chain(msg.additionals.iter())
        .filter(|r| r.record_type() != RecordType::OPT)
        .map(|r| u64::from(r.ttl))
        .min()?;
    if min < min_ttl {
        return None; // below the operator's cacheability threshold
    }
    Some(min.min(max_ttl))
}

/// RFC 2308 negative-caching TTL for NXDOMAIN / NODATA responses: the
/// minimum of the SOA record TTL and its MINIMUM field, capped at
/// `negative_max_ttl`. Returns `None` when the response is not cacheable
/// (truncated, missing SOA, other rcodes, ...).
pub fn negative_ttl(resp_bytes: &[u8], negative_max_ttl: u64) -> Option<u64> {
    let msg = Message::from_vec(resp_bytes).ok()?;
    if msg.metadata.truncation || msg.queries.len() != 1 {
        return None;
    }
    let qtype = msg.queries[0].query_type();
    match msg.metadata.response_code {
        ResponseCode::NoError => {
            // NODATA is NOERROR with no data for the requested type. A CNAME
            // chain may precede the (absent) target data; it must still be
            // negatively cached when the authority section carries an SOA.
            // A CNAME answer is real data when CNAME (or ANY) was requested.
            let has_requested_data = msg.answers.iter().any(|r| {
                r.record_type() != RecordType::CNAME
                    || qtype == RecordType::CNAME
                    || qtype == RecordType::ANY
            });
            if has_requested_data {
                return None; // positive answers are handled by cacheable_ttl
            }
        }
        ResponseCode::NXDomain => {
            // NXDOMAIN may legally arrive with a CNAME chain in the answer
            // section (RFC 2308 §2.1: referral-by-CNAME with no target data
            // below the alias) — those answers carry no data for the qname
            // and must still be negatively cached. Any real data record means
            // this is not a negative response.
            if msg
                .answers
                .iter()
                .any(|r| r.record_type() != RecordType::CNAME)
            {
                return None;
            }
        }
        _ => return None, // SERVFAIL / REFUSED / ... are never cached
    }
    let soa = msg
        .authorities
        .iter()
        .find(|r| r.record_type() == RecordType::SOA)?;
    let soa_ttl = soa.ttl as u64;
    let minimum = match &soa.data {
        hickory_proto::rr::RData::SOA(s) => u64::from(s.minimum),
        _ => 0,
    };
    Some(soa_ttl.min(minimum).min(negative_max_ttl))
}

/// Clamp every non-OPT record TTL in a response to `ceiling` (seconds).
///
/// Cached responses are stored with these clamped TTLs so the first client,
/// and every later cache hit, sees the same operator-configured upper bound.
/// Doing this in the wire buffer keeps the bytes and the cache expiry in
/// agreement. Returns `false` when the message layout cannot be walked (the
/// caller will not be able to cache it either).
pub fn clamp_ttls(resp_bytes: &mut [u8], ceiling: u32) -> bool {
    let Some(slots) = collect_ttl_slots(resp_bytes) else {
        return false;
    };
    for (off, ttl) in slots {
        let clamped = ttl.min(ceiling);
        resp_bytes[off..off + 4].copy_from_slice(&clamped.to_be_bytes());
    }
    true
}

/// Positions (byte offsets) and original values of every record TTL in the
/// message, so cached responses can serve *decremented* TTLs on each hit
/// (RFC 1035 §3.2.1: TTL counts down while cached). The OPT pseudo-record
/// (type 41) is skipped — its TTL field carries EDNS flags, not a lifetime.
pub fn collect_ttl_slots(resp_bytes: &[u8]) -> Option<Vec<(usize, u32)>> {
    if resp_bytes.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([resp_bytes[4], resp_bytes[5]]) as usize;
    let sections = u16::from_be_bytes([resp_bytes[6], resp_bytes[7]]) as usize
        + u16::from_be_bytes([resp_bytes[8], resp_bytes[9]]) as usize
        + u16::from_be_bytes([resp_bytes[10], resp_bytes[11]]) as usize;
    let mut pos = 12usize;
    for _ in 0..qdcount {
        pos = skip_name(resp_bytes, pos)?;
        pos = pos.checked_add(4)?; // type + class
    }
    let mut slots = Vec::with_capacity(sections);
    for _ in 0..sections {
        pos = skip_name(resp_bytes, pos)?;
        if pos.checked_add(10)? > resp_bytes.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([resp_bytes[pos], resp_bytes[pos + 1]]);
        let ttl_offset = pos + 4;
        let ttl = u32::from_be_bytes([
            resp_bytes[ttl_offset],
            resp_bytes[ttl_offset + 1],
            resp_bytes[ttl_offset + 2],
            resp_bytes[ttl_offset + 3],
        ]);
        let rdlen = u16::from_be_bytes([resp_bytes[pos + 8], resp_bytes[pos + 9]]) as usize;
        if rtype != 41 {
            slots.push((ttl_offset, ttl));
        }
        pos = pos.checked_add(10 + rdlen)?;
    }
    Some(slots)
}

/// Advance past a (possibly compressed) domain name. Returns the offset of
/// the next field.
fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *buf.get(pos)?;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            return pos.checked_add(2);
        }
        if len & 0xC0 != 0 {
            return None;
        }
        pos = pos.checked_add(1 + len as usize)?;
    }
}

/// Rewrite the transaction id of a cached response in place.
pub fn set_transaction_id(bytes: &mut [u8], id: u16) {
    if bytes.len() >= 2 {
        bytes[0] = (id >> 8) as u8;
        bytes[1] = id as u8;
    }
}

/// Byte span `[start, end)` of the first question section in `bytes`
/// (offset 12 through type+class), or `None` when the layout is unusable.
fn question_span(bytes: &[u8]) -> Option<(usize, usize)> {
    if bytes.len() < 12 || u16::from_be_bytes([bytes[4], bytes[5]]) != 1 {
        return None;
    }
    let end = skip_name(bytes, 12)?.checked_add(4)?;
    (end <= bytes.len()).then_some((12, end))
}

/// Byte spans of every OPT pseudo-record (type 41) in the message, in wire
/// order. Walks all three RR sections so a misplaced OPT is found (and can be
/// stripped) too. Returns `None` on a malformed layout.
fn find_opt_spans(bytes: &[u8]) -> Option<Vec<(usize, usize)>> {
    if bytes.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    let rr_total = u16::from_be_bytes([bytes[6], bytes[7]]) as usize
        + u16::from_be_bytes([bytes[8], bytes[9]]) as usize
        + u16::from_be_bytes([bytes[10], bytes[11]]) as usize;
    let mut pos = 12usize;
    for _ in 0..qd {
        pos = skip_name(bytes, pos)?;
        pos = pos.checked_add(4)?;
    }
    let mut spans = Vec::new();
    for _ in 0..rr_total {
        let start = pos;
        pos = skip_name(bytes, pos)?;
        if pos.checked_add(10)? > bytes.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
        let rdlen = u16::from_be_bytes([bytes[pos + 8], bytes[pos + 9]]) as usize;
        pos = pos.checked_add(10 + rdlen)?;
        if pos > bytes.len() {
            return None;
        }
        if rtype == 41 {
            spans.push((start, pos));
        }
    }
    Some(spans)
}

/// Adjust the header's ARCOUNT (additional-integer overflow is impossible
/// for a well-formed message but checked anyway).
fn bump_arcount(bytes: &mut [u8], delta: i32) -> Option<()> {
    let cur = u16::from_be_bytes([bytes[10], bytes[11]]);
    let next = i32::from(cur) + delta;
    if !(0..=u16::MAX as i32).contains(&next) {
        return None;
    }
    let next = next as u16;
    bytes[10] = (next >> 8) as u8;
    bytes[11] = next as u8;
    Some(())
}

/// Align a proxied/cached/follower response to the *current* query before it
/// goes on the wire:
///
/// * transaction id — follower/cached bytes may carry another client's id;
/// * RD and CD header flags — echo this client's intent, not the leader's;
/// * the question section's exact bytes — 0x20 randomisation means a cached
///   answer stored under one qname casing must not be served to a query
///   sent with a different casing (RFC 7816);
/// * the OPT pseudo-record — present exactly once iff *this* client sent
///   one, advertising *this* client's payload size and DO bit (RFC 6891);
///   a non-EDNS client never receives an OPT, and duplicates are dropped
///   (a message with >1 OPT is malformed).
///
/// Returns `false` when the packet cannot be aligned (malformed response);
/// callers must discard it instead of sending it.
pub fn align_response_to_query(resp: &mut Vec<u8>, query: &ParsedQuery, query_raw: &[u8]) -> bool {
    if resp.len() < 12 || query_raw.len() < 12 {
        return false;
    }
    set_transaction_id(resp, query.id);
    let mut flags = u16::from_be_bytes([resp[2], resp[3]]);
    flags = if query.recursion_desired {
        flags | 0x0100
    } else {
        flags & !0x0100
    };
    flags = if query.checking_disabled {
        flags | 0x0010
    } else {
        flags & !0x0010
    };
    resp[2] = (flags >> 8) as u8;
    resp[3] = flags as u8;

    // Question bytes: mirror the query's casing when the wire spans match
    // (the common uncompressed case). When they cannot be spliced — e.g. the
    // response compressed its question, which points into later sections —
    // rebuild the message with the query's question via hickory instead.
    let r_span = question_span(resp);
    let q_span = question_span(query_raw);
    match (r_span, q_span) {
        (Some((rs, re)), Some((qs, qe))) if (re - rs) == (qe - qs) => {
            resp[rs..re].copy_from_slice(&query_raw[qs..qe]);
        }
        _ => {
            let mut rebuilt = match Message::from_vec(resp) {
                Ok(m) => m,
                Err(_) => return false,
            };
            rebuilt.metadata.id = query.id;
            rebuilt.metadata.recursion_desired = query.recursion_desired;
            rebuilt.metadata.checking_disabled = query.checking_disabled;
            rebuilt.queries = query.queries.clone();
            match rebuilt.to_vec() {
                Ok(v) => *resp = v,
                Err(_) => return false,
            }
        }
    }

    align_opt(resp, query)
}

/// Strip/patch/append the OPT record so the response matches `query`'s EDNS
/// advertisement exactly. Returns `false` only when the record layout cannot
/// be safely rewritten.
fn align_opt(resp: &mut Vec<u8>, query: &ParsedQuery) -> bool {
    let mut spans = match find_opt_spans(resp) {
        Some(s) => s,
        None => return false,
    };
    if query.has_edns {
        if spans.is_empty() {
            // No OPT from upstream: add one advertising *this* client's size.
            let payload = query.edns_payload.unwrap_or(512).max(512);
            let flags: u16 = if query.dnssec_ok { 0x8000 } else { 0 };
            resp.extend_from_slice(&[
                0x00, // root name
                0x00,
                0x29, // type 41 (OPT)
                (payload >> 8) as u8,
                payload as u8, // class = UDP payload size
                0x00,
                0x00, // extended rcode + version
                (flags >> 8) as u8,
                flags as u8, // flags (DO)
                0x00,
                0x00, // rdlength
            ]);
            return bump_arcount(resp, 1).is_some();
        }
        // Keep the first OPT, drop duplicates (RFC 6891 §6.1.1: at most one
        // OPT per message).
        if spans.len() > 1 {
            for (start, end) in spans.iter().skip(1).rev() {
                resp.drain(*start..*end);
                if bump_arcount(resp, -1).is_none() {
                    return false;
                }
            }
        }
        // Option-free queries never opted into client-specific EDNS data.
        // Drop any upstream options (ECS/COOKIE/...) before serving,
        // otherwise an option-free client could receive another transaction's
        // options from the shared cache. Re-encode
        // because option lengths are part of the wire layout; compression
        // offsets after OPT must not be left dangling.
        if !query.has_edns_options {
            if !strip_opt_options(resp) {
                return false;
            }
            spans = match find_opt_spans(resp) {
                Some(s) => s,
                None => return false,
            };
        }
        // Patch payload size (class) and flags (TTL low 16: DO bit) to this
        // client's values; extended-rcode/version bytes are preserved.
        let start = spans[0].0;
        let rtype_pos = match skip_name(resp, start) {
            Some(p) if p + 10 <= resp.len() => p,
            _ => return false,
        };
        let payload = query.edns_payload.unwrap_or(512).max(512);
        resp[rtype_pos + 2] = (payload >> 8) as u8;
        resp[rtype_pos + 3] = payload as u8;
        let flags: u16 = if query.dnssec_ok { 0x8000 } else { 0 };
        resp[rtype_pos + 6] = (flags >> 8) as u8;
        resp[rtype_pos + 7] = flags as u8;
        true
    } else {
        // Non-EDNS client: never serve an OPT (it would leak the EDNS
        // advertisement of whichever client populated the cache).
        if spans.is_empty() {
            return true;
        }
        for (start, end) in spans.iter().rev() {
            resp.drain(*start..*end);
            if bump_arcount(resp, -1).is_none() {
                return false;
            }
        }
        true
    }
}

/// Remove all EDNS options from the (single) OPT record, preserving the
/// pseudo-record itself, extended rcode/version and DNSSEC-OK flag. Returns
/// `false` only when the message cannot be decoded/re-encoded safely.
fn strip_opt_options(resp: &mut Vec<u8>) -> bool {
    let Ok(mut msg) = Message::from_vec(resp) else {
        return false;
    };
    let Some(edns) = msg.edns.as_mut() else {
        return true;
    };
    if edns.options().as_ref().is_empty() {
        return true;
    }
    edns.options_mut().as_mut().clear();
    match msg.to_vec() {
        Ok(bytes) => {
            *resp = bytes;
            true
        }
        Err(_) => false,
    }
}

/// `DNSClass` value of the IN class (RFC 1035) — used by the cache key.
pub const CLASS_IN: u16 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_query() -> Vec<u8> {
        build_query("example.com", "A").unwrap()
    }

    #[test]
    fn parses_valid_query() {
        let bytes = sample_query();
        let q = parse_query(&bytes).unwrap();
        assert_eq!(q.op_code, OpCode::Query);
        assert!(q.recursion_desired);
        assert_eq!(q.qtype(), RecordType::A);
        assert_eq!(
            q.question().name().to_ascii().to_lowercase(),
            "example.com."
        );
    }

    #[test]
    fn rejects_trailing_bytes_after_query() {
        let mut bytes = sample_query();
        bytes.push(0);
        assert_eq!(parse_query(&bytes), Err(QueryReject::Malformed));
    }

    #[test]
    fn rejects_short_packet() {
        assert_eq!(parse_query(&[0u8; 4]), Err(QueryReject::TooShort));
    }

    #[test]
    fn rejects_garbage() {
        let mut bytes = vec![0u8; 12];
        bytes[0] = 0xff;
        bytes[1] = 0xff;
        // 65535 questions declared but no data
        bytes[4] = 0xff;
        bytes[5] = 0xff;
        assert_eq!(parse_query(&bytes), Err(QueryReject::Malformed));
    }

    #[test]
    fn rejects_response_packets() {
        let mut bytes = sample_query();
        bytes[2] |= 0x80; // QR = 1
        assert_eq!(parse_query(&bytes), Err(QueryReject::NotAQuery));
    }

    #[test]
    fn rejects_no_question() {
        let mut msg = Message::query();
        msg.metadata.id = 1234;
        let bytes = msg.to_vec().unwrap();
        assert_eq!(parse_query(&bytes), Err(QueryReject::NoQuestion));
    }

    #[test]
    fn rejects_unsupported_opcode() {
        let mut msg = Message::new(1, MessageType::Query, OpCode::Update);
        msg.queries.push(Query::query(
            Name::from_ascii("example.com").unwrap(),
            RecordType::A,
        ));
        let bytes = msg.to_vec().unwrap();
        assert_eq!(parse_query(&bytes), Err(QueryReject::UnsupportedOpcode));
    }

    #[test]
    fn error_response_echoes_question_and_id() {
        let bytes = sample_query();
        let q = parse_query(&bytes).unwrap();
        let resp = error_response(&q, Rcode::Refused);
        let view = parse_response(&resp).unwrap();
        assert_eq!(view.id, q.id);
        assert_eq!(view.rcode, Rcode::Refused);
        assert_eq!(view.question.unwrap().0, "example.com.");
    }

    #[test]
    fn response_parser_requires_exactly_one_question_and_query_opcode() {
        let no_question = Message::response(7, OpCode::Query)
            .to_vec()
            .expect("encode empty response");
        assert!(
            parse_response(&no_question).is_err(),
            "QDCOUNT=0 must not correlate by id alone"
        );

        let update = Message::response(7, OpCode::Update)
            .to_vec()
            .expect("encode UPDATE response");
        assert!(
            parse_response(&update).is_err(),
            "non-query opcode must be rejected"
        );

        let mut q = sample_query();
        q[2] |= 0x80; // QR=1
        q.extend_from_slice(&[0xDE, 0xAD]);
        assert!(
            parse_response(&q).is_err(),
            "trailing bytes must be rejected"
        );
    }

    #[test]
    fn correlation_checks_id_and_question() {
        use hickory_proto::rr::DNSClass;

        let q = parse_query(&sample_query()).unwrap();

        let mut good = sample_query();
        good[0] = q.id.to_be_bytes()[0];
        good[1] = q.id.to_be_bytes()[1];
        // Turn it into a response.
        good[2] |= 0x80;
        let good_view = parse_response(&good).unwrap();
        assert!(correlates(&q, &good_view));

        let mut wrong_id = good.clone();
        wrong_id[0] = wrong_id[0].wrapping_add(1);
        let wrong_id_view = parse_response(&wrong_id).unwrap();
        assert!(!correlates(&q, &wrong_id_view));

        // A forged reply must match the exact question: name, type and class.
        let response = |name: &str, qtype: RecordType, qclass: DNSClass| {
            let mut m = Message::response(q.id, q.op_code);
            let mut question = Query::query(Name::from_ascii(name).unwrap(), qtype);
            question.set_query_class(qclass);
            m.queries.push(question);
            parse_response(&m.to_vec().unwrap()).unwrap()
        };
        assert!(correlates(
            &q,
            &response("example.com", RecordType::A, DNSClass::IN)
        ));
        assert!(
            !correlates(&q, &response("exampld.com", RecordType::A, DNSClass::IN)),
            "different name must be rejected"
        );
        assert!(
            !correlates(&q, &response("example.com", RecordType::AAAA, DNSClass::IN)),
            "different qtype must be rejected"
        );
        assert!(
            !correlates(&q, &response("example.com", RecordType::A, DNSClass::CH)),
            "different qclass must be rejected"
        );
    }

    #[test]
    fn response_parser_rejects_short_and_query_packets() {
        assert!(parse_response(&[0u8; 11]).is_err());
        let query = sample_query();
        assert!(parse_response(&query).is_err(), "QR=0 is not a response");
    }

    #[test]
    fn response_parser_rejects_compression_pointer_loop() {
        // Minimal response whose single question name points at itself.
        let mut bytes = vec![0u8; 12];
        bytes[0..2].copy_from_slice(&7u16.to_be_bytes());
        bytes[2] = 0x81; // QR=1, RD=1
        bytes[3] = 0x80; // RA=1
        bytes[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
        bytes.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);
        assert!(
            parse_response(&bytes).is_err(),
            "self-referential compression must be rejected"
        );
    }

    #[test]
    fn cache_key_normalizes_case_and_isolates_class_type_and_cd() {
        use hickory_proto::rr::DNSClass;

        let lower = parse_query(&build_query("example.com", "A").unwrap()).unwrap();
        let upper = parse_query(&build_query("EXAMPLE.COM", "A").unwrap()).unwrap();
        assert_eq!(
            question_key(
                lower.question(),
                lower.checking_disabled,
                lower.recursion_desired
            ),
            question_key(
                upper.question(),
                upper.checking_disabled,
                upper.recursion_desired
            ),
            "0x20 casing must share one cache entry"
        );

        let base = question_key(lower.question(), false, true);
        let mut qclass = lower.question().clone();
        qclass.set_query_class(DNSClass::CH);
        assert_ne!(base, question_key(&qclass, false, true));
        let qtype = Query::query(Name::from_ascii("example.com").unwrap(), RecordType::AAAA);
        assert_ne!(base, question_key(&qtype, false, true));
        assert_ne!(base, question_key(lower.question(), true, true));
        assert_ne!(
            base,
            question_key(lower.question(), false, false),
            "RD=0 responses must not mix with recursive cache entries"
        );
    }

    #[test]
    fn parses_edns_options_as_client_specific() {
        use hickory_proto::op::Edns;
        use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsOption};

        let plain = parse_query(&sample_query()).unwrap();
        assert!(!plain.has_edns_options);

        let mut m = Message::query();
        m.queries.push(Query::query(
            Name::from_ascii("example.com").unwrap(),
            RecordType::A,
        ));
        let mut edns = Edns::new();
        edns.options_mut()
            .insert(EdnsOption::Subnet(ClientSubnet::new(
                "192.0.2.0".parse().unwrap(),
                24,
                0,
            )));
        m.set_edns(edns);
        let q = parse_query(&m.to_vec().unwrap()).unwrap();
        assert!(q.has_edns);
        assert!(
            q.has_edns_options,
            "ECS must mark the query client-specific"
        );
    }

    #[test]
    fn record_type_parsing() {
        assert_eq!(parse_record_type("a").unwrap(), RecordType::A);
        assert_eq!(parse_record_type(" AAAA ").unwrap(), RecordType::AAAA);
        assert_eq!(parse_record_type("DNSKEY").unwrap(), RecordType::DNSKEY);
        assert!(parse_record_type("BOGUS").is_err());
    }

    #[test]
    fn build_query_root_ns() {
        let bytes = build_query(".", "NS").unwrap();
        let q = parse_query(&bytes).unwrap();
        assert_eq!(q.qtype(), RecordType::NS);
        assert_eq!(q.question().name().to_ascii(), ".");
    }

    #[test]
    fn cache_ttl_rules() {
        // Build a synthetic NOERROR response with one A record, TTL 60.
        let query = parse_query(&sample_query()).unwrap();
        let mut resp = Message::response(query.id, OpCode::Query);
        resp.queries = query.queries.clone();
        let rec = hickory_proto::rr::Record::from_rdata(
            Name::from_ascii("example.com").unwrap(),
            60,
            hickory_proto::rr::RData::A("1.2.3.4".parse().unwrap()),
        );
        resp.answers.push(rec);
        let bytes = resp.to_vec().unwrap();

        // TTL 60: cached as-is; max_ttl caps downwards; min_ttl below is a
        // pass-through; min_ttl above *skips* (never extends).
        assert_eq!(cacheable_ttl(&bytes, 0, 3600), Some(60));
        assert_eq!(cacheable_ttl(&bytes, 30, 3600), Some(60));
        assert_eq!(cacheable_ttl(&bytes, 0, 30), Some(30));
        assert_eq!(cacheable_ttl(&bytes, 120, 3600), None, "must not extend");
        assert_eq!(cacheable_ttl(&bytes, 60, 3600), Some(60), "boundary keeps");

        // Truncated responses are never cached.
        let mut truncated = Message::response(query.id, OpCode::Query);
        truncated.queries = query.queries.clone();
        truncated.metadata.truncation = true;
        truncated
            .answers
            .push(hickory_proto::rr::Record::from_rdata(
                Name::from_ascii("example.com").unwrap(),
                60,
                hickory_proto::rr::RData::A("1.2.3.4".parse().unwrap()),
            ));
        let tbytes = truncated.to_vec().unwrap();
        assert_eq!(cacheable_ttl(&tbytes, 0, 3600), None);
    }

    #[test]
    fn negative_ttl_uses_soa_minimum() {
        let query = parse_query(&sample_query()).unwrap();
        let mut resp = Message::response(query.id, OpCode::Query);
        resp.queries = query.queries.clone();
        resp.metadata.response_code = ResponseCode::NXDomain;
        let soa = hickory_proto::rr::Record::from_rdata(
            Name::from_ascii("example.com").unwrap(),
            300, // SOA record TTL
            hickory_proto::rr::RData::SOA(hickory_proto::rr::rdata::SOA::new(
                Name::from_ascii("ns.example.com").unwrap(),
                Name::from_ascii("admin.example.com").unwrap(),
                1,         // serial
                7200,      // refresh
                3600,      // retry
                1_209_600, // expire
                60,        // minimum (negative-caching TTL)
            )),
        );
        resp.authorities.push(soa);
        let bytes = resp.to_vec().unwrap();

        // min(SOA TTL 300, MINIMUM 60) = 60.
        assert_eq!(negative_ttl(&bytes, 300), Some(60));
        // Cap applies.
        assert_eq!(negative_ttl(&bytes, 30), Some(30));
        // Positive answers are not negative-cacheable.
        resp.answers.push(hickory_proto::rr::Record::from_rdata(
            Name::from_ascii("example.com").unwrap(),
            60,
            hickory_proto::rr::RData::A("1.2.3.4".parse().unwrap()),
        ));
        let positive = resp.to_vec().unwrap();
        assert_eq!(negative_ttl(&positive, 300), None);
        // SERVFAIL is never cached.
        let mut sf = Message::response(query.id, OpCode::Query);
        sf.queries = query.queries.clone();
        sf.metadata.response_code = ResponseCode::ServFail;
        assert_eq!(negative_ttl(&sf.to_vec().unwrap(), 300), None);
        // NXDOMAIN without SOA is not cacheable.
        let mut bare = Message::response(query.id, OpCode::Query);
        bare.queries = query.queries.clone();
        bare.metadata.response_code = ResponseCode::NXDomain;
        assert_eq!(negative_ttl(&bare.to_vec().unwrap(), 300), None);
    }

    #[test]
    fn noerror_cname_chain_with_soa_is_negative_nodata() {
        let query = parse_query(&sample_query()).unwrap();
        let mut resp = Message::response(query.id, OpCode::Query);
        resp.queries = query.queries.clone();
        resp.answers.push(hickory_proto::rr::Record::from_rdata(
            Name::from_ascii("www.example.com").unwrap(),
            300,
            hickory_proto::rr::RData::CNAME(hickory_proto::rr::rdata::CNAME(
                Name::from_ascii("alias.example.com").unwrap(),
            )),
        ));
        resp.authorities.push(hickory_proto::rr::Record::from_rdata(
            Name::from_ascii("example.com").unwrap(),
            300,
            hickory_proto::rr::RData::SOA(hickory_proto::rr::rdata::SOA::new(
                Name::from_ascii("ns.example.com").unwrap(),
                Name::from_ascii("admin.example.com").unwrap(),
                1,
                7200,
                3600,
                1_209_600,
                60,
            )),
        ));
        let bytes = resp.to_vec().unwrap();

        // NOERROR + CNAME-only answers + SOA is NODATA below the alias:
        // it must use RFC 2308 negative caching, not the CNAME's TTL.
        assert_eq!(cacheable_ttl(&bytes, 0, 3600), None);
        assert_eq!(negative_ttl(&bytes, 300), Some(60));

        // Without an SOA there is no negative answer to cache; the CNAME is
        // a legal positive answer and may be cached as such.
        resp.authorities.clear();
        let cname_only = resp.to_vec().unwrap();
        assert_eq!(cacheable_ttl(&cname_only, 0, 3600), Some(300));
        assert_eq!(negative_ttl(&cname_only, 300), None);

        // When the client asked for CNAME, that same answer is positive.
        let cname_query = parse_query(&build_query("www.example.com", "CNAME").unwrap()).unwrap();
        let mut cname_resp = Message::response(cname_query.id, OpCode::Query);
        cname_resp.queries = cname_query.queries.clone();
        cname_resp
            .answers
            .push(hickory_proto::rr::Record::from_rdata(
                Name::from_ascii("www.example.com").unwrap(),
                300,
                hickory_proto::rr::RData::CNAME(hickory_proto::rr::rdata::CNAME(
                    Name::from_ascii("alias.example.com").unwrap(),
                )),
            ));
        cname_resp
            .authorities
            .push(resp.authorities.first().cloned().unwrap_or_else(|| {
                hickory_proto::rr::Record::from_rdata(
                    Name::from_ascii("example.com").unwrap(),
                    300,
                    hickory_proto::rr::RData::SOA(hickory_proto::rr::rdata::SOA::new(
                        Name::from_ascii("ns.example.com").unwrap(),
                        Name::from_ascii("admin.example.com").unwrap(),
                        1,
                        7200,
                        3600,
                        1_209_600,
                        60,
                    )),
                )
            }));
        let cname_bytes = cname_resp.to_vec().unwrap();
        assert_eq!(cacheable_ttl(&cname_bytes, 0, 3600), Some(300));
        assert_eq!(cacheable_ttl(&cname_bytes, 0, 100), Some(100));
        assert_eq!(negative_ttl(&cname_bytes, 300), None);
    }

    #[test]
    fn clamp_ttls_caps_every_section() {
        let query = parse_query(&sample_query()).unwrap();
        let mut resp = Message::response(query.id, OpCode::Query);
        resp.queries = query.queries.clone();
        resp.answers.push(hickory_proto::rr::Record::from_rdata(
            Name::from_ascii("example.com").unwrap(),
            600,
            hickory_proto::rr::RData::A("1.2.3.4".parse().unwrap()),
        ));
        resp.authorities.push(hickory_proto::rr::Record::from_rdata(
            Name::from_ascii("example.com").unwrap(),
            300,
            hickory_proto::rr::RData::NS(hickory_proto::rr::rdata::NS(
                Name::from_ascii("ns.example.com").unwrap(),
            )),
        ));
        resp.additionals.push(hickory_proto::rr::Record::from_rdata(
            Name::from_ascii("ns.example.com").unwrap(),
            120,
            hickory_proto::rr::RData::A("1.2.3.5".parse().unwrap()),
        ));
        let mut bytes = resp.to_vec().unwrap();
        assert!(clamp_ttls(&mut bytes, 30));
        let decoded = Message::from_vec(&bytes).unwrap();
        assert_eq!(decoded.answers[0].ttl, 30);
        assert_eq!(decoded.authorities[0].ttl, 30);
        assert_eq!(decoded.additionals[0].ttl, 30);

        let mut malformed = [0u8; 3];
        assert!(!clamp_ttls(&mut malformed, 30));
    }

    #[test]
    fn ttl_slots_cover_all_sections() {
        let query = parse_query(&sample_query()).unwrap();
        let mut resp = Message::response(query.id, OpCode::Query);
        resp.queries = query.queries.clone();
        resp.answers.push(hickory_proto::rr::Record::from_rdata(
            Name::from_ascii("example.com").unwrap(),
            60,
            hickory_proto::rr::RData::A("1.2.3.4".parse().unwrap()),
        ));
        resp.authorities.push(hickory_proto::rr::Record::from_rdata(
            Name::from_ascii("example.com").unwrap(),
            300,
            hickory_proto::rr::RData::SOA(hickory_proto::rr::rdata::SOA::new(
                Name::from_ascii("ns.example.com").unwrap(),
                Name::from_ascii("admin.example.com").unwrap(),
                1,
                7200,
                3600,
                1_209_600,
                60,
            )),
        ));
        let bytes = resp.to_vec().unwrap();
        let slots = collect_ttl_slots(&bytes).expect("slots");
        assert_eq!(slots.len(), 2, "answer + SOA");
        for (off, ttl) in &slots {
            assert_eq!(
                u32::from_be_bytes([
                    bytes[*off],
                    bytes[*off + 1],
                    bytes[*off + 2],
                    bytes[*off + 3]
                ]),
                *ttl
            );
        }
        assert_eq!(slots[0].1, 60);
        assert_eq!(slots[1].1, 300);

        // Decrement simulation: rewrite both TTLs as a cache hit at t+10s.
        let mut hit = bytes.clone();
        let elapsed = 10u32;
        for (off, ttl) in &slots {
            let v = ttl.saturating_sub(elapsed);
            hit[*off..*off + 4].copy_from_slice(&v.to_be_bytes());
        }
        let view = parse_response(&hit).unwrap();
        assert_eq!(view.id, query.id);
        let decoded = Message::from_vec(&hit).unwrap();
        assert_eq!(decoded.answers[0].ttl, 50);
        assert_eq!(decoded.authorities[0].ttl, 290);
    }

    #[test]
    fn set_transaction_id_rewrites() {
        let mut bytes = sample_query();
        set_transaction_id(&mut bytes, 0xABCD);
        assert_eq!(u16::from_be_bytes([bytes[0], bytes[1]]), 0xABCD);
    }

    #[test]
    fn parse_rcode_names() {
        assert_eq!(parse_rcode("NOERROR"), Some(Rcode::NoError));
        assert_eq!(parse_rcode("nxdomain"), Some(Rcode::NXDomain));
        assert_eq!(parse_rcode(" SERVFAIL "), Some(Rcode::ServFail));
        assert_eq!(parse_rcode("REFUSED"), Some(Rcode::Refused));
        assert_eq!(parse_rcode("FORMERR"), Some(Rcode::FormErr));
        assert_eq!(parse_rcode("NOTIMP"), Some(Rcode::NotImp));
        assert_eq!(
            parse_rcode("OTHER"),
            None,
            "internal bucket, not a wire rcode"
        );
        assert_eq!(parse_rcode("BOGUS"), None);
        assert_eq!(parse_rcode(""), None);
    }

    // ---- EDNS-aware local responses (RFC 6891) ----

    /// Build a raw query whose qname keeps its (0x20-style) mixed case and,
    /// when `edns` is set, append an OPT record advertising `payload` + DO.
    fn edns_query(name: &str, edns: Option<(u16, bool)>) -> Vec<u8> {
        let mut raw = build_query(name, "A").unwrap();
        if let Some((payload, do_bit)) = edns {
            let flags: u16 = if do_bit { 0x8000 } else { 0 };
            raw.extend_from_slice(&[
                0x00,
                0x00,
                0x29,
                (payload >> 8) as u8,
                payload as u8,
                0x00,
                0x00,
                (flags >> 8) as u8,
                flags as u8,
                0x00,
                0x00,
            ]);
            let ar = u16::from_be_bytes([raw[10], raw[11]]) + 1;
            raw[10] = (ar >> 8) as u8;
            raw[11] = ar as u8;
        }
        raw
    }

    fn opt_count(bytes: &[u8]) -> usize {
        find_opt_spans(bytes).map(|s| s.len()).unwrap_or(0)
    }

    #[test]
    fn error_response_carries_opt_only_for_edns_queries() {
        let plain = edns_query("example.com", None);
        let q_plain = parse_query(&plain).unwrap();
        let resp = error_response(&q_plain, Rcode::Refused);
        assert_eq!(opt_count(&resp), 0, "plain query must not get an OPT");
        assert_eq!(u16::from_be_bytes([resp[10], resp[11]]), 0);

        let with_opt = edns_query("example.com", Some((4096, true)));
        let q_edns = parse_query(&with_opt).unwrap();
        let resp = error_response(&q_edns, Rcode::NotImp);
        assert_eq!(opt_count(&resp), 1, "RFC 6891: EDNS query => EDNS response");
        let decoded = Message::from_vec(&resp).unwrap();
        let edns = decoded.edns.expect("OPT present");
        assert_eq!(edns.max_payload(), 4096);
        assert!(edns.flags().dnssec_ok, "DO bit mirrors the query");
    }

    // ---- Response alignment (0x20 question case + per-client OPT) ----

    #[test]
    fn align_mirrors_question_case_flags_and_adds_opt() {
        // A response built for the *lowercase* spelling, no EDNS, RD off —
        // as a cache entry populated by an earlier client might be.
        let plain_lower = edns_query("example.com", None);
        let q_lower = parse_query(&plain_lower).unwrap();
        let mut resp = error_response(&q_lower, Rcode::NoError);
        // Ensure RD is off in the response for this test.
        let mut flags = u16::from_be_bytes([resp[2], resp[3]]);
        flags &= !0x0100;
        resp[2] = (flags >> 8) as u8;
        resp[3] = flags as u8;

        // Current client: mixed-case qname, EDNS 4096, DO set, RD set.
        let raw = edns_query("ExAmPle.CoM", Some((4096, true)));
        let q = parse_query(&raw).unwrap();
        assert!(align_response_to_query(&mut resp, &q, &raw));

        // Id + RD.
        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), q.id);
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        assert_ne!(flags & 0x0100, 0, "RD must echo the current query");
        // Question bytes are the query's (mixed case).
        let (rs, re) = question_span(&resp).expect("resp question");
        let (qs, qe) = question_span(&raw).expect("query question");
        assert_eq!(&resp[rs..re], &raw[qs..qe], "0x20 case must be mirrored");
        // OPT added with *this* client's advertisement.
        assert_eq!(opt_count(&resp), 1);
        let decoded = Message::from_vec(&resp).unwrap();
        let edns = decoded.edns.expect("OPT added");
        assert_eq!(edns.max_payload(), 4096);
        assert!(edns.flags().dnssec_ok);
    }

    #[test]
    fn align_strips_opt_for_non_edns_clients_and_drops_duplicates() {
        let with_opt = edns_query("example.com", Some((4096, false)));
        let q_edns = parse_query(&with_opt).unwrap();
        // Response with an OPT (from an EDNS-populated cache entry)...
        let mut resp = error_response(&q_edns, Rcode::NoError);
        assert_eq!(opt_count(&resp), 1);

        // ...served to a plain-UDP client: OPT must be gone.
        let plain = edns_query("example.com", None);
        let q_plain = parse_query(&plain).unwrap();
        assert!(align_response_to_query(&mut resp, &q_plain, &plain));
        assert_eq!(opt_count(&resp), 0, "no OPT leak to a non-EDNS client");
        assert_eq!(
            u16::from_be_bytes([resp[10], resp[11]]),
            0,
            "arcount must follow"
        );

        // A response carrying *two* OPT records is malformed: alignment keeps
        // exactly one (append a duplicate by hand).
        let mut dup = error_response(&q_edns, Rcode::NoError);
        let ar = u16::from_be_bytes([dup[10], dup[11]]);
        // Duplicate by re-encoding a second OPT onto the wire: splice a copy
        // of the existing OPT bytes before the end and bump arcount.
        let spans = find_opt_spans(&dup).expect("spans");
        let (s, e) = spans[0];
        let opt_rr = dup[s..e].to_vec();
        dup.extend_from_slice(&opt_rr);
        dup[10] = ((ar + 1) >> 8) as u8;
        dup[11] = (ar + 1) as u8;
        assert_eq!(opt_count(&dup), 2);
        assert!(align_response_to_query(&mut dup, &q_edns, &with_opt));
        assert_eq!(opt_count(&dup), 1, "duplicates are collapsed");
        assert_eq!(
            u16::from_be_bytes([dup[10], dup[11]]),
            1,
            "arcount corrected"
        );
    }

    #[test]
    fn align_strips_upstream_edns_options_for_option_free_clients() {
        use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsOption};

        // Upstream attached an ECS option even though the downstream query
        // carried none (or the bytes were cached after such an exchange).
        let ecs = edns_query("example.com", Some((4096, false)));
        let q_ecs = parse_query(&ecs).unwrap();
        let mut resp = error_response(&q_ecs, Rcode::NoError);
        let mut msg = Message::from_vec(&resp).unwrap();
        let mut edns = msg.edns.take().expect("response OPT");
        edns.options_mut()
            .insert(EdnsOption::Subnet(ClientSubnet::new(
                "198.51.100.0".parse().unwrap(),
                24,
                0,
            )));
        msg.set_edns(edns);
        resp = msg.to_vec().unwrap();

        // An option-free EDNS client must receive an OPT for its own payload
        // size but none of the upstream's client-specific options.
        let raw = edns_query("example.com", Some((1232, false)));
        let q = parse_query(&raw).unwrap();
        assert!(q.has_edns);
        assert!(!q.has_edns_options);
        assert!(align_response_to_query(&mut resp, &q, &raw));

        let decoded = Message::from_vec(&resp).unwrap();
        let edns = decoded.edns.expect("OPT retained");
        assert!(
            edns.options().as_ref().is_empty(),
            "upstream EDNS options must not leak to option-free clients"
        );
        assert_eq!(edns.max_payload(), 1232);
        assert!(!edns.flags().dnssec_ok);
    }

    #[test]
    fn align_rejects_garbage() {
        let raw = edns_query("example.com", None);
        let q = parse_query(&raw).unwrap();
        let mut junk = vec![0x00u8; 3];
        assert!(!align_response_to_query(&mut junk, &q, &raw));
    }

    // ---- TTL correctness across sections (RFC 2181 / 2308) ----

    #[test]
    fn cacheable_ttl_bounds_by_shortest_record_in_any_section() {
        let query = parse_query(&sample_query()).unwrap();
        let mut resp = Message::response(query.id, OpCode::Query);
        resp.queries = query.queries.clone();
        resp.answers.push(hickory_proto::rr::Record::from_rdata(
            Name::from_ascii("example.com").unwrap(),
            600,
            hickory_proto::rr::RData::A("1.2.3.4".parse().unwrap()),
        ));
        resp.authorities.push(hickory_proto::rr::Record::from_rdata(
            Name::from_ascii("ns.example.com").unwrap(),
            60,
            hickory_proto::rr::RData::NS(hickory_proto::rr::rdata::NS(
                Name::from_ascii("ns.example.com").unwrap(),
            )),
        ));
        let bytes = resp.to_vec().unwrap();

        // Answer says 600, the authority says 60: cache for 60 (§5.2).
        assert_eq!(cacheable_ttl(&bytes, 0, 3600), Some(60));
        // The threshold applies to the bound, not just the answer.
        assert_eq!(cacheable_ttl(&bytes, 120, 3600), None);
    }

    #[test]
    fn negative_ttl_accepts_nxdomain_with_cname_answers_only() {
        let query = parse_query(&sample_query()).unwrap();
        let mut resp = Message::response(query.id, OpCode::Query);
        resp.queries = query.queries.clone();
        resp.metadata.response_code = ResponseCode::NXDomain;
        resp.answers.push(hickory_proto::rr::Record::from_rdata(
            Name::from_ascii("www.example.com").unwrap(),
            300,
            hickory_proto::rr::RData::CNAME(hickory_proto::rr::rdata::CNAME(
                Name::from_ascii("alias.example.com").unwrap(),
            )),
        ));
        resp.authorities.push(hickory_proto::rr::Record::from_rdata(
            Name::from_ascii("example.com").unwrap(),
            300,
            hickory_proto::rr::RData::SOA(hickory_proto::rr::rdata::SOA::new(
                Name::from_ascii("ns.example.com").unwrap(),
                Name::from_ascii("admin.example.com").unwrap(),
                1,
                7200,
                3600,
                1_209_600,
                60,
            )),
        ));
        let bytes = resp.to_vec().unwrap();
        assert_eq!(
            negative_ttl(&bytes, 300),
            Some(60),
            "NXDOMAIN below a CNAME chain is still a negative answer (RFC 2308 §2.1)"
        );

        // Real data records in the answer section mean it is not negative.
        resp.answers.clear();
        resp.answers.push(hickory_proto::rr::Record::from_rdata(
            Name::from_ascii("www.example.com").unwrap(),
            300,
            hickory_proto::rr::RData::A("1.2.3.4".parse().unwrap()),
        ));
        assert_eq!(negative_ttl(&resp.to_vec().unwrap(), 300), None);
    }
}
