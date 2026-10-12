//! DNS message parsing, validation and local error-response construction.
//!
//! Wire format handling is delegated to `hickory-proto`; res owns the
//! validation policy and the gateway-level responses (REFUSED, SERVFAIL, ...).

use std::str::FromStr;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};

/// Gateway-level response code classification (bounded label set).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    let msg = Message::from_vec(bytes).map_err(|_| QueryReject::Malformed)?;
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
    Ok(ParsedQuery {
        id: msg.metadata.id,
        op_code: msg.metadata.op_code,
        recursion_desired: msg.metadata.recursion_desired,
        has_edns,
        dnssec_ok,
        checking_disabled: msg.metadata.checking_disabled,
        edns_payload,
        queries: msg.queries,
    })
}

/// Build a local gateway response for a rejected/failed query. The question
/// section is echoed, as most resolvers expect.
pub fn error_response(req: &ParsedQuery, rcode: Rcode) -> Vec<u8> {
    let mut msg = Message::error_msg(req.id, req.op_code, rcode.to_response_code());
    msg.metadata.recursion_desired = req.recursion_desired;
    msg.metadata.recursion_available = true;
    msg.queries = req.queries.clone();
    msg.to_vec().unwrap_or_default()
}

/// Build a local SERVFAIL for a query whose header could still be read.
pub fn servfail_for_id(id: u16, op_code: OpCode) -> Vec<u8> {
    let msg = Message::error_msg(id, op_code, ResponseCode::ServFail);
    msg.to_vec().unwrap_or_default()
}

/// Inspect an upstream response (id, rcode, truncation, question).
///
/// Hot path: only the header and the first question are decoded — the answer
/// section is never touched. Falls back to the full `hickory-proto` decoder
/// for unusual encodings (compressed question names) so behaviour stays
/// correct for every message the full parser accepts.
pub fn parse_response(bytes: &[u8]) -> Result<ResponseView, String> {
    if bytes.len() < 12 {
        return Err("short response".into());
    }
    let id = u16::from_be_bytes([bytes[0], bytes[1]]);
    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
    if flags & 0x8000 == 0 {
        return Err("message is not a response".into());
    }
    let truncated = flags & 0x0200 != 0;
    let rcode = rcode_from_bits((flags & 0x000F) as u8);
    let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]);

    let question = if qdcount == 0 {
        None
    } else {
        match parse_question_wire(bytes, 12) {
            Some(q) => Some(q),
            // Compressed/unusual question section: full decode (rare).
            None => {
                let msg = Message::from_vec(bytes).map_err(|e| format!("decode error: {e}"))?;
                if msg.metadata.message_type != MessageType::Response {
                    return Err("message is not a response".into());
                }
                msg.queries.first().map(|q| {
                    (
                        q.name().to_ascii().to_lowercase(),
                        u16::from(q.query_type()),
                        u16::from(q.query_class()),
                    )
                })
            }
        }
    };
    Ok(ResponseView {
        id,
        rcode,
        truncated,
        question,
    })
}

/// Map the 4-bit header rcode (extended rcodes are out of scope here; they
/// only appear in EDNS version-negotiation edge cases and are classified as
/// `Other` via their low nibble).
fn rcode_from_bits(bits: u8) -> Rcode {
    match bits {
        0 => Rcode::NoError,
        1 => Rcode::FormErr,
        2 => Rcode::ServFail,
        3 => Rcode::NXDomain,
        4 => Rcode::NotImp,
        5 => Rcode::Refused,
        _ => Rcode::Other,
    }
}

/// Decode one question at `pos`. Returns `None` when the name uses a
/// compression pointer (callers fall back to the full decoder).
fn parse_question_wire(bytes: &[u8], pos: usize) -> Option<(String, u16, u16)> {
    let mut name = String::new();
    let mut p = pos;
    loop {
        let len = *bytes.get(p)?;
        if len == 0 {
            p += 1;
            break;
        }
        if len & 0xC0 != 0 {
            return None; // compression pointer: not handled here
        }
        let label = bytes.get(p + 1..p + 1 + len as usize)?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(label).to_lowercase());
        p += 1 + len as usize;
    }
    let qtype = u16::from_be_bytes([*bytes.get(p)?, *bytes.get(p + 1)?]);
    let qclass = u16::from_be_bytes([*bytes.get(p + 2)?, *bytes.get(p + 3)?]);
    name.push('.');
    Some((name, qtype, qclass))
}

/// Correlate an upstream response with the query we sent.
pub fn correlates(query: &ParsedQuery, resp: &ResponseView) -> bool {
    if resp.id != query.id {
        return false;
    }
    match &resp.question {
        // Some servers omit the question section; id + source IP/port
        // (connected UDP socket) still protect us in that case.
        None => true,
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

/// Question key used by the cache (lowercased name, type, class, CD bit).
pub fn question_key(q: &Query, checking_disabled: bool) -> crate::cache::CacheKey {
    crate::cache::CacheKey {
        name: q.name().to_ascii().to_lowercase(),
        qtype: u16::from(q.query_type()),
        qclass: u16::from(q.query_class()),
        cd: checking_disabled,
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
    let min = msg.answers.iter().map(|r| r.ttl).min()? as u64;
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
    if msg.metadata.truncation {
        return None;
    }
    match msg.metadata.response_code {
        ResponseCode::NoError | ResponseCode::NXDomain => {}
        _ => return None, // SERVFAIL / REFUSED / ... are never cached
    }
    if !msg.answers.is_empty() {
        return None; // positive answers are handled by cacheable_ttl
    }
    if msg.queries.len() != 1 {
        return None;
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
    fn correlation_checks_id_and_question() {
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
}
