//! DNS message parsing, validation and local error-response construction.
//!
//! Wire format handling is delegated to `hickory-proto`; OutisDNS owns the
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
    Ok(ParsedQuery {
        id: msg.metadata.id,
        op_code: msg.metadata.op_code,
        recursion_desired: msg.metadata.recursion_desired,
        has_edns,
        dnssec_ok,
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
pub fn parse_response(bytes: &[u8]) -> Result<ResponseView, String> {
    let msg = Message::from_vec(bytes).map_err(|e| format!("decode error: {e}"))?;
    if msg.metadata.message_type != MessageType::Response {
        return Err("message is not a response".into());
    }
    let question = msg.queries.first().map(|q| {
        (
            q.name().to_ascii().to_lowercase(),
            u16::from(q.query_type()),
            u16::from(q.query_class()),
        )
    });
    Ok(ResponseView {
        id: msg.metadata.id,
        rcode: Rcode::from_response_code(msg.metadata.response_code),
        truncated: msg.metadata.truncation,
        question,
    })
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

/// Question key used by the cache (lowercased name, type, class).
pub fn question_key(q: &Query) -> (String, u16, u16) {
    (
        q.name().to_ascii().to_lowercase(),
        u16::from(q.query_type()),
        u16::from(q.query_class()),
    )
}

/// Compute the effective TTL for caching: the minimum TTL across answers,
/// clamped to the configured bounds. Returns `None` when not cacheable.
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
    Some(min.clamp(min_ttl, max_ttl))
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

        assert_eq!(cacheable_ttl(&bytes, 0, 3600), Some(60));
        assert_eq!(cacheable_ttl(&bytes, 120, 3600), Some(120));
        assert_eq!(cacheable_ttl(&bytes, 0, 30), Some(30));

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
    fn set_transaction_id_rewrites() {
        let mut bytes = sample_query();
        set_transaction_id(&mut bytes, 0xABCD);
        assert_eq!(u16::from_be_bytes([bytes[0], bytes[1]]), 0xABCD);
    }
}
