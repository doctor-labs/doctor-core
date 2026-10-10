//! The crate's own conformance self-test: whatever it builds satisfies contract sections 1-5, 8.

use crate::*;
use serde_json::{json, Value};

fn finding(id: &str, sev: Severity, state: Option<BaselineState>) -> Finding {
    Finding {
        id: id.into(),
        fingerprint: fingerprint(id.as_bytes()),
        severity: sev,
        confidence: None,
        category: "x".into(),
        message: "m".into(),
        location: Location::new(LocationKind::Device, "AA"),
        evidence: vec![],
        remedy: None,
        baseline_state: state,
        extra: Default::default(),
    }
}

#[test]
fn envelope_has_contract_shape() {
    let mut fs = vec![
        finding("b", Severity::Low, None),
        finding("a", Severity::Critical, None),
        finding("a", Severity::Low, None),
    ];
    Finding::sort(&mut fs);
    let ids: Vec<_> = fs.iter().map(|f| (f.severity, f.id.as_str())).collect();
    assert_eq!(
        ids,
        [
            (Severity::Critical, "a"),
            (Severity::Low, "a"),
            (Severity::Low, "b")
        ]
    );
    let env = Envelope::new("t", "1.0.0", 1, Score::new(72, "t/1", 0), fs, json!({}));
    let v = env.to_value();
    let mut keys: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "data",
            "exit_code",
            "findings",
            "schema",
            "score",
            "tool",
            "version"
        ]
    );
    assert_eq!(v["schema"], "doctor/1");
    assert_eq!(v["score"]["label"], "needs work");
    for f in v["findings"].as_array().unwrap() {
        for k in [
            "id",
            "fingerprint",
            "severity",
            "category",
            "message",
            "location",
            "remedy",
        ] {
            assert!(f.get(k).is_some(), "missing {k}");
        }
        assert!(f["remedy"].is_null());
        assert!(f.get("baseline_state").is_none());
        let fp = f["fingerprint"].as_str().unwrap();
        assert!(fp.len() == 16 && fp.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')));
        assert!(Severity::parse(f["severity"].as_str().unwrap()).is_some());
        assert_eq!(f["location"]["ref"], "AA");
        assert_eq!(f["location"]["kind"], "device");
    }
    // round trip
    assert_eq!(serde_json::from_value::<Envelope>(v).unwrap(), env);
}

#[test]
fn baseline_and_extra_keys() {
    let mut f = finding("a", Severity::High, Some(BaselineState::New));
    f.extra.insert("detail".into(), json!(1));
    let mut env = Envelope::new("t", "1", 3, Score::new(100, "t/1", 0), vec![f], json!({}));
    env.baseline = Some(BaselineCounts {
        new: 1,
        unchanged: 0,
        fixed: 2,
    });
    let v = env.to_value();
    assert_eq!(v["baseline"], json!({"new": 1, "unchanged": 0, "fixed": 2}));
    assert_eq!(v["findings"][0]["baseline_state"], "new");
    assert_eq!(v["findings"][0]["detail"], 1);
}

#[test]
fn location_kinds_serialize_per_contract() {
    let kinds = [
        (LocationKind::File, "file"),
        (LocationKind::Flow, "flow"),
        (LocationKind::Frame, "frame"),
        (LocationKind::Image, "image"),
        (LocationKind::CardPath, "card-path"),
        (LocationKind::Device, "device"),
        (LocationKind::Service, "service"),
        (LocationKind::None, "none"),
    ];
    for (k, s) in kinds {
        assert_eq!(serde_json::to_value(k).unwrap(), s);
    }
}

#[test]
fn severity_vocab_and_sarif_levels() {
    assert!(Severity::Info < Severity::Low && Severity::High < Severity::Critical);
    assert_eq!(Severity::parse_legacy("error"), Some(Severity::Critical));
    assert_eq!(Severity::parse_legacy("warn"), Some(Severity::Low));
    assert_eq!(Severity::parse("warn"), None);
    let lv: Vec<_> = Severity::ALL.map(Severity::sarif_level).to_vec();
    assert_eq!(lv, ["note", "note", "warning", "error", "error"]);
    assert_eq!(serde_json::to_string(&Severity::High).unwrap(), "\"high\"");
}

#[test]
fn exit_codes_are_the_documented_numbers() {
    let c: Vec<_> = ExitCode::ALL.map(ExitCode::code).to_vec();
    assert_eq!(c, [0, 1, 2, 3, 130]);
}

#[test]
fn score_labels() {
    assert_eq!(score_label(100, 0), "good");
    assert_eq!(score_label(90, 0), "good");
    assert_eq!(score_label(90, 1), "incomplete");
    assert_eq!(score_label(89, 1), "needs work");
    assert_eq!(score_label(60, 0), "needs work");
    assert_eq!(score_label(59, 0), "critical");
    assert_eq!(Score::new(250, "t/1", 0).value, 100);
}

#[test]
fn fingerprint_is_sha256_prefix() {
    // sha256("abc") = ba7816bf8f01cfea...
    assert_eq!(fingerprint(b"abc"), "ba7816bf8f01cfea");
}

#[test]
fn sanitize_strips_section_8_set() {
    let evil = "a\x1b[31m\u{202e}b\u{2066}c\u{200b}d\u{feff}e\u{2028}f\u{2029}g\u{85}h";
    for out in [sanitize(evil), sanitize_spaced(evil)] {
        assert!(!out.chars().any(|c| c.is_control()
            || matches!(c as u32, 0x202A..=0x202E | 0x2066..=0x2069 | 0x200B..=0x200D | 0xFEFF | 0x2028 | 0x2029)));
        assert!(out.starts_with('a') && out.ends_with('h'));
    }
    assert_eq!(sanitize("a\x1bb\tc"), "ab c");
    assert_eq!(sanitize_spaced("a\x1bb"), "a b");
}

#[test]
fn sarif_document_carries_score_and_fingerprint_key() {
    let score = Score::new(80, "t/1", 0);
    let doc = sarif::document(
        "t",
        "1",
        "https://x",
        vec![],
        vec![json!({
            "partialFingerprints": sarif::partial_fingerprints("0123456789abcdef")
        })],
        &score,
    );
    assert_eq!(doc["version"], "2.1.0");
    let run = &doc["runs"][0];
    assert_eq!(run["properties"]["score"]["model"], "t/1");
    assert_eq!(
        run["results"][0]["partialFingerprints"]["doctorFinding/v1"],
        Value::from("0123456789abcdef")
    );
}
