//! Turning fuzzer bytes into FFI string arguments.
//!
//! Each target has a list of honest arguments captured from a real protocol
//! run. The first input byte selects how the fuzzer bytes replace them:
//!
//! * `0` (raw): one argument (chosen by the second byte) becomes the rest of
//!   the input verbatim, truncated at the first NUL as a C caller would.
//!   This reaches invalid UTF-8, broken JSON and type confusion.
//! * `1` (structured): one honest argument (chosen from the input) is taken
//!   as a JSON tree and a sequence of tree mutations driven by `arbitrary` is applied
//!   (replace numbers with edge values, splice subtrees, drop or duplicate
//!   array items, delete keys, corrupt hex strings, ...). This keeps inputs
//!   well-formed enough to reach the protocol code.
//! * `2` (text): byte-level edits (overwrite, insert, delete) applied to the
//!   serialized honest text of one argument.
//!
//! An input consisting of the single byte `1` or `2` reproduces the honest
//! call, so the seed corpus exercises the full success path.

use std::ffi::CString;

use arbitrary::{Result, Unstructured};
use serde_json::{Map, Number, Value};

/// One honest FFI string argument, with its rendered bytes cached (DKLs23
/// keyshares are several hundred KB of JSON).
pub struct Arg {
    value: Value,
    text: bool,
    bytes: Vec<u8>,
}

impl Arg {
    /// A JSON document (message list, keyshare, ...).
    pub fn json(value: Value) -> Self {
        let bytes =
            serde_json::to_vec(&value).expect("JSON values serialize");
        Arg {
            value,
            text: false,
            bytes,
        }
    }

    /// Plain text such as a derivation path or a hex signature. Structured
    /// mutations treat it as a JSON string.
    pub fn text(s: &str) -> Self {
        Arg {
            value: Value::String(s.to_owned()),
            text: true,
            bytes: s.as_bytes().to_vec(),
        }
    }

    fn render(&self, v: &Value) -> Vec<u8> {
        match v {
            Value::String(s) if self.text => s.clone().into_bytes(),
            _ => serde_json::to_vec(v).expect("JSON values serialize"),
        }
    }
}

/// A C string from arbitrary bytes, cut at the first NUL like `strlen`.
pub fn c_string(bytes: &[u8]) -> CString {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    CString::new(&bytes[..end]).expect("no interior NUL after truncation")
}

/// Build the C string arguments for one fuzz iteration. At most one
/// argument differs from the honest one.
pub fn args(data: &[u8], honest: &[Arg]) -> Vec<CString> {
    let fuzzed = match data.first().map(|m| m % 3) {
        None => None,
        Some(0) => {
            let idx =
                data.get(1).map_or(0, |&b| usize::from(b) % honest.len());
            Some((idx, data.get(2..).unwrap_or_default().to_vec()))
        }
        Some(1) => {
            let mut u = Unstructured::new(&data[1..]);
            let idx = u.choose_index(honest.len()).unwrap_or(0);
            let mut value = honest[idx].value.clone();
            let _ = mutate_tree(&mut value, &mut u);
            Some((idx, honest[idx].render(&value)))
        }
        Some(_) => {
            let mut u = Unstructured::new(&data[1..]);
            let idx = u.choose_index(honest.len()).unwrap_or(0);
            let mut bytes = honest[idx].bytes.clone();
            let _ = edit_text(&mut bytes, &mut u);
            Some((idx, bytes))
        }
    };
    honest
        .iter()
        .enumerate()
        .map(|(i, arg)| match &fuzzed {
            Some((idx, bytes)) if *idx == i => c_string(bytes),
            _ => c_string(&arg.bytes),
        })
        .collect()
}

// -------------------- Text edits --------------------

fn edit_text(text: &mut Vec<u8>, u: &mut Unstructured) -> Result<()> {
    for _ in 0..u.int_in_range(0..=16)? {
        let pos = if text.is_empty() {
            0
        } else {
            u.choose_index(text.len() + 1)?
        };
        match u.int_in_range(0..=3)? {
            0 if pos < text.len() => text[pos] = u.arbitrary()?,
            1 => {
                let bytes: Vec<u8> = u.arbitrary()?;
                text.splice(pos..pos, bytes);
            }
            2 => {
                let len = u.int_in_range(0..=64)?;
                let end = (pos + len).min(text.len());
                text.drain(pos..end);
            }
            _ => {
                // Duplicate a slice of the text somewhere else.
                let start =
                    u.choose_index(text.len().max(1))?.min(text.len());
                let len = u.int_in_range(0..=256)?;
                let end = (start + len).min(text.len());
                let chunk = text[start..end].to_vec();
                text.splice(pos..pos, chunk);
            }
        }
    }
    Ok(())
}

// -------------------- JSON tree mutations --------------------

const INTERESTING: &[i128] = &[
    0,
    1,
    2,
    3,
    4,
    7,
    8,
    15,
    16,
    31,
    32,
    33,
    63,
    64,
    65,
    127,
    128,
    255,
    256,
    257,
    65535,
    65536,
    u32::MAX as i128,
    u32::MAX as i128 + 1,
    u64::MAX as i128,
    -1,
    i64::MIN as i128,
];

const KEYS: &[&str] = &[
    "from_id",
    "to_id",
    "from",
    "party_id",
    "participant_id",
    "threshold",
    "rank_list",
    "x_i_list",
    "presignature_handle",
    "package",
    "commitments",
    "session_id",
];

fn number(n: i128) -> Value {
    if let Ok(v) = u64::try_from(n) {
        Value::Number(v.into())
    } else if let Ok(v) = i64::try_from(n) {
        Value::Number(v.into())
    } else {
        Value::Null
    }
}

fn mutate_tree(root: &mut Value, u: &mut Unstructured) -> Result<()> {
    for _ in 0..u.int_in_range(0..=8)? {
        let donor = pick(root, u)?.clone();
        let node = pick_mut(root, u)?;
        mutate_node(node, donor, u)?;
    }
    Ok(())
}

fn children(v: &Value) -> usize {
    match v {
        Value::Array(a) => a.len(),
        Value::Object(o) => o.len(),
        _ => 0,
    }
}

/// Random walk from the root; stops at a leaf or with probability 1/4.
fn pick<'a>(mut v: &'a Value, u: &mut Unstructured) -> Result<&'a Value> {
    loop {
        let n = children(v);
        if n == 0 || u.ratio(1, 4)? {
            return Ok(v);
        }
        let i = u.choose_index(n)?;
        v = match v {
            Value::Array(a) => &a[i],
            Value::Object(o) => o.values().nth(i).expect("index in range"),
            _ => unreachable!(),
        };
    }
}

fn pick_mut<'a>(
    mut v: &'a mut Value,
    u: &mut Unstructured,
) -> Result<&'a mut Value> {
    loop {
        let n = children(v);
        if n == 0 || u.ratio(1, 4)? {
            return Ok(v);
        }
        let i = u.choose_index(n)?;
        v = match v {
            Value::Array(a) => &mut a[i],
            Value::Object(o) => {
                o.values_mut().nth(i).expect("index in range")
            }
            _ => unreachable!(),
        };
    }
}

fn hex_string(u: &mut Unstructured) -> Result<String> {
    let len = match u.int_in_range(0..=5)? {
        0 => 0,
        1 => 32,
        2 => 33,
        3 => 64,
        4 => 65,
        _ => u.int_in_range(0..=200)?,
    };
    let bytes = match u.int_in_range(0..=2)? {
        0 => vec![0u8; len],
        1 => vec![0xffu8; len],
        _ => (0..len).map(|_| u.arbitrary()).collect::<Result<_>>()?,
    };
    Ok(hex::encode(bytes))
}

fn mutate_string(s: &mut String, u: &mut Unstructured) -> Result<()> {
    let mut bytes = std::mem::take(s).into_bytes();
    match u.int_in_range(0..=4)? {
        0 => {
            let len = u.choose_index(bytes.len() + 1)?;
            bytes.truncate(len);
        }
        1 if !bytes.is_empty() => {
            // Flip one hex nibble (or any ASCII char) in place.
            let i = u.choose_index(bytes.len())?;
            let digits = b"0123456789abcdef";
            bytes[i] = digits[u.choose_index(digits.len())?];
        }
        2 => {
            let extra: String = u.arbitrary()?;
            bytes.extend_from_slice(extra.as_bytes());
        }
        3 => {
            let copy = bytes.clone();
            bytes.extend_from_slice(&copy);
        }
        _ => bytes.extend_from_slice(b"00"),
    }
    *s = String::from_utf8_lossy(&bytes).into_owned();
    Ok(())
}

fn mutate_node(
    node: &mut Value,
    donor: Value,
    u: &mut Unstructured,
) -> Result<()> {
    match u.int_in_range(0..=15)? {
        0 => *node = number(*u.choose(INTERESTING)?),
        1 => *node = Value::Number(u.arbitrary::<u64>()?.into()),
        2 => *node = Value::Number(u.arbitrary::<i64>()?.into()),
        3 => *node = Value::String(u.arbitrary()?),
        4 => *node = Value::String(hex_string(u)?),
        5 => match node {
            Value::String(s) => mutate_string(s, u)?,
            _ => *node = Value::String(hex_string(u)?),
        },
        6 => {
            *node = match u.int_in_range(0..=4)? {
                0 => Value::Null,
                1 => Value::Bool(u.arbitrary()?),
                2 => Value::Object(Map::new()),
                3 => Value::Array(Vec::new()),
                _ => Number::from_f64(u.arbitrary()?)
                    .map_or(Value::Null, Value::Number),
            }
        }
        7 => {
            if let Value::Array(a) = node {
                if !a.is_empty() {
                    let i = u.choose_index(a.len())?;
                    a.remove(i);
                }
            }
        }
        8 => {
            if let Value::Array(a) = node {
                if !a.is_empty() {
                    let i = u.choose_index(a.len())?;
                    let item = a[i].clone();
                    a.insert(i, item);
                }
            }
        }
        9 => {
            if let Value::Array(a) = node {
                if !a.is_empty() {
                    let i = u.choose_index(a.len())?;
                    let j = u.choose_index(a.len())?;
                    a.swap(i, j);
                }
            }
        }
        10 => match node {
            Value::Array(a) => a.push(donor),
            _ => *node = Value::Array(vec![donor]),
        },
        11 => {
            if let Value::Object(o) = node {
                if !o.is_empty() {
                    let i = u.choose_index(o.len())?;
                    let key = o.keys().nth(i).expect("in range").clone();
                    o.remove(&key);
                }
            }
        }
        12 => {
            if let Value::Object(o) = node {
                let key = if u.arbitrary()? {
                    u.choose(KEYS)?.to_string()
                } else {
                    u.arbitrary()?
                };
                o.insert(key, donor);
            }
        }
        13 => *node = donor,
        14 => {
            if let Value::Number(n) = node {
                let v = n
                    .as_u64()
                    .map(i128::from)
                    .or_else(|| n.as_i64().map(i128::from))
                    .unwrap_or(0);
                let delta: i8 = u.arbitrary()?;
                *node = number(v + i128::from(delta));
            }
        }
        _ => {
            // Truncate a list to a prefix.
            if let Value::Array(a) = node {
                let len = u.choose_index(a.len() + 1)?;
                a.truncate(len);
            }
        }
    }
    Ok(())
}
