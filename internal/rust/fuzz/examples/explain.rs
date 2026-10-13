//! Show how a crash input changes the honest arguments of a target.
//! usage: explain <dkls_keyshare|frost_keyshare|...> <file>
use mpc_ffi_fuzz::input::{args, Arg};
use serde_json::Value;

fn diff(path: &str, a: &Value, b: &Value) {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            for (k, v) in x {
                match y.get(k) {
                    Some(w) => diff(&format!("{path}.{k}"), v, w),
                    None => println!("{path}.{k}: removed"),
                }
            }
            for (k, w) in y {
                if !x.contains_key(k) {
                    println!("{path}.{k}: added {}", trunc(w))
                }
            }
        }
        (Value::Array(x), Value::Array(y)) if x.len() == y.len() => {
            for (i, (v, w)) in x.iter().zip(y).enumerate() {
                diff(&format!("{path}[{i}]"), v, w)
            }
        }
        _ if a != b => println!("{path}: {} -> {}", trunc(a), trunc(b)),
        _ => {}
    }
}
fn trunc(v: &Value) -> String {
    let s = v.to_string();
    if s.len() > 200 {
        format!(
            "{}... (len {})",
            &s[..200],
            match v {
                Value::Array(a) => a.len(),
                _ => s.len(),
            }
        )
    } else {
        s
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let data = std::fs::read(&a[2]).unwrap();
    let honest: Vec<Value> = match a[1].as_str() {
        "dkls_keyshare" => {
            let f = mpc_ffi_fuzz::dkls_fixture::dkls();
            vec![
                f.keyshares[0].clone(),
                Value::String(mpc_ffi_fuzz::dkls_fixture::PATH.into()),
            ]
        }
        "dkls_dsg1" => {
            vec![mpc_ffi_fuzz::dkls_fixture::dkls().dsg_input[0].clone()]
        }
        "dkls_dsg2" => {
            vec![mpc_ffi_fuzz::dkls_fixture::dkls().dsg_input[1].clone()]
        }
        "dkls_dsg3" => {
            vec![mpc_ffi_fuzz::dkls_fixture::dkls().dsg_input[2].clone()]
        }
        "dkls_combine" => {
            let f = mpc_ffi_fuzz::dkls_fixture::dkls();
            vec![f.partial.clone(), f.msg4_others.clone()]
        }
        "frost_keyshare" => {
            vec![mpc_ffi_fuzz::frost_fixture::frost().keyshares[0].clone()]
        }
        "frost_commit" => vec![mpc_ffi_fuzz::frost_fixture::frost()
            .commitments_others
            .clone()],
        "frost_combine" => {
            let f = mpc_ffi_fuzz::frost_fixture::frost();
            vec![f.bundle.clone(), f.bundles_others.clone()]
        }
        "frost_dkg1" => {
            vec![mpc_ffi_fuzz::frost_fixture::frost().dkg_msg1_others.clone()]
        }
        "frost_dkg2" => {
            vec![mpc_ffi_fuzz::frost_fixture::frost().dkg_msg2_to_me.clone()]
        }
        other => panic!("unknown {other}"),
    };
    let wrapped: Vec<Arg> = honest
        .iter()
        .map(|v| match v {
            Value::String(s) if !s.starts_with('{') => Arg::text(s),
            _ => Arg::json(v.clone()),
        })
        .collect();
    let out = args(&data, &wrapped);
    println!("mode {}", data[0] % 3);
    for (i, (c, h)) in out.iter().zip(&honest).enumerate() {
        let s = c.to_string_lossy();
        match serde_json::from_str::<Value>(&s) {
            Ok(v) => {
                println!("arg {i}:");
                diff("", h, &v)
            }
            Err(e) => println!(
                "arg {i} (not JSON: {e}): {}",
                if s.len() > 300 { &s[..300] } else { &s }
            ),
        }
    }
}
