/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */
use std::cell::OnceCell;

use crate::{Expr, eval::EvalContext, interop::Context, parse};

thread_local! {
    static AST: OnceCell<Expr> = OnceCell::new();
}

pub(crate) fn calc_hash(password: &[u8], salt: &[u8]) -> String {
    let mut eval_ctx = EvalContext::new();
    eval_ctx.set_var("p", password);
    eval_ctx.set_var("s", salt);
    if salt.contains(&b'*') {
        for (i, s) in salt.split(|&b| b == b'*').enumerate() {
            eval_ctx.set_var(format!("s{}", i + 1), s);
        }
    }
    let result = AST.with(|c| {
        let ast = c.get().expect("no algorithm");
        eval_ctx.eval(ast)
    });
    if let Ok(v) = result
        && let Ok(digest) = String::from_utf8(v)
    {
        digest
    } else {
        String::new()
    }
}

pub(crate) fn thread_init(ctx: &mut Context) {
    match parse::parse(&ctx.bridge_parameter2) {
        Ok(ast) => {
            AST.with(|c| {
                c.set(ast).unwrap_or_default();
            });
        }
        Err(err) => {
            eprintln!("ERROR: failed to parse --bridge-parameter2 value: {}", err);
        }
    };
}

#[allow(unused_variables)]
pub(crate) fn thread_term(ctx: &mut Context) {}
