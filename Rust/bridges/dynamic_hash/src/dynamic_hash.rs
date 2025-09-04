/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */
use std::cell::OnceCell;

use crate::{Expr, eval::EvalContext, interop::ThreadContext, parse};

thread_local! {
    static AST: OnceCell<Expr> = OnceCell::new();
}

pub(crate) fn calc_hash(password: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut eval_ctx = EvalContext::new();
    eval_ctx.set_var("p", password);
    eval_ctx.set_var("s", salt);
    if salt.contains(&b'*') {
        for (i, s) in salt.split(|&b| b == b'*').enumerate() {
            eval_ctx.set_var(format!("s{}", i + 1), s);
        }
    }
    AST.with(|c| {
        let ast = c.get().expect("no algorithm");
        eval_ctx.eval(ast)
    })
    .unwrap_or_default()
}

pub(crate) fn thread_init(ctx: &mut ThreadContext) {
    let ast = parse::parse(&ctx.bridge_parameter2).expect("invalid algorithm description");
    AST.with(|c| {
        c.set(ast).unwrap_or_default();
    });
}

pub(crate) fn thread_term(_ctx: &mut ThreadContext) {}
