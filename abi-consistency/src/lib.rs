//! Source-level parser and comparer for `const NAME: ty = expr;` items.
//!
//! `kernel/` and the ring-3 hosts are deliberately standalone crates, so
//! values like heap sizes, boot-info virtual addresses and syscall numbers
//! are duplicated by hand. This library extracts those constants from the
//! Rust source text (no compilation) so `main.rs` can compare them.

use std::collections::HashMap;

/// Replace comments with spaces (newlines kept), leaving string and char
/// literals intact.
pub fn strip_comments(src: &str) -> String {
    let b: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        if c == '/' && next == Some('/') {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            let mut depth = 1;
            i += 2;
            while i < b.len() && depth > 0 {
                if b[i] == '/' && b.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if b[i] == '*' && b.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                } else {
                    if b[i] == '\n' {
                        out.push('\n');
                    }
                    i += 1;
                }
            }
            out.push(' ');
        } else if c == '"' {
            out.push(c);
            i += 1;
            while i < b.len() {
                out.push(b[i]);
                if b[i] == '\\' && i + 1 < b.len() {
                    out.push(b[i + 1]);
                    i += 2;
                    continue;
                }
                i += 1;
                if b[i - 1] == '"' {
                    break;
                }
            }
        } else if c == '\'' {
            // Char literal ('x' or '\x') vs lifetime ('a).
            let lit_len = if b.get(i + 1) == Some(&'\\') && b.get(i + 3) == Some(&'\'') {
                Some(4)
            } else if b.get(i + 2) == Some(&'\'') && b.get(i + 1) != Some(&'\\') {
                Some(3)
            } else {
                None
            };
            match lit_len {
                Some(n) => {
                    out.extend(&b[i..i + n]);
                    i += n;
                }
                None => {
                    out.push(c);
                    i += 1;
                }
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// One parsed `const` item: (name, type text, expression text), whitespace
/// normalized.
pub type ConstItem = (String, String, String);

fn squash_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Extract every `const NAME: TYPE = EXPR;` (any visibility, any nesting).
/// `const fn`, `*const T` and `const` generics do not match because a
/// `:` must follow the identifier.
pub fn parse_consts(src: &str) -> Vec<ConstItem> {
    let s: Vec<char> = strip_comments(src).chars().collect();
    let mut items = Vec::new();
    let mut i = 0;
    while i < s.len() {
        let at_word_start = i == 0 || !is_ident_char(s[i - 1]);
        if at_word_start
            && s[i..].starts_with(&['c', 'o', 'n', 's', 't'])
            && s.get(i + 5).is_some_and(|c| c.is_whitespace())
        {
            let mut j = i + 5;
            while s.get(j).is_some_and(|c| c.is_whitespace()) {
                j += 1;
            }
            let name_start = j;
            while s.get(j).is_some_and(|c| is_ident_char(*c)) {
                j += 1;
            }
            let name: String = s[name_start..j].iter().collect();
            while s.get(j).is_some_and(|c| c.is_whitespace()) {
                j += 1;
            }
            if !name.is_empty() && s.get(j) == Some(&':') {
                j += 1;
                let ty_start = j;
                let mut depth = 0i32;
                while j < s.len() {
                    match s[j] {
                        '[' | '(' | '<' => depth += 1,
                        ']' | ')' | '>' => depth -= 1,
                        '=' | ';' if depth <= 0 => break,
                        _ => {}
                    }
                    j += 1;
                }
                if s.get(j) == Some(&'=') {
                    let ty: String = s[ty_start..j].iter().collect();
                    j += 1;
                    let ex_start = j;
                    let mut depth = 0i32;
                    let mut in_str = false;
                    while j < s.len() {
                        let c = s[j];
                        if in_str {
                            if c == '\\' {
                                j += 1;
                            } else if c == '"' {
                                in_str = false;
                            }
                        } else {
                            match c {
                                '\'' if s.get(j + 2) == Some(&'\'') => j += 2,
                                '\'' if s.get(j + 1) == Some(&'\\')
                                    && s.get(j + 3) == Some(&'\'') =>
                                {
                                    j += 3
                                }
                                '"' => in_str = true,
                                '[' | '(' | '{' => depth += 1,
                                ']' | ')' | '}' => depth -= 1,
                                ';' if depth <= 0 => break,
                                _ => {}
                            }
                        }
                        j += 1;
                    }
                    let expr: String = s[ex_start..j.min(s.len())].iter().collect();
                    items.push((name, squash_ws(&ty), squash_ws(&expr)));
                    i = j;
                    continue;
                }
            }
        }
        i += 1;
    }
    items
}

/// All constants of one source file, by name.
#[derive(Debug, Default, Clone)]
pub struct ConstTable {
    exprs: HashMap<String, Vec<String>>,
}

impl ConstTable {
    pub fn from_source(src: &str) -> Self {
        let mut exprs: HashMap<String, Vec<String>> = HashMap::new();
        for (name, _ty, expr) in parse_consts(src) {
            exprs.entry(name).or_default().push(expr);
        }
        ConstTable { exprs }
    }

    pub fn names(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.exprs.keys().map(String::as_str).collect();
        v.sort_unstable();
        v
    }

    pub fn contains(&self, name: &str) -> bool {
        self.exprs.contains_key(name)
    }

    /// Evaluate a constant by name. Duplicate definitions (e.g. one in a
    /// `#[cfg(test)]` module) are fine if they all evaluate equal.
    pub fn value(&self, name: &str) -> Result<i128, String> {
        self.value_depth(name, 0)
    }

    fn value_depth(&self, name: &str, depth: u32) -> Result<i128, String> {
        if depth > 32 {
            return Err(format!("const `{name}`: reference chain too deep"));
        }
        let defs = self
            .exprs
            .get(name)
            .ok_or_else(|| format!("const `{name}` not found"))?;
        let mut found: Option<i128> = None;
        for e in defs {
            let v = eval_expr(e, &|n| self.value_depth(n, depth + 1))
                .map_err(|m| format!("const `{name}` = `{e}`: {m}"))?;
            match found {
                Some(prev) if prev != v => {
                    return Err(format!(
                        "const `{name}` is defined more than once with different values"
                    ))
                }
                _ => found = Some(v),
            }
        }
        found.ok_or_else(|| format!("const `{name}` not found"))
    }
}

#[derive(Debug, PartialEq, Clone)]
enum Tok {
    Num(i128),
    Ident(String),
    Op(char),
    Shl,
    Shr,
}

fn tokenize(e: &str) -> Result<Vec<Tok>, String> {
    let c: Vec<char> = e.chars().collect();
    let mut t = Vec::new();
    let mut i = 0;
    while i < c.len() {
        let ch = c[i];
        if ch.is_whitespace() {
            i += 1;
        } else if ch.is_ascii_digit() {
            let (radix, mut j) = match (ch, c.get(i + 1)) {
                ('0', Some('x')) => (16, i + 2),
                ('0', Some('b')) => (2, i + 2),
                ('0', Some('o')) => (8, i + 2),
                _ => (10, i),
            };
            let mut digits = String::new();
            while j < c.len() && (c[j] == '_' || c[j].is_digit(radix)) {
                if c[j] != '_' {
                    digits.push(c[j]);
                }
                j += 1;
            }
            // Optional type suffix (u64, usize, i32 ...).
            if j < c.len() && (c[j] == 'u' || c[j] == 'i') {
                while j < c.len() && is_ident_char(c[j]) {
                    j += 1;
                }
            }
            let v = i128::from_str_radix(&digits, radix).map_err(|_| {
                format!(
                    "bad integer literal near `{}`",
                    c[i..j].iter().collect::<String>()
                )
            })?;
            t.push(Tok::Num(v));
            i = j;
        } else if ch.is_alphabetic() || ch == '_' {
            let mut j = i;
            while j < c.len() && (is_ident_char(c[j]) || c[j] == ':') {
                j += 1;
            }
            t.push(Tok::Ident(c[i..j].iter().collect()));
            i = j;
        } else if ch == '<' && c.get(i + 1) == Some(&'<') {
            t.push(Tok::Shl);
            i += 2;
        } else if ch == '>' && c.get(i + 1) == Some(&'>') {
            t.push(Tok::Shr);
            i += 2;
        } else if "+-*/()|&".contains(ch) {
            t.push(Tok::Op(ch));
            i += 1;
        } else {
            return Err(format!(
                "unsupported token `{ch}` (not a simple integer expression)"
            ));
        }
    }
    Ok(t)
}

type Lookup<'a> = &'a dyn Fn(&str) -> Result<i128, String>;

struct Parser<'a> {
    t: Vec<Tok>,
    p: usize,
    lookup: Lookup<'a>,
}

/// Evaluate a simple integer expression: literals, same-file const names
/// (via `lookup`), `+ - * / << >> | &`, parentheses, and `as <type>` casts
/// (ignored; the checker compares mathematical values).
pub fn eval_expr(e: &str, lookup: Lookup<'_>) -> Result<i128, String> {
    let mut p = Parser {
        t: tokenize(e)?,
        p: 0,
        lookup,
    };
    let v = p.or()?;
    if p.p != p.t.len() {
        return Err("trailing tokens in expression".to_string());
    }
    Ok(v)
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.t.get(self.p)
    }
    fn skip_casts(&mut self) {
        while matches!(self.peek(), Some(Tok::Ident(s)) if s == "as") {
            self.p += 2;
        }
    }
    fn or(&mut self) -> Result<i128, String> {
        let mut v = self.and()?;
        while self.peek() == Some(&Tok::Op('|')) {
            self.p += 1;
            v |= self.and()?;
        }
        Ok(v)
    }
    fn and(&mut self) -> Result<i128, String> {
        let mut v = self.shift()?;
        while self.peek() == Some(&Tok::Op('&')) {
            self.p += 1;
            v &= self.shift()?;
        }
        Ok(v)
    }
    fn shift(&mut self) -> Result<i128, String> {
        let mut v = self.sum()?;
        loop {
            match self.peek() {
                Some(Tok::Shl) => {
                    self.p += 1;
                    let r = self.sum()?;
                    v = u32::try_from(r)
                        .ok()
                        .and_then(|r| v.checked_shl(r))
                        .ok_or("shift overflow")?;
                }
                Some(Tok::Shr) => {
                    self.p += 1;
                    let r = self.sum()?;
                    v = u32::try_from(r)
                        .ok()
                        .and_then(|r| v.checked_shr(r))
                        .ok_or("shift overflow")?;
                }
                _ => return Ok(v),
            }
        }
    }
    fn sum(&mut self) -> Result<i128, String> {
        let mut v = self.prod()?;
        loop {
            match self.peek() {
                Some(Tok::Op('+')) => {
                    self.p += 1;
                    v = v.checked_add(self.prod()?).ok_or("overflow")?;
                }
                Some(Tok::Op('-')) => {
                    self.p += 1;
                    v = v.checked_sub(self.prod()?).ok_or("overflow")?;
                }
                _ => return Ok(v),
            }
        }
    }
    fn prod(&mut self) -> Result<i128, String> {
        let mut v = self.atom()?;
        loop {
            match self.peek() {
                Some(Tok::Op('*')) => {
                    self.p += 1;
                    v = v.checked_mul(self.atom()?).ok_or("overflow")?;
                }
                Some(Tok::Op('/')) => {
                    self.p += 1;
                    v = v.checked_div(self.atom()?).ok_or("division by zero")?;
                }
                _ => return Ok(v),
            }
        }
    }
    fn atom(&mut self) -> Result<i128, String> {
        let tok = self.peek().cloned().ok_or("unexpected end of expression")?;
        self.p += 1;
        let v = match tok {
            Tok::Num(n) => n,
            // Paths such as `u64::MAX` or `runix_ipc::X` and anything not
            // defined in the same file are errors, never guessed.
            Tok::Ident(name) => (self.lookup)(&name)?,
            Tok::Op('(') => {
                let v = self.or()?;
                if self.peek() != Some(&Tok::Op(')')) {
                    return Err("missing `)`".to_string());
                }
                self.p += 1;
                v
            }
            other => return Err(format!("unexpected token {other:?}")),
        };
        self.skip_casts();
        Ok(v)
    }
}

/// Fields (`name: type`) of `struct NAME { .. }`, types whitespace-
/// normalized with array lengths evaluated through `env`.
pub fn parse_struct_fields(
    src: &str,
    struct_name: &str,
    env: Lookup<'_>,
) -> Result<Vec<(String, String)>, String> {
    let s = strip_comments(src);
    let needle = format!("struct {struct_name}");
    let mut from = 0;
    let start = loop {
        let idx = s[from..]
            .find(&needle)
            .ok_or_else(|| format!("struct `{struct_name}` not found"))?
            + from;
        let after = idx + needle.len();
        if s[after..].trim_start().starts_with('{') {
            break after;
        }
        from = after;
    };
    let open = s[start..]
        .find('{')
        .map(|o| o + start)
        .ok_or("missing `{`")?;
    let close = s[open..].find('}').map(|o| o + open).ok_or("missing `}`")?;
    let mut fields = Vec::new();
    for raw in s[open + 1..close].split(',') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let (n, t) = raw
            .split_once(':')
            .ok_or_else(|| format!("cannot parse field `{raw}`"))?;
        fields.push((
            n.trim().trim_start_matches("pub ").to_string(),
            normalize_type(t, env)?,
        ));
    }
    Ok(fields)
}

fn normalize_type(t: &str, env: Lookup<'_>) -> Result<String, String> {
    let t = squash_ws(t);
    if let Some(inner) = t.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
        if let Some((elem, len)) = inner.rsplit_once(';') {
            let n = eval_expr(len.trim(), env)?;
            return Ok(format!("[{}; {n}]", elem.trim()));
        }
    }
    Ok(t)
}

/// One side of a comparison: a const in a file (path relative to repo root).
#[derive(Debug, Clone, PartialEq)]
pub struct Loc {
    pub file: String,
    pub name: String,
}

pub fn loc(file: &str, name: &str) -> Loc {
    Loc {
        file: file.to_string(),
        name: name.to_string(),
    }
}

/// Compare two already-evaluated sides; the message names both files.
pub fn compare(
    a: &Loc,
    av: Result<i128, String>,
    b: &Loc,
    bv: Result<i128, String>,
) -> Result<(), String> {
    match (av, bv) {
        (Ok(x), Ok(y)) if x == y => Ok(()),
        (Ok(x), Ok(y)) => Err(format!(
            "MISMATCH: {}::{} = {x:#x} but {}::{} = {y:#x}",
            a.file, a.name, b.file, b.name
        )),
        (Err(e), _) => Err(format!(
            "{}: {e} (paired with {}::{})",
            a.file, b.file, b.name
        )),
        (_, Err(e)) => Err(format!(
            "{}: {e} (paired with {}::{})",
            b.file, a.file, a.name
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn none(n: &str) -> Result<i128, String> {
        Err(format!("unresolved `{n}`"))
    }

    #[test]
    fn parses_hex_with_underscores_and_pub() {
        let t = ConstTable::from_source("pub const HEAP_START: usize = 0x_0999_1111_0000;\n");
        assert_eq!(t.value("HEAP_START"), Ok(0x0999_1111_0000));
        let t = ConstTable::from_source(
            "pub(crate) const A: u64 = 0x_2222_2222_0000; // c\nconst B: u8 = 1;",
        );
        assert_eq!(t.value("A"), Ok(0x2222_2222_0000));
        assert_eq!(t.value("B"), Ok(1));
    }

    #[test]
    fn evaluates_simple_expressions_and_refs() {
        let src = "const S: usize = 4 * 1024 * 1024;\nconst O: usize = 0;\nconst L: usize = 16;\n\
                   const D: usize = O + L;\nconst X: u64 = (1 << 12) as u64 + 0x10u64;\n\
                   const M: usize = runix_ipc::M as usize;";
        let t = ConstTable::from_source(src);
        assert_eq!(t.value("S"), Ok(4 * 1024 * 1024));
        assert_eq!(t.value("D"), Ok(16));
        assert_eq!(t.value("X"), Ok(4096 + 16));
        assert!(
            t.value("M").is_err(),
            "unresolvable path must error, not guess"
        );
        assert!(t.value("NOPE").unwrap_err().contains("not found"));
    }

    #[test]
    fn ignores_comments_strings_fns_and_array_types() {
        let src = "// const FAKE: u8 = 9;\n/* const FAKE2: u8 = 8; */\n\
                   const fn f() {}\nstatic P: *const u8 = 0 as *const u8;\n\
                   const NAME: [u8; 11] = *b\"HELLO   TXT\";\nconst REAL: u8 = 7; // trailing ; ok\n\
                   const Q: u8 = b'\"' as u8;\nconst AFTER: u8 = 3;";
        let t = ConstTable::from_source(src);
        assert!(!t.contains("FAKE") && !t.contains("FAKE2"));
        assert_eq!(t.value("REAL"), Ok(7));
        assert_eq!(
            t.value("AFTER"),
            Ok(3),
            "char literal must not derail the scanner"
        );
        assert!(t.value("NAME").is_err());
    }

    #[test]
    fn duplicate_definitions_must_agree() {
        let t = ConstTable::from_source("const A: u8 = 1;\nmod m { const A: u8 = 1; }");
        assert_eq!(t.value("A"), Ok(1));
        let t = ConstTable::from_source("const A: u8 = 1;\nmod m { const A: u8 = 2; }");
        assert!(t.value("A").unwrap_err().contains("more than once"));
    }

    #[test]
    fn compare_reports_both_files_on_mismatch() {
        let a = loc("host/main.rs", "HEAP_SIZE");
        let b = loc("kernel/main.rs", "HEAP_SIZE");
        assert!(compare(&a, Ok(8), &b, Ok(8)).is_ok());
        let e = compare(&a, Ok(8 * 1024 * 1024), &b, Ok(4 * 1024 * 1024)).unwrap_err();
        assert!(
            e.contains("host/main.rs") && e.contains("kernel/main.rs") && e.contains("MISMATCH"),
            "{e}"
        );
        let e = compare(&a, Ok(1), &b, none("HEAP_SIZE")).unwrap_err();
        assert!(
            e.contains("kernel/main.rs") && e.contains("host/main.rs"),
            "{e}"
        );
    }

    #[test]
    fn struct_fields_resolve_array_lengths() {
        let src = "#[repr(C)]\nstruct Info {\n    io_base: u16,\n    // c\n    _pad: u16,\n    bufs: [u64; N],\n    last: u8,\n}";
        let env = |n: &str| if n == "N" { Ok(8) } else { none(n) };
        let f = parse_struct_fields(src, "Info", &env).unwrap();
        assert_eq!(f[2], ("bufs".to_string(), "[u64; 8]".to_string()));
        assert_eq!(f.len(), 4);
        let g = parse_struct_fields(&src.replace("N]", "9]"), "Info", &env).unwrap();
        assert_ne!(f, g);
    }
}
