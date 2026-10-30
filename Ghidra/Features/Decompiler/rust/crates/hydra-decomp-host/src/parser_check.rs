// Shared by src/lib.rs (as a module) and build.rs (through include!), so keep it dependency-free.

/// Names of the bison parser globals in a generated parser (`prefix` = the parser's name prefix,
/// e.g. `xml` for `xmllval`) that are not declared `thread_local`. Empty means the D10 edits are in.
pub fn missing_thread_local(src: &str, prefix: &str) -> Vec<String> {
    let mut v = Vec::new();
    for (name, decl) in [
        ("yychar", "int yychar;"),
        ("yylval", "YYSTYPE yylval;"),
        ("yynerrs", "int yynerrs;"),
    ] {
        if !src.contains(&format!("thread_local {decl}")) {
            v.push(name.to_string());
        }
    }
    let ext = format!(
        "extern thread_local {}STYPE {prefix}lval;",
        prefix.to_uppercase()
    );
    if !src.contains(&ext) {
        v.push(format!("extern {prefix}lval"));
    }
    v
}
