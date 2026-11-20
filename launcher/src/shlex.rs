//! POSIX shell word quoting and splitting with Python's `shlex` semantics.

fn is_safe(character: char) -> bool {
    character.is_ascii_alphanumeric() || "_@%+=:,./-".contains(character)
}

pub fn quote(word: &str) -> String {
    if word.is_empty() {
        return "''".to_string();
    }
    if word.chars().all(is_safe) {
        return word.to_string();
    }
    format!("'{}'", word.replace('\'', "'\"'\"'"))
}

pub fn join<S: AsRef<str>>(words: &[S]) -> String {
    words
        .iter()
        .map(|word| quote(word.as_ref()))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Splits like `shlex.split(text)`: quotes group, a backslash escapes, no comments.
pub fn split(text: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut started = false;
    let mut chars = text.chars();
    while let Some(character) = chars.next() {
        match character {
            ' ' | '\t' | '\r' | '\n' => {
                if started {
                    words.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            '\\' => {
                current.push(chars.next().ok_or("No escaped character")?);
                started = true;
            }
            '\'' => {
                started = true;
                loop {
                    match chars.next().ok_or("No closing quotation")? {
                        '\'' => break,
                        other => current.push(other),
                    }
                }
            }
            '"' => {
                started = true;
                loop {
                    match chars.next().ok_or("No closing quotation")? {
                        '"' => break,
                        '\\' => {
                            let escaped = chars.next().ok_or("No closing quotation")?;
                            if escaped != '"' && escaped != '\\' {
                                current.push('\\');
                            }
                            current.push(escaped);
                        }
                        other => current.push(other),
                    }
                }
            }
            other => {
                current.push(other);
                started = true;
            }
        }
    }
    if started {
        words.push(current);
    }
    Ok(words)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_matches_python() {
        assert_eq!(quote(""), "''");
        assert_eq!(quote("/a/b-c_d.e"), "/a/b-c_d.e");
        assert_eq!(quote("Proton with spaces"), "'Proton with spaces'");
        assert_eq!(quote("it's"), "'it'\"'\"'s'");
        assert_eq!(join(&["a b", "c"]), "'a b' c");
    }

    #[test]
    fn splitting_round_trips_quoted_words() {
        let words = ["/p/Proton with spaces/proton", "%verb%", "it's", "", "x\"y"];
        assert_eq!(split(&join(&words)).unwrap(), words);
        assert_eq!(
            split("'/p/Proton x'/proton %verb%").unwrap(),
            ["/p/Proton x/proton", "%verb%"]
        );
        assert_eq!(split("a\\ b \"c\\\"d\\e\"").unwrap(), ["a b", "c\"d\\e"]);
    }

    #[test]
    fn unterminated_input_is_an_error() {
        assert!(split("'open").is_err());
        assert!(split("trailing\\").is_err());
    }
}
