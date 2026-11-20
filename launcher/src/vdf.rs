//! Valve KeyValues text files (`toolmanifest.vdf`) with the behaviour of umu's `vdf` module.

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Text(String),
    Map(Map),
}

/// An insertion-ordered map; assigning an existing key keeps its position.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Map(Vec<(String, Value)>);

impl Map {
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        self.0
            .iter_mut()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    }

    pub fn text(&self, key: &str) -> Option<&str> {
        match self.get(key) {
            Some(Value::Text(text)) => Some(text),
            _ => None,
        }
    }

    pub fn map(&self, key: &str) -> Option<&Map> {
        match self.get(key) {
            Some(Value::Map(map)) => Some(map),
            _ => None,
        }
    }

    pub fn insert(&mut self, key: impl Into<String>, value: Value) {
        let key = key.into();
        match self.get_mut(&key) {
            Some(slot) => *slot = value,
            None => self.0.push((key, value)),
        }
    }

    pub fn set_text(&mut self, key: &str, text: impl Into<String>) {
        self.insert(key, Value::Text(text.into()));
    }

    pub fn iter(&self) -> impl Iterator<Item = &(String, Value)> {
        self.0.iter()
    }
}

const ESCAPES: [(char, &str); 11] = [
    ('\n', "\\n"),
    ('\t', "\\t"),
    ('\u{b}', "\\v"),
    ('\u{8}', "\\b"),
    ('\r', "\\r"),
    ('\u{c}', "\\f"),
    ('\u{7}', "\\a"),
    ('\\', "\\\\"),
    ('?', "\\?"),
    ('"', "\\\""),
    ('\'', "\\'"),
];

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match ESCAPES.iter().find(|(plain, _)| *plain == character) {
            Some((_, escaped)) => out.push_str(escaped),
            None => out.push(character),
        }
    }
    out
}

fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '\\'
            && let Some(next) = chars.peek().copied()
            && let Some((plain, _)) = ESCAPES
                .iter()
                .find(|(_, escaped)| escaped.chars().nth(1) == Some(next))
        {
            out.push(*plain);
            chars.next();
            continue;
        }
        out.push(character);
    }
    out
}

#[derive(Debug, PartialEq)]
enum Token {
    Text(String),
    Open,
    Close,
}

fn tokenize(text: &str) -> Result<Vec<Token>, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        match chars[index] {
            c if c.is_whitespace() => index += 1,
            '/' if chars.get(index + 1) == Some(&'/') => {
                while index < chars.len() && chars[index] != '\n' {
                    index += 1;
                }
            }
            '{' => {
                index += 1;
                tokens.push(Token::Open);
            }
            '}' => {
                index += 1;
                tokens.push(Token::Close);
            }
            '"' => {
                index += 1;
                let mut raw = String::new();
                loop {
                    match chars.get(index) {
                        None => return Err("vdf: unexpected EOF (open quote)".into()),
                        Some('"') => break,
                        Some('\\') => {
                            let escaped = chars
                                .get(index + 1)
                                .ok_or("vdf: unexpected EOF (open quote)")?;
                            raw.push('\\');
                            raw.push(*escaped);
                            index += 2;
                        }
                        Some(other) => {
                            raw.push(*other);
                            index += 1;
                        }
                    }
                }
                index += 1;
                tokens.push(Token::Text(unescape(&raw)));
            }
            _ => {
                let mut raw = String::new();
                while let Some(&c) = chars.get(index) {
                    if c.is_whitespace() || "{}\"".contains(c) {
                        break;
                    }
                    raw.push(c);
                    index += 1;
                }
                tokens.push(Token::Text(unescape(&raw)));
            }
        }
    }
    Ok(tokens)
}

fn parse_block(
    tokens: &mut std::vec::IntoIter<Token>,
    into: &mut Map,
    nested: bool,
) -> Result<(), String> {
    loop {
        let key = match tokens.next() {
            None if nested => return Err("vdf: unclosed parenthesis (EOF)".into()),
            None => return Ok(()),
            Some(Token::Close) if nested => return Ok(()),
            Some(Token::Close) => return Err("vdf: one too many closing parenthesis".into()),
            Some(Token::Open) => return Err("vdf: unexpected opening bracket".into()),
            Some(Token::Text(key)) => key,
        };
        match tokens.next() {
            Some(Token::Text(value)) => into.set_text(&key, value),
            Some(Token::Open) => {
                // Repeated blocks merge, as umu does; a scalar of the same name is replaced.
                if !matches!(into.get(&key), Some(Value::Map(_))) {
                    into.insert(key.clone(), Value::Map(Map::default()));
                }
                let Some(Value::Map(child)) = into.get_mut(&key) else {
                    unreachable!("the key was just set to a map");
                };
                parse_block(tokens, child, true)?;
            }
            Some(Token::Close) | None => return Err(format!("vdf: key {key:?} has no value")),
        }
    }
}

pub fn parse(text: &str) -> Result<Map, String> {
    let mut tokens = tokenize(text)?.into_iter();
    let mut root = Map::default();
    parse_block(&mut tokens, &mut root, false)?;
    Ok(root)
}

fn dump_into(out: &mut String, map: &Map, level: usize) {
    let indent = "\t".repeat(level);
    for (key, value) in map.iter() {
        match value {
            Value::Map(child) => {
                out.push_str(&format!("{indent}\"{}\"\n{indent}{{\n", escape(key)));
                dump_into(out, child, level + 1);
                out.push_str(&format!("{indent}}}\n"));
            }
            Value::Text(text) => {
                out.push_str(&format!(
                    "{indent}\"{}\" \"{}\"\n",
                    escape(key),
                    escape(text)
                ));
            }
        }
    }
}

/// The pretty form (`vdf.dump(..., pretty=True)`).
pub fn dump(map: &Map) -> String {
    let mut out = String::new();
    dump_into(&mut out, map, 0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = "\"manifest\"\n{\n  \"version\" \"2\"\n  \"commandline\" \"/proton %verb%\"\n  \"require_tool_appid\" \"4183110\"\n}\n";

    #[test]
    fn parses_a_tool_manifest() {
        let document = parse(MANIFEST).unwrap();
        let manifest = document.map("manifest").unwrap();
        assert_eq!(manifest.text("commandline"), Some("/proton %verb%"));
        assert_eq!(manifest.text("require_tool_appid"), Some("4183110"));
        assert_eq!(manifest.text("missing"), None);
    }

    #[test]
    fn dump_is_tab_indented_and_round_trips() {
        let document = parse(MANIFEST).unwrap();
        let text = dump(&document);
        assert_eq!(
            text,
            "\"manifest\"\n{\n\t\"version\" \"2\"\n\t\"commandline\" \"/proton %verb%\"\n\t\"require_tool_appid\" \"4183110\"\n}\n"
        );
        assert_eq!(parse(&text).unwrap(), document);
    }

    #[test]
    fn special_characters_use_umus_escapes() {
        let mut manifest = Map::default();
        manifest.set_text("commandline", "/proton 'a b' \"q\" back\\slash why?");
        let mut document = Map::default();
        document.insert("manifest", Value::Map(manifest));
        let text = dump(&document);
        assert!(
            text.contains(r#""/proton \'a b\' \"q\" back\\slash why\?""#),
            "{text}"
        );
        assert_eq!(parse(&text).unwrap(), document);
    }

    #[test]
    fn comments_bom_and_duplicates_are_handled() {
        let document =
            parse("\u{feff}// note\n\"a\" { \"x\" \"1\" }\n\"a\" { \"y\" \"2\" \"x\" \"3\" }\n")
                .unwrap();
        let a = document.map("a").unwrap();
        assert_eq!(a.text("x"), Some("3"));
        assert_eq!(a.text("y"), Some("2"));
        assert_eq!(a.iter().next().unwrap().0, "x");
    }

    #[test]
    fn malformed_input_is_rejected() {
        assert!(parse("\"a\" {").is_err());
        assert!(parse("}").is_err());
        assert!(parse("\"a\" \"unterminated").is_err());
        assert!(parse("\"key\"").is_err());
    }
}
