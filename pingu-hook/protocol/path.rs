//! The two compatibility paths pingu-hook implements and how a process picks
//! one. The runtime reads [`HookPath::ENV`] once at load time.

/// Which protocol a process speaks with its game.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HookPath {
    /// The Reflex/Denuvo protocol (`reflex64.dll`, early `artifact.dll`).
    Reflex = 0,
    /// The Artifact VBS 1.9 and 2.0 protocol.
    Artifact = 1,
}

impl HookPath {
    /// Environment variable that selects the path.
    pub const ENV: &'static str = "PINGU_HOOK_PATH";

    /// `reflex` or `artifact`, case-insensitive.
    pub fn parse(value: &[u8]) -> Option<Self> {
        if value.eq_ignore_ascii_case(b"reflex") {
            Some(Self::Reflex)
        } else if value.eq_ignore_ascii_case(b"artifact") {
            Some(Self::Artifact)
        } else {
            None
        }
    }

    /// The path for the variable's value; unset or unknown values select Reflex.
    pub fn from_env(value: Option<&[u8]>) -> Self {
        value.and_then(Self::parse).unwrap_or(Self::Reflex)
    }

    pub const fn from_raw(raw: u8) -> Self {
        match raw {
            1 => Self::Artifact,
            _ => Self::Reflex,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Reflex => "reflex",
            Self::Artifact => "artifact",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::HookPath;

    #[test]
    fn names_select_their_path_regardless_of_case() {
        assert_eq!(HookPath::parse(b"reflex"), Some(HookPath::Reflex));
        assert_eq!(HookPath::parse(b"Artifact"), Some(HookPath::Artifact));
        assert_eq!(HookPath::parse(b"ARTIFACT"), Some(HookPath::Artifact));
        assert_eq!(HookPath::parse(b"artifact "), None);
        assert_eq!(HookPath::parse(b""), None);
    }

    #[test]
    fn unset_or_unknown_values_select_reflex() {
        assert_eq!(HookPath::from_env(None), HookPath::Reflex);
        assert_eq!(HookPath::from_env(Some(b"1")), HookPath::Reflex);
        assert_eq!(HookPath::from_env(Some(b"artifact")), HookPath::Artifact);
    }

    #[test]
    fn raw_values_round_trip() {
        for path in [HookPath::Reflex, HookPath::Artifact] {
            assert_eq!(HookPath::from_raw(path as u8), path);
            assert_eq!(HookPath::parse(path.name().as_bytes()), Some(path));
        }
    }
}
