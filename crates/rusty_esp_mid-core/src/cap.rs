//! Capability matching with `mata-cap` semantics, over borrowed strings.
//!
//! A capability is `component:action` or `component:action@scope`. A held
//! grant satisfies a need when component and action match and the grant is
//! either unscoped (covers every scope) or scoped to exactly the needed scope.

/// A parsed capability string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cap<'a> {
    /// The component, e.g. `camera`.
    pub component: &'a str,
    /// The action, e.g. `snapshot`.
    pub action: &'a str,
    /// Optional scope, e.g. `front-door`.
    pub scope: Option<&'a str>,
}

impl<'a> Cap<'a> {
    /// Parse `component:action[@scope]`. Every present part must be non-empty
    /// and must not contain another separator.
    #[must_use]
    pub fn parse(s: &'a str) -> Option<Self> {
        let (component, rest) = s.split_once(':')?;
        let (action, scope) = match rest.split_once('@') {
            Some((a, sc)) => (a, Some(sc)),
            None => (rest, None),
        };
        let clean = |p: &str| !p.is_empty() && !p.contains(':') && !p.contains('@');
        if !clean(component) || !clean(action) || !scope.is_none_or(clean) {
            return None;
        }
        Some(Cap {
            component,
            action,
            scope,
        })
    }

    /// Does this held grant satisfy `needed`?
    #[must_use]
    pub fn satisfies(&self, needed: &Cap<'_>) -> bool {
        self.component == needed.component
            && self.action == needed.action
            && (self.scope.is_none() || self.scope == needed.scope)
    }
}

/// Does the grant string satisfy the needed string? Unparsable strings never
/// satisfy anything.
#[must_use]
pub fn grant_satisfies(grant: &str, needed: &str) -> bool {
    match (Cap::parse(grant), Cap::parse(needed)) {
        (Some(g), Some(n)) => g.satisfies(&n),
        _ => false,
    }
}

/// Does any grant in `grants` satisfy `needed`?
#[must_use]
pub fn any_satisfies<'a>(grants: impl IntoIterator<Item = &'a str>, needed: &str) -> bool {
    let Some(n) = Cap::parse(needed) else {
        return false;
    };
    grants
        .into_iter()
        .filter_map(Cap::parse)
        .any(|g| g.satisfies(&n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_rules_match_mata_cap() {
        assert!(grant_satisfies("ledger:read", "ledger:read"));
        assert!(grant_satisfies("ledger:read", "ledger:read@eu"));
        assert!(grant_satisfies("ledger:read@us", "ledger:read@us"));
        assert!(!grant_satisfies("ledger:read@us", "ledger:read@eu"));
        assert!(!grant_satisfies("ledger:read@us", "ledger:read"));
        assert!(!grant_satisfies("ledger:read", "ledger:admin"));
    }

    #[test]
    fn malformed_never_satisfies() {
        assert!(!grant_satisfies("ledger", "ledger:read"));
        assert!(!grant_satisfies("ledger:read", "ledger"));
        assert!(!grant_satisfies(":read", ":read"));
        assert!(!grant_satisfies("a:b@", "a:b@"));
        assert!(Cap::parse("a:b:c").is_none());
        assert!(Cap::parse("a:b@c@d").is_none());
    }

    #[test]
    fn any_over_a_grant_list() {
        let grants = ["camera:snapshot@front", "telemetry:read"];
        assert!(any_satisfies(grants, "telemetry:read@anything"));
        assert!(any_satisfies(grants, "camera:snapshot@front"));
        assert!(!any_satisfies(grants, "camera:snapshot@back"));
        assert!(!any_satisfies(grants, "gpio:set"));
    }
}
