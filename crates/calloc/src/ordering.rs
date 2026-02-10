use std::cmp::Ordering;

/// Ordering policy version string.
pub const ORDERING_VERSION: &str = "v1-anchor-priority-path-digest";

/// Sort key for deterministic block order.
#[derive(Debug, Clone)]
pub(crate) struct OrderingKey {
    pub(crate) anchor_rank: u8,
    pub(crate) priority: i32,
    pub(crate) canonical_path: String,
    pub(crate) digest: [u8; 32],
}

/// Sorts values by deterministic key.
pub(crate) fn sort_by_key<T>(values: &mut [T], key_for: impl Fn(&T) -> &OrderingKey) {
    values.sort_by(|left, right| compare_keys(key_for(left), key_for(right)));
}

fn compare_keys(left: &OrderingKey, right: &OrderingKey) -> Ordering {
    left.anchor_rank
        .cmp(&right.anchor_rank)
        .then_with(|| right.priority.cmp(&left.priority))
        .then_with(|| left.canonical_path.cmp(&right.canonical_path))
        .then_with(|| left.digest.cmp(&right.digest))
}

#[cfg(test)]
mod tests {
    use super::{OrderingKey, sort_by_key};

    #[test]
    fn sorts_by_anchor_priority_path_digest() {
        let mut values = vec![
            OrderingKey {
                anchor_rank: 1,
                priority: 0,
                canonical_path: "b.rs".to_string(),
                digest: [2; 32],
            },
            OrderingKey {
                anchor_rank: 0,
                priority: 0,
                canonical_path: "z.rs".to_string(),
                digest: [2; 32],
            },
            OrderingKey {
                anchor_rank: 1,
                priority: 100,
                canonical_path: "a.rs".to_string(),
                digest: [1; 32],
            },
        ];

        sort_by_key(&mut values, |item| item);

        assert_eq!(values[0].anchor_rank, 0);
        assert_eq!(values[1].priority, 100);
    }
}
