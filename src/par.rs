//! Data parallelism over `std::thread::scope` (no dependencies).
//!
//! All helpers are deterministic: chunk boundaries depend only on lengths,
//! and every output element is a pure function of its inputs, so results
//! are bit-identical at any thread count. Work below per-call thresholds
//! runs sequentially, so small inputs never pay spawn overhead.
//!
//! Deliberately not parallelized: single NTTs (already sub-millisecond at
//! our sizes) and cross-column loops (few columns; internal Merkle work is
//! parallel instead).

/// Worker count for `units` items with at least `min_per_thread` each.
///
/// Returns 1 (caller runs sequentially) when parallelism would not pay.
#[must_use]
pub fn worker_count(units: usize, min_per_thread: usize) -> usize {
    let max_workers = match std::thread::available_parallelism() {
        Ok(count) => count.get(),
        Err(_) => 1,
    };
    let floor = min_per_thread.max(1);
    let by_work = units / floor;
    by_work.min(max_workers).max(1).min(units.max(1))
}

/// Apply `f` to disjoint mutable chunks with their base indices, in
/// parallel when worthwhile (`min_chunk` bounds chunk size from below).
pub fn for_each_indexed<T, F>(items: &mut [T], min_chunk: usize, f: F)
where
    T: Send,
    F: Fn(usize, &mut [T]) + Sync,
{
    let workers = worker_count(items.len(), min_chunk);
    if workers <= 1 {
        f(0, items);
        return;
    }
    let chunk = (items.len() + workers - 1) / workers;
    std::thread::scope(|scope| {
        let shared = &f;
        for (k, piece) in items.chunks_mut(chunk).enumerate() {
            let base = k * chunk;
            scope.spawn(move || shared(base, piece));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scramble(piece: &mut [u64]) {
        for value in piece.iter_mut() {
            *value = value
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .wrapping_add(0xbf58_476d_1ce4_e5b9);
        }
    }

    #[test]
    fn parallel_matches_sequential() {
        // Force the parallel path (tiny chunks) and compare against a
        // sequential reference over the same pure function.
        let mut parallel: Vec<u64> = (0..5000).collect();
        let mut sequential = parallel.clone();
        for_each_indexed(&mut parallel, 1, |_, piece| scramble(piece));
        scramble(&mut sequential);
        assert_eq!(parallel, sequential);
    }

    #[test]
    fn small_inputs_stay_sequential() {
        assert_eq!(worker_count(0, 64), 1);
        assert_eq!(worker_count(100, 64), 1);
        assert_eq!(worker_count(127, 64), 1);
        // Exact threshold behavior is machine-dependent beyond this; only
        // assert the shape (at least 1, at most units).
        let workers = worker_count(1_000_000, 64);
        assert!((1..=1_000_000).contains(&workers));
    }
}
