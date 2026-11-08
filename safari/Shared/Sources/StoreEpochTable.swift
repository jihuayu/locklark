import Foundation

/// Lock-guarded current store plus its generation ("epoch").
///
/// Accepted relay connections capture a lease from this table *once*, at accept
/// time, and then serve every request from the captured store. Starting the
/// relay again installs a fresh store and bumps the epoch, so an old accepted
/// worker can never reach the new store: its lease is no longer current and its
/// captured store has already been closed by `closeAll`.
public final class StoreEpochTable<Store> {
    /// The store a connection was accepted against, and its generation.
    public struct Lease {
        public let store: Store
        public let epoch: UInt64
    }

    private let lock = NSLock()
    private var store: Store
    private var epoch: UInt64 = 1

    public init(_ store: Store) {
        self.store = store
    }

    public func capture() -> Lease {
        lock.lock()
        defer { lock.unlock() }
        return Lease(store: store, epoch: epoch)
    }

    /// True only while the given generation is still the installed one.
    public func isCurrent(_ epoch: UInt64) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return self.epoch == epoch
    }

    public var currentEpoch: UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return epoch
    }

    /// Installs a new store and bumps the epoch. Every lease captured before
    /// this call stops being current. Returns the replaced store so the caller
    /// can close it.
    @discardableResult
    public func replace(with next: Store) -> Store {
        lock.lock()
        defer { lock.unlock() }
        let previous = store
        store = next
        epoch &+= 1
        return previous
    }
}
