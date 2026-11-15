import Foundation

// A single worker owns this buffer after capture. Cleanup also runs when its
// lifecycle ticket is cancelled before the worker starts. Swift/ObjC may make
// immutable bridge copies; this does not claim physical erasure of all copies.
final class NativeSecretBuffer {
    private(set) var data: Data
    init(_ text: String) { data = Data(text.utf8) }
    init(data: Data) { self.data = data }
    func clear() { data.resetBytes(in: 0..<data.count) }
    deinit { clear() }
}
