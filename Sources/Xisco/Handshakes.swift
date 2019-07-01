import Foundation
import Ristretto255

// First character:
//  N = No static key for initiator
//  K = Static key for initiator Known to responder
//  X = Static key for initiator Xmitted ("transmitted") to responder
//  I = Static key for initiator Immediately transmitted to responder
//
// Second character:
//  N = No static key for responder
//  K = Static key for responder Known to initiator
//  X = Static key for responder Xmitted ("transmitted") to initiator

public final class Initiator {}
public final class Responder {}


// K:
//  -> s
//  <- s
//  ...
//  -> e, es, ss

extension Initiator {
    public final class K: Handshake {
        let s: KeyPair
        let e = KeyPair()
        let rs: PublicKey
        
        public init(my s: KeyPair, their rs: PublicKey) {
            self.s = s
            self.rs = rs
            super.init(.initiator, "K")
        }
        
        public func write<M: MutableDataProtocol>(to buffer: inout M) throws {
            operation(order: 1)
            buffer.append(e)
            symmetricState.mixHash(e)
            symmetricState.mixKey(try e ^ rs)
            symmetricState.mixKey(try s ^ rs)
        }
    }
}

extension Responder {
    public final class K: Handshake {
        let s: KeyPair
        let rs: PublicKey
        
        public init(my s: KeyPair, their rs: PublicKey) {
            self.s = s
            self.rs = rs
            super.init(.responder, "K")
        }
        
        public func read<D: DataProtocol>(from buffer: D) throws {
            operation(order: 1)
            let re = try PublicKey(from: buffer)
            symmetricState.mixHash(re)
            symmetricState.mixKey(try s ^ re)
            symmetricState.mixKey(try s ^ rs)
        }
    }
}


// N:
//  <- s
//  ...
//  -> e, es

extension Initiator {
    public final class N: Handshake {
        let e = KeyPair()
        let rs: PublicKey
        
        public init(their rs: PublicKey) {
            self.rs = rs
            super.init(.initiator, "N")
        }
        
        public func write<M: MutableDataProtocol>(to buffer: inout M) throws {
            operation(order: 1)
            buffer.append(e)
            symmetricState.mixHash(e)
            symmetricState.mixKey(try e ^ rs)
        }
    }
}

extension Responder {
    public final class N: Handshake {
        let s: KeyPair
        let e = KeyPair()
        
        public init(my s: KeyPair) {
            self.s = s
            super.init(.responder, "N")
        }
        
        public func read<D: DataProtocol>(from buffer: D) throws {
            operation(order: 1)
            let re = try PublicKey(from: buffer)
            symmetricState.mixHash(re)
            symmetricState.mixKey(try s ^ re)
        }
    }
}


// X:
//  <- s
//  ...
//  -> e, es, s, ss

extension Initiator {
    public final class X: Handshake {
        let s: KeyPair
        let e = KeyPair()
        let rs: PublicKey
        
        public init(my s: KeyPair, their rs: PublicKey) {
            self.s = s
            self.rs = rs
            super.init(.initiator, "X")
        }
        
        public func write<M: MutableDataProtocol>(to buffer: inout M) throws {
            longOperation(order: 1)
            buffer.append(e)
            symmetricState.mixHash(e)
            symmetricState.mixKey(try e ^ rs)
            symmetricState.encrypt(from: s, to: &buffer)
            symmetricState.mixKey(try s ^ rs)
        }
    }
}

extension Responder {
    public final class X: Handshake {
        let s: KeyPair
        
        public var rs: PublicKey?
        
        public init(my s: KeyPair) {
            self.s = s
            super.init(.responder, "X")
        }
        
        public func read<D: DataProtocol>(from buffer: D) throws {
            longOperation(order: 1)
            let re = try PublicKey(from: buffer)
            symmetricState.mixHash(re)
            symmetricState.mixKey(try s ^ re)
            let suffix = buffer.suffix(buffer.count - PublicKey.length)
            rs = try PublicKey(from: try symmetricState.decrypt(from: suffix))
            symmetricState.mixKey(try s ^ rs!)
        }
    }
}


// NNpsk2:
//  -> e
//  <- e, ee, psk

extension Initiator {
    public final class NNpsk2: Handshake {
        let psk: [UInt8]
        let e = KeyPair()
        
        public init<D: DataProtocol>(psk: D) {
            self.psk = .init(psk)
            super.init(.initiator, "NNpsk2")
        }
        
        public func write<M: MutableDataProtocol>(to buffer: inout M) throws {
            operation(order: 1)
            buffer.append(e)
            symmetricState.mixHash(e)
        }
        
        public func read<D: DataProtocol>(from buffer: D) throws {
            operation(order: 2)
            let re = try PublicKey(from: buffer)
            symmetricState.mixHash(re)
            symmetricState.mixKey(try e ^ re)
            symmetricState.mixKey(psk)
        }
    }
}

extension Responder {
    public final class NNpsk2: Handshake {
        let psk: [UInt8]
        let e = KeyPair()
        var re: PublicKey?
        
        public init<D: DataProtocol>(psk: D) {
            self.psk = .init(psk)
            super.init(.responder, "NNpsk2")
        }
        
        public func read<D: DataProtocol>(from buffer: D) throws {
            operation(order: 1)
            re = try PublicKey(from: buffer)
            symmetricState.mixHash(re!)
        }
        
        public func write<M: MutableDataProtocol>(to buffer: inout M) throws {
            operation(order: 2)
            buffer.append(e)
            symmetricState.mixHash(e)
            symmetricState.mixKey(try e ^ re!)
            symmetricState.mixKey(psk)
        }
    }
}


// KK:
//  -> s
//  <- s
//  ...
//  -> e, es, ss
//  <- e, ee, se

extension Initiator {
    public final class KK: Handshake {
        let s: KeyPair
        let e = KeyPair()
        let rs: PublicKey
        
        public init(my s: KeyPair, their rs: PublicKey) {
            self.s = s
            self.rs = rs
            super.init(.initiator, "KK")
        }
        
        public func write<M: MutableDataProtocol>(to buffer: inout M) throws {
            operation(order: 1)
            buffer.append(e)
            symmetricState.mixHash(e)
            symmetricState.mixKey(try e ^ rs)
            symmetricState.mixKey(try s ^ rs)
        }
        
        public func read<D: DataProtocol>(from buffer: D) throws {
            operation(order: 2)
            let re = try PublicKey(from: buffer)
            symmetricState.mixHash(re)
            symmetricState.mixKey(try e ^ re)
            symmetricState.mixKey(try s ^ re)
        }
    }
}

extension Responder {
    public final class KK: Handshake {
        let s: KeyPair
        let e = KeyPair()
        let rs: PublicKey
        var re: PublicKey?
        
        public init(my s: KeyPair, their rs: PublicKey) {
            self.s = s
            self.rs = rs
            super.init(.responder, "KK")
        }
        
        public func read<D: DataProtocol>(from buffer: D) throws {
            operation(order: 1)
            re = try PublicKey(from: buffer)
            symmetricState.mixHash(re!)
            symmetricState.mixKey(try s ^ re!)
            symmetricState.mixKey(try s ^ rs)
        }
        
        public func write<M: MutableDataProtocol>(to buffer: inout M) throws {
            operation(order: 2)
            buffer.append(e)
            symmetricState.mixHash(e)
            symmetricState.mixKey(try e ^ re!)
            symmetricState.mixKey(try e ^ rs)
        }
    }
}


// NK:
//  <- s
//  ...
//  -> e, es
//  <- e, ee

extension Initiator {
    public final class NK: Handshake {
        let e = KeyPair()
        let rs: PublicKey
        
        public init(their rs: PublicKey) {
            self.rs = rs
            super.init(.initiator, "NK")
        }
        
        public func write<M: MutableDataProtocol>(to buffer: inout M) throws {
            operation(order: 1)
            buffer.append(e)
            symmetricState.mixHash(e)
            symmetricState.mixKey(try e ^ rs)
        }
        
        public func read<D: DataProtocol>(from buffer: D) throws {
            operation(order: 2)
            let re = try PublicKey(from: buffer)
            symmetricState.mixHash(re)
            symmetricState.mixKey(try e ^ re)
        }
    }
}

extension Responder {
    public final class NK: Handshake {
        let s: KeyPair
        let e = KeyPair()
        var re: PublicKey?
        
        public init(my s: KeyPair) {
            self.s = s
            super.init(.responder, "NK")
        }
        
        public func read<D: DataProtocol>(from buffer: D) throws {
            operation(order: 1)
            re = try PublicKey(from: buffer)
            symmetricState.mixHash(re!)
            symmetricState.mixKey(try s ^ re!)
        }
        
        public func write<M: MutableDataProtocol>(to buffer: inout M) throws {
            operation(order: 2)
            buffer.append(e)
            symmetricState.mixHash(e)
            symmetricState.mixKey(try e ^ re!)
        }
    }
}


// NX:
//  -> e
//  <- e, ee, s, es

extension Initiator {
    public final class NX: Handshake {
        let e = KeyPair()
        
        public var rs: PublicKey?
        
        public init() {
            super.init(.initiator, "NX")
        }
        
        public func write<M: MutableDataProtocol>(to buffer: inout M) {
            operation(order: 1)
            buffer.append(e)
            symmetricState.mixHash(e)
        }
        
        public func read<D: DataProtocol>(from buffer: D) throws {
            longOperation(order: 2)
            let re = try PublicKey(from: buffer)
            symmetricState.mixHash(re)
            symmetricState.mixKey(try e ^ re)
            let suffix = buffer.suffix(buffer.count - PublicKey.length)
            rs = try PublicKey(from: try symmetricState.decrypt(from: suffix))
            symmetricState.mixKey(try e ^ rs!)
        }
    }
}

extension Responder {
    public final class NX: Handshake {
        let s: KeyPair
        let e = KeyPair()
        var re: PublicKey?
        
        public init(my s: KeyPair) {
            self.s = s
            super.init(.responder, "NX")
        }
        
        public func read<D: DataProtocol>(from buffer: D) throws {
            operation(order: 1)
            re = try PublicKey(from: buffer)
            symmetricState.mixHash(re!)
        }
        
        public func write<M: MutableDataProtocol>(to buffer: inout M) throws {
            longOperation(order: 2)
            buffer.append(e)
            symmetricState.mixHash(e)
            symmetricState.mixKey(try e ^ re!)
            symmetricState.encrypt(from: s, to: &buffer)
            symmetricState.mixKey(try s ^ re!)
        }
    }
}


// XX:
//  -> e
//  <- e, ee, s, es
//  -> s, se

extension Initiator {
    public final class XX: Handshake {
        let s: KeyPair
        let e = KeyPair()
        var re: PublicKey?
        
        public var rs: PublicKey?
        
        public init(my s: KeyPair) {
            self.s = s
            super.init(.initiator, "XX")
        }
        
        public func firstWrite<M: MutableDataProtocol>(to buffer: inout M) {
            operation(order: 1)
            buffer.append(e)
            symmetricState.mixHash(e)
        }
        
        public func read<D: DataProtocol>(from buffer: D) throws {
            longOperation(order: 2)
            re = try PublicKey(from: buffer)
            symmetricState.mixHash(re!)
            symmetricState.mixKey(try e ^ re!)
            let suffix = buffer.suffix(buffer.count - PublicKey.length)
            rs = try PublicKey(from: try symmetricState.decrypt(from: suffix))
            symmetricState.mixKey(try e ^ rs!)
        }
        
        public func secondWrite<M: MutableDataProtocol>(to buffer: inout M) throws {
            operation(order: 3)
            symmetricState.encrypt(from: s, to: &buffer)
            symmetricState.mixKey(try s ^ re!)
        }
    }
}

extension Responder {
    public final class XX: Handshake {
        let s: KeyPair
        let e = KeyPair()
        var re: PublicKey?
        
        public var rs: PublicKey?
        
        public init(my s: KeyPair) {
            self.s = s
            super.init(.responder, "XX")
        }
        
        public func firstRead<D: DataProtocol>(from buffer: D) throws {
            operation(order: 1)
            re = try PublicKey(from: buffer)
            symmetricState.mixHash(re!)
        }
        
        public func write<M: MutableDataProtocol>(to buffer: inout M) throws {
            longOperation(order: 2)
            buffer.append(e)
            symmetricState.mixHash(e)
            symmetricState.mixKey(try e ^ re!)
            symmetricState.encrypt(from: s, to: &buffer)
            symmetricState.mixKey(try s ^ re!)
        }
        
        public func secondRead<D: DataProtocol>(from buffer: D) throws {
            operation(order: 3)
            rs = try PublicKey(from: try symmetricState.decrypt(from: buffer))
            symmetricState.mixKey(try e ^ rs!)
        }
    }
}


// IK:
//  <- s
//  ...
//  -> e, es, s, ss
//  <- e, ee, se

extension Initiator {
    public final class IK: Handshake {
        let s: KeyPair
        let e = KeyPair()
        let rs: PublicKey
        var re: PublicKey?
        
        public init(my s: KeyPair, their rs: PublicKey) {
            self.s = s
            self.rs = rs
            super.init(.initiator, "IK")
        }
        
        public func write<M: MutableDataProtocol>(to buffer: inout M) throws {
            longOperation(order: 1)
            buffer.append(e)
            symmetricState.mixHash(e)
            symmetricState.mixKey(try e ^ rs)
            symmetricState.encrypt(from: s, to: &buffer)
            symmetricState.mixKey(try s ^ rs)
        }
        
        public func read<D: DataProtocol>(from buffer: D) throws {
            operation(order: 2)
            let re = try PublicKey(from: buffer)
            symmetricState.mixHash(re)
            symmetricState.mixKey(try e ^ re)
            symmetricState.mixKey(try s ^ re)
        }
    }
}

extension Responder {
    public final class IK: Handshake {
        let s: KeyPair
        let e = KeyPair()
        var re: PublicKey?
        
        public var rs: PublicKey?
        
        public init(my s: KeyPair) {
            self.s = s
            super.init(.responder, "IK")
        }
        
        public func read<D: DataProtocol>(from buffer: D) throws {
            longOperation(order: 1)
            re = try PublicKey(from: buffer)
            symmetricState.mixHash(re!)
            symmetricState.mixKey(try s ^ re!)
            let suffix = buffer.suffix(buffer.count - PublicKey.length)
            rs = try PublicKey(from: try symmetricState.decrypt(from: suffix))
            symmetricState.mixKey(try s ^ rs!)
        }
        
        public func write<M: MutableDataProtocol>(to buffer: inout M) throws {
            operation(order: 2)
            buffer.append(e)
            symmetricState.mixHash(e)
            symmetricState.mixKey(try e ^ re!)
            symmetricState.mixKey(try e ^ rs!)
        }
    }
}
