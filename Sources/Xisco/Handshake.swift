import Foundation
import Ristretto255

enum Role: UInt8 {
    case initiator = 0x00
    case responder = 0xff
}

public class Handshake {
    let role: Role
    var symmetricState: SymmetricState
    
    var done = false
    var operation = 1
    var offset = 0
    
    init(_ role: Role, _ pattern: String) {
        self.role = role
        symmetricState = SymmetricState(id: "Xisco-v\(Xisco.version)_\(pattern)".utf8CString.map(UInt8.init))
    }
    
    func operation(order: Int) {
        precondition(!done)
        precondition(self.operation == order)
        self.operation += 1
        offset = PublicKey.length
    }
    
    func longOperation(order: Int) {
        operation(order: order)
        self.offset += PublicKey.length + symmetricState.tagLength
    }
    
    public func encryptPayload<D: DataProtocol, M: MutableDataProtocol>(from payload: D, to buffer: inout M) {
        precondition(!done)
        precondition(offset + payload.count <= Xisco.maximumMessageLength)
        symmetricState.encrypt(from: payload, to: &buffer)
    }
    
    public func decryptPayload<D: DataProtocol, M: MutableDataProtocol>(from buffer: D, to payload: inout M) throws {
        precondition(!done)
        precondition(buffer.count <= Xisco.maximumMessageLength)
        try symmetricState.decrypt(from: buffer.suffix(buffer.count - offset), to: &payload)
    }
    
    public func finalize() -> Xisco {
        precondition(!done)
        done = true
        var key = [UInt8]()
        symmetricState.xoodyak.squeezeKey(count: 32, to: &key)
        return Xisco(key: key, role: role)
    }
}


// Helper methods:

extension MutableDataProtocol {
    public mutating func append(_ keyPair: KeyPair) {
        self.append(contentsOf: keyPair.publicKey.data)
    }
}

extension SymmetricState {
    mutating func mixHash(_ keyPair: KeyPair) {
        mixHash(keyPair.publicKey.data)
    }
    
    mutating func mixHash(_ publicKey: PublicKey) {
        mixHash(publicKey.data)
    }
    
    mutating func encrypt<M: MutableDataProtocol>(from keyPair: KeyPair, to ciphertext: inout M) {
        encrypt(from: keyPair.publicKey.data, to: &ciphertext)
    }
}
