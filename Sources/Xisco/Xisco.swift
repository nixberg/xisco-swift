import Foundation
import Xoodyak

enum XiscoError: Error {
    case ciphertextTooShort
    case messageCorrupted
}

public struct Xisco {
    static let version = 0
    static let tagLength = 16
    static let maximumMessageLength = 65535
    
    var aborted = false
    var sender: Xoodyak
    var senderNonce: UInt64 = 0
    var receiver: Xoodyak
    var receiverNonce: UInt64 = 0
    
    init<D: DataProtocol>(key: D, role: Role) {
        sender   = Xoodyak(key: key, id: [ role.rawValue], counter: [])
        receiver = Xoodyak(key: key, id: [~role.rawValue], counter: [])
    }
    
    public mutating func encrypt<D: DataProtocol, M: MutableDataProtocol>(from plaintext: D, withAD ad: D? = nil, to ciphertext: inout M) {
        precondition(!aborted)
        precondition(plaintext.count + Xisco.tagLength + (ad?.count ?? 0) <= Xisco.maximumMessageLength)
        precondition(senderNonce < UInt64.max)

        var ephemeral = sender
        ephemeral.absorb(nonce: senderNonce)
        if let ad = ad {
            ephemeral.absorb(from: ad)
        }
        ephemeral.encrypt(from: plaintext, to: &ciphertext)
        ephemeral.squeeze(count: Xisco.tagLength, to: &ciphertext)
        
        senderNonce += 1
    }
        
    public mutating func decrypt<D: DataProtocol, M: MutableDataProtocol>(from ciphertext: D, withAD ad: D? = nil, to plaintext: inout M) throws {
        precondition(!aborted)
        precondition(plaintext.count + (ad?.count ?? 0) <= Xisco.maximumMessageLength)
        precondition(receiverNonce < UInt64.max)
        guard ciphertext.count >= Xisco.tagLength else {
            throw XiscoError.ciphertextTooShort
        }
        
        var ephemeral = receiver
        ephemeral.absorb(nonce: receiverNonce)
        if let ad = ad {
            ephemeral.absorb(from: ad)
        }
        let actualCiphertext = ciphertext.prefix(ciphertext.count - Xisco.tagLength)
        let tag = ciphertext.suffix(Xisco.tagLength)
        ephemeral.decrypt(from: actualCiphertext, to: &plaintext)
        var newTag = [UInt8]()
        ephemeral.squeeze(count: Xisco.tagLength, to: &newTag)
        guard zip(tag, newTag).map(^).reduce(0, |) == 0 else {
            aborted = true
            // TODO: Clear
            throw XiscoError.messageCorrupted
        }

        receiverNonce += 1
    }
    
    public mutating func rekeySender() {
        precondition(!aborted)
        sender.ratchet()
    }
    
    public mutating func rekeyReceiver() {
        precondition(!aborted)
        receiver.ratchet()
    }
    
    public mutating func rekey() {
        rekeySender()
        rekeyReceiver()
    }
}

extension Xoodyak {
    mutating func absorb(nonce: UInt64) {
        var littleEndian = nonce.littleEndian
        withUnsafeBytes(of: &littleEndian) { self.absorb(from: $0) }
    }
}
