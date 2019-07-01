import Foundation
import Xoodyak

public struct SymmetricState {
    var xoodyak: Xoodyak
    var isKeyed = false
    let tagLength = Xisco.tagLength

    init<D: DataProtocol>(id: D) {
        xoodyak = Xoodyak(key: [], id: id, counter: [])
    }
    
    mutating func mixKey<D: DataProtocol>(_ key: D) {
        xoodyak.absorb(from: key)
        isKeyed = true
    }
    
    mutating func mixHash<D: DataProtocol>(_ data: D) {
        xoodyak.absorb(from: data)
    }
    
    mutating func encrypt<D: DataProtocol, M: MutableDataProtocol>(from plaintext: D, to ciphertext: inout M) {
        precondition(isKeyed)
        xoodyak.encrypt(from: plaintext, to: &ciphertext)
        xoodyak.squeeze(count: tagLength, to: &ciphertext)
    }
    
    mutating func decrypt<D: DataProtocol, M: MutableDataProtocol>(from ciphertext: D, to plaintext: inout M) throws {
        precondition(isKeyed)
        guard ciphertext.count >= tagLength else {
            throw XiscoError.ciphertextTooShort
        }
        let actualCiphertext = ciphertext.prefix(ciphertext.count - tagLength)
        let tag = ciphertext.suffix(tagLength)
        xoodyak.decrypt(from: actualCiphertext, to: &plaintext)
        var newTag = [UInt8]()
        xoodyak.squeeze(count: tagLength, to: &newTag)
        guard zip(tag, newTag).map(^).reduce(0, |) == 0 else {
            // TODO: Clear
            throw XiscoError.messageCorrupted
        }
    }
    
    mutating func decrypt<D: DataProtocol>(from ciphertext: D) throws -> [UInt8] {
        var data = [UInt8]()
        data.reserveCapacity(ciphertext.count - tagLength)
        try decrypt(from: ciphertext, to: &data)
        return data
    }
}
