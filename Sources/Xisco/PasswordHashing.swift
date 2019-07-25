import Foundation
import Xoodyak

fileprivate let blockSize = 32

extension Int {
    fileprivate func modulo(_ n: Int) -> Int {
        let remainder = self % n
        return remainder >= 0 ? remainder : remainder &+ n
    }
}

extension Xoodyak {
    fileprivate mutating func squeeze(to buffer: inout [UInt8]) {
        self.squeeze(count: blockSize, to: &buffer)
    }
    
    fileprivate mutating func squeezeInt() -> Int {
        var block = [UInt8]()
        self.squeeze(count: 8, to: &block)
        return UnsafeRawPointer(block).assumingMemoryBound(to: Int.self).pointee.littleEndian
    }
}

public func hash<D: DataProtocol, M: MutableDataProtocol>(password: D, salt: D, to data: inout M, spaceCost: Int, timeCost: Int) {
    assert(spaceCost >= 0 && timeCost >= 0)
    
    let delta = 3
    var buffer = [[UInt8]](repeating: [UInt8](repeating: 0, count: blockSize), count: spaceCost)
    
    var xoodyak = Xoodyak()
    xoodyak.absorb(from: password)
    xoodyak.absorb(from: salt)
    xoodyak.squeeze(to: &buffer[0])
    
    for m in 1..<spaceCost {
        xoodyak.absorb(from: buffer[m &- 1])
        xoodyak.squeeze(to: &buffer[m])
    }
    
    for t in 0..<timeCost {
        for m in 0..<spaceCost {
            xoodyak.absorb(from: buffer[(m &- 1).modulo(spaceCost)])
            xoodyak.absorb(from: buffer[m])
            xoodyak.squeeze(to: &buffer[m])
            
            for i in 0..<delta {
                xoodyak.absorb(from: salt)
                xoodyak.absorb(nonce: UInt64(t))
                xoodyak.absorb(nonce: UInt64(m))
                xoodyak.absorb(nonce: UInt64(i))
                let randomIndex = xoodyak.squeezeInt().modulo(spaceCost)
                
                xoodyak.absorb(from: buffer[m])
                xoodyak.absorb(from: buffer[randomIndex])
                xoodyak.squeeze(to: &buffer[m])
            }
        }
    }

    data.append(contentsOf: buffer.last!)
}
