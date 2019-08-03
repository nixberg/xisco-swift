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
    fileprivate mutating func absorb(_ n: Int) {
        var n = n.littleEndian
        withUnsafeBytes(of: &n) { self.absorb(from: $0) }
    }
    
    fileprivate mutating func squeeze(count: Int) -> [UInt8] {
        var data = [UInt8]()
        self.squeeze(count: count, to: &data)
        return data
    }
    
    fileprivate mutating func squeeze() -> Int {
        UnsafeRawPointer(self.squeeze(count: 8)).load(as: Int.self).littleEndian
    }
}

public func hash<D: DataProtocol, M: MutableDataProtocol>(password: D, salt: D, to data: inout M, spaceCost: Int, timeCost: Int) {
    assert(spaceCost >= 0 && timeCost >= 0)
    
    var counter = 0
    func hash<D: DataProtocol>(_ buffers: D...) -> [UInt8] {
        var xoodyak = Xoodyak()
        xoodyak.absorb(counter)
        counter += 1
        for buffer in buffers {
            xoodyak.absorb(from: buffer)
        }
        return xoodyak.squeeze(count: blockSize)
    }
    
    let delta = 3
    
    var buffer = [hash(password, salt)]
    for m in 0..<(spaceCost - 1) {
        buffer.append(hash(buffer[m]))
    }
    
    for t in 0..<timeCost {
        for m in 0..<spaceCost {
            buffer[m] = hash(buffer[(m - 1).modulo(spaceCost)], buffer[m])
            
            for i in 0..<delta {
                var xoodyak = Xoodyak()
                xoodyak.absorb(counter)
                counter += 1
                xoodyak.absorb(from: salt)
                xoodyak.absorb(t)
                xoodyak.absorb(m)
                xoodyak.absorb(i)
                let randomIndex = xoodyak.squeeze().modulo(spaceCost)
                
                buffer[m] = hash(buffer[m], buffer[randomIndex])
            }
        }
    }
    
    data.append(contentsOf: buffer.last!)
}
