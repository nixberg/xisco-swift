import XCTest
import Ristretto255
@testable import Xisco

final class XiscoTests: XCTestCase {
    let iStatic = KeyPair()
    let rStatic = KeyPair()
    
    func greet(_ initiator: Handshake, _ responder: Handshake, line: UInt = #line) {
        var a = initiator.finalize()
        var b = responder.finalize()
        
        let m1 = "Lorem".data(using: .utf8)!
        let m2 = "ipsum".data(using: .utf8)!
        
        var e1 = Data()
        var e2 = Data()
        var d1 = Data()
        var d2 = Data()
        
        a.encrypt(from: m1, to: &e1)
        a.encrypt(from: m2, to: &e2)
        try! b.decrypt(from: e1, to: &d1)
        try! b.decrypt(from: e2, to: &d2)
        XCTAssertEqual(m1, d1, line: line)
        XCTAssertEqual(m2, d2, line: line)
        
        e1.removeAll()
        e2.removeAll()
        d1.removeAll()
        d2.removeAll()
        
        b.encrypt(from: m1, to: &e1)
        try! a.decrypt(from: e1, to: &d1)
        b.encrypt(from: m2, to: &e2)
        try! a.decrypt(from: e2, to: &d2)
        XCTAssertEqual(m1, d1, line: line)
        XCTAssertEqual(m2, d2, line: line)
    }
    
    func testK() {
        let initiator = Initiator.K(my: iStatic, their: rStatic.publicKey)
        let responder = Responder.K(my: rStatic, their: iStatic.publicKey)
        
        var networkBuffer = Data()
        try! initiator.write(to: &networkBuffer)
        try! responder.read(from: networkBuffer)
        
        greet(initiator, responder)
    }
    
    func testN() {
        let initiator = Initiator.N(their: rStatic.publicKey)
        let responder = Responder.N(my: rStatic)
        
        var networkBuffer = Data()
        try! initiator.write(to: &networkBuffer)
        try! responder.read(from: networkBuffer)
        
        greet(initiator, responder)
    }
    
    func testX() {
        let initiator = Initiator.X(my: iStatic, their: rStatic.publicKey)
        let responder = Responder.X(my: rStatic)
        
        var networkBuffer = Data()
        try! initiator.write(to: &networkBuffer)
        try! responder.read(from: networkBuffer)
        
        greet(initiator, responder)
    }
    
    func testNNpsk2() {
        let psk = (0..<32).map { _ in UInt8.random(in: 0...255) }
        
        let initiator = Initiator.NNpsk2(psk: psk)
        let responder = Responder.NNpsk2(psk: psk)
        
        var networkBuffer = Data()
        try! initiator.write(to: &networkBuffer)
        try! responder.read(from: networkBuffer)
        
        networkBuffer.removeAll()
        try! responder.write(to: &networkBuffer)
        try! initiator.read(from: networkBuffer)
        
        greet(initiator, responder)
    }
    
    func testKK() {
        let initiator = Initiator.KK(my: iStatic, their: rStatic.publicKey)
        let responder = Responder.KK(my: rStatic, their: iStatic.publicKey)
        
        var networkBuffer = Data()
        try! initiator.write(to: &networkBuffer)
        try! responder.read(from: networkBuffer)
        
        networkBuffer.removeAll()
        try! responder.write(to: &networkBuffer)
        try! initiator.read(from: networkBuffer)
        
        greet(initiator, responder)
    }
    
    func testNK() {
        let initiator = Initiator.NK(their: rStatic.publicKey)
        let responder = Responder.NK(my: rStatic)
        
        var networkBuffer = Data()
        try! initiator.write(to: &networkBuffer)
        try! responder.read(from: networkBuffer)
        
        networkBuffer.removeAll()
        try! responder.write(to: &networkBuffer)
        try! initiator.read(from: networkBuffer)
        
        greet(initiator, responder)
    }
    
    func testNX() {
        let initiator = Initiator.NX()
        let responder = Responder.NX(my: rStatic)
        
        var networkBuffer = Data()
        initiator.write(to: &networkBuffer)
        try! responder.read(from: networkBuffer)
        
        networkBuffer.removeAll()
        try! responder.write(to: &networkBuffer)
        try! initiator.read(from: networkBuffer)
        
        greet(initiator, responder)
    }
    
    func testXX() {
        let initiator = Initiator.XX(my: iStatic)
        let responder = Responder.XX(my: rStatic)
        
        var networkBuffer = Data()
        initiator.firstWrite(to: &networkBuffer)
        try! responder.firstRead(from: networkBuffer)
        
        networkBuffer.removeAll()
        try! responder.write(to: &networkBuffer)
        try! initiator.read(from: networkBuffer)
        
        networkBuffer.removeAll()
        try! initiator.secondWrite(to: &networkBuffer)
        try! responder.secondRead(from: networkBuffer)
        
        greet(initiator, responder)
    }
    
    func testIK() {
        let initiator = Initiator.IK(my: iStatic, their: rStatic.publicKey)
        let responder = Responder.IK(my: rStatic)
        
        var networkBuffer = Data()
        try! initiator.write(to: &networkBuffer)
        try! responder.read(from: networkBuffer)
        
        networkBuffer.removeAll()
        try! responder.write(to: &networkBuffer)
        try! initiator.read(from: networkBuffer)
        
        greet(initiator, responder)
    }
    
    static var allTests = [
        ("K", testK),
        ("N", testN),
        ("X", testX),
        ("NNpsk2", testNNpsk2),
        ("KK", testKK),
        ("NK", testNK),
        ("NX", testNX),
        ("XX", testXX),
        ("IK", testIK),
    ]
}
