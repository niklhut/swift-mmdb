//import Foundation
//public class MMDB {
//
//    /// The data field type tag read from the MMDB file as given in *MaxMind DB File Format Specification 2.0*
//    enum FieldType : UInt8 {
//        case pointer = 1
//        case string = 2
//        case double = 3
//        case bytes = 4
//        case uint16 = 5
//        case uint32 = 6
//        case map = 7
//        case int32 = 8
//        case uint64 = 9
//        case uint128 = 10
//        case array = 11
//        case dataCacheContainer = 12
//        case endMarker = 13
//        case boolean = 14
//        case float = 15
//
//
//        /// Scan a Value once the FieldType is known.
//        /// - Parameters:
//        ///   - bytes: A slice of UInt8 which are the data
//        /// - Returns: Read a `MMDB.Value` from a block of bytes. Does not work for `.map`,  `.pointer`, and `.array`, only
//        ///   the simple types.
//        func scan(bytes: ArraySlice<UInt8>) -> Value? {
//            switch self {
//            case .string:
//                guard let s = String(bytes: Array(bytes), encoding: .utf8) else {
//                    return nil
//                }
//                return .string(s)
//            case .double:
//                if bytes.count != 8 {
//                    return nil
//                }
//                let r = bytes.reduce(0, { ($0 << 8) | UInt64($1) })
//
//                return .double(Double(bitPattern: r))
//            case .float:
//                if bytes.count != 4 {
//                    return nil
//                }
//                let r = bytes.reduce(0, { ($0 << 8) | UInt32($1)} )
//
//                return .float(Float(bitPattern: r))
//            case .bytes:
//                return .bytes(Array(bytes))
//            case .uint16:
//                return .uint16(bytes.reduce(0, { ($0 << 8) | UInt16($1)} ))
//            case .uint32:
//                return .uint32(bytes.reduce(0, { ($0 << 8) | UInt32($1)} ))
//            case .uint64:
//                return .uint64(bytes.reduce(0, { ($0 << 8) | UInt64($1)} ))
//            case .int32:
//                let u = bytes.reduce(0, { ($0 << 8) | UInt32($1)} )
//                if u & 0x80000000 == 0 {
//                    return .int32(Int32(u))
//                } else {
//                    return .int32(-Int32( ~u) - 1)
//                }
//            case .uint128:
//                var b = Array(bytes)
//                if bytes.count < 16 {
//                    b = Array(repeating: 0, count: 16 - bytes.count) + b
//                }
//                let high = b[0..<8].reduce(0, { ($0 << 8) | UInt64($1)} )
//                let low = b[8..<16].reduce(0, { ($0 << 8) | UInt64($1)} )
//                return .uint128(high: high, low: low)
//            case .dataCacheContainer:
//                return nil
//                //                fatalError("Field type '\(self)' not supported")
//            case .endMarker:
//                return nil
//                //                fatalError("Field type '\(self)' not supported")
//
//                //
//                // `map` and `array` need to be able to recursively call into the
//                // Store's readValue function. They have to be handled at a higher
//                // level.
//                //
//            case .map:
//                fatalError("Field type '.map' can not be scanned by FieldType")
//            case .array:
//                fatalError("Field type '.array' can not be scanned by FieldType")
//            case .pointer:
//                fatalError("Field type '.map' can not be scanned by FieldType")
//            case .boolean:
//                fatalError("Field type '.boolean' can not be scanned by FieldType")
//            }
//        }
//    }
//
//
//    /// A *value* read from an MMDB file. This parallels the `FieldType` tags, but includes an associated value
//    /// and you can't mix rawValues and associated values
//    public indirect enum Value {
//        case string(String)
//        case map([String:Value])
//        case uint16(UInt16)
//        case uint32(UInt32)
//        case uint64(UInt64)
//        case uint128(high: UInt64, low: UInt64)
//        case int32(Int32)
//        case double(Double)
//        case float(Float)
//        case bytes([UInt8] )
//        case array([Value])
//        case boolean(Bool)
//
//        /// Dump out a value using print().
//        ///
//        /// Just a little gift to developers, mostly so you can call it from the debugger.
//        /// - Parameter level: The indentation level, roughly speaking, two spaces per indent level.
//        func dump(level: Int = 0) {
//            let indent = String(repeating: "  ", count: level)
//            switch self {
//            case .string(let s):
//                print( "\(indent)\"\(s)\"")
//            case .map(let m):
//                print( "\(indent){")
//                for (k,v) in m {
//                    print( "\(indent): \(k) = ")
//                    v.dump(level: level+1)
//                }
//                print( "\(indent)}")
//            case .uint16(let v):
//                print( "\(indent)\(v) u16")
//            case .uint32(let v):
//                print( "\(indent)\(v) u32")
//            case .uint64(let v):
//                print( "\(indent)\(v) u64")
//            case .uint128(high: let high, low: let low):
//                print( "\(indent)0x\(String(format:"%08x%08x", high, low)) u128")
//            case .int32(let v):
//                print( "\(indent)\(v) i32")
//            case .double(let v):
//                print( "\(indent)\(v) double")
//            case .float(let v):
//                print( "\(indent)\(v) float")
//            case .bytes(let b):
//                print( "\(indent)[\(b.count) bytes]")
//            case .array(let elements):
//                print( "\(indent){")
//                elements.forEach{ $0.dump( level: level+1)}
//                print( "\(indent)}")
//            case .boolean(let v):
//                print( "\(indent)\(v ? "true" : "false")")
//            }
//        }
//    }
//
//    struct Store {
//        private let bytes: [UInt8]
//
//        public init(data: Data) {
//            bytes = data.withUnsafeBytes{ body in
//                let buf = body.bindMemory(to: UInt8.self)
//                return .init(buf)
//            }
//        }
//
//        func locateMetadata() -> Int? {
//            // This is "\xab\xcd\xefMaxMind.com" per the spec, but that is invalid UTF8, so we are kind of screwed there.
//            let marker : [UInt8] = [ 0xab, 0xcd, 0xef, 0x4D, 0x61, 0x78, 0x4D, 0x69, 0x6E, 0x64, 0x2E, 0x63, 0x6F, 0x6D ]
//
//            // Look back from the end of the file until we find the last match.
//            for i in (0 ..< bytes.count - marker.count).reversed()  {
//                guard bytes[i] == marker.first! else { continue }
//                if marker.indices.allSatisfy({ bytes[i + $0] == marker[$0]}) {
//                    return i + marker.count
//                }
//            }
//
//            return nil
//        }
//
//        func decodePointer(from controlByte: UInt8, offset: inout Int, pointerBase: Int) -> Int {
//            let pointerSize = Int((controlByte >> 3) & 0x3)
//            let buffer = read(from: offset, numberOfBytes: pointerSize + 1)
//
//            print("Pointer size: \(pointerSize)")
//            offset += pointerSize + 1
//
//            let pointerOffset = [0, 2048, 526336, 0]
//
//            let packed: ArraySlice<UInt8>
//            if pointerSize == 3 {
//                packed = buffer
//            } else {
//                let pointerSizeBits = controlByte & 0x7
//                // TODO: this could be a problem, but it might not be one as well
//                packed = [pointerSizeBits] + buffer
//            }
//            return Int(decodeUInt32(from: packed)) + pointerBase + pointerOffset[pointerSize]
//        }
//
//        func decodeUInt32(from bytes: ArraySlice<UInt8>) -> UInt32 {
//            bytes.reduce(0) { ($0 << 8) | UInt32($1) }
//        }
//
//        func read(from offset: Int, numberOfBytes: Int) -> ArraySlice<UInt8> {
//            return bytes[offset..<offset + numberOfBytes]
//        }
//
//        func readValue(pointer: inout Int, sectionStart: Int) -> Value? {
//            //
//            // Read the ControlByte
//            //
//            guard bytes.indices.contains(pointer) else { return nil }
//            let controlByte = bytes[pointer]
//            pointer += 1
//
//            let top3 = controlByte >> 5 // first 3 bits of control byte
//            let payloadSize0 = controlByte & 0x1f // last 5 bits of control byte
//            let fieldType: FieldType
//            let payloadSize: Int
//
//            //
//            // Decode the FieldType
//            //
//            switch top3 {
//            case 0:
//                let extendedFieldTypeValue = bytes[pointer] + 7
//                guard extendedFieldTypeValue >= 8 else {
//                    fatalError()
////                    throw MMDBError(message: "Invalid Extended Type at offset: \(offset)")
//                }
//                guard let newFieldType = FieldType(rawValue: extendedFieldTypeValue) else {
//                    fatalError()
//                    return nil
//                }
//                pointer += 1
//                fieldType = newFieldType
//            default:
//                guard let ft = FieldType(rawValue: top3) else {
//                    return nil   // bad field type, really shouldn't be able to happen
//                }
//                fieldType = ft
//            }
//            let bits = bitsFrom(controlByte).map(\.rawValue).joined()
//            print(fieldType, bits, pointer)
//
//            //
//            // .pointer is special! It interprets payloadSize0 differently, we can't let
//            // the payloadSize calculator eat bytes.
//            //
//            if fieldType == .pointer {
////                var pointer = decodePointer(from: controlByte, offset: &pointer, pointerBase: sectionStart)
////                let value = try readValue(pointer: &pointer, sectionStart: sectionStart)
////                print("encountered pointer with value: \(value), offset: \(pointer), pointer: \(pointer)")
////                return value
//                let valueBits: UInt = UInt(payloadSize0 & 0x7)   // low three bits are going to end up on top of the size
//                let sizeBits = (payloadSize0) >> 3 & 0x3  // which crazy size function will we use?
//
//                switch sizeBits {
//                case 0:
//                    if pointer >= bytes.count {
//                        return nil
//                    }
//                    let p = (valueBits << 8) | UInt(bytes[pointer])
//                    pointer += 1
//                    var np : Int = sectionStart + Int(p)
//                    return readValue(pointer: &np, sectionStart: sectionStart)
//                case 1:
//                    if pointer + 1 >= bytes.count {
//                        return nil
//                    }
//                    let p = 2048 + ((valueBits << 16) | ( UInt(bytes[pointer]) << 8) | UInt(bytes[pointer + 1]))
//                    pointer += 2
//                    var np: Int = sectionStart + Int(p)
//                    return readValue(pointer: &np, sectionStart: sectionStart)
//                case 2:
//                    if pointer + 2 >= bytes.count {
//                        return nil
//                    }
//                    let p = 526336 + ((valueBits << 24) | ( UInt(bytes[pointer]) << 16) | (UInt(bytes[pointer + 1] << 8)) | UInt(bytes[pointer + 2]))
//                    pointer += 3
//                    var np : Int = sectionStart + Int(p)
//                    return readValue(pointer: &np, sectionStart: sectionStart)
//                case 3:
//                    if pointer + 3 >= bytes.count {
//                        return nil
//                    }
//                    let p = (UInt(bytes[pointer]) << 24) | (UInt(bytes[pointer + 1]) << 16) | (UInt(bytes[pointer + 2]) << 8 ) | UInt(bytes[pointer + 3])
//                    pointer += 4
//                    var np : Int = sectionStart + Int(p)
//                    return readValue(pointer: &np, sectionStart: sectionStart)
//                default:
//                    fatalError("The impossible has happened.")
//                }
//            }
//
//            //
//            // Decode the payloadSize
//            //
//            switch payloadSize0 {
//            case 29:
//                if pointer >= bytes.count {
//                    return nil
//                }
//                payloadSize = 29 + Int(bytes[pointer])
//                pointer += 1
//            case 30:
//                if pointer + 1 >= bytes.count {
//                    return nil
//                }
//                payloadSize = 285 + (Int(bytes[pointer]) << 8) + Int(bytes[pointer+1])
//                pointer += 2
//            case 31:
//                if pointer + 2 >= bytes.count {
//                    return nil
//                }
//                payloadSize = 65821 + (Int(bytes[pointer]) << 16) + (Int(bytes[pointer+1]) << 8) + Int(bytes[pointer+2])
//                pointer += 3
//            default:
//                payloadSize = Int(payloadSize0)
//            }
//
//            //
//            // Read the Value. map and array are special, we need to handle them so we can
//            // recurse. The rest of the field types are just scanned by their enum.
//            //
//            switch fieldType {
//            case .map:
//                var result : [String:Value] = [:]
//                for _ in 0 ..< payloadSize {
//                    guard case let .string(key) = readValue(pointer: &pointer, sectionStart: sectionStart) else {
//                        return nil   // key must be a string
//                    }
////                    if key == "latitude" || key == "longitude" || key == "location" {
////                        return .map(result)
////                    }
//                    guard let val = readValue(pointer: &pointer, sectionStart: sectionStart) else {
//                        return nil
//                    }
//                    result[key] = val
//                }
//                print(Value.map(result))
//                return .map(result)
//            case .array:
//                var result : [Value] = []
//                for _ in 0 ..< payloadSize {
//                    guard let val = readValue(pointer: &pointer, sectionStart: sectionStart) else {
//                        return nil
//                    }
//                    result.append(val)
//                }
//                print(Value.array(result))
//                return .array(result)
//            case .boolean:
//                print(Value.boolean(payloadSize != 0))
//                return .boolean(payloadSize != 0)
//            default:
//                let past = pointer + payloadSize
//                if past > bytes.count {
//                    return nil
//                }
//                let r = fieldType.scan(bytes: bytes[pointer ..< past])
//                pointer += payloadSize
//                print(r ?? "no value here!!!")
//                return r
//            }
//        }
//
//        func node6( _ number: UInt, side: UInt) -> UInt {
//            let base = Int(number * 6)
//            if side == 0 {
//                return ((UInt(bytes[base]) << 16) | (UInt( bytes[base+1]) << 8) | UInt(bytes[base+2]))
//            } else {
//                return ((UInt(bytes[base+3]) << 16) | (UInt( bytes[base+4]) << 8) | UInt(bytes[base+5]))
//            }
//        }
//        func node7( _ number: UInt, side: UInt) -> UInt {
//            let base = Int(number * 7)
//            if side == 0 {
//                return ((UInt(bytes[base+3] >> 4 ) << 24) + (UInt(bytes[base]) << 16) | (UInt( bytes[base+1]) << 8) | UInt(bytes[base+2]))
//            } else {
//                return ((UInt(bytes[base+3] & 0x0f ) << 24) + (UInt(bytes[base+4]) << 16) | (UInt( bytes[base+5]) << 8) | UInt(bytes[base+6]))
//            }
//        }
//        func node8( _ number: UInt, side: UInt) -> UInt {
//            let base = Int(number * 8)
//            if side == 0 {
//                return ((UInt(bytes[base]) << 24) | (UInt(bytes[base+1]) << 16) | (UInt( bytes[base+2]) << 8) | UInt(bytes[base+3]))
//            } else {
//                return ((UInt(bytes[base+4]) << 24) | (UInt(bytes[base+5]) << 16) | (UInt( bytes[base+6]) << 8) | UInt(bytes[base+7]))
//            }
//        }
//    }
//
//    private let store: Store
//    let metadata: Metadata
//
//    lazy var ipv4Root: UInt = computeIPv4Root()
//
//    public init?(data: Data) throws {
//        self.store = Store(data: data)
//
//        guard let metadataOffset = store.locateMetadata() else {
//            return nil
//        }
//
//        var metadataPointer = metadataOffset
//        guard case let .map(metadataMap) = store.readValue(pointer: &metadataPointer, sectionStart: metadataOffset) else {
//            throw MMDBError(message: "Could not decode metadata")
//        }
//
//        self.metadata = try Metadata(metadataMap)
//
//        if metadata.searchTreeSize > metadataOffset {
//            throw MMDBError(message: "Search tree size cannot be larger than metadata offset.")
//        }
//    }
//
//    public convenience init?(from: URL) throws {
//        guard let d = try? Data( contentsOf: from) else {
//            return nil
//        }
//        try self.init( data: d)
//    }
//
//    func computeIPv4Root() -> UInt {
//        if metadata.ipVersion == 6,
//           case let .partial(zero64) = search(value: 0, bits: 64),
//           case let .partial(zero96) = search(starting: zero64, value: 0, bits: 32) {
//            return zero96
//        }
//        return 0
//    }
//
//
//    private func node(_ number: UInt, side: UInt) -> UInt {
//        switch metadata.recordSize {
//        case 24:
//            return store.node6(number, side: side)
//        case 28:
//            return store.node7(number, side: side)
//        case 32:
//            return store.node8(number, side: side)
//        default:
//            fatalError("Unsupported record size")
//        }
//    }
//
//    public enum SearchResult {
//        case notFound
//        case partial(UInt)
//        case value(Value)
//        case failed(String)
//    }
//
//    /// Search the database for a match.
//    ///
//    /// The bits to be search *must* be in the high order bit positions in `value`. It is presumed that there will
//    /// be a layer above MMDB, say one that deals with IPv4 and IPv6 addresses and they will absorb the fiddling
//    /// with bits.
//    ///
//    /// Using `starting` you can start from some place other than the root of the search tree. You will want to have
//    /// received this value from a `.partial` result of a preceding search. (_Hint:_ if you are looking up IPv4
//    /// addresses in an IPv6 database, you probably want to start *after* the first 96 zeroes have been fed into the
//    /// search.
//    /// - Parameters:
//    ///   - starting: The starting node. This defaults to 0 for the root of the database. You might also pass in a value you
//    ///   recieved as a .partial result from `search`.
//    ///   - value: The binary value you are searching for. The bits must begin at the most significant bit.
//    ///   - bits: The maximum number of bits to process. If an answer has not been determined, then
//    ///   a .partial result will be given at this point.
//    /// - Returns: A `SearchResult`, so a value, a 'not found' indicator, a partial result marker, or a failure message.
//    /// Failures should never occur in proper use of an uncorrupted database. You might get them during development.
//    func search(starting: UInt = 0, value: UInt, bits: Int) -> SearchResult {
//        if starting >= metadata.nodeCount {
//            return .failed("Invalid starting node number")
//        }
//        if bits < 0 || bits > 64 {
//            return .failed("Invalid bit count")
//        }
//        var n = starting
//        for b in 0 ..< bits {
//            if (value & (1 << (63-b))) == 0 {
//                n = node( n, side: 0)
//            } else {
//                n = node( n, side: 1)
//            }
//            if n == metadata.nodeCount {
//                return .notFound
//            }
//            if n > metadata.nodeCount {
//                let dataOffset = n - metadata.nodeCount - 16
//                var pointer : Int = Int(metadata.dataSectionStart + dataOffset)
//                guard let v = store.readValue(pointer: &pointer, sectionStart: Int(metadata.dataSectionStart) ) else {
//                    return .failed("Failed to read value in search")
//                }
//                return .value(v)
//            }
//        }
//        return .partial(n)
//    }
//}
//
//extension MMDB {
//    func search<T>(value: [T], bits: Int) -> SearchResult where T : FixedWidthInteger {
//        var n : UInt = 0
//        var togo = bits
//
//        for v in value {
//            let c = UInt(v) << (64 - T.bitWidth)
//            switch search(starting: n, value: c, bits: min( togo, T.bitWidth)) {
//            case .notFound:
//                return .notFound
//            case .partial(let nn):
//                n = nn
//                togo -= T.bitWidth
//            case .value(let vv):
//                return .value(vv)
//            case .failed(let m):
//                return .failed(m)
//            }
//        }
//        return .partial(n)
//    }
//}
//
//extension MMDB {
//    /// Get the MMDB.Value record for an IP address in text form. Does not look up host names.
//    /// You will need to use a numeric form. It accepts both IPv4 and IPv6 addresses.
//    /// - Parameter address: A numeric IPv4 or IPv6 address as accepted by `inet_addr`
//    /// or `inet_pton`
//    /// - Returns: The MMDB.Value record found, or a .notFound, or maybe a .failure if your name
//    /// was not valid.
//    public func search(address: String) -> MMDB.SearchResult {
//        let ipv4 = inet_addr(address)
//        if ipv4 != UInt32.max {
//            return search(starting: ipv4Root, value: UInt(ipv4.bigEndian)<<32, bits: 32)
//        }
//
//        var ipv6 = in6_addr()
//        switch withUnsafeMutablePointer(to: &ipv6, ({ inet_pton(AF_INET6, address, UnsafeMutablePointer($0))})) {
//        case -1:
//            break  // error
//        case 0:
//            break  // not a valid address
//        default:
//#if canImport(Glibc)
//            let (a,b,c,d) = ipv6.__in6_u.__u6_addr32
//#else
//            let (a,b,c,d) = ipv6.__u6_addr.__u6_addr32
//#endif
//            let parts = [a.bigEndian, b.bigEndian, c.bigEndian, d.bigEndian]
//            var n : UInt = 0
//            for p in parts {
//                switch search(starting: n, value: UInt(p)<<32, bits: 32) {
//                case .notFound:
//                    return .notFound
//                case .partial(let nn):
//                    n = nn
//                case .value(let v):
//                    return .value(v)
//                case .failed(let m):
//                    return .failed(m)
//                }
//            }
//        }
//
//        return .notFound
//    }
//}
//
//extension MMDB {
//    public func enumerate(_ handler: ([UInt32],Int)->Void ) {
//        func crunch(_ path: [UInt8]) -> [UInt32] {
//            var result : [UInt32] = []
//            var accumulate : UInt32 = 0
//
//            for i in path.indices {
//                accumulate = (accumulate << 1) + UInt32(path[i] & 1)
//                if (i % 32) == 31 {
//                    result.append(accumulate)
//                    accumulate = 0
//                }
//            }
//            if path.count % 32 != 0 {
//                accumulate = accumulate << ( 32 - (path.count % 32) )
//                result.append(accumulate)
//            }
//            return result
//        }
//
//        func doNode(_ n: UInt, path: [UInt8] ) {
//            // Catch and abort loops in the search tree
//            if metadata.ipVersion == 4 && path.count >= 32 { return }
//            if metadata.ipVersion == 6 && path.count >= 128 { return }
//
//            let left = node(n, side: 0)
//            if left > metadata.nodeCount {
//                handler(crunch(path + [0]), path.count+1 )
//            } else if left < metadata.nodeCount {
//                doNode( left, path: path + [0])
//            }
//            // = nodeCount means 'not found'
//
//            let right = node(n, side:1)
//            if right > metadata.nodeCount {
//                handler(crunch(path + [1]), path.count+1)
//            } else if right < metadata.nodeCount {
//                doNode(right, path: path + [1])
//            }
//            // = nodeCount means 'not found'
//        }
//
//        doNode(0, path:[])
//    }
//}
//
//// TODO: remove
//enum Bit: String {
//    case zero = "0"
//    case one = "1"
//}
//
//func bit(_ i: Int, of uint8: UInt8) -> Bit {
//    let first8PowersOf2 = (0...7).map { return UInt8(1) << $0 }
//    return (uint8 & first8PowersOf2[i] != 0) ? Bit.one : Bit.zero
//}
//
//func bitsFrom(_ uint8: UInt8) -> [Bit] {
//    return Array((0...7)).reversed().map { bit($0, of: uint8) }
//}
