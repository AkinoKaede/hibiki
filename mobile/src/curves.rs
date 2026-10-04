// Standard mathematical parameters serialized for GnuPG keygrips.
pub fn parameters(name: &str) -> Option<[&'static str; 5]> {
    match name {
        "Ed25519" => Some([
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
            "01",
            "2dfc9311d490018c7338bf8688861767ff8ff5b2bebe27548a14b235eca6874a",
            "04216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A6666666666666666666666666666666666666666666666666666666666666658",
            "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
        ]),
        "Curve25519" => Some([
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
            "01db41",
            "01",
            "04000000000000000000000000000000000000000000000000000000000000000920AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9",
            "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
        ]),
        "NIST P-256" => Some([
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
            "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
            "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
            "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        ]),
        "NIST P-384" => Some([
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc",
            "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
            "04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
            "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
        ]),
        "NIST P-521" => Some([
            "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc",
            "51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
            "0400c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
            "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
        ]),
        _ => None,
    }
}
