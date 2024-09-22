const std = @import("std");

const es = @import("algorithms/es.zig");
const hs = @import("algorithms/hs.zig");

pub const hs256 = struct {
    pub const SignerVerifier = hs.SignerVerifier(std.crypto.auth.hmac.sha2.HmacSha256, "HS256");

    test SignerVerifier {
        try hs.testSignerVerifier(SignerVerifier.init("testsecret"));
    }
};

pub const hs384 = struct {
    pub const SignerVerifier = hs.SignerVerifier(std.crypto.auth.hmac.sha2.HmacSha384, "HS384");

    test SignerVerifier {
        try hs.testSignerVerifier(SignerVerifier.init("testsecret"));
    }
};

pub const hs512 = struct {
    pub const SignerVerifier = hs.SignerVerifier(std.crypto.auth.hmac.sha2.HmacSha512, "HS512");

    test SignerVerifier {
        try hs.testSignerVerifier(SignerVerifier.init("testsecret"));
    }
};

pub const es256 = struct {
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

    pub const SignerVerifier = es.SignerVerifier(Ecdsa, "ES256");
    pub const Verifier = es.Verifier(Ecdsa);

    test "es256" {
        const sk_pem =
            \\-----BEGIN PRIVATE KEY-----
            \\MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
            \\OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
            \\1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
            \\-----END PRIVATE KEY-----
        ;
        const pk_pem =
            \\-----BEGIN PUBLIC KEY-----
            \\MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
            \\q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
            \\-----END PUBLIC KEY-----
        ;

        const signer_verifier = try SignerVerifier.fromPem(std.testing.allocator, sk_pem);
        const verifier = try Verifier.fromPem(std.testing.allocator, pk_pem);

        try es.testSignerVerifier(signer_verifier, verifier);
    }
};

pub const es384 = struct {
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP384Sha384;

    pub const SignerVerifier = es.SignerVerifier(Ecdsa, "ES384");
    pub const Verifier = es.Verifier(Ecdsa);

    test "es384" {
        const sk_pem =
            \\-----BEGIN PRIVATE KEY-----
            \\MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCAHpFQ62QnGCEvYh/p
            \\E9QmR1C9aLcDItRbslbmhen/h1tt8AyMhskeenT+rAyyPhGhZANiAAQLW5ZJePZz
            \\MIPAxMtZXkEWbDF0zo9f2n4+T1h/2sh/fviblc/VTyrv10GEtIi5qiOy85Pf1RRw
            \\8lE5IPUWpgu553SteKigiKLUPeNpbqmYZUkWGh3MLfVzLmx85ii2vMU=
            \\-----END PRIVATE KEY-----
        ;
        const pk_pem =
            \\-----BEGIN PUBLIC KEY-----
            \\MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEC1uWSXj2czCDwMTLWV5BFmwxdM6PX9p+
            \\Pk9Yf9rIf374m5XP1U8q79dBhLSIuaojsvOT39UUcPJROSD1FqYLued0rXiooIii
            \\1D3jaW6pmGVJFhodzC31cy5sfOYotrzF
            \\-----END PUBLIC KEY-----
        ;

        const signer_verifier = try SignerVerifier.fromPem(std.testing.allocator, sk_pem);
        const verifier = try Verifier.fromPem(std.testing.allocator, pk_pem);

        try es.testSignerVerifier(signer_verifier, verifier);
    }
};

test {
    std.testing.refAllDecls(@This());
}
