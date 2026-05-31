//! AES CBC/CTR/CFB/OFB vectors from cryptonite `atest_aes.c`.
pub struct CbcVector {
    pub key: &'static str,
    pub iv: &'static str,
    pub data: &'static str,
    pub exp: &'static str,
}
pub const AES_CBC_DATA: &[CbcVector] = &[
    CbcVector {
        key: "2b7e151628aed2a6abf7158809cf4f3c",
        iv: "000102030405060708090A0B0C0D0E0F",
        data: "6bc1bee22e409f96e93d7e1173930202",
        exp: "4C86A0972A0C13D970CDF7F26D40E58F",
    },
    CbcVector {
        key: "2b7e151628aed2a6abf7158809cf4f3c",
        iv: "7649ABAC8119B246CEE98E9B12E9197D",
        data: "ae2d8a571e03ac9c9eb76fac45af8e51",
        exp: "5086cb9b507219ee95db113a917678b2",
    },
    CbcVector {
        key: "2b7e151628aed2a6abf7158809cf4f3c",
        iv: "5086CB9B507219EE95DB113A917678B2",
        data: "30c81c46a35ce411e5fbc1191a0a52ef",
        exp: "73bed6b8e3c1743b7116e69e22229516",
    },
    CbcVector {
        key: "2b7e151628aed2a6abf7158809cf4f3c",
        iv: "73BED6B8E3C1743B7116E69E22229516",
        data: "f69f2445df4f9b17ad2b417be66c3710",
        exp: "3ff1caa1681fac09120eca307586e1a7",
    },
    CbcVector {
        key: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        iv: "000102030405060708090A0B0C0D0E0F",
        data: "6bc1bee22e409f96e93d7e117393172a",
        exp: "4f021db243bc633d7178183a9fa071e8",
    },
    CbcVector {
        key: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        iv: "4F021DB243BC633D7178183A9FA071E8",
        data: "ae2d8a571e03ac9c9eb76fac45af8e51",
        exp: "b4d9ada9ad7dedf4e5e738763f69145a",
    },
    CbcVector {
        key: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        iv: "B4D9ADA9AD7DEDF4E5E738763F69145A",
        data: "30c81c46a35ce411e5fbc1191a0a52ef",
        exp: "571b242012fb7ae07fa9baac3df102e0",
    },
    CbcVector {
        key: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        iv: "571B242012FB7AE07FA9BAAC3DF102E0",
        data: "f69f2445df4f9b17ad2b417be66c3710",
        exp: "08b0e27988598881d920a9e64f5615cd",
    },
    CbcVector {
        key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        iv: "000102030405060708090A0B0C0D0E0F",
        data: "6bc1bee22e409f96e93d7e117393172a",
        exp: "f58c4c04d6e5f1ba779eabfb5f7bfbd6",
    },
    CbcVector {
        key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        iv: "F58C4C04D6E5F1BA779EABFB5F7BFBD6",
        data: "ae2d8a571e03ac9c9eb76fac45af8e51",
        exp: "9cfc4e967edb808d679f777bc6702c7d",
    },
    CbcVector {
        key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        iv: "9CFC4E967EDB808D679F777BC6702C7D",
        data: "30c81c46a35ce411e5fbc1191a0a52ef",
        exp: "39f23369a9d9bacfa530e26304231461",
    },
    CbcVector {
        key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        iv: "39F23369A9D9BACFA530E26304231461",
        data: "f69f2445df4f9b17ad2b417be66c3710",
        exp: "b2eb05e2c39be9fcda6c19078c6a9d1b",
    },
];

pub struct ModeVector {
    pub key: &'static str,
    pub iv: &'static str,
    pub data: &'static str,
    pub exp: &'static str,
}

pub const AES_CTR_DATA: &[ModeVector] = &[
    ModeVector {
        key: "2b7e151628aed2a6abf7158809cf4f3c",
        iv: "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        data: "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        exp: "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee",
    },
    ModeVector {
        key: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        iv: "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        data: "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        exp: "1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050",
    },
    ModeVector {
        key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        iv: "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        data: "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        exp: "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6",
    },
];

pub const AES_CFB_DATA: &[ModeVector] = &[
    ModeVector {
        key: "2b7e151628aed2a6abf7158809cf4f3c",
        iv: "000102030405060708090a0b0c0d0e0f",
        data: "6bc1bee22e409f96e93d7e117393172a",
        exp: "3b3fd92eb72dad20333449f8e83cfb4a",
    },
    ModeVector {
        key: "2b7e151628aed2a6abf7158809cf4f3c",
        iv: "3B3FD92EB72DAD20333449F8E83CFB4A",
        data: "ae2d8a571e03ac9c9eb76fac45af8e51",
        exp: "c8a64537a0b3a93fcde3cdad9f1ce58b",
    },
    ModeVector {
        key: "2b7e151628aed2a6abf7158809cf4f3c",
        iv: "C8A64537A0B3A93FCDE3CDAD9F1CE58B",
        data: "30c81c46a35ce411e5fbc1191a0a52ef",
        exp: "26751f67a3cbb140b1808cf187a4f4df",
    },
    ModeVector {
        key: "2b7e151628aed2a6abf7158809cf4f3c",
        iv: "26751F67A3CBB140B1808CF187A4F4DF",
        data: "f69f2445df4f9b17ad2b417be66c3710",
        exp: "c04b05357c5d1c0eeac4c66f9ff7f2e6",
    },
    ModeVector {
        key: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        iv: "000102030405060708090A0B0C0D0E0F",
        data: "6bc1bee22e409f96e93d7e117393172a",
        exp: "cdc80d6fddf18cab34c25909c99a4174",
    },
    ModeVector {
        key: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        iv: "CDC80D6FDDF18CAB34C25909C99A4174",
        data: "ae2d8a571e03ac9c9eb76fac45af8e51",
        exp: "67ce7f7f81173621961a2b70171d3d7a",
    },
    ModeVector {
        key: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        iv: "67CE7F7F81173621961A2B70171D3D7A",
        data: "30c81c46a35ce411e5fbc1191a0a52ef",
        exp: "2e1e8a1dd59b88b1c8e60fed1efac4c9",
    },
    ModeVector {
        key: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        iv: "2E1E8A1DD59B88B1C8E60FED1EFAC4C9",
        data: "f69f2445df4f9b17ad2b417be66c3710",
        exp: "c05f9f9ca9834fa042ae8fba584b09ff",
    },
    ModeVector {
        key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        iv: "000102030405060708090A0B0C0D0E0F",
        data: "6bc1bee22e409f96e93d7e117393172a",
        exp: "DC7E84BFDA79164B7ECD8486985D3860",
    },
    ModeVector {
        key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        iv: "DC7E84BFDA79164B7ECD8486985D3860",
        data: "ae2d8a571e03ac9c9eb76fac45af8e51",
        exp: "39ffed143b28b1c832113c6331e5407b",
    },
    ModeVector {
        key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        iv: "39FFED143B28B1C832113C6331E5407B",
        data: "30c81c46a35ce411e5fbc1191a0a52ef",
        exp: "df10132415e54b92a13ed0a8267ae2f9",
    },
    ModeVector {
        key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        iv: "DF10132415E54B92A13ED0A8267AE2F9",
        data: "f69f2445df4f9b17ad2b417be66c3710",
        exp: "75a385741ab9cef82031623d55b1e471",
    },
];

pub const AES_OFB_DATA: &[ModeVector] = &[
    ModeVector {
        key: "2b7e151628aed2a6abf7158809cf4f3c",
        iv: "000102030405060708090A0B0C0D0E0F",
        data: "6bc1bee22e409f96e93d7e117393172a",
        exp: "3b3fd92eb72dad20333449f8e83cfb4a",
    },
    ModeVector {
        key: "2b7e151628aed2a6abf7158809cf4f3c",
        iv: "50FE67CC996D32B6DA0937E99BAFEC60",
        data: "ae2d8a571e03ac9c9eb76fac45af8e51",
        exp: "7789508d16918f03f53c52dac54ed825",
    },
    ModeVector {
        key: "2b7e151628aed2a6abf7158809cf4f3c",
        iv: "D9A4DADA0892239F6B8B3D7680E15674",
        data: "30c81c46a35ce411e5fbc1191a0a52ef",
        exp: "9740051e9c5fecf64344f7a82260edcc",
    },
    ModeVector {
        key: "2b7e151628aed2a6abf7158809cf4f3c",
        iv: "A78819583F0308E7A6BF36B1386ABF23",
        data: "f69f2445df4f9b17ad2b417be66c3710",
        exp: "304c6528f659c77866a510d9c1d6ae5e",
    },
    ModeVector {
        key: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        iv: "000102030405060708090A0B0C0D0E0F",
        data: "6bc1bee22e409f96e93d7e117393172a",
        exp: "cdc80d6fddf18cab34c25909c99a4174",
    },
    ModeVector {
        key: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        iv: "A609B38DF3B1133DDDFF2718BA09565E",
        data: "ae2d8a571e03ac9c9eb76fac45af8e51",
        exp: "fcc28b8d4c63837c09e81700c1100401",
    },
    ModeVector {
        key: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        iv: "52EF01DA52602FE0975F78AC84BF8A50",
        data: "30c81c46a35ce411e5fbc1191a0a52ef",
        exp: "8d9a9aeac0f6596f559c6d4daf59a5f2",
    },
    ModeVector {
        key: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        iv: "BD5286AC63AABD7EB067AC54B553F71D",
        data: "f69f2445df4f9b17ad2b417be66c3710",
        exp: "6d9f200857ca6c3e9cac524bd9acc92a",
    },
    ModeVector {
        key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        iv: "000102030405060708090A0B0C0D0E0F",
        data: "6bc1bee22e409f96e93d7e117393172a",
        exp: "dc7e84bfda79164b7ecd8486985d3860",
    },
    ModeVector {
        key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        iv: "B7BF3A5DF43989DD97F0FA97EBCE2F4A",
        data: "ae2d8a571e03ac9c9eb76fac45af8e51",
        exp: "4febdc6740d20b3ac88f6ad82a4fb08d",
    },
    ModeVector {
        key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        iv: "E1C656305ED1A7A6563805746FE03EDC",
        data: "30c81c46a35ce411e5fbc1191a0a52ef",
        exp: "71ab47a086e86eedf39d1c5bba97c408",
    },
    ModeVector {
        key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        iv: "41635BE625B48AFC1666DD42A09D96E7",
        data: "f69f2445df4f9b17ad2b417be66c3710",
        exp: "0126141d67f37be8538f5a8be740e484",
    },
];
