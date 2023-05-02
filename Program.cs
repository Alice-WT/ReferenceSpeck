var ptBytes = Convert.FromHexString("706f6f6e65722e20496e2074686f7365");
var kBytes = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
var pt = Alice.Security.Cryptography.Speck.ToUInt64Array(ptBytes);
var k = Alice.Security.Cryptography.Speck.ToUInt64Array(kBytes);
var rk = new UInt64[34];
Alice.Security.Cryptography.Speck.Speck128256KeySchedule(k, rk);
//This is the key schedule. It should match the NSA documentation.
for (int i = 0; i < rk.Length; ++i)
    Console.WriteLine($"rk[{i}]={rk[i]:X8}");
var ct = new UInt64[pt.Length];
Alice.Security.Cryptography.Speck.Speck128256Encrypt(pt, ct, rk);
//The final encrypted data. It should match the final ciphertext from the NSA documentation.
for (int i = 0; i < ct.Length; ++i)
    Console.WriteLine($"ct[{i}]={ct[i]:X8}");
var pt2 = new UInt64[ct.Length];
Alice.Security.Cryptography.Speck.Speck128256Decrypt(pt2, ct, rk);
//The decrypted data. It should match the original data.
for (int i = 0; i < pt2.Length; ++i)
    Console.WriteLine($"pt2[{i}]={pt2[i]:X8}");
var pt2Bytes = Alice.Security.Cryptography.Speck.ToBytes(pt2);
Console.WriteLine($"Decrypted: {Convert.ToHexString(pt2Bytes)}");
Console.WriteLine($"Plaintext: {Convert.ToHexString(ptBytes)}");
