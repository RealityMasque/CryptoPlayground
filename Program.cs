using System.Security.Cryptography;
using System.Text;

string message = "Hello, World!";
Console.WriteLine();
Console.WriteLine($"Message: {message}");
Console.WriteLine();
Console.WriteLine();

Console.WriteLine("Generate RSA keys, sign message, and verify signatures");
Console.WriteLine("======================================================================");
Console.WriteLine();

using RSA rsa = RSA.Create(2048);
string publicKey = rsa.ToXmlString(false);
string privateKey = rsa.ToXmlString(true);
byte[] rsaMessageBytes = Encoding.UTF8.GetBytes(message);
byte[] signature = rsa.SignData(rsaMessageBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
bool isValid = rsa.VerifyData(rsaMessageBytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

Console.WriteLine($"Public Key: {publicKey}");
Console.WriteLine();

Console.WriteLine($"Private Key: {privateKey}");
Console.WriteLine();

Console.WriteLine($"Signature: {Convert.ToBase64String(signature)}");
Console.WriteLine();

Console.WriteLine($"Is the signature valid? {isValid}");
Console.WriteLine();
Console.WriteLine();



using Aes aes = Aes.Create();
aes.KeySize = 256;
byte[] aesKey = aes.Key;
byte[] aesIV = aes.IV;
byte[] encryptedMessage;
using(ICryptoTransform encryptor = aes.CreateEncryptor())
{
    byte[] aesMessageBytes = Encoding.UTF8.GetBytes(message);
    encryptedMessage = encryptor.TransformFinalBlock(aesMessageBytes, 0, aesMessageBytes.Length);
}
byte[] encryptedAesKey = rsa.Encrypt(aesKey, RSAEncryptionPadding.Pkcs1);
byte[] decryptedAesKey = rsa.Decrypt(encryptedAesKey, RSAEncryptionPadding.Pkcs1);
byte[] decryptedMessage;
using(Aes aesForDecrypt = Aes.Create())
{
    aesForDecrypt.Key = decryptedAesKey;
    aesForDecrypt.IV = aesIV;

    using(ICryptoTransform decryptor = aesForDecrypt.CreateDecryptor())
    {
        decryptedMessage = decryptor.TransformFinalBlock(encryptedMessage, 0, encryptedMessage.Length);
    }
}

Console.WriteLine("Generate AES key, encrypt/decrypt AES Key, and encrypt/decrypt message");
Console.WriteLine("======================================================================");
Console.WriteLine();

Console.WriteLine($"AES Key: {Convert.ToBase64String(aesKey)}");
Console.WriteLine($"AES IV: {Convert.ToBase64String(aesIV)}");
Console.WriteLine();

Console.WriteLine($"Encrypted Message (AES): {Convert.ToBase64String(encryptedMessage)}");
Console.WriteLine();

Console.WriteLine($"Encrypted AES Key (RSA): {Convert.ToBase64String(encryptedAesKey)}");
Console.WriteLine();

Console.WriteLine($"Decrypted AES Key: {Convert.ToBase64String(decryptedAesKey)}");
Console.WriteLine();

Console.WriteLine($"Decrypted Message: {Encoding.UTF8.GetString(decryptedMessage)}");
Console.WriteLine();
