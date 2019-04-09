var body = "test body";
var YourPrivateRSA = UtilLib.PemKey.GetRSAProviderFromPemFileName ("../../priv/private.pem");
var signedBody = YourPrivateRSA.SignData(Encoding.UTF8.GetBytes(body), CryptoConfig.MapNameToOID("SHA256"));
var signature = System.Convert.ToBase64String(signedBody);
Console.WriteLine($"The signature done with Your private key is:\n\r{signature}.");

var YourPublicRSA = UtilLib.PemKey.GetRSAProviderFromPemFileName ("../../priv/public.pub");

var decoded_signature = System.Convert.FromBase64String(signature);
var valid = YourPublicRSA.VerifyData(Encoding.UTF8.GetBytes(body), CryptoConfig.MapNameToOID("SHA256"), decoded_signature);
Console.WriteLine($"signature is valid: \r{valid}");
