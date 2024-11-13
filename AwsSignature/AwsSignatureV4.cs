using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace AwsSignature;

public class AwsSignatureV4
{
    // Constants
    public const string AWS_SCHEMA = "AWS4-HMAC-SHA256";
    public const string EMPTY_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    public const string ISO8601BasicFormat = "yyyyMMddTHHmmssZ";
    public const string DateStringFormat = "yyyyMMdd";
    public const string X_Amz_Date = "X-Amz-Date";
    public const string X_Amz_Content_SHA256 = "X-Amz-Content-Sha256";
    public const string AWS4_REQUEST = "aws4_request";
    
    
    public static string ComputeSignature(ComputeSignatureRequest request)
    {
        DateTime requestDateTime = DateTime.UtcNow;
        string dateTimeStampIso = requestDateTime.ToString(ISO8601BasicFormat, CultureInfo.InvariantCulture);
        string dateStamp = requestDateTime.ToString(DateStringFormat, CultureInfo.InvariantCulture);
        string region = request.Region;
        string service = request.Service;
        Uri uri = request.Uri;
        
        if (!request.Headers.ContainsKey("Host"))
        {
            var hostHeader = uri.Host;
            if (!uri.IsDefaultPort)
                hostHeader += ":" + uri.Port;
            request.Headers.Add("Host", hostHeader);
        }
        
        
        request.Headers.Add(X_Amz_Date, dateTimeStampIso);
        if (!request.Headers.ContainsKey(X_Amz_Content_SHA256))
            request.Headers.Add(X_Amz_Content_SHA256, request.BodyHash);

        

        string canonicalRequest = CanonicalRequest(
            request.HttpMethod.ToString(),
            CanonicalUri(uri),
            CanonicalQueryString(uri),
            CanonicalHeaders(request.Headers),
            SignedHeaders(request.Headers),
            request.BodyHash);
        
        
        string scope = $"{dateStamp}/{region}/{service}/{AWS4_REQUEST}";
        string stringToSign = $"AWS4-HMAC-SHA256\n" +
                              $"{dateTimeStampIso}\n" +
                              $"{scope}\n" +
                              $"{ToHexString(HashAlgorithm.Create("SHA256").ComputeHash(Encoding.UTF8.GetBytes(canonicalRequest)),true)}";
        

        var kha= KeyedHashAlgorithm.Create("HMACSHA256");
        kha!.Key = Encoding.UTF8.GetBytes($"AWS4{request.AwsSecretKey}");
        var dateKey = kha.ComputeHash(Encoding.UTF8.GetBytes(dateStamp));
        kha.Key = dateKey;
        var dateRegionKey = kha.ComputeHash(Encoding.UTF8.GetBytes(region));
        kha.Key = dateRegionKey;
        var dateRegionServiceKey = kha.ComputeHash(Encoding.UTF8.GetBytes(service));
        kha.Key = dateRegionServiceKey;
        var signingKey = kha.ComputeHash(Encoding.UTF8.GetBytes(AWS4_REQUEST));
        kha.Key = signingKey;
        string signature = ToHexString(kha.ComputeHash(Encoding.UTF8.GetBytes(stringToSign)), true);


        string authHeader = AWS_SCHEMA +
                            $" Credential={request.AwsAccessKey}/{dateStamp}/{region}/{service}/{AWS4_REQUEST}, " +
                            $"SignedHeaders={SignedHeaders(request.Headers)}, " +
                            $"Signature={signature}";

        return authHeader;
    }


    // TODO Make hashing function
    public static string HashBody(string body)
    {
        var sha256Hash = ComputeSha256Hash(body);
        
        
        return sha256Hash;
    }
    
    
    // =============================================================================
    // private methods

    static string ComputeSha256Hash(string rawData)
    {
        // Create a SHA256
        using (SHA256 sha256Hash = SHA256.Create())
        {
            // ComputeHash - returns byte array
            byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));

            // Convert byte array to a string
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
            {
                builder.Append(bytes[i].ToString("x2"));
            }
            return builder.ToString();
        }
    }
    
    //TODO Remake this function
    private static string UriEncode(string s)
    {
        const string validUrlCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";
        
        var encoded = new StringBuilder(s.Length * 2);
        
        string unreservedChars = String.Concat(validUrlCharacters, (true ? "/:" : ""));

        foreach (char symbol in Encoding.UTF8.GetBytes(s))
        {
            if (unreservedChars.IndexOf(symbol) != -1)
                encoded.Append(symbol);
            else
                encoded.Append("%").Append(String.Format("{0:X2}", (int)symbol));
        }
        
        
        return encoded.ToString();
    }
    
    private static string ToHexString(byte[] data, bool lowercase)
    {
        var sb = new StringBuilder();
        for (var i = 0; i < data.Length; i++)
        {
            sb.Append(data[i].ToString(lowercase ? "x2" : "X2"));
        }

        return sb.ToString();
    }
    
    private static string CanonicalRequest(string method,
                                          string canonicalUri,
                                          string canonicalQueryString,
                                          string canonicalHeaders,
                                          string signedHeaders,
                                          string hashedPayload)
    {
        var canonicalRequest = new StringBuilder();

        canonicalRequest.Append($"{method}\n");
        canonicalRequest.Append($"{canonicalUri}\n");
        canonicalRequest.Append($"{canonicalQueryString}\n");
        canonicalRequest.Append($"{canonicalHeaders}\n");
        canonicalRequest.Append($"{signedHeaders}\n");
        canonicalRequest.Append($"{hashedPayload}");
        
        return canonicalRequest.ToString();
    }

    private static string CanonicalUri(Uri uri)
    {
        if (string.IsNullOrEmpty(uri.AbsolutePath))
            return "/";

        return uri.AbsolutePath;
    }

    private static string CanonicalQueryString(Uri uri)
    {
        Dictionary<string, string> dictionary = new Dictionary<string, string>();
        string query;

        if (string.IsNullOrEmpty(uri.Query))
            return "";
        
        query = uri.Query.Substring(1);
        

        dictionary = query.Split('&').Select(p => p.Split('='))
            .ToDictionary(s => s[0],
                          s => s.Length > 1 ? s[1] : "");

        StringBuilder sb = new StringBuilder();

        List<string> keys = new List<string>(dictionary.Keys);
        keys.Sort(StringComparer.Ordinal);
        
        foreach (var key in keys)
        {
            if (sb.Length > 0)
                sb.Append('&');
            sb.Append($"{UriEncode(key)}={UriEncode(dictionary[key])}");
        }
        
        return sb.ToString();
    }

    private static string CanonicalHeaders(Dictionary<string, string> headers)
    {
        SortedDictionary<string, string> sortedDictionary = new SortedDictionary<string, string>();
        
        foreach (var header in headers.Keys)
        {
            sortedDictionary.Add(header, headers[header]);
        }
        
        StringBuilder sb = new StringBuilder();
        foreach (var header in sortedDictionary.Keys)
        {
            sb.Append($"{header.ToLower()}:{sortedDictionary[header].Trim()}\n");
        }
        
        return sb.ToString();
    }

    private static string SignedHeaders(Dictionary<string, string> headers)
    {
        List<string> sortedHeaders = new List<string>(headers.Keys);
        sortedHeaders.Sort(StringComparer.OrdinalIgnoreCase);

        StringBuilder sb = new StringBuilder();
        foreach (var header in sortedHeaders)
        {
            if (sb.Length > 1)
                sb.Append(';');
            sb.Append(header.ToLower());
        }
        return sb.ToString();
    }
}