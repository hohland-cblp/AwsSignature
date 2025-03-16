
namespace AwsSignature;

/// <summary>
/// Compute signature v4 request
/// </summary>
/// <param name="Uri">Service uri</param>
/// <param name="HttpMethod">Http request method</param>
/// <param name="Service">Aws service name. e.g. s3, ec2</param>
/// <param name="Region">Service region. Default value: "default"</param>
/// <param name="Headers">Dictionary with Content-MD5 or x-amz-* headers you want to add. Default value: empty dictionary</param>
/// <param name="BodyHash">Service region. Default value: empty body hash SHA256.</param>
/// <param name="UnsignedPayload">Set whether s3 will check payload hash. Not require. Default value: false</param>
/// <param name="AwsAccessKey">You AWS access key</param>
/// <param name="AwsSecretKey">You AWS secret key</param>
public class ComputeSignatureV4Request
{
    public Uri Uri { get; init; }
    public HttpMethod HttpMethod { get; init; }
    public string Service { get; init; }
    public string Region { get; init; } = "default";
    public Dictionary<string, string> Headers { get; init; } = new Dictionary<string, string>();
    public string BodyHash { get; init; } = AwsSignatureV4.EMPTY_BODY_SHA256;
    public bool UnsignedPayload { get; init; } = false;
    public string AwsAccessKey {get; init; }
    public string AwsSecretKey {get; init; }
}