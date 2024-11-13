
namespace AwsSignature;

public class ComputeSignatureRequest
{
    public Uri Uri { get; init; }
    public HttpMethodEnum HttpMethod { get; init; }
    public string Service { get; init; }
    public string Region { get; init; } = "default";
    public Dictionary<string, string> Headers { get; init; }
    public string QueryParameters { get; init; }
    public string BodyHash { get; init; }
    public string AwsAccessKey {get; init; }
    public string AwsSecretKey {get; init; }
}