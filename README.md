# AwsSignature
## Library for easy creation of AWS signature

[![NuGet version](http://img.shields.io/nuget/v/AwsSignature.svg)](https://www.nuget.org/packages/AwsSignature/)
[![NuGet downloads](http://img.shields.io/nuget/dt/AwsSignature.svg)](https://www.nuget.org/packages/AwsSignature/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/HOHLAND-CblP/AwsSignature/refs/heads/main/LICENSE)


## How to use AwsSignature library

Use method with parameters. This function will return a dictionary of headers required to be added to the request.
```csharp
using AwsSignature;

Dictionary<string, string> headers = AwsSignautureV4.ComputeSignature(new Uri("https://bucket.s3.amazonaws.com/photo1.jpg",
    HttpMethod.Get, "s3", "ACCESS_KEY", "SECRET_KEY");
```
What parameters are used in the method:

| Parameter          | Type                          | Description                                                               | Default             |
|--------------------|-------------------------------|---------------------------------------------------------------------------|---------------------|
| `uri`              | `Uri`                         | Full request URI (e.g., `https://bucket.s3.amazonaws.com/photo1.jpg`)     | **Required**        |
| `httpMethod`       | `HttpMethod`                  | HTTP method (`HttpMethod.Get`, `HttpMethod.Post`, `HttpMethod.Put`, etc.) | **Required**        |
| `service`          | `string`                      | Target service identifier (e.g., `s3`, `ec2`)                             | **Required**        |
| `accessKey`        | `string`                      | AWS access key                                                            | **Required**        |
| `secretKey`        | `string`                      | AWS secret key                                                            | **Required**        |
| `region`           | `string`                      | AWS-like region identifier                                                | `"default"`         |
| `headers`          | `Dictionary<string, string>`  | Additional headers to include in the signature                            | `empty dictionary`  |
| `bodyHash`         | `string`                      | SHA-256 hash of the request body                                          | `EMPTY_BODY_SHA256` |
| `unsignedPayload`  | `bool`                        | Skip payload signing                                                      | `false`             |

You can also use the method with a request:

```csharp
using AwsSignature;

Dictionary<string, string> headers = AwsSignautureV4.ComputeSignature(
    new ComputeSignatureV4Request
    {
        Uri = new Uri("https://bucket.s3.amazonaws.com/photo1.jpg"),
        HttpMethod = HttpMethod.Get,
        Service = "s3",
        AwsAccessKey = "ACCESS_KEY",
        AwsSecretKey = "SECRET_KEY",
        Region = "default",
        Headers = new Dictionary<string, string>(),
        BodyHash = AwsSignautureV4.EMPTY_BODY_SHA256,
        UnsignedPayload = false
    });
```

What parameters does ComputeSignatureV4Request have:

| Parameter         | Type                          | Description                                                               | Default             |
|-------------------|-------------------------------|---------------------------------------------------------------------------|---------------------|
| `Uri`             | `Uri`                         | Full request URI (e.g., `https://bucket.s3.amazonaws.com/photo1.jpg`)     | **Required**        |
| `HttpMethod`      | `HttpMethod`                  | HTTP method (`HttpMethod.Get`, `HttpMethod.Post`, `HttpMethod.Put`, etc.) | **Required**        |
| `Service`         | `string`                      | Target service identifier (e.g., `s3`, `ec2`)                             | **Required**        |
| `AccessKey`       | `string`                      | AWS access key                                                            | **Required**        |
| `SecretKey`       | `string`                      | AWS secret key                                                            | **Required**        |
| `Region`          | `string`                      | AWS-like region identifier                                                | `"default"`         |
| `Headers`         | `Dictionary<string, string>`  | Additional headers to include in the signature                            | `empty dictionary`  |
| `BodyHash`        | `string`                      | SHA-256 hash of the request body                                          | `EMPTY_BODY_SHA256` |
| `UnsignedPayload` | `bool`                        | Skip payload signing                                                      | `false`             |
