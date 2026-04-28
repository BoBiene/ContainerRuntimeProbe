using ContainerRuntimeProbe.Internal;

namespace ContainerRuntimeProbe.Tests;

public sealed class RedactionTests
{
    [Theory]
    [InlineData("TOKEN")]
    [InlineData("SECRET")]
    [InlineData("PASSWORD")]
    [InlineData("PASSWD")]
    [InlineData("PRIVATE")]
    [InlineData("KEY")]
    [InlineData("CERT")]
    [InlineData("CONNECTIONSTRING")]
    [InlineData("CONNECTION_STRING")]
    [InlineData("AUTHORIZATION")]
    [InlineData("COOKIE")]
    [InlineData("CREDENTIAL")]
    [InlineData("SAS")]
    public void IsSensitiveKey_RecognizesSecretPatterns(string keyFragment)
    {
        Assert.True(Redaction.IsSensitiveKey(keyFragment));
        Assert.True(Redaction.IsSensitiveKey(keyFragment.ToLowerInvariant()));
        Assert.True(Redaction.IsSensitiveKey($"MY_{keyFragment}_VALUE"));
    }

    [Theory]
    [InlineData("HOSTNAME")]
    [InlineData("KUBERNETES_SERVICE_HOST")]
    [InlineData("K_SERVICE")]
    [InlineData("CONTAINER_APP_NAME")]
    [InlineData("AWS_REGION")]
    public void IsSensitiveKey_DoesNotFlagPublicKeys(string key)
    {
        Assert.False(Redaction.IsSensitiveKey(key));
    }

    [Fact]
    public void MaybeRedact_RedactsSensitiveByDefault()
    {
        var result = Redaction.MaybeRedact("MY_SECRET_KEY", "super-secret-value", includeSensitive: false);
        Assert.Equal("<redacted>", result);
    }

    [Fact]
    public void MaybeRedact_RevealsWhenIncludeSensitiveTrue()
    {
        var result = Redaction.MaybeRedact("MY_SECRET_KEY", "super-secret-value", includeSensitive: true);
        Assert.Equal("super-secret-value", result);
    }

    [Fact]
    public void MaybeRedact_DoesNotRedactPublicKeys()
    {
        var result = Redaction.MaybeRedact("HOSTNAME", "my-host", includeSensitive: false);
        Assert.Equal("my-host", result);
    }

    [Fact]
    public void MaybeRedact_NullValue_ReturnsNull()
    {
        var result = Redaction.MaybeRedact("MY_TOKEN", null, includeSensitive: false);
        Assert.Null(result);
    }
}
