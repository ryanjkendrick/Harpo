using Microsoft.Extensions.Configuration;

namespace Harpo.Tests;

public class FileConfigurationSecretsTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("harpo-secrets-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string WriteSecret(string name, string content)
    {
        var path = Path.Combine(_dir, name);
        File.WriteAllText(path, content);
        return path;
    }

    [Fact]
    public void File_value_lands_on_the_parent_key_trimmed()
    {
        var path = WriteSecret("master_key", "s3cret-from-file\n");
        var config = new ConfigurationManager();
        config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Harpo:MasterKey:File"] = path,
            ["Replication:Key:File"] = WriteSecret("repl_key", "  repl-secret  "),
        });

        FileConfigurationSecrets.ApplyFileIndirection(config);

        Assert.Equal("s3cret-from-file", config["Harpo:MasterKey"]);
        Assert.Equal("repl-secret", config["Replication:Key"]);
    }

    [Fact]
    public void File_indirection_overrides_an_inline_value()
    {
        var config = new ConfigurationManager();
        config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Harpo:MasterKey"] = "inline-value",
            ["Harpo:MasterKey:File"] = WriteSecret("k", "file-value"),
        });

        FileConfigurationSecrets.ApplyFileIndirection(config);

        Assert.Equal("file-value", config["Harpo:MasterKey"]);
    }

    [Fact]
    public void Missing_secret_file_fails_startup_loudly()
    {
        var config = new ConfigurationManager();
        config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Harpo:MasterKey:File"] = Path.Combine(_dir, "does-not-exist"),
        });

        var ex = Assert.Throws<InvalidOperationException>(
            () => FileConfigurationSecrets.ApplyFileIndirection(config));
        Assert.Contains("does not exist", ex.Message);
    }

    [Fact]
    public void Unrelated_keys_and_empty_file_settings_are_untouched()
    {
        var config = new ConfigurationManager();
        config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Harpo:SiteId"] = "alpha",
            ["Harpo:DatabaseKey:File"] = "",
        });

        FileConfigurationSecrets.ApplyFileIndirection(config);

        Assert.Equal("alpha", config["Harpo:SiteId"]);
        Assert.Null(config["Harpo:DatabaseKey"]);
    }
}
