using Microsoft.Data.Sqlite;

namespace Harpo.Data;

/// <summary>
/// Keeps a second Harpo off a database file for as long as this one runs, by holding
/// an exclusive lock on an empty file beside it. SQLite's own locks cannot do this: a
/// Harpo that opens the file while another holds it is left with a handle on the file
/// it opened, so if that one then replaces the file during a key change, the second
/// carries on writing to a file that is gone. The lock file is never replaced, so the
/// lock means the same thing to everyone. It stays on disk: removing it could leave
/// two processes holding locks on two different files. The kernel lets go of it when
/// the process ends, however it ends, including across containers sharing a volume.
/// </summary>
public sealed class DbFileLock : IDisposable
{
    public const string Suffix = ".lock";

    // What a lock held elsewhere comes back as: EAGAIN on Linux and macOS, and
    // ERROR_SHARING_VIOLATION on Windows. Anything else means the file could not be opened.
    private const int HeldOnLinux = 11;
    private const int HeldOnMac = 35;
    private const int HeldOnWindows = unchecked((int)0x80070020);

    private static readonly TimeSpan RetryEvery = TimeSpan.FromMilliseconds(250);

    private readonly FileStream? _file;

    private DbFileLock(FileStream? file) => _file = file;

    /// <summary>
    /// Takes the lock, waiting a while so that a restart does not trip over the Harpo
    /// it replaces, or throws if another Harpo goes on holding it. If the lock file
    /// cannot be written that is only logged: the volume's problems are reported better
    /// by what comes next, and SQLite's locks still stop a key change under a running site.
    /// </summary>
    public static async Task<DbFileLock> AcquireAsync(string connectionString, ILogger logger, int waitSeconds = 30)
    {
        var path = new SqliteConnectionStringBuilder(connectionString).DataSource;
        if (string.IsNullOrEmpty(path) || path == ":memory:")
        {
            return new DbFileLock(null);
        }

        var lockPath = path + Suffix;
        var deadline = TimeProvider.System.GetTimestamp() + (long)(waitSeconds * (double)TimeProvider.System.TimestampFrequency);
        var waited = false;
        while (true)
        {
            try
            {
                if (Path.GetDirectoryName(Path.GetFullPath(lockPath)) is { Length: > 0 } dir)
                {
                    Directory.CreateDirectory(dir);
                }
                var file = new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
                if (waited)
                {
                    logger.LogInformation("The other Harpo has let go of the database at '{Path}'.", path);
                }
                if (!IsHonoured(lockPath))
                {
                    logger.LogWarning(
                        "Locks on '{File}' have no effect on this filesystem, as on a Docker Desktop bind mount or some " +
                        "network shares, so nothing stops a second Harpo starting on this database. Only one Harpo may " +
                        "use a database file.", lockPath);
                }
                return new DbFileLock(file);
            }
            catch (IOException ex) when (ex.HResult is HeldOnLinux or HeldOnMac or HeldOnWindows)
            {
                if (TimeProvider.System.GetTimestamp() >= deadline)
                {
                    throw new InvalidOperationException(
                        $"Another Harpo is using the database at '{path}': it still holds '{lockPath}' after waiting " +
                        $"{waitSeconds} seconds. Only one Harpo may use a database file, so this one has not touched it. " +
                        "Stop the other one and start this one again.", ex);
                }
                if (!waited)
                {
                    waited = true;
                    logger.LogWarning(
                        "Another Harpo is using the database at '{Path}'. Waiting up to {Seconds} seconds for it to stop.",
                        path, waitSeconds);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                logger.LogWarning(
                    "Could not take the lock file '{File}' ({Error}), so nothing stops a second Harpo starting on this " +
                    "database. Only one Harpo may use a database file.", lockPath, ex.Message);
                return new DbFileLock(null);
            }
            await Task.Delay(RetryEvery);
        }
    }

    /// <summary>Some filesystems grant every lock asked for, so a lock already held is asked for again.</summary>
    private static bool IsHonoured(string lockPath)
    {
        try
        {
            using var again = new FileStream(lockPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            return false;
        }
        catch (IOException ex) when (ex.HResult is HeldOnLinux or HeldOnMac or HeldOnWindows)
        {
            return true;
        }
    }

    public void Dispose() => _file?.Dispose();
}
