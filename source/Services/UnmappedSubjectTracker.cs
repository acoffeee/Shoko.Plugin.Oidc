using System;
using System.Collections.Generic;
using System.Linq;

namespace Shoko.Plugin.Oidc.Services;

/// <summary>
///   Remembers the subjects that signed in at the identity provider but are
///   not mapped to a Shoko user, so an admin can map them without digging the
///   subject out of a log.
/// </summary>
/// <remarks>
///   Kept in memory, and only the most recent ones.
/// </remarks>
public sealed class UnmappedSubjectTracker
{
    private const int MaxEntries = 50;

    private readonly object _lock = new();

    private readonly Dictionary<string, UnmappedSubject> _entries = new(StringComparer.Ordinal);

    /// <summary>
    ///   Records a sign-in by a subject that is not mapped.
    /// </summary>
    public void Record(OidcIdentity identity, DateTime now)
    {
        lock (_lock)
        {
            if (_entries.TryGetValue(identity.Subject, out var existing))
            {
                _entries[identity.Subject] = existing with
                {
                    PreferredUsername = identity.PreferredUsername ?? existing.PreferredUsername,
                    Name = identity.Name ?? existing.Name,
                    Email = identity.Email ?? existing.Email,
                    LastSeenAt = now,
                    Attempts = existing.Attempts + 1,
                };
                return;
            }

            if (_entries.Count >= MaxEntries)
                _entries.Remove(_entries.Values.MinBy(entry => entry.LastSeenAt)!.Subject);
            _entries[identity.Subject] = new(identity.Subject, identity.PreferredUsername, identity.Name, identity.Email, now, now, 1);
        }
    }

    /// <summary>
    ///   Gets the subjects seen, the most recent first.
    /// </summary>
    public IReadOnlyList<UnmappedSubject> GetAll()
    {
        lock (_lock)
            return _entries.Values.OrderByDescending(entry => entry.LastSeenAt).ToList();
    }

    /// <summary>
    ///   Forgets a subject, once it is mapped or dismissed.
    /// </summary>
    public bool Remove(string subject)
    {
        lock (_lock)
            return _entries.Remove(subject);
    }
}

/// <summary>
///   A subject that signed in without being mapped.
/// </summary>
/// <param name="Subject">The <c>sub</c> claim.</param>
/// <param name="PreferredUsername">The <c>preferred_username</c> claim, if the provider shared it.</param>
/// <param name="Name">The <c>name</c> claim, if the provider shared it.</param>
/// <param name="Email">The <c>email</c> claim, if the provider shared it.</param>
/// <param name="FirstSeenAt">When the subject first tried to sign in.</param>
/// <param name="LastSeenAt">When the subject last tried to sign in.</param>
/// <param name="Attempts">How often the subject tried to sign in.</param>
public sealed record UnmappedSubject(
    string Subject,
    string? PreferredUsername,
    string? Name,
    string? Email,
    DateTime FirstSeenAt,
    DateTime LastSeenAt,
    int Attempts
);
