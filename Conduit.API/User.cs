namespace Conduit.API;

public class User
{
    public string Email { get; set; } = string.Empty;
    public string UserName { get; set; } = string.Empty;
    public byte[] PasswordHash { get; set; }
    public byte[] PasswordSalt { get; set; }
}