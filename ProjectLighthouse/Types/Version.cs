namespace LBPUnion.ProjectLighthouse.Types;

public struct Version
{
    public byte Major { get; set; }
    public byte Minor { get; set; }

    public Version(byte major, byte minor)
    {
        this.Major = major;
        this.Minor = minor;
    }

    public override string ToString() => $"{this.Major}.{this.Minor}";

    public static implicit operator string(Version v) => v.ToString();
}