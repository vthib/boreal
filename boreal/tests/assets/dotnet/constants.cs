public static class Globals
{
    public const int CONST_INT = 34;
    public static string MY_STATIC_STRING = "I AM STATIC";
    public static readonly string RO_STRING = "I AM readonly";
    public static byte[] rawData = {
        0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0x00, 0x00, 0x00, 0x00,
    };
}

public class Foo
{
    public int bar = 23;

    public void dot(string b = "toto") {}
    public void net(bool c = true) {}

    public string Hours
    {
        get { return "abc"; }
        set {}
    }
}

public class MainClass
{
    static void Main() {}
}
