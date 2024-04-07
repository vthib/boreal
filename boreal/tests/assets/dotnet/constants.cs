extern alias MyClasses;

using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;

// ExportedType table
[assembly:TypeForwardedToAttribute(typeof(MyClasses::Public))]

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

// All the rest is unused for the moment, but declares tables in the final
// binary that needs to be properly parsed to parse everything properly.

// FieldMarshall table
class Program
{
    public void M1([MarshalAs(UnmanagedType.LPWStr)]string msg) {}

    class MsgText {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string msg = "Hello World";
    }
}

// FieldLayout table
[StructLayout(LayoutKind.Explicit)]
public struct SYSTEM_INFO
{
    [FieldOffset(16)] public ulong OemId;
    [FieldOffset(8)] public ulong PageSize;
    [FieldOffset(32)] public ulong ActiveProcessorMask;
    [FieldOffset(24)] public ulong NumberOfProcessors;
    [FieldOffset(0)] public ulong ProcessorType;
}

// Event + EventMap + MethodSpec table
public class Publisher
{
    public delegate void EventHandler(object sender);

    public event EventHandler FirstEvent;
    public event EventHandler SecondEvent;
}

// MethodImpl table
interface Iface1 {
    public abstract void foo();
}
interface Iface2 {
    public abstract void foo();
}
class MethodImpl : Iface1, Iface2 {
    void Iface1.foo() {}
    void Iface2.foo() {}
}

// ImplMap table
public class ImplMap {
    [DllImport(@"kernel32.dll")]
    public static extern int GetProcessId(int process);
}

// GenericParamConstraint Table
interface GPCI {}
class GPC1<C> where C: GPCI {}
class GPC2<C> where C: GPCI {}
