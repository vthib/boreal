using System;

public class Container<C, D>
{
    public void simple(
        sbyte a,
        byte b,
        short c,
        ushort d,
        int e,
        uint f,
        long g,
        ulong h,
        char i,
        float j,
        double k,
        bool m,
        decimal n
    ) {}

    public void tptr(
        IntPtr i,
        UIntPtr u,
        object o,
        TypedReference tr
    ) {}

    public void tenum(Color color) {}
    public sbyte ttuple((int, string) tuple) { return 3; }
    public void topt(bool? b) {}
    public B generic<A, B>(B b, D d, A a, C c) { return b; }
    public object arr(int[] a, short[,] b, sbyte[,,] c, bool [,][,,,,][,,][][,,,] d) { return a; }

    unsafe static void tunsafe(int* pi1, ref int* pi2) {}
    unsafe public void tfnptr(
        delegate*<void> ip,
        delegate*<void>* fp,
        delegate*<sbyte, ref int*, IntPtr> *fp2
    ) {}
}

public enum Color : long
{
    Red,
    Green,
    Blue
}

public class MainClass
{
    static void Main() {}
}
