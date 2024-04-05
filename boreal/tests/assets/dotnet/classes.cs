public class Public {
    public virtual void mPublic() {}
}

class Outer {
    class NestedNaked {}
    public abstract class NestedPublic {}
    private interface NestedPrivate {}
    sealed internal class NestedInternal {}

    class Inner {
        protected interface NestedProtected {}
        private protected class NestedPrivateProtected {}
        protected internal interface NestedProtectedInternal {}
    }

    interface Iface1 {}
    private interface Iface2 {}

    sealed class Grandchild : NestedNaked, Iface2, Iface1 {}
}

abstract class All : Public {
    static All() {}
    All() {}

    static void mNaked() {}
    public sealed override void mPublic() {}
    private void mPrivate() {}
    internal abstract void mInternal();
    protected virtual void mProtected() {}
    private protected void mPrivateProtected() {}
    protected internal static void mProtectedInternal() {}
}
