public class Test
{
    unsafe void foo(
        // 16 pointers, below the recursive limit
        int *** *** *** *** *** *a,
        // 17 pointers, above  the recursive limit
        int *** *** *** *** *** **b
    ) {}
}
