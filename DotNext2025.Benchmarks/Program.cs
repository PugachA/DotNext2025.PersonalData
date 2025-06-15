using BenchmarkDotNet.Running;
using DotNext2025.Benchmarks.Benchmarks;
using DotNext2025.Benchmarks.Examples;

//AesExample.Run();
//RsaExample.Run();
//await VaultExample.Run();
//await JweExample.Run();

try
{
    BenchmarkRunner.Run<AesVsRsaBenchmark>();
}
catch (Exception e)
{
    Console.WriteLine(e);
}
