using BenchmarkDotNet.Running;
using DotNext2025.Benchmarks.Benchmarks;

//AesExample.Run();
//RsaExample.Run();
//await VaultExample.Run();
//await JweExample.Run();

try
{
    BenchmarkRunner.Run<AwsVsJweVsCustomBenchmark>();
}
catch (Exception e)
{
    Console.WriteLine(e);
}
