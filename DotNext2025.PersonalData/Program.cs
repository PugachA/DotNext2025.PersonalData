using Confluent.Kafka;
using Confluent.Kafka.SyncOverAsync;
using DotNext2025.PersonalData;
using DotNext2025.PersonalData.Core;
using DotNext2025.PersonalData.Cryptography.Vault;
using DotNext2025.PersonalData.Kafka;
using Microsoft.Extensions.Logging;
using System.Text.Json;
using VaultSharp.V1.AuthMethods.Token;

var options = new JsonSerializerOptions
{
    WriteIndented = true
};

var loggerFactory = LoggerFactory.Create(b => b.AddConsole());
var logger = loggerFactory.CreateLogger("Main");
var vaultConfig = new CachedVaultConfig
{
    VaultServer = "http://localhost:8201",
    MountPoint = "transit",
    Timeout = TimeSpan.FromSeconds(30),
    LatestKeyCacheExpiration = TimeSpan.FromHours(1)
};
var authMethod = new TokenAuthMethodInfo("00000000-0000-0000-0000-000000000000");
var kmsProvider = VaultKmsProviderFactory.CreateCachedProvider(vaultConfig, authMethod, loggerFactory);

var topic = "Order.v1";
var producerConfig = new ProducerConfig()
{
    BootstrapServers = "127.0.0.1:15000",
    SecurityProtocol = SecurityProtocol.Plaintext,
    Acks = Acks.All
};
var valueSerializer = new EncryptedKafkaJsonSerializer<Order>(kmsProvider);
var producerBuilder = new ProducerBuilder<string, Order>(producerConfig)
    .SetKeySerializer(Serializers.Utf8)
    .SetValueSerializer(valueSerializer);

var producer = producerBuilder.Build();

var customer = Fakers.Order.Generate();
var message = new Message<string, Order>
{
    Key = customer.GetKey().ToString(),
    Value = customer
};
await producer.ProduceAsync(topic, message);

var consumerGroup = Guid.NewGuid().ToString();
var consumerConfig = new ConsumerConfig
{
    BootstrapServers = "127.0.0.1:15000",
    AutoOffsetReset = AutoOffsetReset.Earliest,
    EnableAutoCommit = false,
    GroupId = consumerGroup
};

var valueDeserializer = new EncryptedKafkaJsonDeserializer<Order>(kmsProvider);
var consumerBuilder = new ConsumerBuilder<string, Order>(consumerConfig)
    .SetKeyDeserializer(Deserializers.Utf8)
    .SetValueDeserializer(new SyncOverAsyncDeserializer<Order>(valueDeserializer!));

var consumer = consumerBuilder.Build();
consumer.Subscribe(topic);
logger.LogInformation($"Connect to {consumerConfig.BootstrapServers} Topic: {topic}");

while (true)
{
    var result = consumer.Consume();
    logger.LogInformation(JsonSerializer.Serialize(result.Message.Value, options));
}

//БД
//1. Параметры храним в отдельной таблице. Делаем перешифровку по параметрам
// Удобно использовать когда данные не перекладываются в другие таблицы
//2. Параметры храним внутри данных и в отдельной таблице. Таблицу используем для перешифровки, а параметры внутри данных для расшифровки.
// Удобно когда нужно дальше использовать данные в ETL процессах.
// Удобно но занимает больше места