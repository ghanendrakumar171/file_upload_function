using Azure.Data.Tables;
using Azure.Storage.Blobs;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = FunctionsApplication.CreateBuilder(args);

// Configuration
builder.ConfigureFunctionsWebApplication();

// Register BlobServiceClient using AzureWebJobsStorage connection string
builder.Services.AddSingleton(sp =>
{
    var config = sp.GetRequiredService<IConfiguration>();
    var connString = config["AzureWebJobsStorage"] ?? throw new InvalidOperationException("AzureWebJobsStorage not configured");
    return new BlobServiceClient(connString);
});

// Register TableClient for table "FileScans" (will be created if missing at runtime)
builder.Services.AddSingleton(sp =>
{
    var config = sp.GetRequiredService<IConfiguration>();
    var connString = config["AzureWebJobsStorage"] ?? throw new InvalidOperationException("AzureWebJobsStorage not configured");
    var tableName = config["FileScanTableName"] ?? "FileScanStatus";
    var client = new TableClient(connString, tableName);
    // create table if not exists (safe to call repeatedly)
    client.CreateIfNotExists();
    return client;
});

// Application Insights
builder.Services
    .AddApplicationInsightsTelemetryWorkerService()
    .ConfigureFunctionsApplicationInsights();

builder.Build().Run();
