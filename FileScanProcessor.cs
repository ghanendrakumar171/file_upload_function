using System;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Azure.Data.Tables;
using Azure.Messaging.EventGrid;
using Azure.Storage.Blobs;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace AIExploration.FileScan.Functions
{
    public class FileScanEventHandler
    {
        private readonly ILogger _logger;
        private readonly BlobServiceClient _blobServiceClient;
        private readonly TableClient _tableClient;

        private readonly string quarantineContainer = "quarantine";
        private readonly string cleanContainer = "clean";
        private readonly string maliciousContainer = "malicious";

        public FileScanEventHandler(
            ILoggerFactory loggerFactory,
            BlobServiceClient blobServiceClient,
            TableClient tableClient)
        {
            _logger = loggerFactory.CreateLogger<FileScanEventHandler>();
            _blobServiceClient = blobServiceClient;
            _tableClient = tableClient;

            // CHECK TABLE ACCESS 

            try
            {
                _tableClient.CreateIfNotExists();
                _logger.LogInformation("Connected to Azure Table Storage. Using table: {TableName}", _tableClient.Name);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Could not access Azure Table Storage. Reason: {Message}", ex.Message);
            }
        }

        [Function("FileScanEventHandler")]
        public async Task RunAsync([EventGridTrigger] EventGridEvent eventGridEvent)
        {
            string eventType = eventGridEvent.EventType;
            _logger.LogInformation("Event Triggered ===== {EventType}", eventType);

            string rawJson = eventGridEvent.Data.ToString();
            _logger.LogInformation("===== RAW EVENT JSON START =====");
            _logger.LogInformation(rawJson);
            _logger.LogInformation("===== RAW EVENT JSON END =====");

            using var doc = JsonDocument.Parse(rawJson);
            var root = doc.RootElement;

            // BLOB CREATED === Insert Pending Table Entry

            if (eventType == "Microsoft.Storage.BlobCreated")
            {
                if (!eventGridEvent.Subject.Contains($"/containers/{quarantineContainer}/"))
                {
                    _logger.LogWarning("Skipping non-quarantine upload event");
                    return;
                }

                string blobUrl = root.GetProperty("url").GetString();
                _logger.LogInformation("Blob URL: {BlobUrl}", blobUrl);

                var uri = new Uri(blobUrl);
                string blobPath = Uri.UnescapeDataString(string.Join("", uri.Segments.Skip(2)));
                _logger.LogInformation("Blob Path: {BlobPath}", blobPath);

                var parts = blobPath.Split('/', 2);
                string fileId = parts[0];
                string fileName = parts.Length > 1 ? parts[1] : "unknown";

                _logger.LogInformation("fileId: {fileId}", fileId);

                // Create Pending Table Entry

                var entity = new TableEntity("Files", fileId)
                {
                    { "FileId", fileId },
                    { "FileName", fileName },
                    { "BlobPath", blobPath },
                    { "Container", quarantineContainer },
                    { "ScanStatus", "Pending" },
                    { "Message", "Waiting for Defender scan" },
                    { "CreatedAt", DateTime.UtcNow }
                };

                await _tableClient.UpsertEntityAsync(entity);
                _logger.LogInformation("Table entry created for fileId={FileId}", fileId);

                return;
            }

            
            // DEFENDER RESULT === Update Table + Move Blob

            if (eventType == "Microsoft.Security.MalwareScanningResult")
            {
                _logger.LogInformation("🛡 Defender Scan Result Received");

                string blobUri = root.GetProperty("blobUri").GetString();
                string scanResult = root.GetProperty("scanResultType").GetString();

                _logger.LogInformation("Blob URI: {BlobUri}", blobUri);
                _logger.LogInformation("Scan Result: {ScanResult}", scanResult);

                if (!blobUri.Contains($"/{quarantineContainer}/"))
                {
                    _logger.LogWarning("Blob not found in quarantine — skipping");
                    return;
                }

                var uri = new Uri(blobUri);
                string blobPath = Uri.UnescapeDataString(string.Join("", uri.Segments.Skip(2)));
                _logger.LogInformation("Decoded Path: {BlobPath}", blobPath);

                var parts = blobPath.Split('/', 2);
                string fileId = parts[0];
                string fileName = parts.Length > 1 ? parts[1] : "unknown";

                bool isMalicious =
                    scanResult.Contains("Malicious", StringComparison.OrdinalIgnoreCase) ||
                    scanResult.Contains("Threat available", StringComparison.OrdinalIgnoreCase);

                string destination = isMalicious ? maliciousContainer : cleanContainer;
                string finalStatus = isMalicious ? "Malicious" : "Clean";

                _logger.LogInformation("Final Status = {FinalStatus}, Destination = {Destination}", finalStatus, destination);

                // Move Blob
                await MoveBlobAsync(blobPath, quarantineContainer, destination);

                // Update Table Entry
                var updatedEntity = new TableEntity("Files", fileId)
                {
                    { "FileId", fileId },
                    { "FileName", fileName },
                    { "BlobPath", blobPath },
                    { "Container", destination },
                    { "ScanStatus", finalStatus },
                    { "Message", scanResult },
                    { "UpdatedAt", DateTime.UtcNow }
                };

                await _tableClient.UpsertEntityAsync(updatedEntity);
                _logger.LogInformation("Table updated for fileId={FileId}", fileId);

                return;
            }

            _logger.LogWarning("Skipping unsupported event type: {EventType}", eventType);
        }

        // COPY , DELETE (Move Blob)

        private async Task MoveBlobAsync(string blobPath, string from, string to)
        {
            var source = _blobServiceClient.GetBlobContainerClient(from);
            var dest = _blobServiceClient.GetBlobContainerClient(to);

            await dest.CreateIfNotExistsAsync();

            var srcBlob = source.GetBlobClient(blobPath);
            var destBlob = dest.GetBlobClient(blobPath);

            _logger.LogInformation("Moving blob from {From} → {To}", from, to);

            await destBlob.StartCopyFromUriAsync(srcBlob.Uri);
            await srcBlob.DeleteIfExistsAsync();

            _logger.LogInformation("Blob move completed");
        }
    }
}
