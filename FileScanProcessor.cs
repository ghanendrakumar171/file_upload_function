using System;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
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

        private readonly string quarantineContainer = "quarantine";
        private readonly string cleanContainer = "clean";
        private readonly string maliciousContainer = "malicious";

        public FileScanEventHandler(
            ILoggerFactory loggerFactory,
            BlobServiceClient blobServiceClient)
        {
            _logger = loggerFactory.CreateLogger<FileScanEventHandler>();
            _blobServiceClient = blobServiceClient;
        }

        [Function("FileScanEventHandler")]
        public async Task RunAsync([EventGridTrigger] EventGridEvent eventGridEvent)
        {
            string eventType = eventGridEvent.EventType;

            _logger.LogInformation("📩 Event Triggered ➝ {EventType}", eventType);

            // Dump RAW JSON
            string rawJson = eventGridEvent.Data.ToString();
            _logger.LogInformation("===== RAW EVENT JSON START =====");
            _logger.LogInformation(rawJson);
            _logger.LogInformation("===== RAW EVENT JSON END =====");

            using var doc = JsonDocument.Parse(rawJson);
            var root = doc.RootElement;

            // ========================================================
            // 1️⃣ HANDLE BLOB CREATED → WAIT FOR SCAN RESULT
            // ========================================================
            if (eventType == "Microsoft.Storage.BlobCreated")
            {
                // Only process quarantine uploads
                if (!eventGridEvent.Subject.Contains($"/containers/{quarantineContainer}/"))
                {
                    _logger.LogWarning("⏭ Skipping non-quarantine BlobCreated event.");
                    return;
                }

                string blobUrl = root.GetProperty("url").GetString();
                _logger.LogInformation("🔗 Blob URL: {BlobUrl}", blobUrl);

                var uri = new Uri(blobUrl);

                string blobPath = Uri.UnescapeDataString(string.Join("", uri.Segments.Skip(2)));
                _logger.LogInformation("📁 Quarantine Blob Path: {BlobPath}", blobPath);

                _logger.LogInformation("🕒 File uploaded → waiting for Defender scan...");
                return;
            }


            // ========================================================
            // 2️⃣ HANDLE DEFENDER SCAN RESULT EVENT
            // ========================================================
            if (eventType == "Microsoft.Security.MalwareScanningResult")
            {
                _logger.LogInformation("🛡 Defender Scan Result Event Received");

                string blobUri = root.GetProperty("blobUri").GetString();
                string scanResult = root.GetProperty("scanResultType").GetString();

                _logger.LogInformation("🔗 Blob URI: {BlobUri}", blobUri);
                _logger.LogInformation("🧪 Scan Result: {ScanResult}", scanResult);

                // ❗ Skip duplicate events where blob already moved
                if (!blobUri.Contains($"/{quarantineContainer}/"))
                {
                    _logger.LogWarning("⏭ Skipping Defender event — blob is no longer in quarantine.");
                    return;
                }

                // Decode path
                var uri = new Uri(blobUri);
                string blobPath = Uri.UnescapeDataString(string.Join("", uri.Segments.Skip(2)));

                _logger.LogInformation("📁 Decoded Blob Path: {BlobPath}", blobPath);

                // Decide clean / malicious
                bool isMalicious =
                    scanResult.Equals("Malicious", StringComparison.OrdinalIgnoreCase) ||
                    scanResult.Equals("ThreatDetected", StringComparison.OrdinalIgnoreCase);

                string destination = isMalicious ? maliciousContainer : cleanContainer;

                _logger.LogInformation("🎯 Final Decision: Moving → {Destination}", destination);

                await MoveBlobAsync(blobPath, quarantineContainer, destination);

                return;
            }


            // ========================================================
            // 3️⃣ IGNORE ALL OTHER EVENTS
            // ========================================================
            _logger.LogWarning("⏭ Skipping unsupported event type: {EventType}", eventType);
        }


        // ========================================================
        // MOVE BLOB FUNCTION (COPY + DELETE)
        // ========================================================
        private async Task MoveBlobAsync(string blobPath, string from, string to)
        {
            var source = _blobServiceClient.GetBlobContainerClient(from);
            var destination = _blobServiceClient.GetBlobContainerClient(to);

            await destination.CreateIfNotExistsAsync();

            var sourceBlob = source.GetBlobClient(blobPath);
            var destBlob = destination.GetBlobClient(blobPath);

            _logger.LogInformation("📦 Copying from {From} ➝ {To}", from, to);

            await destBlob.StartCopyFromUriAsync(sourceBlob.Uri);
            await sourceBlob.DeleteIfExistsAsync();

            _logger.LogInformation("🆗 Move complete");
        }
    }
}
