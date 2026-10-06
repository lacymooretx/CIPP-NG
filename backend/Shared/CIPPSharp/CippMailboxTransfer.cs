#nullable enable
using System;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;

namespace CIPP
{
    // =====================================================================
    // CippMailboxTransfer
    // =====================================================================
    // Moves one mailbox item from a Graph exportItems call to a mailbox
    // import session without ever turning the item into a .NET string.
    //
    // Why this exists: the export returns the item as base64 inside JSON, and
    // the stream runs far beyond the item's reported size. Through
    // Invoke-RestMethod/ConvertFrom-Json each item existed as the response
    // string, the parsed property, the import body string and its UTF-8 bytes
    // - roughly 7x the base64 length, UTF-16 doubling most of it. On the B2
    // plan (3.5 GB, shared with the rest of CIPP) three copy lanes ran out of
    // memory on archives with attachments (3E, 2026-10-05).
    //
    // Here the response is read once into a byte buffer. The export answers
    //   {...,"value":[{"itemId":"..","changeKey":"..","data":"BASE64"}]}   (compact JSON)
    // and the import wants
    //   {"FolderId":"..","Mode":"create","Data":"BASE64"}
    // so the import prefix is written into the bytes just before BASE64 and
    // the request is sent straight from that slice: `"}` already follows the
    // closing quote. Peak memory is about one copy of the base64, in bytes.
    // When the layout differs (no room before the data, other field order)
    // it falls back to one extra copy.
    // =====================================================================
    public sealed class MailboxExport
    {
        public bool    HasData     { get; internal set; }
        public int     StatusCode  { get; internal set; }
        /// <summary>Response text when there is no item data (errors, redirects, empty value).</summary>
        public string  Body        { get; internal set; } = string.Empty;
        public double  RetryAfterSeconds { get; internal set; }
        public long    DataLength  { get; internal set; }

        internal byte[]? Buffer;
        internal int     Offset;
        internal int     Count;

        /// <summary>Drops the item bytes as soon as the import is done.</summary>
        public void Release() { Buffer = null; Count = 0; }
    }

    public sealed class MailboxImportResult
    {
        public bool    Success     { get; internal set; }
        public int     StatusCode  { get; internal set; }
        public string  Body        { get; internal set; } = string.Empty;
        public double  RetryAfterSeconds { get; internal set; }
    }

    public static class CippMailboxTransfer
    {
        // One client for the process: sockets are pooled, and long timeouts cover 150 MB items.
        private static readonly HttpClient Client = new HttpClient { Timeout = TimeSpan.FromMinutes(20) };
        private static readonly byte[] DataKey = Encoding.ASCII.GetBytes("\"data\"");

        /// <summary>Exports one item and stages it for import into <paramref name="folderId"/>.</summary>
        public static MailboxExport Export(string exportUri, string authorization, string itemId, string folderId)
            => Export(exportUri, authorization, itemId, folderId, 0);

        /// <summary>
        /// As above, abandoning the call after <paramref name="timeoutSeconds"/> (0 = client default). The copy
        /// activity passes the time left before Craft kills the task (Worker:BgTimeoutSeconds, 1200s), so a
        /// slow call ends in a catchable timeout instead of a killed task that never records its progress.
        /// </summary>
        public static MailboxExport Export(string exportUri, string authorization, string itemId, string folderId, int timeoutSeconds)
        {
            using var cts = timeoutSeconds > 0 ? new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds)) : new CancellationTokenSource();
            var result = new MailboxExport();
            using var request = new HttpRequestMessage(HttpMethod.Post, exportUri);
            request.Headers.TryAddWithoutValidation("Authorization", authorization);
            request.Content = new StringContent("{\"itemIds\":[\"" + itemId + "\"]}", Encoding.UTF8, "application/json");

            byte[] buffer;
            int length;
            using (var response = Client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token).GetAwaiter().GetResult())
            {
                result.StatusCode = (int)response.StatusCode;
                result.RetryAfterSeconds = RetryAfter(response);
                if (!response.IsSuccessStatusCode)
                {
                    result.Body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                    return result;
                }
                long? declared = response.Content.Headers.ContentLength;
                using var ms = declared.HasValue && declared.Value < int.MaxValue ? new MemoryStream((int)declared.Value) : new MemoryStream();
                using (var stream = response.Content.ReadAsStreamAsync(cts.Token).GetAwaiter().GetResult()) { stream.CopyToAsync(ms, cts.Token).GetAwaiter().GetResult(); }
                buffer = ms.GetBuffer();
                length = (int)ms.Length;
            }

            int start = FindDataValue(buffer, length);
            if (start < 0)
            {
                // No item data: an error entry, an archive redirect, or an empty value array.
                result.Body = Encoding.UTF8.GetString(buffer, 0, Math.Min(length, 65536));
                return result;
            }
            int end = Array.IndexOf(buffer, (byte)'"', start, length - start);
            if (end < 0)
            {
                result.Body = "Export response was cut off inside the item data.";
                return result;
            }
            result.DataLength = end - start;

            byte[] prefix = Encoding.UTF8.GetBytes("{\"FolderId\":\"" + folderId + "\",\"Mode\":\"create\",\"Data\":\"");
            bool inPlace = start >= prefix.Length && end + 1 < length && buffer[end + 1] == (byte)'}';
            if (inPlace)
            {
                // Overwrite the export's own fields just before the data with the import prefix; the
                // closing `"}` is already there. No second copy of the item.
                System.Buffer.BlockCopy(prefix, 0, buffer, start - prefix.Length, prefix.Length);
                result.Buffer = buffer;
                result.Offset = start - prefix.Length;
                result.Count = prefix.Length + (end - start) + 2;
            }
            else
            {
                var body = new byte[prefix.Length + (end - start) + 2];
                System.Buffer.BlockCopy(prefix, 0, body, 0, prefix.Length);
                System.Buffer.BlockCopy(buffer, start, body, prefix.Length, end - start);
                body[^2] = (byte)'"';
                body[^1] = (byte)'}';
                result.Buffer = body;
                result.Offset = 0;
                result.Count = body.Length;
            }
            result.HasData = true;
            return result;
        }

        /// <summary>Posts a staged item to a (pre-authenticated) import URL. Safe to call again on retry.</summary>
        public static MailboxImportResult Import(MailboxExport item, string importUrl) => Import(item, importUrl, 0);

        /// <summary>As above, abandoning the call after <paramref name="timeoutSeconds"/> (0 = client default).</summary>
        public static MailboxImportResult Import(MailboxExport item, string importUrl, int timeoutSeconds)
        {
            using var cts = timeoutSeconds > 0 ? new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds)) : new CancellationTokenSource();
            var result = new MailboxImportResult();
            if (!item.HasData || item.Buffer == null)
            {
                result.Body = "No exported data to import.";
                return result;
            }
            using var request = new HttpRequestMessage(HttpMethod.Post, importUrl);
            var content = new ByteArrayContent(item.Buffer, item.Offset, item.Count);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            request.Content = content;
            using var response = Client.SendAsync(request, cts.Token).GetAwaiter().GetResult();
            result.StatusCode = (int)response.StatusCode;
            result.Success = response.IsSuccessStatusCode;
            result.RetryAfterSeconds = RetryAfter(response);
            if (!result.Success) { result.Body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult(); }
            return result;
        }

        private static double RetryAfter(HttpResponseMessage response)
        {
            var header = response.Headers.RetryAfter;
            if (header == null) { return 0; }
            if (header.Delta.HasValue) { return header.Delta.Value.TotalSeconds; }
            if (header.Date.HasValue) { return Math.Max(0, (header.Date.Value - DateTimeOffset.UtcNow).TotalSeconds); }
            return 0;
        }

        /// <summary>Index of the first character of the "data" string value, tolerating JSON whitespace; -1 if absent.</summary>
        internal static int FindDataValue(byte[] buffer, int length)
        {
            int from = 0;
            while (true)
            {
                int key = IndexOf(buffer, length, DataKey, from);
                if (key < 0) { return -1; }
                int i = SkipSpace(buffer, length, key + DataKey.Length);
                if (i < length && buffer[i] == (byte)':')
                {
                    i = SkipSpace(buffer, length, i + 1);
                    if (i < length && buffer[i] == (byte)'"') { return i + 1; }
                }
                from = key + DataKey.Length;
            }
        }

        private static int SkipSpace(byte[] buffer, int length, int i)
        {
            while (i < length && (buffer[i] == (byte)' ' || buffer[i] == (byte)'\t' || buffer[i] == (byte)'\r' || buffer[i] == (byte)'\n')) { i++; }
            return i;
        }

        internal static int IndexOf(byte[] haystack, int length, byte[] needle, int from)
        {
            return haystack.AsSpan(from, length - from).IndexOf(needle) is var i && i >= 0 ? i + from : -1;
        }
    }
}
